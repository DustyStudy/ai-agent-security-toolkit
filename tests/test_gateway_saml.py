"""SAML 2.0 sign-in: the attacks the service provider must refuse, and the happy path."""

from __future__ import annotations

import asyncio
import base64
import datetime
import json
import re
import zlib
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

pytest.importorskip("signxml")
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from lxml import etree  # noqa: E402
from signxml import XMLSigner  # noqa: E402

from agentsec.gateway import ConfigError, Gateway  # noqa: E402
from agentsec.middleware.audit import MemorySink  # noqa: E402
from tests.test_gateway import FakeUpstream, chat, write_config  # noqa: E402

IDP, SP = "https://idp.corp.example/saml", "https://gw.corp.example/saml/metadata"
SSO, ACS = "https://idp.corp.example/sso", "https://gw.corp.example/saml/acs"
P, A = "urn:oasis:names:tc:SAML:2.0:protocol", "urn:oasis:names:tc:SAML:2.0:assertion"
MFA_CTX = "http://schemas.microsoft.com/claims/multipleauthn"
PWD_CTX = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"


def keypair(cn="idp"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return key_pem, cert.public_bytes(serialization.Encoding.PEM)


IDP_KEY, IDP_CERT = keypair()
EVIL_KEY, EVIL_CERT = keypair("evil")


def stamp(offset_s=0):
    t = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=offset_s)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def assertion_xml(rid, *, user="alice@corp.example", aid="_a1", issuer=IDP, audience=SP,
                  recipient=ACS, expires=300, ctx=MFA_CTX, groups=("eng",)):  # fmt: skip
    attrs = "".join(f"<saml:AttributeValue>{g}</saml:AttributeValue>" for g in groups)
    return (
        f'<saml:Assertion xmlns:saml="{A}" ID="{aid}" Version="2.0" IssueInstant="{stamp()}">'
        f"<saml:Issuer>{issuer}</saml:Issuer>"
        "<saml:Subject><saml:NameID>" + user + "</saml:NameID>"
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml:SubjectConfirmationData InResponseTo="{rid}" Recipient="{recipient}"'
        f' NotOnOrAfter="{stamp(expires)}"/></saml:SubjectConfirmation></saml:Subject>'
        f'<saml:Conditions NotBefore="{stamp(-60)}" NotOnOrAfter="{stamp(expires)}">'
        f"<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience>"
        "</saml:AudienceRestriction></saml:Conditions>"
        f'<saml:AuthnStatement AuthnInstant="{stamp()}"><saml:AuthnContext>'
        f"<saml:AuthnContextClassRef>{ctx}</saml:AuthnContextClassRef></saml:AuthnContext>"
        "</saml:AuthnStatement>"
        f'<saml:AttributeStatement><saml:Attribute Name="groups">{attrs}</saml:Attribute>'
        "</saml:AttributeStatement></saml:Assertion>"
    )


class _AnySigner(XMLSigner):
    def check_deprecated_methods(self):  # lets the test make a SHA-1 signature an IdP could
        pass


def sign(element, key=IDP_KEY, cert=IDP_CERT, alg="rsa-sha256", digest="sha256"):
    signer = _AnySigner(
        signature_algorithm=alg,
        digest_algorithm=digest,
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    )
    return signer.sign(element, key=key, cert=cert, reference_uri=element.get("ID"))


def response(rid, *, sign_assertion=True, sign_response=False, status="Success",
             tamper=None, extra="", key=IDP_KEY, alg="rsa-sha256", digest="sha256",
             **kw):  # fmt: skip
    assertion = etree.fromstring(assertion_xml(rid, **kw))
    if sign_assertion:
        assertion = sign(assertion, key=key, alg=alg, digest=digest)
    if tamper:
        tamper(assertion)
    root = etree.fromstring(
        f'<samlp:Response xmlns:samlp="{P}" xmlns:saml="{A}" ID="_r1" Version="2.0"'
        f' IssueInstant="{stamp()}" Destination="{ACS}" InResponseTo="{rid}">'
        f"<saml:Issuer>{IDP}</saml:Issuer><samlp:Status>"
        f'<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:{status}"/>'
        f"</samlp:Status>{extra}</samlp:Response>"
    )
    root.append(assertion)
    if sign_response:
        root = sign(root, key=key)
    return base64.b64encode(etree.tostring(root)).decode()


def raw_call(app, path, method="GET", body=b"", headers=()):
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [(b"host", b"gw.corp.example"), *headers],
        "client": ("127.0.0.1", 5555),
    }
    sent = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    return (
        sent[0]["status"],
        dict(sent[0]["headers"]),
        b"".join(m.get("body", b"") for m in sent[1:]),
    )


SAML = f"""
saml:
  idp_entity_id: {IDP}
  idp_sso_url: {SSO}
  idp_cert: idp.pem
  sp_entity_id: {SP}
  acs_url: {ACS}
  groups_attribute: groups
"""
TOKENS = "tokens:\n  store: tokens.db\n"
LISTEN = "listen:\n  allowed_hosts: [gw.corp.example]\n"


def saml_gateway(tmp_path, extra="", saml_extra=""):
    (tmp_path / "idp.pem").write_bytes(IDP_CERT)
    cfg = write_config(tmp_path, SAML + saml_extra + TOKENS + LISTEN + extra)
    sink = MemorySink()
    return Gateway(cfg, transport=FakeUpstream(), sink=sink), sink


def login(app):
    status, headers, _ = raw_call(app, "/saml/login")
    assert status == 302
    location = headers[b"location"].decode()
    assert location.startswith(SSO + "?")
    xml = zlib.decompress(
        base64.b64decode(parse_qs(urlsplit(location).query)["SAMLRequest"][0]), -15
    )
    rid = etree.fromstring(xml).get("ID")
    cookie = headers[b"set-cookie"].decode()
    assert "HttpOnly" in cookie and "Secure" in cookie and f"agentsec_saml={rid}" in cookie
    return rid, cookie.split(";")[0]


def acs(app, saml_response, cookie, origin=b"https://idp.corp.example"):
    body = urlencode({"SAMLResponse": saml_response}).encode()
    headers = [(b"content-type", b"application/x-www-form-urlencoded"), (b"origin", origin)]
    if cookie:
        headers.append((b"cookie", cookie.encode()))
    return raw_call(app, "/saml/acs", "POST", body, headers)


def token_from(page: bytes) -> str:
    return re.search(rb"<code>(agt_[^<]+)</code>", page).group(1).decode()


def test_sign_in_mints_a_token_that_works(tmp_path):
    app, sink = saml_gateway(tmp_path)
    rid, cookie = login(app)
    status, headers, page = acs(app, response(rid), cookie)
    assert status == 200, page
    assert headers[b"cache-control"] == b"no-store" and b"Max-Age=0" in headers[b"set-cookie"]
    token = token_from(page)
    hdrs = [(b"authorization", f"Bearer {token}".encode())]
    status, _, body = raw_call(
        app, "/v1/chat/completions", "POST", json.dumps(chat()).encode(), hdrs
    )
    assert status == 200
    issued = [r for r in sink.records if r["event"] == "gateway_token_issued"]
    assert issued[0]["actor"] == "alice@corp.example" and issued[0]["data"]["via"] == "saml"


def test_a_signature_on_the_response_also_counts(tmp_path):
    app, _ = saml_gateway(tmp_path)
    rid, cookie = login(app)
    assert acs(app, response(rid, sign_assertion=False, sign_response=True), cookie)[0] == 200


def _set_user(evil):
    def tamper(a):
        a.find(f"{{{A}}}Subject/{{{A}}}NameID").text = evil

    return tamper


def _wrap(rid):
    """Signature wrapping: keep the signed assertion, add an unsigned one for another user."""
    evil = assertion_xml(rid, user="mallory@corp.example", aid="_evil")
    return f"<samlp:Extensions>{evil}</samlp:Extensions>"


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(lambda rid: response(rid, sign_assertion=False), id="unsigned"),
        pytest.param(lambda rid: response(rid, key=EVIL_KEY), id="other-key"),
        pytest.param(lambda rid: response(rid, tamper=_set_user("mallory")), id="tampered"),
        pytest.param(lambda rid: response(rid, extra=_wrap(rid)), id="wrapping"),
        pytest.param(lambda rid: response(rid, issuer="https://evil.example"), id="issuer"),
        pytest.param(lambda rid: response(rid, audience="https://other.example"), id="audience"),
        pytest.param(
            lambda rid: response(rid, recipient="https://evil.example/acs"), id="recipient"
        ),
        pytest.param(lambda rid: response(rid, expires=-600), id="expired"),
        pytest.param(lambda rid: response("_other"), id="in-response-to"),
        pytest.param(lambda rid: response(rid, status="Requester"), id="status"),
        pytest.param(lambda rid: response(rid, alg="rsa-sha1", digest="sha1"), id="sha1-signature"),
        pytest.param(
            lambda rid: base64.b64encode(
                b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
                + f'<samlp:Response xmlns:samlp="{P}">&x;</samlp:Response>'.encode()
            ).decode(),
            id="xxe",
        ),
        pytest.param(
            lambda rid: base64.b64encode(
                f'<samlp:Response xmlns:samlp="{P}" xmlns:saml="{A}"><samlp:Status>'
                '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
                "</samlp:Status><saml:EncryptedAssertion/></samlp:Response>".encode()
            ).decode(),
            id="encrypted",
        ),
        pytest.param(lambda rid: "not base64!", id="garbage"),
    ],
)
def test_forged_or_wrong_answers_are_refused(tmp_path, make):
    app, sink = saml_gateway(tmp_path)
    rid, cookie = login(app)
    status, _, body = acs(app, make(rid), cookie)
    assert status == 401, body
    assert any(r["event"] == "gateway_auth_failed" for r in sink.records)
    assert not any(r["event"] == "gateway_token_issued" for r in sink.records)


def test_the_answer_must_reach_the_browser_that_started_and_only_once(tmp_path):
    app, _ = saml_gateway(tmp_path)
    rid, cookie = login(app)
    answer = response(rid)
    assert acs(app, answer, None)[0] == 401  # no cookie: login CSRF or a stolen answer
    other_rid, other_cookie = login(app)
    assert acs(app, answer, other_cookie)[0] == 401  # another browser's sign-in
    assert acs(app, answer, cookie)[0] == 200
    assert acs(app, answer, cookie)[0] == 401  # replay


def test_only_the_idp_origin_may_post_the_answer(tmp_path):
    app, _ = saml_gateway(tmp_path)
    rid, cookie = login(app)
    assert acs(app, response(rid), cookie, origin=b"https://evil.example")[0] == 403
    assert raw_call(app, "/v1/models", headers=[(b"origin", b"https://idp.corp.example")])[0] == 403


def test_gateway_rules_and_mfa_apply_to_saml_sign_ins(tmp_path):
    extra = "identity:\n  trusted_proxies: [127.0.0.1/32]\n  block_personal_domains: true\n"
    app, sink = saml_gateway(tmp_path, extra)
    rid, cookie = login(app)
    status, _, body = acs(app, response(rid, user="bob@gmail.com"), cookie)
    assert status == 403 and json.loads(body)["error"]["code"] == "account_not_allowed"

    mfa = "  require_mfa: true\n  mfa_contexts: [" + MFA_CTX + "]\n"
    (tmp_path / "mfa").mkdir()
    app, sink = saml_gateway(tmp_path / "mfa", saml_extra=mfa)
    rid, cookie = login(app)
    status, _, body = acs(app, response(rid, ctx=PWD_CTX), cookie)
    assert status == 403 and json.loads(body)["error"]["code"] == "mfa_required"
    assert any(r["event"] == "gateway_mfa_required" for r in sink.records)
    rid, cookie = login(app)
    assert acs(app, response(rid, aid="_a2"), cookie)[0] == 200


def test_config_checks(tmp_path):
    (tmp_path / "idp.pem").write_bytes(IDP_CERT)
    with pytest.raises(ConfigError, match="tokens"):
        write_config(tmp_path, SAML)
    for old, new in (
        (SSO, "http://idp.corp.example/sso"),
        (ACS, "https://gw.corp.example/other"),
        ("idp.pem", "missing.pem"),
        ("groups_attribute: groups", "require_mfa: true"),
        ("groups_attribute: groups", "bogus: 1"),
    ):
        with pytest.raises(ConfigError):
            write_config(tmp_path, SAML.replace(old, new) + TOKENS)
    (tmp_path / "bad.pem").write_text("not a certificate")
    with pytest.raises(ConfigError):
        write_config(tmp_path, SAML.replace("idp.pem", "bad.pem") + TOKENS)
