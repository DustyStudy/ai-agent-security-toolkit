"""SAML 2.0 sign-in for the gateway: SP-initiated, HTTP-Redirect out, HTTP-POST back.

A browser visits ``/saml/login``, signs in at the IdP and comes back to ``/saml/acs`` with a
signed ``SAMLResponse``. The gateway checks it and mints an access token for IDEs and scripts,
shown once. XML signature checking is ``signxml``'s (the ``saml`` extra); this module decides
which key, which element and which rules apply. Fail closed: any doubt refuses the sign-in.

Defences, each with a test:

* only the IdP certificate from the config verifies, with SHA-2 RSA/ECDSA signatures only;
* every value is read from the element the signature covers, never from the unverified tree,
  and the document may hold exactly one assertion (signature wrapping);
* no DTDs, entities or network access in the parser (XXE), and a size cap;
* encrypted assertions are refused (not supported) rather than half-handled;
* issuer, audience, recipient, destination, time window and ``InResponseTo`` must all match,
  the request must be one this gateway started for this browser (a cookie), and an assertion
  is accepted once (replay).
"""

from __future__ import annotations

import base64
import secrets
import threading
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode
from xml.sax.saxutils import escape, quoteattr

MAX_RESPONSE_BYTES = 256 * 1024
REQUEST_TTL_S = 300.0  # a sign-in must finish within five minutes
MAX_PENDING = 10_000
NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}
_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"


class SamlRejected(Exception):
    """The reason is for the audit log; the browser gets a plain refusal."""


@dataclass(frozen=True)
class SamlSettings:
    idp_entity_id: str
    idp_sso_url: str
    idp_cert_pem: str
    sp_entity_id: str
    acs_url: str
    user_attribute: str | None = None  # None: the NameID
    groups_attribute: str | None = None
    require_mfa: bool = False
    mfa_contexts: tuple[str, ...] = ()  # AuthnContextClassRef values that mean MFA
    leeway_s: float = 60.0
    token_ttl_s: float | None = None  # None: the tokens section's default


def _q(tag: str) -> str:
    prefix, _, name = tag.partition(":")
    return f"{{{NS[prefix]}}}{name}"


def _instant(text: str | None) -> float:
    if not text:
        raise SamlRejected("missing timestamp")
    try:
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise SamlRejected("malformed timestamp") from None
    if value.tzinfo is None:
        raise SamlRejected("timestamp without a time zone")
    return value.timestamp()


class SamlServiceProvider:
    def __init__(self, settings: SamlSettings, *, clock: Callable[[], float] = time.time) -> None:
        from cryptography import x509
        from signxml import SignatureConfiguration, SignatureMethod

        self.settings = settings
        self._clock = clock
        self._cert = x509.load_pem_x509_certificate(settings.idp_cert_pem.encode())
        m = SignatureMethod
        self._expect = SignatureConfiguration(
            require_x509=True,
            expect_references=1,
            signature_methods=frozenset(
                {
                    m.RSA_SHA256,
                    m.RSA_SHA384,
                    m.RSA_SHA512,
                    m.ECDSA_SHA256,
                    m.ECDSA_SHA384,
                    m.ECDSA_SHA512,
                    m.SHA256_RSA_MGF1,
                    m.SHA384_RSA_MGF1,
                    m.SHA512_RSA_MGF1,
                }
            ),  # fmt: skip
        )
        self._lock = threading.Lock()
        self._pending: dict[str, float] = {}  # request id -> expiry
        self._seen: dict[str, float] = {}  # assertion id -> keep until

    # ------------------------------------------------------------------ outbound
    def login_redirect(self) -> tuple[str, str]:
        """``(IdP URL to redirect to, request id for the browser's cookie)``."""
        s, now = self.settings, self._clock()
        request_id = "_" + secrets.token_hex(16)
        with self._lock:
            self._sweep(now)
            if len(self._pending) >= MAX_PENDING:
                raise SamlRejected("too many sign-ins in progress")
            self._pending[request_id] = now + REQUEST_TTL_S
        issued = datetime.fromtimestamp(now, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        xml = (
            f'<samlp:AuthnRequest xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}"'
            f' ID="{request_id}" Version="2.0" IssueInstant="{issued}"'
            f" Destination={quoteattr(s.idp_sso_url)} AssertionConsumerServiceURL="
            f"{quoteattr(s.acs_url)}"
            ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
            f"<saml:Issuer>{escape(s.sp_entity_id)}</saml:Issuer></samlp:AuthnRequest>"
        )
        deflated = zlib.compressobj(wbits=-15)
        raw = deflated.compress(xml.encode()) + deflated.flush()
        sep = "&" if "?" in s.idp_sso_url else "?"
        query = urlencode({"SAMLRequest": base64.b64encode(raw).decode()})
        return f"{s.idp_sso_url}{sep}{query}", request_id

    def _sweep(self, now: float) -> None:
        for table in (self._pending, self._seen):
            for key in [k for k, until in table.items() if until <= now]:
                del table[key]

    # ------------------------------------------------------------------ inbound
    def consume(self, saml_response: str, browser_request_id: str | None) -> dict[str, Any]:
        """Check a POSTed ``SAMLResponse``; ``{"user", "groups", "mfa"}`` or SamlRejected."""
        from lxml import etree
        from signxml import XMLVerifier

        s, now = self.settings, self._clock()
        if len(saml_response) > MAX_RESPONSE_BYTES * 4 // 3 + 4:
            raise SamlRejected("response too large")
        try:
            raw = base64.b64decode(saml_response, validate=True)
        except ValueError:
            raise SamlRejected("response is not base64") from None
        parser = etree.XMLParser(
            resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False
        )
        try:
            root = etree.fromstring(raw, parser=parser)
        except etree.XMLSyntaxError:
            raise SamlRejected("response is not XML") from None
        if root.getroottree().docinfo.doctype:
            raise SamlRejected("a DOCTYPE is not allowed")
        if root.tag != _q("samlp:Response"):
            raise SamlRejected("not a SAML Response")
        if root.findall(".//" + _q("saml:EncryptedAssertion")):
            raise SamlRejected("encrypted assertions are not supported")
        if len(root.findall(".//" + _q("saml:Assertion"))) != 1:
            raise SamlRejected("the response must hold exactly one assertion")
        status = root.find(f"{_q('samlp:Status')}/{_q('samlp:StatusCode')}")
        if status is None or status.get("Value") != _SUCCESS:
            raise SamlRejected("the IdP did not report success")
        destination = root.get("Destination")
        if destination is not None and destination != s.acs_url:
            raise SamlRejected("response Destination is not this gateway")

        try:
            result = XMLVerifier().verify(
                root, x509_cert=self._cert, expect_config=self._expect, validate_schema=True
            )
        except Exception as e:  # noqa: BLE001 - every signxml failure refuses
            raise SamlRejected(f"signature check failed: {type(e).__name__}") from None
        signed = result.signed_xml if not isinstance(result, list) else None
        if signed is None:
            raise SamlRejected("signature check failed")
        if signed.tag == _q("saml:Assertion"):
            assertion = signed
        elif signed.tag == _q("samlp:Response"):
            found = signed.findall(_q("saml:Assertion"))
            if len(found) != 1:
                raise SamlRejected("the signed response must hold exactly one assertion")
            assertion = found[0]
        else:
            raise SamlRejected("the signature covers neither the response nor the assertion")
        return self._check_assertion(assertion, browser_request_id, now)

    def _check_assertion(
        self, a: Any, browser_request_id: str | None, now: float
    ) -> dict[str, Any]:
        s, leeway = self.settings, self.settings.leeway_s
        issuer = a.find(_q("saml:Issuer"))
        if issuer is None or (issuer.text or "").strip() != s.idp_entity_id:
            raise SamlRejected("assertion issuer is not the configured IdP")
        conditions = a.find(_q("saml:Conditions"))
        if conditions is None:
            raise SamlRejected("assertion has no Conditions")
        if conditions.get("NotBefore") and now + leeway < _instant(conditions.get("NotBefore")):
            raise SamlRejected("assertion is not valid yet")
        not_after = _instant(conditions.get("NotOnOrAfter"))
        if now - leeway >= not_after:
            raise SamlRejected("assertion has expired")
        audiences = [
            (e.text or "").strip()
            for e in conditions.iterfind(f"{_q('saml:AudienceRestriction')}/{_q('saml:Audience')}")
        ]
        if s.sp_entity_id not in audiences:
            raise SamlRejected("assertion audience is not this gateway")

        subject = a.find(_q("saml:Subject"))
        if subject is None:
            raise SamlRejected("assertion has no Subject")
        request_id = None
        for sc in subject.iterfind(_q("saml:SubjectConfirmation")):
            data = sc.find(_q("saml:SubjectConfirmationData"))
            if sc.get("Method") != _BEARER or data is None:
                continue
            if data.get("Recipient") != s.acs_url:
                continue
            if now - leeway >= _instant(data.get("NotOnOrAfter")):
                continue
            request_id = data.get("InResponseTo")
            break
        if request_id is None:
            raise SamlRejected("no valid bearer SubjectConfirmation for this gateway")
        if not browser_request_id or not secrets.compare_digest(request_id, browser_request_id):
            raise SamlRejected("the response answers a sign-in this browser did not start")

        authn = a.find(_q("saml:AuthnStatement"))
        if authn is None:
            raise SamlRejected("assertion has no AuthnStatement")
        ref = authn.find(f"{_q('saml:AuthnContext')}/{_q('saml:AuthnContextClassRef')}")
        mfa = ref is not None and (ref.text or "").strip() in s.mfa_contexts

        user = self._user(a, subject)
        groups = tuple(self._values(a, s.groups_attribute)) if s.groups_attribute else ()

        assertion_id = a.get("ID")
        if not assertion_id:
            raise SamlRejected("assertion has no ID")
        with self._lock:
            self._sweep(now)
            if assertion_id in self._seen:
                raise SamlRejected("assertion was already used")
            if self._pending.pop(request_id, None) is None:
                raise SamlRejected("unknown or expired sign-in request")
            self._seen[assertion_id] = not_after + leeway
        if s.require_mfa and not mfa:
            raise SamlMfaRequired(user)
        return {"user": user, "groups": groups, "mfa": mfa}

    def _user(self, a: Any, subject: Any) -> str:
        s = self.settings
        if s.user_attribute:
            values = self._values(a, s.user_attribute)
            user = values[0] if len(values) == 1 else ""
        else:
            name_id = subject.find(_q("saml:NameID"))
            user = (name_id.text or "").strip() if name_id is not None else ""
        if not user or len(user) > 256 or not user.isprintable():
            raise SamlRejected("the assertion names no usable user")
        return user

    @staticmethod
    def _values(a: Any, name: str) -> list[str]:
        out = []
        for attr in a.iterfind(f"{_q('saml:AttributeStatement')}/{_q('saml:Attribute')}"):
            if attr.get("Name") == name:
                for v in attr.iterfind(_q("saml:AttributeValue")):
                    text = (v.text or "").strip()
                    if text and text.isprintable():
                        out.append(text)
        return out


class SamlMfaRequired(SamlRejected):
    def __init__(self, user: str) -> None:
        super().__init__("sign-in did not use multi-factor authentication")
        self.user = user


__all__ = ["SamlMfaRequired", "SamlRejected", "SamlServiceProvider", "SamlSettings"]
