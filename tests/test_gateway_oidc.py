"""OIDC bearer-token identity: the token attacks the verifier must refuse, and key caching."""

from __future__ import annotations

import base64
import json
import time

import pytest

jwt = pytest.importorskip("jwt")
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402

from agentsec.gateway import ConfigError, Gateway, load_config  # noqa: E402
from agentsec.gateway.oidc import OidcSettings, OidcVerifier, TokenRejected  # noqa: E402
from agentsec.middleware.audit import MemorySink  # noqa: E402
from tests.test_gateway import POLICY, FakeUpstream, call, chat  # noqa: E402

ISS, AUD = "https://idp.corp.example/realms/main", "agentsec-gateway"
RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_KEY = ec.generate_private_key(ec.SECP256R1())
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk(key, kid, **extra):
    algo = (
        jwt.algorithms.RSAAlgorithm
        if isinstance(key, rsa.RSAPrivateKey)
        else jwt.algorithms.ECAlgorithm
    )
    return {**json.loads(algo.to_jwk(key.public_key())), "kid": kid, **extra}


JWKS = {"keys": [jwk(RSA_KEY, "rsa1", alg="RS256"), jwk(EC_KEY, "ec1")]}


class Fetcher:
    def __init__(self, doc=JWKS):
        self.doc, self.calls, self.fail = doc, 0, False

    def __call__(self, url):
        self.calls += 1
        if self.fail:
            raise OSError("idp down")
        return self.doc


def token(key=RSA_KEY, alg="RS256", kid="rsa1", **claims):
    now = int(time.time())
    body = {"iss": ISS, "aud": AUD, "sub": "alice", "iat": now, "exp": now + 300, "groups": ["eng"]}
    body.update(claims)
    body = {k: v for k, v in body.items() if v is not None}
    return jwt.encode(body, key, algorithm=alg, headers={"kid": kid} if kid else {})


def verifier(fetch=None, clock=time.monotonic, **kw):
    settings = OidcSettings(issuer=ISS, audience=AUD, jwks_url="https://idp/jwks", **kw)
    return OidcVerifier(settings, fetch=fetch or Fetcher(), clock=clock)


def b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_valid_rsa_and_ec_tokens_identify_the_user():
    v = verifier()
    assert v.verify(token()) == ("alice", ("eng",))
    assert v.verify(token(EC_KEY, "ES256", "ec1", groups=None)) == ("alice", ())


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(
            lambda: b64({"alg": "none", "kid": "rsa1"}) + "." + b64({"sub": "x"}) + ".",
            id="alg-none",
        ),
        pytest.param(lambda: token(iss="https://evil.example"), id="wrong-issuer"),
        pytest.param(lambda: token(aud="other-app"), id="wrong-audience"),
        pytest.param(lambda: token(exp=int(time.time()) - 3600), id="expired"),
        pytest.param(lambda: token(nbf=int(time.time()) + 3600), id="not-yet-valid"),
        pytest.param(lambda: token(sub=" alice"), id="ambiguous-user"),
        pytest.param(lambda: token(sub=None), id="no-sub"),
        pytest.param(lambda: token(exp=None), id="no-exp"),
        pytest.param(lambda: token(OTHER_KEY), id="signed-by-another-key"),
        pytest.param(lambda: token(kid=None), id="no-kid"),
        pytest.param(lambda: token(kid="nope"), id="unknown-kid"),
        pytest.param(lambda: token(groups="admin"), id="groups-not-a-list"),
        pytest.param(lambda: token(sub="al\x07ice"), id="control-char-user"),
        pytest.param(lambda: "x" * 9000, id="oversized"),
        pytest.param(lambda: "not.a.jwt", id="garbage"),
    ],
)
def test_bad_tokens_are_refused(bad):
    with pytest.raises(TokenRejected):
        verifier().verify(bad())


def test_hs256_signed_with_the_public_key_is_refused():
    """The classic RS/HS confusion: use the published key as an HMAC secret."""
    from cryptography.hazmat.primitives import serialization

    pem = RSA_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    import hashlib
    import hmac

    signing_input = (
        b64({"alg": "HS256", "kid": "rsa1"})
        + "."
        + b64({"iss": ISS, "aud": AUD, "sub": "mallory", "iat": 1, "exp": 2**40})
    )
    sig = base64.urlsafe_b64encode(hmac.new(pem, signing_input.encode(), hashlib.sha256).digest())
    forged = signing_input + "." + sig.rstrip(b"=").decode()
    with pytest.raises(TokenRejected, match="not allowed"):
        verifier(algorithms=("RS256", "ES256", "PS256")).verify(forged)


def test_a_key_that_declares_its_algorithm_only_verifies_that_algorithm():
    # rsa1 says alg RS256; a PS256 token under it is refused even though PS256 is allowed.
    v = verifier(algorithms=("RS256", "PS256"))
    with pytest.raises(TokenRejected, match="does not match"):
        v.verify(token(alg="PS256"))


def test_unknown_kid_flood_refreshes_the_keys_at_most_once_a_minute():
    now = [1000.0]
    fetch = Fetcher()
    v = verifier(fetch, clock=lambda: now[0])
    v.verify(token())  # first use fetches the keys
    for i in range(50):
        with pytest.raises(TokenRejected):
            v.verify(token(kid=f"made-up-{i}"))
    assert fetch.calls == 1  # the keys were just fetched: no refetch inside the cooldown
    now[0] += 61
    for i in range(50):
        with pytest.raises(TokenRejected):
            v.verify(token(kid=f"again-{i}"))
    assert fetch.calls == 2  # one refresh for the whole flood


def test_cached_keys_survive_an_idp_outage_until_the_cache_expires():
    now = [0.0]
    fetch = Fetcher()
    v = verifier(fetch, clock=lambda: now[0], jwks_cache_s=600)
    v.verify(token())
    fetch.fail = True
    now[0] = 400  # past the soft refresh point; the refresh fails, the cached keys still work
    assert v.verify(token())[0] == "alice"
    now[0] = 700  # past the cache lifetime: refuse rather than trust stale keys
    with pytest.raises(TokenRejected, match="unavailable"):
        v.verify(token())


# --------------------------------------------------------------------- the gateway


def oidc_gateway(tmp_path, extra=""):
    (tmp_path / "policy.yaml").write_text(POLICY)
    (tmp_path / "gateway.yaml").write_text(
        "identity:\n"
        "  mode: oidc\n"
        f"  oidc: {{issuer: '{ISS}', audience: {AUD}, jwks_url: 'https://idp.corp.example/jwks'}}\n"
        f"{extra}"
        "policy: policy.yaml\n"
        "upstreams: {local: {url: 'http://127.0.0.1:11434/v1', model: m}}\n"
        "audit: {file: audit.jsonl}\n"
    )
    sink = MemorySink()
    app = Gateway(
        load_config(tmp_path / "gateway.yaml"),
        transport=FakeUpstream(),
        sink=sink,
        jwks_fetch=Fetcher(),
    )
    return app, sink


def bearer(tok):
    return [(b"authorization", f"Bearer {tok}".encode())]


def test_gateway_accepts_a_valid_token_and_records_the_user(tmp_path):
    app, sink = oidc_gateway(tmp_path)
    assert call(app, body=chat(), headers=bearer(token()))[0] == 200
    req = next(r for r in sink.records if r["event"] == "gateway_request")
    assert req["actor"] == "alice" and req["data"]["groups"] == ["eng"]


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [(b"x-auth-request-user", b"alice")],  # the header path is off in oidc mode
        [(b"authorization", b"Basic YWxpY2U6eA==")],
        bearer(token()) + bearer(token()),  # two Authorization headers
        bearer(token(aud="other")),
    ],
)
def test_gateway_refuses_requests_without_one_valid_token(tmp_path, headers):
    app, sink = oidc_gateway(tmp_path)
    status, body = call(app, body=chat(), headers=headers)
    assert status == 401 and body["error"]["message"] == "unauthenticated"
    assert any(r["event"] == "gateway_auth_failed" for r in sink.records)


def test_token_groups_drive_allowed_groups(tmp_path):
    app, _ = oidc_gateway(tmp_path, extra="  allowed_groups: [finance]\n")
    assert call(app, body=chat(), headers=bearer(token()))[0] == 403
    assert call(app, body=chat(), headers=bearer(token(groups=["finance"])))[0] == 200


@pytest.mark.parametrize(
    ("oidc", "match"),
    [
        (f"{{issuer: '{ISS}', audience: a, jwks_url: 'http://idp.corp.example/jwks'}}", "https"),
        (
            f"{{issuer: '{ISS}', audience: a, jwks_url: 'https://i/j', algorithms: [HS256]}}",
            "asymmetric",
        ),
        (
            f"{{issuer: '{ISS}', audience: a, jwks_url: 'https://i/j', algorithms: [none]}}",
            "asymmetric",
        ),
        (f"{{issuer: '{ISS}', audience: a, jwks_url: 'https://i/j', leeway_s: 3600}}", "leeway"),
        (f"{{issuer: '{ISS}', jwks_url: 'https://i/j'}}", "audience"),
    ],
)
def test_unsafe_oidc_config_is_refused(tmp_path, oidc, match):
    (tmp_path / "policy.yaml").write_text(POLICY)
    (tmp_path / "g.yaml").write_text(
        f"identity: {{mode: oidc, oidc: {oidc}}}\npolicy: policy.yaml\n"
        "upstreams: {local: {url: 'http://127.0.0.1:1/v1'}}\naudit: {file: a.jsonl}\n"
    )
    with pytest.raises(ConfigError, match=match):
        load_config(tmp_path / "g.yaml")


def test_oidc_mode_refuses_header_identity_settings(tmp_path):
    (tmp_path / "policy.yaml").write_text(POLICY)
    (tmp_path / "g.yaml").write_text(
        "identity: {mode: oidc, trusted_proxies: [127.0.0.1/32], "
        f"oidc: {{issuer: '{ISS}', audience: a, jwks_url: 'https://i/j'}}}}\n"
        "policy: policy.yaml\nupstreams: {local: {url: 'http://127.0.0.1:1/v1'}}\n"
        "audit: {file: a.jsonl}\n"
    )
    with pytest.raises(ConfigError, match="no trusted_proxies"):
        load_config(tmp_path / "g.yaml")


# ------------------------------------------------------------ review findings


def test_an_idp_outage_does_not_turn_logins_into_a_fetch_per_request():
    now = [0.0]
    fetch = Fetcher()
    v = verifier(fetch, clock=lambda: now[0], jwks_cache_s=600)
    v.verify(token())
    fetch.fail = True
    now[0] = 301  # stale: the first verification tries a refresh, the rest wait out the cooldown
    for i in range(10):
        with pytest.raises(TokenRejected):
            v.verify(token(kid=f"x{i}"))
    assert fetch.calls == 2


def test_a_slow_failed_fetch_does_not_extend_the_key_lifetime():
    now = [0.0]

    class Slow(Fetcher):
        def __call__(self, url):
            if self.calls:
                now[0] = 1000  # the fetch runs past the key lifetime, then fails
                self.calls += 1
                raise OSError("timeout")
            return super().__call__(url)

    v = verifier(Slow(), clock=lambda: now[0], jwks_cache_s=600)
    v.verify(token())
    now[0] = 599
    with pytest.raises(TokenRejected, match="unavailable"):
        v.verify(token())


def test_a_key_type_mismatch_is_a_rejection_not_a_crash():
    # An ES256 token naming an RSA key that declares no alg: PyJWT raises TypeError inside.
    v = verifier(Fetcher({"keys": [jwk(RSA_KEY, "k")]}))
    with pytest.raises(TokenRejected):
        v.verify(token(EC_KEY, "ES256", "k"))


@pytest.mark.parametrize("value", [".nan", ".inf"])
def test_non_finite_numbers_are_refused_in_config(tmp_path, value):
    (tmp_path / "policy.yaml").write_text(POLICY)
    (tmp_path / "g.yaml").write_text(
        f"identity: {{mode: oidc, oidc: {{issuer: '{ISS}', audience: a, jwks_url: 'https://i/j', "
        f"jwks_cache_s: {value}}}}}\npolicy: policy.yaml\n"
        "upstreams: {local: {url: 'http://127.0.0.1:1/v1'}}\naudit: {file: a.jsonl}\n"
    )
    with pytest.raises(ConfigError, match="finite"):
        load_config(tmp_path / "g.yaml")


def test_a_failed_login_is_audited_once(tmp_path):
    app, sink = oidc_gateway(tmp_path)
    call(app, body=chat(), headers=bearer("not.a.jwt"))
    events = [r["event"] for r in sink.records if r["event"] != "gateway_start"]
    assert events == ["gateway_auth_failed"]


def test_token_verification_is_bounded_across_clients(tmp_path, monkeypatch):
    import asyncio
    import threading

    import agentsec.gateway.app as app_mod

    monkeypatch.setattr(app_mod, "MAX_CONCURRENT_AUTH", 1)
    app, _ = oidc_gateway(tmp_path)
    started, release = threading.Event(), threading.Event()
    real = app._oidc.verify

    def slow_verify(tok):
        started.set()
        release.wait(5)
        return real(tok)

    app._oidc.verify = slow_verify
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/chat/completions",
        "headers": bearer(token()),
        "client": ("10.0.0.9", 1),
    }
    out: list = []

    async def receive():
        return {"type": "http.request", "body": json.dumps(chat()).encode()}

    def sender(who):
        async def send(message):
            out.append((who, message))

        return send

    async def main():
        first = asyncio.create_task(app(scope, receive, sender("a")))
        while not started.is_set():
            await asyncio.sleep(0.005)
        await app(scope, receive, sender("b"))  # the only verification slot is taken
        release.set()
        await first

    asyncio.run(main())
    status = {who: m["status"] for who, m in out if m["type"] == "http.response.start"}
    assert status == {"a": 200, "b": 503}


def test_jwks_fetch_has_a_total_deadline():
    import http.server
    import threading

    from agentsec.gateway.oidc import fetch_jwks

    class Drip(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            for _ in range(100):
                self.wfile.write(b" ")
                self.wfile.flush()
                time.sleep(0.05)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Drip)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with pytest.raises(TimeoutError):
            fetch_jwks(f"http://127.0.0.1:{server.server_address[1]}/jwks", timeout=0.3)
    finally:
        server.shutdown()


def test_jwk_must_permit_verification():
    keys = {"keys": [jwk(RSA_KEY, "rsa1", key_ops=["encrypt"])]}
    with pytest.raises(TokenRejected):
        verifier(Fetcher(keys)).verify(token())
