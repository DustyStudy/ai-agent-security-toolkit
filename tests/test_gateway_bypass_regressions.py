"""Regression pins for the gateway bypass classes published against AI gateways in 2026.

Nothing here was found broken: these hold the properties that keep the gateway out of each class.

1. Auth fail-open (the CVE-2026-59822 class): a rejected, malformed or repeated credential,
   or a verifier that raises, is a refusal and never an identity.
2. Public-route confusion (the ``?.well-known`` trick): only ``GET /healthz``, matched as an
   exact path, is served without an identity.
3. Self-service privilege escalation (the CVE-2026-47101 class): ``POST /tokens`` takes a
   name and a lifetime; user, groups and the lifetime cap come from the sign-in and config.
4. Trusted-header identity counts only from a configured proxy, and only when sent once.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json

import pytest

from agentsec.gateway import Gateway
from agentsec.middleware.audit import MemorySink
from tests.test_gateway import USER, FakeUpstream, call, chat, write_config
from tests.test_gateway_tokens import JSON, TOKENS, bearer

HAS_MCP = importlib.util.find_spec("mcp") is not None
MCP = "mcp_upstreams:\n  docs: {url: 'https://docs.internal/mcp'}\n" if HAS_MCP else ""
needs_mcp = pytest.mark.skipif(not HAS_MCP, reason="/mcp is only routed with the mcp extra")
CHAT = "/v1/chat/completions"
ROUTES = [
    ("POST", CHAT),
    ("GET", "/v1/models"),
    ("POST", "/tokens"),
    ("GET", "/tokens"),
    pytest.param("POST", "/mcp", marks=needs_mcp),
]
BOB = [(b"x-auth-request-user", b"bob"), (b"x-auth-request-groups", b"eng")]
UNKNOWN = "agt_" + "A" * 43  # token-shaped, never issued
OUTSIDE = "10.20.30.40"  # not in trusted_proxies
# Every audit event a request that was never identified may leave behind.
REFUSAL_EVENTS = {"gateway_start", "gateway_auth_failed", "gateway_rejected"}


def gateway(tmp_path, extra=TOKENS + MCP):
    upstream, sink = FakeUpstream(), MemorySink()
    app = Gateway(write_config(tmp_path, extra), transport=upstream, sink=sink)
    return app, sink, upstream


def attempt(app, method, path, headers, peer="127.0.0.1"):
    body = chat() if path == CHAT else {"name": "x"} if method == "POST" else None
    return call(app, path, body=body, method=method, headers=[*headers, *JSON], peer=peer)


def ask(app, path, *, method="GET", headers=(), query=b"", raw_path=None, raw=b""):
    """Like ``call``, with the scope keys a server fills from the request line, and raw bytes."""
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode() if raw_path is None else raw_path,
        "query_string": query,
        "headers": list(headers),
        "client": ("127.0.0.1", 5555),
    }
    sent = []

    async def receive():
        return {"type": "http.request", "body": raw, "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    return sent[0]["status"], json.loads(b"".join(m.get("body", b"") for m in sent[1:]))


def assert_refused(result, sink, upstream, statuses=(401,)):
    status, body = result
    assert status in statuses and "error" in body
    assert upstream.requests == []
    assert {r["event"] for r in sink.records} <= REFUSAL_EVENTS


def issue(app, headers=USER):
    status, issued = call(app, "/tokens", body={"name": "ide"}, headers=[*headers, *JSON])
    assert status == 201
    return issued


# ------------------------------------------------------- 1. auth fail-open (CVE-2026-59822)

BAD_AUTHORIZATION = [
    [],
    [b""],
    [b"Bearer"],
    [b"Bearer "],
    [b"Bearer x"],
    [b"Bearer null"],
    [b"Bearer agt_"],
    [f"Bearer {UNKNOWN}".encode()],
    [f"bearer {UNKNOWN}".encode()],
    [f"Token {UNKNOWN}".encode()],
    [UNKNOWN.encode()],
    [b"Basic YWxpY2U6eA=="],
    [b"Bearer \xff\xfe"],
    [f"Bearer {UNKNOWN}".encode()] * 2,
    [b"Bearer x", f"Bearer {UNKNOWN}".encode()],
]


@pytest.mark.parametrize(("method", "path"), ROUTES)
@pytest.mark.parametrize("values", BAD_AUTHORIZATION)
@pytest.mark.parametrize("peer", [OUTSIDE, "127.0.0.1"])
def test_a_bad_authorization_header_is_never_an_identity(tmp_path, method, path, values, peer):
    app, sink, upstream = gateway(tmp_path)
    headers = [(b"authorization", v) for v in values]
    assert_refused(attempt(app, method, path, headers, peer), sink, upstream)


def test_a_live_token_is_accepted_only_as_one_exact_bearer(tmp_path):
    app, sink, upstream = gateway(tmp_path)
    token = issue(app)["token"]
    assert attempt(app, "GET", "/v1/models", bearer(token), OUTSIDE)[0] == 200  # the control
    upstream.requests.clear()
    sink.records.clear()
    for headers in (
        bearer(token) * 2,
        [*bearer(token), (b"authorization", b"Bearer x")],
        [(b"authorization", b"Bearer x"), *bearer(token)],
        bearer(f"{token} x"),
        bearer(f"{token},{token}"),
        bearer(token[:-1]),
        bearer(token + "A"),
        bearer(token.swapcase()),
        [(b"authorization", f"Basic {token}".encode())],
        [(b"authorization", token.encode())],
        [(b"x-api-key", token.encode())],
        [(b"cookie", f"token={token}".encode())],
    ):
        for method, path in (("POST", CHAT), ("GET", "/v1/models")):
            assert_refused(attempt(app, method, path, headers, OUTSIDE), sink, upstream)


@pytest.mark.parametrize("error", [RuntimeError("boom"), KeyError("kid"), OSError("disk")])
def test_a_token_store_that_raises_is_a_refusal(tmp_path, monkeypatch, error):
    app, sink, upstream = gateway(tmp_path)
    token = issue(app)["token"]
    sink.records.clear()

    def verify(_token):
        raise error

    monkeypatch.setattr(app._tokens, "verify", verify)
    for method, path in (("POST", CHAT), ("GET", "/v1/models"), ("GET", "/tokens")):
        result = attempt(app, method, path, bearer(token), OUTSIDE)
        assert_refused(result, sink, upstream, statuses=(500, 503))


def oidc_gateway(tmp_path):
    pytest.importorskip("jwt")
    from tests.test_gateway_oidc import oidc_gateway as build

    app, sink = build(tmp_path, extra=TOKENS)
    return app, sink, app._transport


def test_oidc_mode_refuses_every_bad_bearer(tmp_path):
    app, sink, upstream = oidc_gateway(tmp_path)
    from tests.test_gateway_oidc import b64
    from tests.test_gateway_oidc import token as jwt_token

    good = jwt_token()
    assert attempt(app, "GET", "/v1/models", bearer(good), OUTSIDE)[0] == 200  # the control
    sink.records.clear()
    unsigned = f"{b64({'alg': 'none'})}.{b64({'sub': 'alice', 'groups': ['eng']})}."
    cases = [
        *BAD_AUTHORIZATION,
        [f"Bearer {good}".encode()] * 2,
        [f"Bearer {good}".encode(), b"Bearer x"],
        [f"Bearer {good} x".encode()],
        [f"Bearer {good[:-2]}".encode()],
        [f"Basic {good}".encode()],
        [good.encode()],
        [f"Bearer {unsigned}".encode()],
        [b"Bearer a.b.c"],
    ]
    for values in cases:
        headers = [(b"authorization", v) for v in values]
        # The identity headers of trusted-header mode count for nothing here, from any peer.
        for extra, peer in (([], OUTSIDE), (USER, "127.0.0.1")):
            for method, path in (("POST", CHAT), ("GET", "/v1/models"), ("POST", "/tokens")):
                result = attempt(app, method, path, [*headers, *extra], peer)
                assert_refused(result, sink, upstream)


@pytest.mark.parametrize("error", [RuntimeError("boom"), KeyError("kid"), OSError("idp down")])
def test_an_oidc_verifier_that_raises_is_a_refusal(tmp_path, monkeypatch, error):
    app, sink, upstream = oidc_gateway(tmp_path)
    from tests.test_gateway_oidc import token as jwt_token

    def verify(_token):
        raise error

    monkeypatch.setattr(app._oidc, "verify", verify)
    for method, path in (("POST", CHAT), ("GET", "/v1/models"), ("POST", "/tokens")):
        result = attempt(app, method, path, bearer(jwt_token()), OUTSIDE)
        assert_refused(result, sink, upstream, statuses=(500, 503))


# ------------------------------------------- 2. public-route confusion (``?.well-known``)

# (path, query_string, raw_path): what an ASGI server could hand over for a request line that
# tries to look like the one public route, or like a route some other layer treats as public.
CONFUSED = [
    ("/mcp", b".well-known", None),
    ("/mcp", b"/healthz", None),
    ("/mcp", b".well-known/oauth-protected-resource", None),
    (CHAT, b".well-known", None),
    (CHAT, b"/healthz", None),
    ("/v1/models", b"/healthz", None),
    ("/tokens", b".well-known", None),
    ("/tokens", b"/healthz", None),
    # The same, from a server that did not split the query off the path.
    ("/mcp?.well-known", b"", None),
    ("/mcp?/healthz", b"", None),
    ("/healthz?/../mcp", b"", None),
    # Dot segments and encoded slashes, both as sent and as a server would decode them.
    ("/healthz/../mcp", b"", None),
    ("/healthz/../mcp", b"", b"/healthz%2f..%2fmcp"),
    ("/healthz%2f..%2fmcp", b"", None),
    ("/healthz%2F..%2Fmcp", b"", None),
    ("/healthz/..;/mcp", b"", None),
    ("/.well-known/../mcp", b"", None),
    ("/healthz/../v1/models", b"", None),
    ("/healthz/../tokens", b"", None),
    # Near misses of the public path and of the protected ones.
    ("/healthz/", b"", None),
    ("/healthz/x", b"", None),
    ("/HEALTHZ", b"", None),
    ("/healthz ", b"", None),
    ("/healthz\x00", b"", None),
    ("healthz", b"", None),
    ("//healthz", b"", None),
    ("//mcp", b"", None),
    ("/MCP", b"", None),
    ("/mcp/", b"", None),
    ("/.well-known/oauth-protected-resource", b"", None),
]


@pytest.mark.parametrize(("path", "query", "raw_path"), CONFUSED)
@pytest.mark.parametrize("method", ["GET", "POST", "DELETE"])
def test_only_the_exact_health_path_is_served_without_an_identity(
    tmp_path, method, path, query, raw_path
):
    app, sink, upstream = gateway(tmp_path)
    result = ask(app, path, method=method, query=query, raw_path=raw_path)
    assert_refused(result, sink, upstream, statuses=(401, 404, 405))


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "HEAD", "OPTIONS", "get"])
def test_health_is_public_for_get_only(tmp_path, method):
    app, sink, upstream = gateway(tmp_path)
    assert ask(app, "/healthz") == (200, {"status": "ok"})  # the control
    assert_refused(ask(app, "/healthz", method=method), sink, upstream, statuses=(401, 404, 405))


@pytest.mark.parametrize("path", [p for p, query, _ in CONFUSED if not query])
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_a_confused_path_reaches_no_route_with_an_identity_either(tmp_path, method, path):
    """Routes are exact paths: nothing is normalised into /mcp, /tokens or a model route."""
    app, sink, upstream = gateway(tmp_path)
    raw = json.dumps(chat()).encode()
    status, body = ask(app, path, method=method, headers=[*USER, *JSON], raw=raw)
    assert status == 404 and body["error"]["code"] == "not_found"
    assert upstream.requests == [] and app._tokens.list() == []


# ------------------------------- 3. self-service privilege escalation (CVE-2026-47101)

ESCALATIONS = [
    b'{"name": "x", "groups": ["admin"]}',
    b'{"name": "x", "group": "admin"}',
    b'{"name": "x", "user": "root"}',
    b'{"name": "x", "sub": "root"}',
    b'{"name": "x", "id": "tok_0000000000000000"}',
    b'{"name": "x", "scope": "admin"}',
    b'{"name": "x", "role": "admin", "is_admin": true}',
    b'{"name": "x", "expires": 99999999999}',
    b'{"name": "x", "max_ttl_days": 3650}',
    b'{"name": "x", "ttl_s": 999999999}',
    b'{"name": "x", "max_per_user": 1000}',
    b'{"name": "x", "ttl_days": 10.001}',  # the test config caps a lifetime at 10 days
    b'{"name": "x", "ttl_days": 3650}',
    b'{"name": "x", "ttl_days": 1e400}',
    b'{"name": "x", "ttl_days": Infinity}',
    b'{"name": "x", "ttl_days": NaN}',
    b'{"name": "x", "ttl_days": -1}',
    b'{"name": "x", "ttl_days": true}',
    b'{"name": "x", "ttl_days": [3650]}',
    b'{"name": "x", "ttl_days": {"days": 3650}}',
    b'{"name": {"groups": ["admin"]}}',
    b'[{"name": "x"}]',
    b'"x"',
]


@pytest.mark.parametrize("raw", ESCALATIONS)
def test_a_token_request_cannot_carry_identity_or_exceed_the_lifetime_cap(tmp_path, raw):
    app, sink, _ = gateway(tmp_path)
    status, body = ask(app, "/tokens", method="POST", headers=[*USER, *JSON], raw=raw)
    assert status == 400 and body["error"]["code"] == "bad_request"
    assert app._tokens.list() == []
    assert "gateway_token_issued" not in {r["event"] for r in sink.records}


def test_a_token_gets_the_callers_identity_and_at_most_the_configured_lifetime(tmp_path):
    app, sink, _ = gateway(tmp_path)
    raw = b'{"name": "x", "ttl_days": 10}'  # exactly the cap
    status, issued = ask(app, "/tokens", method="POST", headers=[*USER, *JSON], raw=raw)
    assert status == 201
    (stored,) = app._tokens.list()
    assert (stored.user, stored.groups) == ("alice", ("eng", "ml"))
    assert stored.expires - stored.created == app.config.tokens.max_ttl_s
    # Using it is being alice, with those groups and no others.
    assert attempt(app, "POST", CHAT, bearer(issued["token"]), OUTSIDE)[0] == 200
    request = [r for r in sink.records if r["event"] == "gateway_request"][-1]
    assert request["actor"] == "alice" and request["data"]["groups"] == ["eng", "ml"]


def test_identity_headers_sent_with_a_token_do_not_change_who_it_is(tmp_path):
    """The token is alice's; headers claiming bob, or more groups, ride along for nothing."""
    app, sink, _ = gateway(tmp_path)
    token = issue(app)["token"]
    claims = [(b"x-auth-request-user", b"bob"), (b"x-auth-request-groups", b"eng, ml, admin")]
    for peer in (OUTSIDE, "127.0.0.1"):
        assert attempt(app, "POST", CHAT, [*bearer(token), *claims], peer)[0] == 200
        request = [r for r in sink.records if r["event"] == "gateway_request"][-1]
        assert request["actor"] == "alice" and request["data"]["groups"] == ["eng", "ml"]


def test_a_token_cannot_mint_list_or_revoke_tokens(tmp_path):
    app, sink, _ = gateway(tmp_path)
    issued = issue(app)
    sink.records.clear()
    # Also not when the request comes through the auth proxy with the owner's own headers.
    for headers, peer in ((bearer(issued["token"]), OUTSIDE), ([*bearer(issued["token"]), *USER],
                                                             "127.0.0.1")):  # fmt: skip
        for method, path in (
            ("POST", "/tokens"),
            ("GET", "/tokens"),
            ("DELETE", f"/tokens/{issued['id']}"),
        ):
            status, body = attempt(app, method, path, headers, peer)
            assert status == 403 and body["error"]["code"] == "forbidden"
    (stored,) = app._tokens.list()
    assert stored.id == issued["id"] and stored.revoked is None
    assert {r["event"] for r in sink.records} == {"gateway_rejected"}


@pytest.mark.parametrize("target", ["{id}", "%", "tok_%", "*", "_" * 20, "{id}/", "../tokens/{id}"])
def test_a_user_cannot_see_or_revoke_another_users_token(tmp_path, target):
    app, _, _ = gateway(tmp_path)
    issued = issue(app)
    assert call(app, "/tokens", method="GET", headers=BOB) == (200, {"data": []})
    path = "/tokens/" + target.format(id=issued["id"])
    assert call(app, path, method="DELETE", headers=BOB)[0] == 404
    # Bob's own token is no more use against alice's than his sign-in.
    theirs = bearer(issue(app, BOB)["token"])
    assert call(app, path, method="DELETE", headers=theirs, peer=OUTSIDE)[0] == 403
    assert [t.revoked for t in app._tokens.list(user="alice")] == [None]
    assert attempt(app, "GET", "/v1/models", bearer(issued["token"]), OUTSIDE)[0] == 200


# ----------------------------------------------------------------- 4. trusted-header mode

FORWARDED = [(b"x-forwarded-for", b"127.0.0.1"), (b"x-real-ip", b"127.0.0.1"),
             (b"forwarded", b"for=127.0.0.1")]  # fmt: skip
SPOOFED = [
    (USER, OUTSIDE),
    (USER, "::ffff:10.20.30.40"),
    (USER, "127.0.0.2"),  # trusted_proxies is 127.0.0.1/32, not loopback as a whole
    (USER, "::1"),
    (USER, "unix"),
    (USER, None),
    ([*USER, *FORWARDED], OUTSIDE),  # the peer is the TCP peer, not what a header says
    ([*USER, USER[0]], "127.0.0.1"),
    ([USER[0], (b"x-auth-request-user", b"admin"), USER[1]], "127.0.0.1"),
    ([USER[0], (b"X-Auth-Request-User", b"admin"), USER[1]], "127.0.0.1"),
    ([*USER, USER[1]], "127.0.0.1"),
    ([*USER, (b"x-auth-request-groups", b"admin")], "127.0.0.1"),
    ([*USER, (b"X-AUTH-REQUEST-GROUPS", b"admin")], "127.0.0.1"),
]


@pytest.mark.parametrize(("method", "path"), ROUTES)
@pytest.mark.parametrize(("headers", "peer"), SPOOFED)
def test_identity_headers_count_once_and_only_from_the_auth_proxy(
    tmp_path, method, path, headers, peer
):
    app, sink, upstream = gateway(tmp_path)
    assert_refused(attempt(app, method, path, headers, peer), sink, upstream)
    assert app._tokens.list() == []
