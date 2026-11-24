"""POST /sessions/revoke on the admin listener: end a user's active sessions now."""

from __future__ import annotations

import asyncio
import json
import time

import pytest

from agentsec.gateway import ConfigError, Gateway
from agentsec.gateway.oidc import TokenRejected
from agentsec.middleware.audit import MemorySink
from tests.test_gateway import USER, FakeUpstream, call, chat, write_config
from tests.test_gateway_tokens import TOKENS, Clock, bearer, issue

SECRET = "r" * 40
ADMIN = "admin:\n  port: 9100\n  revoke_token: env:REVOKE\n"


def revoke(app, body, secret=SECRET):
    raw = json.dumps(body).encode() if not isinstance(body, bytes) else body
    headers = [(b"authorization", f"Bearer {secret}".encode())] if secret else []
    scope = {"type": "http", "method": "POST", "path": "/sessions/revoke", "headers": headers,
             "client": ("127.0.0.1", 1)}  # fmt: skip
    sent = []

    async def receive():
        return {"type": "http.request", "body": raw, "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app.admin(scope, receive, send))
    return sent[0]["status"], json.loads(b"".join(m.get("body", b"") for m in sent[1:]))


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("REVOKE", SECRET)
    sink = MemorySink()
    cfg = write_config(tmp_path, TOKENS + ADMIN)
    return Gateway(cfg, transport=FakeUpstream(), sink=sink, wall_clock=Clock()), sink


def test_revoke_ends_every_access_token_of_the_user(app):
    gw, sink = app
    tokens = [issue(gw)[1]["token"] for _ in range(2)]
    assert all(call(gw, body=chat(), headers=bearer(t))[0] == 200 for t in tokens)
    status, answer = revoke(gw, {"user": "alice"})
    assert status == 200 and answer["tokens_revoked"] == 2 and not answer["disabled"]
    assert all(call(gw, body=chat(), headers=bearer(t))[0] == 401 for t in tokens)
    assert call(gw, body=chat())[0] == 200  # a fresh SSO sign-in still works
    assert [r for r in sink.records if r["event"] == "gateway_sessions_revoked"]


def test_disable_also_refuses_the_sso_identity_and_new_tokens(app):
    gw, _ = app
    status, answer = revoke(gw, {"user": "alice", "disable": True})
    assert status == 200 and answer["disabled"]
    assert call(gw, body=chat(), headers=USER)[0] == 403
    assert issue(gw)[0] == 403


@pytest.mark.parametrize("secret", [None, "wrong" * 8, SECRET[:-1]])
def test_the_secret_is_required(app, secret):
    gw, _ = app
    issued = issue(gw)[1]["token"]
    assert revoke(gw, {"user": "alice"}, secret=secret)[0] == 401
    assert call(gw, body=chat(), headers=bearer(issued))[0] == 200  # nothing was revoked


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        [],
        {"user": ""},
        {"user": 5},
        {"user": "a", "disable": "yes"},
        {"user": "a", "extra": 1},
        {"user": "a\x00b"},
    ],  # fmt: skip
)
def test_bad_bodies_are_refused(app, body):
    assert revoke(app[0], body)[0] == 400


def test_without_revoke_token_there_is_no_endpoint(tmp_path):
    gw = Gateway(write_config(tmp_path, TOKENS), transport=FakeUpstream(), sink=MemorySink())
    assert revoke(gw, {"user": "alice"})[0] == 404


@pytest.mark.parametrize(
    ("extra", "error"),
    [
        ("admin:\n  port: 9100\n  revoke_token: literal-secret\n", "reference"),
        ("admin:\n  revoke_token: env:REVOKE\n", "admin.port"),
    ],
)
def test_bad_config_is_refused(tmp_path, monkeypatch, extra, error):
    monkeypatch.setenv("REVOKE", SECRET)
    with pytest.raises(ConfigError, match=error):
        write_config(tmp_path, extra)


def test_a_short_secret_refuses_startup(tmp_path, monkeypatch):
    monkeypatch.setenv("REVOKE", "short")
    with pytest.raises(ConfigError, match="32"):
        Gateway(write_config(tmp_path, ADMIN), transport=FakeUpstream(), sink=MemorySink())


def test_oidc_tokens_issued_before_a_revocation_are_refused():
    from tests.test_gateway_oidc import token, verifier

    v = verifier()
    old = token(iat=int(time.time()) - 10)
    assert v.verify(old)[0] == "alice"
    v.revoked_before["alice"] = time.time() - 5
    with pytest.raises(TokenRejected, match="revoked"):
        v.verify(old)
    assert v.verify(token(iat=int(time.time())))[0] == "alice"  # signed in again afterwards
    assert v.verify(token(sub="bob", iat=int(time.time()) - 10))[0] == "bob"  # per user


def test_mcp_sessions_of_the_user_are_ended():
    pytest.importorskip("mcp")
    from agentsec.gateway.mcp import McpGateway

    gw = McpGateway.__new__(McpGateway)  # only the session bookkeeping is under test
    gw._owners = {"s1": ("alice", 0.0), "s2": ("bob", 0.0), "s3": ("alice", 0.0)}
    gw._ended = {}
    gw._clock = lambda: 1.0
    assert gw.end_sessions("alice") == 2
    assert set(gw._ended) == {"s1", "s3"}
