"""Request hardening: content parts, thread pools, error and rejection records, audit budget."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import stat
import subprocess
import sys
import threading

import pytest

from agentsec.gateway import Gateway, load_config
from agentsec.gateway import app as gw
from agentsec.middleware.audit import MemorySink
from tests.test_gateway import USER, FakeUpstream, call, chat, gateway, write_config
from tests.test_gateway_tokens import JSON, TOKENS
from tests.test_gateway_tokens import gateway as token_gateway

INLINE_IMAGE = {"type": "image_url", "image_url": {"url": "data:image/png;base64,AA=="}}


def records(sink, event):
    return [r for r in sink.records if r["event"] == event]


def bearer(token):
    return [(b"authorization", f"Bearer {token}".encode())]


# ------------------------------------------------------------------ G1: content parts


@pytest.mark.parametrize(
    "part",
    [
        {"type": "video_url", "video_url": {"url": "http://169.254.169.254/latest"}},
        {"type": "audio_url", "audio_url": {"url": "http://10.0.0.1/a.wav"}},
        {"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}},
        {"type": "file", "file": {"file_data": "data:text/plain;base64,AAAA"}},
        {"video_url": {"url": "http://10.0.0.1/v.mp4"}},
        {"type": "text", "text": 5},
        {"type": "image_url"},
        "http://10.0.0.1/",
    ],
)
@pytest.mark.parametrize("mode", ["enforce", "monitor"])
def test_only_text_and_image_parts_are_accepted(tmp_path, part, mode):
    upstream = FakeUpstream()
    app, _ = gateway(tmp_path, upstream, mode=mode)
    status, out = call(app, body=chat([{"type": "text", "text": "hi"}, part]))
    assert status == 400 and out["error"]["code"] == "bad_request"
    assert upstream.requests == []


def test_accepted_parts_are_rebuilt_without_extra_keys(tmp_path):
    upstream = FakeUpstream()
    app, _ = gateway(tmp_path, upstream)
    smuggled = {"type": "text", "text": "hi", "video_url": {"url": "http://10.0.0.1/v.mp4"}}
    assert call(app, body=chat([smuggled, INLINE_IMAGE]))[0] == 200
    assert upstream.requests[0]["messages"][0]["content"] == [
        {"type": "text", "text": "hi"},
        INLINE_IMAGE,
    ]


# ------------------------------------------------------------------ G2: thread pools


def many(app, scopes):
    """Run several requests on one event loop; returns their statuses in order."""

    async def one(scope, body):
        sent = []

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            sent.append(message)

        await app(scope, receive, send)
        return sent[0]["status"]

    async def main():
        return await asyncio.gather(*(one(s, b) for s, b in scopes))

    return asyncio.run(main())


def scope(path, method, user, body=b""):
    headers = [(b"x-auth-request-user", user.encode()), (b"x-auth-request-groups", b"eng")]
    return {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers,
        "client": ("127.0.0.1", 5555),
    }, body


def test_a_full_upstream_pool_answers_busy_and_does_not_starve_other_work(tmp_path, monkeypatch):
    monkeypatch.setattr(gw, "MAX_CONCURRENT_UPSTREAM", 2)
    release, entered = threading.Event(), threading.Semaphore(0)
    statuses = {}

    def slow(upstream, body, timeout, max_bytes):
        entered.release()
        assert release.wait(10)
        return {"choices": [{"message": {"role": "assistant", "content": "ok"}}]}

    app = Gateway(write_config(tmp_path), transport=slow, sink=MemorySink())
    body = json.dumps(chat()).encode()

    def late():
        # Both upstream threads are held: a third model call is refused at once, and a request
        # that needs only a policy lookup is still served.
        entered.acquire(timeout=10)
        entered.acquire(timeout=10)
        try:
            statuses["late"] = many(
                app,
                [
                    scope("/v1/chat/completions", "POST", "carol", body),
                    scope("/v1/models", "GET", "dave"),
                ],
            )
        finally:
            release.set()

    thread = threading.Thread(target=late)
    thread.start()
    held = many(app, [scope("/v1/chat/completions", "POST", u, body) for u in ("alice", "bob")])
    thread.join(15)
    assert held == [200, 200]
    assert statuses["late"] == [503, 200]
    assert app._upstream_active == 0
    assert call(app, body=chat())[0] == 200  # the slots were given back


def test_contextvars_reach_the_worker_thread(tmp_path):
    app, sink, _ = token_gateway(tmp_path)
    token = call(app, "/tokens", body={"name": "x"}, headers=[*USER, *JSON])[1]
    assert call(app, body=chat(), headers=bearer(token["token"]), peer="10.1.1.1")[0] == 200
    assert records(sink, "gateway_request")[-1]["data"]["token_id"] == token["id"]


# ------------------------------------------------------------- G3: internal failures


@pytest.mark.parametrize(
    ("error", "status"), [(OSError("key file /run/secrets/k"), 503), (KeyError("s3cr3t"), 500)]
)
def test_internal_failures_are_logged_and_audited_by_type_only(tmp_path, caplog, error, status):
    def broken(upstream, body, timeout, max_bytes):
        raise error

    sink = MemorySink()
    app = Gateway(write_config(tmp_path), transport=broken, sink=sink)
    with caplog.at_level(logging.ERROR, logger="agentsec.gateway"):
        got, out = call(app, body=chat())
    assert got == status and out["error"]["message"] in {"unavailable", "internal error"}
    (record,) = records(sink, "gateway_error")
    assert record["actor"] == "alice" and record["data"]["peer"] == "127.0.0.1"
    assert record["data"]["error"] == type(error).__name__
    assert str(error.args[0]) not in str(record)
    assert any(r.exc_info for r in caplog.records)


def test_a_failure_with_the_audit_log_down_still_answers(tmp_path):
    class BrokenSink(MemorySink):
        fail = False

        def write(self, record):
            if self.fail:
                raise OSError("disk full")
            super().write(record)

    sink = BrokenSink()
    app = Gateway(write_config(tmp_path), transport=FakeUpstream(), sink=sink)
    sink.fail = True
    assert call(app, body=chat())[0] == 503


# ---------------------------------------------------------- G4: attributable rejections


def test_a_refused_user_is_named_on_the_rejection_record(tmp_path):
    app, sink = gateway(tmp_path)
    assert call(app, "/nope", method="GET", peer="127.0.0.1")[0] == 404
    (record,) = records(sink, "gateway_rejected")
    assert record["actor"] == "alice" and record["data"]["peer"] == "127.0.0.1"


def test_a_user_outside_the_allowed_groups_is_named_once(tmp_path):
    write_config(tmp_path)
    path = tmp_path / "gateway.yaml"
    path.write_text(path.read_text().replace("identity:\n", "identity:\n  allowed_groups: [ops]\n"))
    sink = MemorySink()
    app = Gateway(load_config(path), transport=FakeUpstream(), sink=sink)
    assert call(app, body=chat())[0] == 403
    (record,) = records(sink, "gateway_rejected")
    assert record["actor"] == "alice" and record["data"]["code"] == "forbidden"


def test_an_unidentified_peer_is_recorded_with_its_address(tmp_path):
    app, sink = gateway(tmp_path)
    assert call(app, body=chat(), peer="10.9.9.9")[0] == 401
    (record,) = records(sink, "gateway_rejected")
    assert record["actor"] == "gateway" and record["data"]["peer"] == "10.9.9.9"


# ------------------------------------------------------------- G5: pre-auth audit budget


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_pre_auth_records_are_budgeted_per_peer_and_summarized(tmp_path, caplog):
    clock, sink = Clock(), MemorySink()
    cfg = write_config(tmp_path, TOKENS + "limits:\n  requests_per_min: 1000\n")
    app = Gateway(cfg, transport=FakeUpstream(), sink=sink, clock=clock)
    bad = bearer("agt_" + "a" * 48)
    for _ in range(gw.PREAUTH_AUDIT_BURST + 5):
        assert call(app, body=chat(), headers=bad, peer="10.6.6.6")[0] == 401
    assert len(records(sink, "gateway_auth_failed")) == gw.PREAUTH_AUDIT_BURST
    assert records(sink, "gateway_auth_failed")[0]["data"]["peer"] == "10.6.6.6"

    # Another peer has its own budget.
    assert call(app, body=chat(), headers=bad, peer="10.7.7.7")[0] == 401
    assert len(records(sink, "gateway_auth_failed")) == gw.PREAUTH_AUDIT_BURST + 1

    # A refused, authenticated user is never dropped.
    for _ in range(gw.PREAUTH_AUDIT_BURST + 5):
        assert call(app, "/nope", method="GET")[0] == 404
    assert len(records(sink, "gateway_rejected")) == gw.PREAUTH_AUDIT_BURST + 5

    clock.now += 60 / gw.PREAUTH_AUDIT_PER_MIN  # one token back
    with caplog.at_level(logging.WARNING, logger="agentsec.gateway"):
        call(app, body=chat(), headers=bad, peer="10.6.6.6")
        call(app, body=chat(), headers=bad, peer="10.6.6.6")
    assert len(records(sink, "gateway_auth_failed")) == gw.PREAUTH_AUDIT_BURST + 2
    assert "suppressed 5 pre-auth audit records" in caplog.text


def test_the_audit_budget_forgets_idle_peers(caplog):
    clock = Clock()
    budget = gw._AuditBudget(1, 6, clock)
    assert budget.allow("a") and not budget.allow("a")
    clock.now += 61
    with caplog.at_level(logging.WARNING, logger="agentsec.gateway"):
        assert budget.allow("b")
    assert set(budget._peers) == {"b"}
    assert "suppressed 1 pre-auth audit records" in caplog.text


def test_an_oidc_failure_reason_does_not_echo_the_token(tmp_path):
    jwt = pytest.importorskip("jwt")
    from tests.test_gateway_oidc import oidc_gateway

    app, sink = oidc_gateway(tmp_path)
    forged = jwt.encode({"sub": "x"}, "k" * 32, algorithm="HS256", headers={"kid": "EVIL-KID"})
    head = base64.urlsafe_b64encode(b'{"alg":"EVIL-ALG","typ":"JWT"}').decode().rstrip("=")
    forged = head + forged[forged.index(".") :]
    assert call(app, body=chat(), headers=bearer(forged), peer="10.5.5.5")[0] == 401
    (record,) = records(sink, "gateway_auth_failed")
    assert record["data"] == {
        "request_id": record["data"]["request_id"],
        "reason": "bearer token rejected",
        "peer": "10.5.5.5",
    }


# ------------------------------------------------------------------- G6: no proxies


def test_the_upstream_opener_ignores_proxy_settings():
    # The opener is built at import, so the proxy has to be in the environment before that.
    code = (
        "import urllib.request as u; from agentsec.gateway import app; "
        "print(any(isinstance(h, u.ProxyHandler) for h in app._OPENER.handlers))"
    )
    env = {**os.environ, "http_proxy": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9"}
    out = subprocess.run(  # noqa: S603 - our own interpreter and a fixed script
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "False"


# --------------------------------------------------------------- G7: audit file mode


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_a_new_audit_file_is_owner_only(tmp_path):
    old = os.umask(0o022)
    try:
        app = Gateway(write_config(tmp_path), transport=FakeUpstream())
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(app.config.audit_file).st_mode) == 0o600


def test_an_existing_audit_file_is_kept(tmp_path):
    cfg = write_config(tmp_path)
    Gateway(cfg, transport=FakeUpstream())
    before = open(cfg.audit_file, encoding="utf-8").read()
    Gateway(cfg, transport=FakeUpstream())
    assert before and open(cfg.audit_file, encoding="utf-8").read().startswith(before)


# ------------------------------------------------------- G8: every request is audited


def test_listing_models_and_tokens_is_audited(tmp_path):
    app, sink, _ = token_gateway(tmp_path)
    assert call(app, "/v1/models", method="GET")[0] == 200
    assert call(app, "/tokens", method="GET")[0] == 200
    request_shape = {"groups", "policy_group", "policy_rev", "mode", "token_id"}
    for event in ("gateway_models_listed", "gateway_tokens_listed"):
        (record,) = records(sink, event)
        assert record["actor"] == "alice" and record["session_id"]
        assert set(record["data"]) == request_shape
        assert record["data"]["groups"] == ["eng", "ml"]


def test_mcp_initialize_and_session_delete_are_audited(tmp_path):
    pytest.importorskip("mcp")
    import httpx2

    from tests import test_gateway_mcp as m

    async def main(url):
        async with httpx2.AsyncClient(headers=m.headers(), timeout=10) as http:
            sid = await m.raw_initialize(http, url)
            hdrs = {"Mcp-Session-Id": sid, "MCP-Protocol-Version": "2025-11-25"}
            return (await http.delete(url, headers=hdrs)).status_code

    sink = MemorySink()
    upstreams = m.Upstreams(docs=m.docs_server(), mail=m.mail_server())
    app = Gateway(m.write_config(tmp_path), sink=sink, mcp_connector=upstreams.connect)
    with m.serving(app) as url:
        assert 200 <= asyncio.run(main(url)) < 300
    seen = [(r["actor"], r["data"]["method"], r["data"]["session"])
            for r in records(sink, "gateway_mcp_request")]  # fmt: skip
    assert seen == [("alice", "POST", False), ("alice", "DELETE", True)]
