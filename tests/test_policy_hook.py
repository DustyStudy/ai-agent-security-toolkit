"""ToolGuard(policy_hook=...): every call the local policy allows is also asked of an external
DLP or policy service, which must answer an explicit allow. Everything else fails closed."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from agentsec.middleware import AuditLogger, MemorySink
from agentsec.sandbox import HttpPolicyHook, Policy, ToolDenied, ToolGuard, Verdict
from agentsec.types import ToolCall

POLICY = Policy.from_dict({"tools": {"send": {"args": {"to": {}}}}})
CALL = ToolCall(name="send", arguments={"to": "a@example.com"})


def _guard(hook, **kw):
    sink = MemorySink()
    return ToolGuard(POLICY, policy_hook=hook, audit=AuditLogger(sink), **kw), sink


def test_an_explicit_allow_lets_the_call_run():
    seen = []
    guard, sink = _guard(lambda call, decision: seen.append(call.arguments) or True)
    assert guard.execute(CALL, lambda to: f"sent {to}") == "sent a@example.com"
    assert seen == [{"to": "a@example.com"}]
    hook = [r for r in sink.records if r["event"] == "policy_hook"]
    assert hook and hook[0]["data"]["allowed"] is True


@pytest.mark.parametrize("answer", [False, None, "true", 1, {"allow": True}])
def test_anything_but_true_denies(answer):
    guard, _ = _guard(lambda call, decision: answer)
    d = guard.authorize(CALL)
    assert d.verdict == Verdict.DENY and "denied by external policy" in d.reasons


def test_an_error_or_a_timeout_fails_closed():
    def boom(call, decision):
        raise ConnectionError("service down: a@example.com")

    guard, sink = _guard(boom)
    d = guard.authorize(CALL)
    assert d.verdict == Verdict.DENY and "ConnectionError" in d.reasons[-1]
    assert "a@example.com" not in json.dumps(sink.records[-2:])  # only the type is logged

    guard, _ = _guard(lambda call, decision: time.sleep(5) or True, policy_hook_timeout_s=0.2)
    started = time.monotonic()
    assert guard.authorize(CALL).verdict == Verdict.DENY
    assert time.monotonic() - started < 2


def test_the_hook_is_not_asked_about_a_call_the_policy_denies():
    asked = []
    guard, _ = _guard(lambda call, decision: asked.append(1) or True)
    assert guard.authorize(ToolCall(name="rm", arguments={})).verdict == Verdict.DENY
    assert asked == []


def test_async_hooks_work_with_aauthorize_and_deny_on_the_sync_api():
    async def hook(call, decision):
        await asyncio.sleep(0)
        return True

    guard, _ = _guard(hook)
    assert asyncio.run(guard.aauthorize(CALL)).verdict == Verdict.ALLOW
    with pytest.raises(ToolDenied):
        guard.execute(CALL, lambda to: "sent")


def test_async_hook_timeout_denies():
    async def slow(call, decision):
        await asyncio.sleep(5)
        return True

    guard, _ = _guard(slow, policy_hook_timeout_s=0.1)
    assert asyncio.run(guard.aauthorize(CALL)).verdict == Verdict.DENY


@pytest.mark.parametrize("bad", [0, -1, float("nan"), True])
def test_timeout_must_be_positive(bad):
    with pytest.raises(ValueError):
        ToolGuard(POLICY, policy_hook=lambda c, d: True, policy_hook_timeout_s=bad)


# ------------------------------------------------------------------------- HttpPolicyHook


@pytest.fixture
def service():
    state = {"status": 200, "body": b'{"allow": true}', "headers": {}, "seen": []}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers["Content-Length"])
            state["seen"].append((dict(self.headers), json.loads(self.rfile.read(length))))
            self.send_response(state["status"])
            for k, v in state["headers"].items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(state["body"])

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    state["url"] = f"http://127.0.0.1:{server.server_port}/check"
    yield state
    server.shutdown()


def test_http_hook_posts_the_call_and_obeys_the_answer(service):
    hook = HttpPolicyHook(service["url"], headers={"Authorization": "Bearer t"}, actor="alice")
    guard, _ = _guard(hook)
    assert guard.authorize(CALL).verdict == Verdict.ALLOW
    headers, body = service["seen"][0]
    assert headers["Authorization"] == "Bearer t"
    assert body == {
        "tool": "send",
        "arguments": {"to": "a@example.com"},
        "verdict": "allow",
        "reasons": [],
        "actor": "alice",
    }
    service["body"] = b'{"allow": false}'
    assert guard.authorize(CALL).verdict == Verdict.DENY


@pytest.mark.parametrize(
    ("status", "body", "headers"),
    [
        (500, b'{"allow": true}', {}),
        (200, b"not json", {}),
        (200, b'{"allow": "yes"}', {}),
        (200, b'{"allow": true, "pad": "' + b"x" * 70000 + b'"}', {}),
        (302, b"", {"Location": "http://127.0.0.1:1/elsewhere"}),
    ],
)
def test_http_hook_fails_closed(service, status, body, headers):
    service.update(status=status, body=body, headers=headers)
    guard, _ = _guard(HttpPolicyHook(service["url"]))
    assert guard.authorize(CALL).verdict == Verdict.DENY


@pytest.mark.parametrize(
    "url", ["http://policy.example/check", "ftp://127.0.0.1/x", "https://u:p@policy.example/"]
)
def test_http_hook_refuses_unsafe_urls(url):
    with pytest.raises(ValueError):
        HttpPolicyHook(url)


# ------------------------------------------------------------------------- gateway wiring


def test_gateway_config_takes_a_policy_hook(tmp_path, monkeypatch):
    from agentsec.gateway import ConfigError
    from tests.test_gateway import write_config

    assert write_config(tmp_path).policy_hook is None
    cfg = write_config(
        tmp_path, "policy_hook:\n  url: https://dlp.example/check\n  timeout_s: 2\n  auth: env:K\n"
    )
    assert cfg.policy_hook.url == "https://dlp.example/check" and cfg.policy_hook.timeout_s == 2
    for bad in (
        "policy_hook:\n  url: http://dlp.example/check\n",
        "policy_hook:\n  url: https://dlp.example/\n  auth: sk-literal\n",
        "policy_hook:\n  url: https://dlp.example/\n  timeout_s: 0\n",
        "policy_hook:\n  url: https://dlp.example/\n  fail: open\n",
    ):
        with pytest.raises(ConfigError):
            write_config(tmp_path, bad)


def test_gateway_withholds_a_tool_call_the_service_refuses(tmp_path, service, monkeypatch):
    from tests.test_gateway import FakeUpstream, call, chat, gateway, tool, tool_call

    monkeypatch.setenv("HOOK_KEY", "k1")
    message = {
        "role": "assistant",
        "content": None,
        "tool_calls": [tool_call("search", '{"q": "q3"}', "a")],
    }
    extra = f"policy_hook:\n  url: {service['url']}\n  auth: env:HOOK_KEY\n"
    app, sink = gateway(tmp_path, FakeUpstream(message), extra=extra)
    status, out = call(app, body=chat(tools=[tool("search")]))
    assert status == 200 and out["choices"][0]["message"]["tool_calls"]
    headers, body = service["seen"][-1]
    assert headers["Authorization"] == "Bearer k1"
    assert body["tool"] == "search" and body["actor"] == "alice"

    service["body"] = b'{"allow": false}'
    status, out = call(app, body=chat(tools=[tool("search")]))
    assert status == 200 and "tool_calls" not in out["choices"][0]["message"]
    assert any(r["event"] == "policy_hook" and not r["data"]["allowed"] for r in sink.records)
