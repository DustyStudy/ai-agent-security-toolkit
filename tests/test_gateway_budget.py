"""Per-user token budgets: limits.tokens_per_user_per_day."""

from __future__ import annotations

import pytest

from agentsec.gateway import ConfigError, Gateway
from agentsec.gateway.app import HttpError, _TokenBudget, _tokens_used
from agentsec.middleware.audit import MemorySink
from tests.test_gateway import USER, FakeUpstream, call, chat, gateway, write_config
from tests.test_gateway_holdback import FakeStream, sse

BOB = [(b"x-auth-request-user", b"bob"), (b"x-auth-request-groups", b"eng")]


def budget(n: int) -> str:
    return f"limits:\n  tokens_per_user_per_day: {n}\n"


def test_off_by_default_and_must_be_positive(tmp_path):
    assert write_config(tmp_path).tokens_per_user_per_day is None
    assert write_config(tmp_path, budget(500)).tokens_per_user_per_day == 500
    for bad in ("0", "-1", ".inf", "1.5", "yes"):
        with pytest.raises(ConfigError):
            write_config(tmp_path, f"limits:\n  tokens_per_user_per_day: {bad}\n")


def test_a_user_over_budget_gets_429_with_retry_after_and_an_audit_record(tmp_path):
    upstream = FakeUpstream()  # reports total_tokens 5
    app, sink = gateway(tmp_path, upstream, extra=budget(10))
    headers: dict = {}
    statuses = [call(app, body=chat())[0] for _ in range(2)]
    status, body = call(app, body=chat(), response_headers=headers)
    assert statuses == [200, 200] and status == 429
    assert body["error"]["code"] == "budget_exceeded"
    assert 1 <= int(headers[b"retry-after"]) <= 86400
    assert len(upstream.requests) == 2  # the refused request never reached the model
    refused = [r for r in sink.records if r["event"] == "gateway_budget_exceeded"]
    assert len(refused) == 1 and refused[0]["actor"] == "alice"
    assert call(app, body=chat(), headers=BOB)[0] == 200  # budgets are per user


def test_a_missing_usage_report_is_charged_max_tokens(tmp_path):
    raw = {"choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}}]}
    app, _ = gateway(tmp_path, FakeUpstream(raw=raw), extra=budget(100))
    assert call(app, body=chat(max_tokens=60))[0] == 200
    assert call(app, body=chat(max_tokens=60))[0] == 200  # 60 spent, still under 100
    assert call(app, body=chat())[0] == 429


def test_holdback_streams_ask_upstream_for_usage_but_only_show_it_when_asked(tmp_path):
    stream = FakeStream(["hello"], usage={"total_tokens": 7})
    cfg = write_config(
        tmp_path, budget(10) + "output:\n  stream_mode: holdback\n  holdback_chars: 32\n"
    )
    app = Gateway(cfg, transport=FakeUpstream(), stream_transport=stream, sink=MemorySink())
    status, text = call(app, body=chat(stream=True))
    assert status == 200
    assert stream.requests[0]["stream_options"] == {"include_usage": True}
    assert not any("usage" in e for e in sse(text)[0])
    assert call(app, body=chat(stream=True))[0] == 200  # 7 spent
    assert call(app, body=chat(stream=True), headers=USER)[0] == 429  # 14 spent


def test_spending_leaves_the_window_after_24_hours_and_retry_after_says_when():
    now = [0.0]
    b = _TokenBudget(10, clock=lambda: now[0])
    b.charge("alice", 6)
    now[0] = 3600.0
    b.charge("alice", 6)
    with pytest.raises(HttpError) as e:
        b.check("alice")
    assert e.value.retry_after == 86400 - 3600  # the first charge must leave the window
    now[0] = 86400.0
    b.check("alice")  # 6 left in the window
    now[0] = 86400.0 + 7200
    b.check("bob")  # sweeps idle users
    assert "alice" not in b._spent and "alice" not in b._totals


def test_tokens_used_prefers_the_reported_total():
    assert _tokens_used({"total_tokens": 9, "prompt_tokens": 1}, 50) == 9
    assert _tokens_used({"prompt_tokens": 3, "completion_tokens": 4}, 50) == 7
    assert _tokens_used({"total_tokens": True}, 50) == 50
    assert _tokens_used(None, 50) == 50
