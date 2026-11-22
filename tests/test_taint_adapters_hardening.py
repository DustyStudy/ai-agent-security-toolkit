from __future__ import annotations

import asyncio
import json

import pytest

from agentsec.middleware import AgentMiddleware, AuditLogger, MemorySink
from agentsec.middleware.validators import Action, OutputGuard, ProtectedStringValidator
from agentsec.sandbox import Policy, Session, ToolGuard
from agentsec.sandbox.adapters import (
    arun_openai_tool_calls,
    parse_openai_tool_call,
    run_anthropic_tool_uses,
    run_openai_tool_calls,
)
from agentsec.types import ToolCall

TAINT_POLICY = {"tools": {"fetch": {"returns_untrusted": True}, "send": {"side_effects": True}}}


def _guard(sink: MemorySink | None = None) -> ToolGuard:
    audit = AuditLogger(sink) if sink is not None else None
    return ToolGuard(Policy.from_dict(TAINT_POLICY), audit=audit)


# ------------------------------------------------------------------ B1: taint on authorize
def test_authorize_taints_like_execute():
    guard, session = _guard(), Session()
    assert guard.authorize(ToolCall("fetch", {}), session).allowed
    assert session.tainted and session.taint_sources == ["fetch"]
    assert not guard.authorize(ToolCall("send", {}), session).allowed


def test_aauthorize_taints_like_aexecute():
    guard, session = _guard(), Session()

    async def go() -> bool:
        assert (await guard.aauthorize(ToolCall("fetch", {}), session)).allowed
        return (await guard.aauthorize(ToolCall("send", {}), session)).allowed

    assert asyncio.run(go()) is False
    assert session.tainted


def test_middleware_authorize_tool_taints():
    session = Session()
    mw = AgentMiddleware(guard=_guard())
    assert mw.authorize_tool(ToolCall("fetch", {}), session).allowed
    assert not mw.authorize_tool(ToolCall("send", {}), session).allowed


def test_denied_untrusted_tool_does_not_taint():
    guard, session = _guard(), Session()
    assert not guard.authorize(ToolCall("fetch", {"unexpected": 1}), session).allowed
    assert not session.tainted


# ------------------------------------------------- B2: withheld output stays out of the log
@pytest.mark.parametrize("action", [Action.BLOCK, Action.REDACT])
def test_screen_output_does_not_audit_withheld_text(action):
    sink = MemorySink()
    mw = AgentMiddleware(
        output_guard=OutputGuard([ProtectedStringValidator(["zebra-canary-7731"], action)]),
        audit=AuditLogger(sink),
    )
    result = mw.screen_output("the code is zebra-canary-7731 ok")
    assert "zebra-canary-7731" not in result.text
    assert "zebra-canary-7731" not in json.dumps(sink.records)
    logged = next(r for r in sink.records if r["event"] == "model_output")
    assert logged["data"]["text"] == result.text


# --------------------------------------------------------- B3: malformed model tool calls
@pytest.mark.parametrize("arguments", ["[" * 100_000, '{"n": ' + "9" * 5000 + "}"])
def test_openai_hostile_arguments_are_denied_and_audited(arguments):
    sink = MemorySink()
    guard = _guard(sink)
    tc = {"id": "c1", "function": {"name": "send", "arguments": arguments}}
    assert parse_openai_tool_call(tc)[1] == "Tool call refused: arguments were not valid JSON"
    messages = run_openai_tool_calls(guard, Session(), [tc], {"send": lambda: "sent"})
    assert messages == [
        {
            "role": "tool",
            "tool_call_id": "c1",
            "content": "Tool call refused: arguments were not valid JSON",
        }
    ]
    assert [r["data"]["verdict"] for r in sink.records if r["event"] == "tool_decision"] == ["deny"]


def test_openai_non_dict_entries_are_denied_and_audited():
    sink = MemorySink()
    guard, session = _guard(sink), Session()
    entries = ["not a dict", None, 7]
    messages = run_openai_tool_calls(guard, session, entries, {})  # type: ignore[arg-type]
    amessages = asyncio.run(arun_openai_tool_calls(guard, session, entries, {}))  # type: ignore[arg-type]
    assert len(messages) == len(amessages) == 3
    assert all(m["content"].startswith("Tool call refused") for m in messages + amessages)
    verdicts = [r["data"]["verdict"] for r in sink.records if r["event"] == "tool_decision"]
    assert verdicts == ["deny"] * 6


def test_anthropic_non_dict_blocks_are_denied_and_audited():
    sink = MemorySink()
    blocks = ["not a dict", {"type": "text", "text": "hi"}, None]
    results = run_anthropic_tool_uses(_guard(sink), Session(), blocks, {})  # type: ignore[arg-type]
    assert len(results) == 2
    assert all(r["is_error"] and r["content"].startswith("Tool call refused") for r in results)
    verdicts = [r["data"]["verdict"] for r in sink.records if r["event"] == "tool_decision"]
    assert verdicts == ["deny", "deny"]
