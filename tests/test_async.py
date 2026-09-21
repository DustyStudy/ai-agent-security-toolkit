"""Async API: ToolGuard.a*, adapters, SafeCommandRunner.arun and async fuzz targets.

These run coroutines with ``asyncio.run`` so the suite needs no async test plugin.
"""

from __future__ import annotations

import asyncio
import gc
import sys
import threading
import warnings

import pytest

from agentsec.fuzzer import FuzzConfig, load_target, run, sync_target, text_target
from agentsec.middleware import AuditLogger, MemorySink
from agentsec.sandbox import (
    ExecRule,
    Policy,
    SafeCommandRunner,
    Session,
    ToolDenied,
    ToolGuard,
    arun_anthropic_tool_uses,
    arun_openai_tool_calls,
    run_anthropic_tool_uses,
    run_openai_tool_calls,
)
from agentsec.sandbox.guard import _ASYNC_APPROVER_REASON
from agentsec.types import AttackInput, ToolCall, coerce_response
from tests import fixtures_target
from tests.conftest import fake_aws_key


def _policy(**tools) -> Policy:
    return Policy.from_dict({"tools": tools})


READ = {"returns_untrusted": True, "args": {"q": {"type": "string"}}}
SEND = {"side_effects": True, "args": {"to": {"type": "string"}}}
PLAIN = {"args": {"n": {"type": "integer"}}}


# ---------------------------------------------------------------- ToolGuard.aexecute


def test_aexecute_runs_async_and_sync_tools_and_audits_in_order():
    sink = MemorySink()
    guard = ToolGuard(_policy(plain=PLAIN), audit=AuditLogger(sink))

    async def async_tool(n):
        return n + 1

    def sync_tool(n):
        return n + 2

    async def go():
        a = await guard.aexecute(ToolCall("plain", {"n": 1}), async_tool)
        b = await guard.aexecute(ToolCall("plain", {"n": 1}), sync_tool)
        return a, b

    assert asyncio.run(go()) == (2, 3)
    events = [r["event"] for r in sink.records]
    assert events == ["tool_request", "tool_decision", "tool_result"] * 2


def test_sync_tools_run_off_the_event_loop_thread():
    guard = ToolGuard(_policy(plain=PLAIN))
    seen: dict[str, int] = {}

    def blocking_tool(n):
        seen["tool"] = threading.get_ident()
        return n

    async def go():
        seen["loop"] = threading.get_ident()
        await guard.aexecute(ToolCall("plain", {"n": 1}), blocking_tool)

    asyncio.run(go())
    assert seen["tool"] != seen["loop"]


def test_partial_and_callable_objects_with_async_call_are_awaited():
    import functools

    guard = ToolGuard(_policy(plain=PLAIN))

    async def base(n, *, add):
        return n + add

    class AsyncCallable:
        async def __call__(self, n):
            return n * 10

    async def go():
        return (
            await guard.aexecute(ToolCall("plain", {"n": 1}), functools.partial(base, add=5)),
            await guard.aexecute(ToolCall("plain", {"n": 2}), AsyncCallable()),
        )

    assert asyncio.run(go()) == (6, 20)


def test_aexecute_default_denies_unlisted_tools_and_bad_arguments():
    guard = ToolGuard(_policy(plain=PLAIN))

    async def tool(**kw):
        raise AssertionError("must not run")

    async def go(call):
        return await guard.aexecute(call, tool)

    with pytest.raises(ToolDenied, match="default deny"):
        asyncio.run(go(ToolCall("nope", {})))
    with pytest.raises(ToolDenied, match="expected"):
        asyncio.run(go(ToolCall("plain", {"n": "not-an-int"})))


def test_awrap_guards_a_function():
    guard = ToolGuard(_policy(plain=PLAIN))

    async def tool(n):
        return n * 3

    wrapped = guard.awrap("plain", tool)
    assert asyncio.run(wrapped(n=4)) == 12
    with pytest.raises(ToolDenied):
        asyncio.run(wrapped(n="x"))


# ------------------------------------------------------------------ approvers


def test_async_and_sync_approvers_work_with_aauthorize():
    policy = _policy(plain={**PLAIN, "require_approval": True})

    async def yes(call, decision):
        await asyncio.sleep(0)
        return True

    def no(call, decision):
        return False

    call = ToolCall("plain", {"n": 1})
    assert asyncio.run(ToolGuard(policy, approver=yes).aauthorize(call)).allowed
    refused = asyncio.run(ToolGuard(policy, approver=no).aauthorize(call))
    assert not refused.allowed and "approval refused" in refused.message()
    none = asyncio.run(ToolGuard(policy).aauthorize(call))
    assert not none.allowed and "no approver configured" in none.message()


def test_async_approver_on_the_sync_path_fails_closed_without_leaking_a_coroutine():
    """An un-awaited coroutine is truthy; it must never be read as 'approved'."""
    ran = []

    async def approve_everything(call, decision):
        ran.append(1)
        return True

    guard = ToolGuard(
        _policy(plain={**PLAIN, "require_approval": True}), approver=approve_everything
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # "coroutine ... was never awaited" would fail the test
        decision = guard.authorize(ToolCall("plain", {"n": 1}))
        gc.collect()
    assert not decision.allowed
    assert _ASYNC_APPROVER_REASON in decision.reasons
    with pytest.raises(ToolDenied):
        guard.execute(ToolCall("plain", {"n": 1}), lambda n: n)


def test_approver_may_mutate_arguments_but_the_tool_runs_the_approved_snapshot():
    args = {"to": "alice@corp.example"}
    seen = {}

    async def approver(call, decision):
        args["to"] = "attacker@evil.example"  # changed while awaiting the human
        return True

    def send(to):
        seen["to"] = to
        return "sent"

    guard = ToolGuard(_policy(send=SEND | {"require_approval": True}), approver=approver)
    asyncio.run(guard.aexecute(ToolCall("send", args), send))
    assert seen["to"] == "alice@corp.example"


# ------------------------------------------------------- limits and concurrency


def test_per_tool_and_total_limits_hold_under_concurrent_tasks():
    guard = ToolGuard(
        Policy.from_dict(
            {"max_total_calls": 3, "tools": {"one": PLAIN | {"max_calls": 1}, "any": PLAIN}}
        )
    )
    session = Session()

    async def tool(n):
        await asyncio.sleep(0)
        return n

    async def go():
        one = await asyncio.gather(
            *[guard.aexecute(ToolCall("one", {"n": i}), tool, session) for i in range(20)],
            return_exceptions=True,
        )
        rest = await asyncio.gather(
            *[guard.aexecute(ToolCall("any", {"n": i}), tool, session) for i in range(20)],
            return_exceptions=True,
        )
        return one, rest

    one, rest = asyncio.run(go())
    assert sum(not isinstance(r, Exception) for r in one) == 1
    assert sum(not isinstance(r, Exception) for r in rest) == 2  # 3 total - 1 already used
    assert session.total_calls == 3


def test_limits_hold_when_an_awaiting_approver_lets_tasks_interleave():
    """While one task waits on the approver, others pass the limit check too. The re-check under
    the lock at commit time is what keeps the limit a limit."""

    async def slow_yes(call, decision):
        await asyncio.sleep(0.01)
        return True

    guard = ToolGuard(
        _policy(one=PLAIN | {"max_calls": 1, "require_approval": True}), approver=slow_yes
    )
    session = Session()

    async def tool(n):
        return n

    async def go():
        return await asyncio.gather(
            *[guard.aexecute(ToolCall("one", {"n": i}), tool, session) for i in range(10)],
            return_exceptions=True,
        )

    results = asyncio.run(go())
    assert sum(not isinstance(r, Exception) for r in results) == 1
    assert session.calls["one"] == 1
    denied = [r for r in results if isinstance(r, ToolDenied)]
    assert len(denied) == 9 and all("limit" in r.decision.message() for r in denied)


def test_a_blocking_tool_does_not_stall_other_tasks():
    guard = ToolGuard(_policy(plain=PLAIN))
    import time

    def slow(n):
        time.sleep(0.3)
        return n

    async def go():
        ticks = 0

        async def ticker():
            nonlocal ticks
            for _ in range(20):
                await asyncio.sleep(0.01)
                ticks += 1

        await asyncio.gather(guard.aexecute(ToolCall("plain", {"n": 1}), slow), ticker())
        return ticks

    assert asyncio.run(go()) == 20


def test_dns_resolving_rules_evaluate_in_a_worker_thread():
    threads = {}

    def resolver(host):
        threads["resolver"] = threading.get_ident()
        return ["93.184.216.34"]

    policy = _policy(fetch={"args": {"url": {"type": "url", "resolve_dns": True}}})
    guard = ToolGuard(policy, resolver=resolver)

    async def go():
        threads["loop"] = threading.get_ident()
        return await guard.aauthorize(ToolCall("fetch", {"url": "https://ok.example/"}))

    assert asyncio.run(go()).allowed
    assert threads["resolver"] != threads["loop"]


# ------------------------------------------------------------------------ taint


def test_taint_from_an_async_read_blocks_a_later_side_effect_tool():
    guard = ToolGuard(_policy(read=READ, send=SEND))
    session = Session()

    async def read(q):
        return "attacker text"

    async def send(to):
        raise AssertionError("must not run")

    async def go():
        await guard.aexecute(ToolCall("read", {"q": "x"}), read, session)
        await guard.aexecute(ToolCall("send", {"to": "a@b.example"}), send, session)

    with pytest.raises(ToolDenied, match="untrusted content"):
        asyncio.run(go())
    assert session.tainted and session.taint_sources == ["read"]


def test_session_is_tainted_even_if_the_untrusted_tool_raises():
    guard = ToolGuard(_policy(read=READ))
    session = Session()

    async def read(q):
        raise RuntimeError("boom after fetching")

    with pytest.raises(RuntimeError):
        asyncio.run(guard.aexecute(ToolCall("read", {"q": "x"}), read, session))
    assert session.tainted


def test_session_is_tainted_when_the_untrusted_tool_is_cancelled():
    guard = ToolGuard(_policy(read=READ))
    session = Session()
    started = asyncio.Event

    async def go():
        gate = started()

        async def read(q):
            gate.set()
            await asyncio.sleep(30)

        task = asyncio.create_task(guard.aexecute(ToolCall("read", {"q": "x"}), read, session))
        await gate.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(go())
    assert session.tainted


# ------------------------------------------------------ sync path with async tools


def test_sync_execute_refuses_async_tools_instead_of_returning_a_coroutine():
    guard = ToolGuard(_policy(read=READ))
    session = Session()
    ran = []

    async def read(q):
        ran.append(q)
        return "text"

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        with pytest.raises(TypeError, match="aexecute"):
            guard.execute(ToolCall("read", {"q": "x"}), read, session)
        gc.collect()
    assert ran == []
    assert session.tainted  # still fail-closed: the tool was authorized


# ------------------------------------------------------------------- adapters


def _registry():
    calls = []

    async def read(q):
        calls.append(("read", q))
        return f"doc about {q}"

    def send(to):
        calls.append(("send", to))
        return "sent"

    async def boom(n):
        raise RuntimeError(f"connect failed for {fake_aws_key()}")

    return calls, {"read": read, "send": send, "boom": boom}


_ADAPTER_POLICY = _policy(read=READ, send=SEND, boom=PLAIN)


def _sync_registry(reg):
    """Sync twins of the async tools so the sync adapters can run the same scenario."""
    import inspect

    def make(fn):
        if not inspect.iscoroutinefunction(fn):
            return fn

        def wrapper(**kw):
            return asyncio.run(fn(**kw))

        return wrapper

    return {name: make(fn) for name, fn in reg.items()}


def test_async_anthropic_adapter_matches_the_sync_adapter():
    blocks = [
        {"type": "text", "text": "thinking"},
        {"type": "tool_use", "id": "1", "name": "read", "input": {"q": "x"}},
        {"type": "tool_use", "id": "2", "name": "send", "input": {"to": "a@b.example"}},
        {"type": "tool_use", "id": "3", "name": "boom", "input": {"n": 1}},
        {"type": "tool_use", "id": "4", "name": "missing", "input": {}},
        {"type": "tool_use", "id": "5", "name": "read", "input": "not-an-object"},
    ]
    _, reg = _registry()
    got = asyncio.run(arun_anthropic_tool_uses(ToolGuard(_ADAPTER_POLICY), Session(), blocks, reg))
    _, reg2 = _registry()
    want = run_anthropic_tool_uses(
        ToolGuard(_ADAPTER_POLICY), Session(), blocks, _sync_registry(reg2)
    )
    assert got == want
    by_id = {r["tool_use_id"]: r for r in got}
    assert by_id["1"]["content"] == "doc about x" and "is_error" not in by_id["1"]
    assert "untrusted content" in by_id["2"]["content"] and by_id["2"]["is_error"]
    assert fake_aws_key() not in by_id["3"]["content"]  # exception text is redacted
    assert "default deny" in by_id["4"]["content"]


def test_async_openai_adapter_matches_the_sync_adapter():
    tool_calls = [
        {"id": "a", "function": {"name": "read", "arguments": '{"q": "x"}'}},
        {"id": "b", "function": {"name": "send", "arguments": '{"to": "a@b.example"}'}},
        {"id": "c", "function": {"name": "read", "arguments": "{not json"}},
        {"id": "d", "function": {"name": "read", "arguments": "[1]"}},
    ]
    _, reg = _registry()
    got = asyncio.run(
        arun_openai_tool_calls(ToolGuard(_ADAPTER_POLICY), Session(), tool_calls, reg)
    )
    _, reg2 = _registry()
    want = run_openai_tool_calls(
        ToolGuard(_ADAPTER_POLICY), Session(), tool_calls, _sync_registry(reg2)
    )
    assert got == want
    assert "not valid JSON" in got[2]["content"]


def test_async_adapters_run_calls_in_model_order_so_taint_applies():
    """Read then send in one turn: the send must see the taint from the read."""
    calls, reg = _registry()
    blocks = [
        {"type": "tool_use", "id": "1", "name": "read", "input": {"q": "x"}},
        {"type": "tool_use", "id": "2", "name": "send", "input": {"to": "a@b.example"}},
    ]
    asyncio.run(arun_anthropic_tool_uses(ToolGuard(_ADAPTER_POLICY), Session(), blocks, reg))
    assert calls == [("read", "x")]  # send never ran


# ---------------------------------------------------------------------- runner


def test_runner_arun_runs_allowlisted_commands_and_denies_the_rest(tmp_path):
    from agentsec.sandbox import CommandDenied

    runner = SafeCommandRunner(
        {"py": ExecRule(executable=sys.executable, allowed_subcommands=["--version"])},
        cwd_roots=[str(tmp_path)],
        timeout=5,
    )
    out = asyncio.run(runner.arun("py", ["--version"]))
    assert out.returncode == 0 and "Python" in (out.stdout + out.stderr)
    with pytest.raises(CommandDenied, match="not allowlisted"):
        asyncio.run(runner.arun("sh", ["-c", "id"]))
    with pytest.raises(CommandDenied, match="subcommand"):
        asyncio.run(runner.arun("py", ["-c", "print(1)"]))


# ----------------------------------------------------------------------- fuzzer


def test_unwrapped_async_target_is_an_error_not_a_silent_zero_percent():
    async def agent(inp):
        return "ok"

    with pytest.raises(TypeError, match="awaitable"):
        coerce_response(agent(AttackInput(user_message="hi")))

    report = run(agent, FuzzConfig(max_cases=3))  # a bare coroutine function as the target
    assert report.total == 3 and all(r.error and "awaitable" in r.error for r in report.results)


def test_async_text_target_is_scored_on_its_real_output():
    safe = run(text_target(fixtures_target.async_echo), FuzzConfig(max_cases=20, seed=1))
    assert safe.total == 20 and safe.successes == 0 and not any(r.error for r in safe.results)

    leaky = run(text_target(fixtures_target.async_compromised), FuzzConfig(max_cases=20, seed=1))
    assert leaky.successes > 0  # echoing the prompt echoes the planted canary


def test_load_target_handles_async_module_callables_and_reuses_one_event_loop():
    fixtures_target.LOOP_IDS.clear()
    target = load_target("tests.fixtures_target:async_compromised")
    report = run(target, FuzzConfig(max_cases=5, seed=1))
    assert report.total == 5 and not any(r.error for r in report.results)
    assert len(fixtures_target.LOOP_IDS) == 5 and len(set(fixtures_target.LOOP_IDS)) == 1
    assert run(load_target("tests.fixtures_target:async_echo"), FuzzConfig(max_cases=3)).total == 3


def test_sync_target_leaves_ordinary_callables_alone_and_keeps_accepts():
    def plain(prompt):
        return "x"

    assert sync_target(plain) is plain

    async def typed(inp):
        return coerce_response("y")

    typed.accepts = "attack_input"
    bridged = sync_target(typed)
    assert bridged.accepts == "attack_input"
    assert bridged(AttackInput(user_message="hi")).text == "y"
