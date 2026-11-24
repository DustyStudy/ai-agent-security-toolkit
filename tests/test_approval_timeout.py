"""ToolGuard(approval_timeout_s=...): an approver that does not answer in time refuses the call."""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from agentsec.middleware import AuditLogger, MemorySink
from agentsec.sandbox import Policy, ToolGuard
from agentsec.types import ToolCall

POLICY = Policy.from_dict({"tools": {"pay": {"require_approval": True, "args": {}}}})
CALL = ToolCall("pay", {})


def approvals(sink):
    return [r["data"]["approved"] for r in sink.records if r["event"] == "approval"]


def test_a_sync_approver_that_hangs_refuses_the_call_in_time():
    release, sink = threading.Event(), MemorySink()
    guard = ToolGuard(
        POLICY,
        approver=lambda c, d: release.wait(10),
        audit=AuditLogger(sink),
        approval_timeout_s=0.05,
    )
    started = time.monotonic()
    decision = guard.authorize(CALL)
    release.set()  # its late True is ignored
    assert time.monotonic() - started < 5
    assert not decision.allowed
    assert "approver failed (TimeoutError); refused" in decision.reasons
    assert approvals(sink) == [False]


def test_an_async_approver_that_hangs_is_cancelled():
    cancelled = []

    async def hang(call, decision):
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            cancelled.append(True)
            raise
        return True

    guard = ToolGuard(POLICY, approver=hang, approval_timeout_s=0.05)
    decision = asyncio.run(guard.aauthorize(CALL))
    assert not decision.allowed and cancelled == [True]
    assert "approver failed (TimeoutError); refused" in decision.reasons


def test_a_slow_sync_approver_in_aauthorize_times_out():
    # asyncio.run waits for the worker thread on exit, so the approver only sleeps briefly.
    guard = ToolGuard(
        POLICY, approver=lambda c, d: time.sleep(0.5) or True, approval_timeout_s=0.05
    )
    decision = asyncio.run(guard.aauthorize(CALL))
    assert not decision.allowed


def test_answers_in_time_still_count():
    assert (
        ToolGuard(POLICY, approver=lambda c, d: True, approval_timeout_s=5).authorize(CALL).allowed
    )
    assert (
        not ToolGuard(POLICY, approver=lambda c, d: "y", approval_timeout_s=5)
        .authorize(CALL)
        .allowed
    )  # only True approves, with or without a limit

    def boom(c, d):
        raise RuntimeError("approval service down")

    decision = ToolGuard(POLICY, approver=boom, approval_timeout_s=5).authorize(CALL)
    assert "approver failed (RuntimeError); refused" in decision.reasons


@pytest.mark.parametrize("bad", [0, -1, float("inf"), float("nan"), True, "5"])
def test_the_limit_must_be_a_positive_finite_number(bad):
    with pytest.raises(ValueError):
        ToolGuard(POLICY, approval_timeout_s=bad)
