"""Wall-clock limit for ``module:callable`` fuzz targets."""

from __future__ import annotations

import threading
import time

import pytest

from agentsec.fuzzer import FuzzConfig, run
from agentsec.fuzzer.harness import NOT_RUN_PREFIX, TargetUnavailable
from agentsec.fuzzer.targets import load_target, text_target, time_limited


def test_an_async_callable_is_cancelled_at_the_limit():
    started = time.monotonic()
    target = load_target("tests.fixtures_target:async_hang", timeout=0.05)
    report = run(target, FuzzConfig(max_cases=2))
    assert time.monotonic() - started < 5
    assert all(r.error and r.error.startswith("TimeoutError") for r in report.results)


def test_a_stuck_sync_callable_times_out_then_stops_the_run():
    release = threading.Event()
    calls = []

    def hang(prompt: str) -> str:
        calls.append(prompt)
        release.wait(10)
        return "late"

    limited = time_limited(hang, 0.05)
    with pytest.raises(TimeoutError, match="0.05s case timeout"):
        limited("a")
    with pytest.raises(TargetUnavailable):
        limited("b")  # the first call still holds the target
    assert calls == ["a"]
    release.set()
    time.sleep(0.2)
    assert limited("c") == "late"  # free again once the stuck call returned


def test_in_a_run_the_cases_after_a_stuck_call_are_not_run():
    release = threading.Event()
    limited = time_limited(lambda prompt: release.wait(10) and "late", 0.05)
    report = run(text_target(limited), FuzzConfig(max_cases=3))
    release.set()
    errors = [r.error for r in report.results]
    assert errors[0].startswith("TimeoutError")
    assert errors[1].startswith("TargetUnavailable") and errors[2].startswith(NOT_RUN_PREFIX)


def test_fast_callables_keep_their_results_errors_and_accepts_flag():
    def boom(prompt: str) -> str:
        raise ValueError("down")

    with pytest.raises(ValueError, match="down"):
        time_limited(boom, 1)("x")

    def agent(inp):
        return "ok"

    agent.accepts = "attack_input"
    limited = time_limited(agent, 1)
    assert limited.accepts == "attack_input" and limited(None) == "ok"


def test_the_default_limit_applies_without_timeout(monkeypatch):
    seen = []
    monkeypatch.setattr("agentsec.fuzzer.targets.time_limited", lambda fn, t: seen.append(t) or fn)
    load_target("tests.fixtures_target:echo")
    load_target("tests.fixtures_target:echo", timeout=7)
    assert seen == [300.0, 7]
