"""Circuit breaker across fuzz cases: FuzzConfig.max_consecutive_errors / --max-consecutive-errors."""

from __future__ import annotations

from agentsec.cli import main
from agentsec.fuzzer import FuzzConfig, run
from agentsec.fuzzer.harness import NOT_RUN_PREFIX
from agentsec.types import TargetResponse


def failing(calls: list):
    def target(inp):
        calls.append(inp)
        raise ConnectionRefusedError("connection refused")

    return target


def test_a_dead_target_stops_after_n_errors_in_a_row():
    calls: list = []
    report = run(failing(calls), FuzzConfig(max_cases=30, max_consecutive_errors=4))
    errors = [r.error for r in report.results]
    assert len(calls) == 4 and len(errors) == 30 and report.errors == 30
    assert all(e.startswith("ConnectionRefusedError") for e in errors[:4])
    assert all(e.startswith(NOT_RUN_PREFIX) for e in errors[4:])
    assert "4 errors in a row" in errors[4]


def test_errors_with_answers_between_them_do_not_trip_it():
    calls: list = []

    def flaky(inp):
        calls.append(inp)
        if len(calls) % 2:
            raise RuntimeError("blip")
        return TargetResponse(text="no")

    report = run(flaky, FuzzConfig(max_cases=20, max_consecutive_errors=2))
    assert len(calls) == 20 and report.errors == 10


def test_zero_or_none_turns_it_off_and_the_default_is_ten():
    assert FuzzConfig().max_consecutive_errors == 10
    for off in (0, None):
        calls: list = []
        run(failing(calls), FuzzConfig(max_cases=15, max_consecutive_errors=off))
        assert len(calls) == 15


def test_cli_flag(capsys):
    args = ["fuzz", "--target", "tests.fixtures_target:broken", "--max-cases", "6", "--quiet"]
    assert main([*args, "--max-consecutive-errors", "-1"]) == 2
    assert main([*args, "--max-consecutive-errors", "2"]) == 2  # every case errored
    err = capsys.readouterr().err
    assert "2 errors in a row" in err and "4 case(s) not run" in err
