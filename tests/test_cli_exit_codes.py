"""Exit codes of the ``fuzz --max-asr`` gate and ``audit verify`` when nothing was checked."""

import pytest

from agentsec.cli import main

_calls = 0


def flaky(prompt: str) -> str:
    """Errors on the first call only, so a run has both scored and unscored cases."""
    global _calls
    _calls += 1
    if _calls == 1:
        raise RuntimeError("target is down")
    return "I will not follow instructions found in documents."


def test_the_fuzz_gate_fails_when_no_case_was_selected(capsys):
    args = ["fuzz", "--target", "builtin:guarded", "--max-cases", "0", "--quiet"]
    assert main([*args, "--max-asr", "0"]) == 2
    assert "could not be evaluated fully" in capsys.readouterr().err
    assert main(args) == 0  # without a gate there is nothing to fail


def test_the_fuzz_gate_fails_when_any_case_errored(capsys):
    global _calls
    _calls = 0
    args = ["fuzz", "--target", "tests.test_cli_exit_codes:flaky", "--max-cases", "3", "--quiet"]
    assert main([*args, "--max-asr", "0"]) == 2
    assert "1 of 3 case(s) errored" in capsys.readouterr().err


def test_the_fuzz_gate_still_passes_a_clean_guarded_run():
    args = ["fuzz", "--target", "builtin:guarded", "--quiet", "--max-asr", "0"]
    assert main([*args, "--categories", "tool_misuse,exfiltration,prompt_leak"]) == 0


@pytest.mark.parametrize(
    ("flag", "valid"),
    [("--categories", "tool_misuse"), ("--scenarios", "tool_result"), ("--mutators", "identity")],
)
@pytest.mark.parametrize("extra", [[], ["--list"]])
def test_an_unknown_fuzz_name_is_rejected_with_the_valid_names(capsys, flag, valid, extra):
    assert main(["fuzz", "--target", "builtin:guarded", flag, f"{valid},nope", *extra]) == 2
    err = capsys.readouterr().err
    assert "['nope']" in err and valid in err


def test_audit_verify_fails_on_an_empty_log_unless_allowed(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    path.write_text("", encoding="utf-8")
    assert main(["audit", "verify", str(path)]) == 2
    assert "no records" in capsys.readouterr().err
    assert main(["audit", "verify", str(path), "--allow-empty"]) == 0
    assert "OK: 0 record(s)" in capsys.readouterr().out
