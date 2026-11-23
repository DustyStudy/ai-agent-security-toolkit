"""scripts/evidence_report.py: test, coverage and fuzz results rendered as evidence."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "evidence_report", ROOT / "scripts" / "evidence_report.py"
)
assert _spec and _spec.loader
evidence_report = importlib.util.module_from_spec(_spec)
sys.modules["evidence_report"] = evidence_report  # dataclasses look the module up
_spec.loader.exec_module(evidence_report)

JUNIT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest">
  <testcase classname="tests.test_a" name="test_ok" time="0.5"/>
  <testcase classname="tests.test_a.TestThing" name="test_ok2" time="0.25"/>
  <testcase classname="tests.test_b" name="test_bad" time="0.1">
    <failure message="assert &lt;script&gt;alert(1)&lt;/script&gt; | pipe">trace</failure>
  </testcase>
  <testcase classname="tests.test_b" name="test_err" time="0"><error message="boom"/></testcase>
  <testcase classname="tests.test_b" name="test_skip" time="0"><skipped message="no sdk"/></testcase>
</testsuite></testsuites>
"""

COVERAGE = """<?xml version="1.0" ?>
<coverage line-rate="0.9583"><packages><package><classes>
  <class filename="src/agentsec/cli.py" line-rate="0.98"/>
  <class filename="src/agentsec/types.py" line-rate="0.5"/>
</classes></package></packages></coverage>
"""


def fuzz_report(path: Path, results: list[tuple[str, bool, str | None]]) -> Path:
    rows = [{"category": c, "success": s, "error": e} for c, s, e in results]
    scored = [r for r in rows if not r["error"]]
    data = {
        "total": len(rows),
        "successes": sum(r["success"] for r in scored),
        "blocked": 0,
        "errors": len(rows) - len(scored),
        "asr": sum(r["success"] for r in scored) / max(len(scored), 1),
        "results": rows,
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def inputs(tmp_path: Path) -> dict[str, Path]:
    (tmp_path / "junit.xml").write_text(JUNIT, encoding="utf-8")
    (tmp_path / "coverage.xml").write_text(COVERAGE, encoding="utf-8")
    fuzz = fuzz_report(
        tmp_path / "fuzz.json",
        [
            ("tool_misuse", False, None),
            ("exfiltration", True, None),
            ("instruction_override", True, None),
            ("prompt_leak", False, "TimeoutError: timed out"),
        ],
    )
    return {"junit": tmp_path / "junit.xml", "coverage": tmp_path / "coverage.xml", "fuzz": fuzz}


def test_junit_counts_and_groups_by_test_file(inputs):
    tests = evidence_report.read_junit([inputs["junit"]])
    assert (tests.passed, tests.failed, tests.errors, tests.skipped) == (2, 1, 1, 1)
    assert tests.total == 5 and not tests.ok
    assert dict(tests.by_file) == {"test_a": [2, 0, 0], "test_b": [0, 2, 1]}
    assert [t for t, _ in tests.failures] == ["tests.test_b::test_bad", "tests.test_b::test_err"]


def test_an_empty_run_is_not_a_pass(tmp_path):
    (tmp_path / "j.xml").write_text("<testsuites/>", encoding="utf-8")
    assert not evidence_report.read_junit([tmp_path / "j.xml"]).ok


def test_fuzz_containment_counts_only_scored_cases(inputs):
    fuzz = evidence_report.read_fuzz("t", inputs["fuzz"])
    assert fuzz.containment == (1, 2)  # the errored prompt_leak case is not scored
    assert fuzz.by_category["instruction_override"] == (1, 1)


def test_cli_writes_markdown_and_html_and_fails_on_failed_tests(inputs, tmp_path):
    md, page = tmp_path / "s.md", tmp_path / "r.html"
    code = evidence_report.main(
        [
            "--junit", str(inputs["junit"]),
            "--coverage", str(inputs["coverage"]),
            "--fuzz", f"guarded={inputs['fuzz']}",
            "--commit", "abc123",
            "--md", str(md),
            "--html", str(page),
        ]
    )  # fmt: skip
    assert code == 1  # a failed test fails the report
    text, html = md.read_text(encoding="utf-8"), page.read_text(encoding="utf-8")
    assert "**Tests: FAIL.** 2 passed, 1 failed, 1 errors, 1 skipped" in text
    assert "95.8%" in text and "| `guarded` | 4 | 2 | 1 / 2 |" in text
    assert "abc123" in text and "abc123" in html
    # Text from the inputs cannot inject markup into the page or break a Markdown table.
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "\\| pipe" in text
    assert html.startswith("<!doctype html>") and "http" not in html  # self-contained


def test_cli_passes_on_a_green_run(tmp_path):
    (tmp_path / "j.xml").write_text(
        '<testsuites><testcase classname="tests.test_a" name="t"/></testsuites>', encoding="utf-8"
    )
    assert evidence_report.main(["--junit", str(tmp_path / "j.xml"), "--md", "-"]) == 0


def test_cli_reports_unreadable_input_with_exit_2(tmp_path, capsys):
    (tmp_path / "bad.xml").write_text("<not xml", encoding="utf-8")
    assert evidence_report.main(["--junit", str(tmp_path / "bad.xml")]) == 2
    assert evidence_report.main(["--junit", str(tmp_path / "missing.xml")]) == 2
    assert "error:" in capsys.readouterr().err


def test_cli_needs_an_input():
    with pytest.raises(SystemExit) as exc:
        evidence_report.main([])
    assert exc.value.code == 2


def test_bounded_strips_control_characters_and_truncates():
    assert evidence_report.bounded("a\x1b[31mb\nc") == "a [31mb c"
    assert len(evidence_report.bounded("x" * 1000)) == evidence_report.MAX_TEXT


def test_committed_evidence_pages_are_self_contained():
    for page in (ROOT / "docs" / "evidence").glob("v*/*.html"):
        text = page.read_text(encoding="utf-8")
        assert "<script" not in text and "http" not in text, page
