"""SARIF and JUnit renderings of a fuzz report."""

from __future__ import annotations

import json
from pathlib import Path
from xml.etree import ElementTree as ET  # noqa: S405 - parsing our own generated output in tests

import jsonschema
import pytest

from agentsec.cli import main
from agentsec.fuzzer import FuzzConfig, run
from agentsec.fuzzer.formats import clean, to_junit, to_sarif
from agentsec.fuzzer.harness import CaseResult
from agentsec.fuzzer.mock_agents import GuardedAgent, NaiveAgent
from agentsec.fuzzer.report import FuzzReport

SCHEMA = json.loads(
    (Path(__file__).parent / "data" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8")
)


def _report(agent, **cfg) -> FuzzReport:
    return run(agent, FuzzConfig(seed=3, **cfg))


def _crafted(**overrides) -> CaseResult:
    base = dict(
        case_id="override-01|identity|direct",
        payload_id="override-01",
        category="instruction_override",
        goal="canary",
        mutator="identity",
        scenario="direct",
        success=True,
        hits=["canary_echoed"],
        evidence="ok",
    )
    return CaseResult(**{**base, **overrides})


def _with(results: list[CaseResult]) -> FuzzReport:
    report = _report(GuardedAgent(), max_cases=1)
    report.results = results
    report.total = len(results)
    report.successes = sum(r.success for r in results)
    report.errors = sum(r.error is not None for r in results)
    return report


# ------------------------------------------------------------------------------ SARIF


def test_sarif_validates_against_the_official_schema():
    report = _report(NaiveAgent(), max_cases=60)
    assert report.successes > 0
    sarif = to_sarif(report, artifact_uri="src/agent.py", target="builtin:naive")
    jsonschema.validate(sarif, SCHEMA)
    run_ = sarif["runs"][0]
    assert len(run_["results"]) == report.successes
    ids = {r["id"] for r in run_["tool"]["driver"]["rules"]}
    assert {res["ruleId"] for res in run_["results"]} <= ids
    loc = run_["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/agent.py" and loc["region"]["startLine"] == 1


def test_sarif_with_no_successes_is_valid_and_empty():
    report = _report(GuardedAgent(), categories=["tool_misuse"], max_cases=40)
    assert report.successes == 0
    sarif = to_sarif(report)
    jsonschema.validate(sarif, SCHEMA)
    assert sarif["runs"][0]["results"] == [] and sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_severity_follows_the_goal_and_fingerprints_are_stable():
    report = _with(
        [
            _crafted(case_id="a", goal="tool_misuse", hits=["forbidden_tool_call"]),
            _crafted(case_id="b", goal="canary"),
            _crafted(case_id="c", goal="something_new"),
            _crafted(case_id="d", success=False, hits=[]),
        ]
    )
    sarif = to_sarif(report)
    jsonschema.validate(sarif, SCHEMA)
    by_case = {
        r["partialFingerprints"]["agentsec/caseId/v1"]: r for r in sarif["runs"][0]["results"]
    }
    assert set(by_case) == {"a", "b", "c"}  # the failed-attack case is not a finding
    assert by_case["a"]["level"] == "error" and by_case["a"]["ruleId"] == "AGSEC-TOOL-MISUSE"
    assert by_case["b"]["level"] == "warning" and by_case["c"]["ruleId"] == "AGSEC-OTHER"
    rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["AGSEC-TOOL-MISUSE"]["properties"]["security-severity"] == "8.5"
    assert "OWASP-LLM-2025-LLM06" in rules["AGSEC-TOOL-MISUSE"]["properties"]["tags"]


def test_hostile_target_output_cannot_break_sarif():
    hostile = "leak\x00\x1b[31m\ud800 <script>alert(1)</script>\r\n" + "A" * 5000
    sarif = to_sarif(_with([_crafted(evidence=hostile)]), target="evil\x00target")
    text = json.dumps(sarif)  # must be serialisable
    jsonschema.validate(json.loads(text), SCHEMA)
    message = sarif["runs"][0]["results"][0]["message"]["text"]
    assert "\x00" not in message and "\x1b" not in message and "\n" not in message
    assert len(message) < 600


# ------------------------------------------------------------------------------ JUnit


def test_junit_is_well_formed_with_failures_and_errors():
    report = _with(
        [
            _crafted(case_id="win", category="tool_misuse", goal="tool_misuse"),
            _crafted(case_id="held", category="tool_misuse", success=False, hits=[]),
            _crafted(
                case_id="crash", category="exfiltration", success=False, hits=[], error="boom"
            ),
        ]
    )
    root = ET.fromstring(to_junit(report))  # noqa: S314 - our own output
    assert root.tag == "testsuites"
    assert (root.get("tests"), root.get("failures"), root.get("errors")) == ("3", "1", "1")
    suites = {s.get("name"): s for s in root.findall("testsuite")}
    assert set(suites) == {"tool_misuse", "exfiltration"}
    cases = {c.get("name"): c for c in root.iter("testcase")}
    assert cases["win"].find("failure") is not None
    assert cases["held"].find("failure") is None and cases["held"].find("error") is None
    assert cases["crash"].find("error").get("message") == "boom"


def test_hostile_target_output_cannot_break_junit():
    hostile = "x\x00\x08\ud800]]><![CDATA[ <!-- \"quote' & " + "B" * 5000
    xml = to_junit(_with([_crafted(evidence=hostile, case_id='id"><injected/>')]))
    root = ET.fromstring(xml)  # noqa: S314 - must parse: no illegal characters, escaped markup
    assert root.find(".//injected") is None
    failure = root.find(".//failure")
    assert failure is not None and len(failure.text or "") <= 300


def test_clean_bounds_and_strips():
    assert clean("a\x00b\nc") == "a b c"
    # bidi-override and zero-width characters could visually spoof text in a report viewer
    assert clean("safe‮evil​!") == "safe evil !"
    assert clean("tab\there") == "tab here" and clean("a b") == "a b"
    assert clean("keep ünïcödé and 日本語") == "keep ünïcödé and 日本語"
    assert len(clean("z" * 1000)) == 300 and clean("z" * 1000).endswith("…")


# --------------------------------------------------------------------------------- CLI


def test_cli_writes_sarif_and_junit(tmp_path):
    sarif, junit = tmp_path / "r.sarif", tmp_path / "r.xml"
    code = main(
        [
            "fuzz",
            "--target",
            "builtin:naive",
            "--max-cases",
            "40",
            "--quiet",
            "--sarif",
            str(sarif),
            "--sarif-artifact",
            "src/my_agent.py",
            "--junit",
            str(junit),
        ]
    )
    assert code == 0
    data = json.loads(sarif.read_text(encoding="utf-8"))
    jsonschema.validate(data, SCHEMA)
    uri = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == "src/my_agent.py"
    assert data["runs"][0]["properties"]["target"] == "builtin:naive"
    assert ET.fromstring(junit.read_text(encoding="utf-8")).tag == "testsuites"  # noqa: S314


@pytest.mark.parametrize("agent", [NaiveAgent, GuardedAgent])
def test_report_methods_match_the_module_functions(agent):
    report = _report(agent(), max_cases=20)
    assert (
        json.loads(report.to_sarif(artifact_uri="x"))["runs"][0]["results"]
        == to_sarif(report, artifact_uri="x")["runs"][0]["results"]
    )
    assert report.to_junit() == to_junit(report)
