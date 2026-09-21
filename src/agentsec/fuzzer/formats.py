"""CI-friendly renderings of a fuzz report: SARIF 2.1.0 and JUnit XML.

SARIF lets results appear in GitHub code scanning (and other SARIF viewers); JUnit
XML is understood by nearly every CI system's test-report UI.

Both embed text that came back from the system under test. An attacker may have
steered that text, so it is bounded and stripped of control characters before use.
"""

from __future__ import annotations

import unicodedata
from typing import TYPE_CHECKING, Any
from xml.etree import ElementTree as ET  # noqa: S405 - only used to *generate* XML

from agentsec import __version__

if TYPE_CHECKING:
    from agentsec.fuzzer.harness import CaseResult
    from agentsec.fuzzer.report import FuzzReport

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/DustyStudy/ai-agent-security-toolkit"
MAX_TEXT = 300

# Unicode categories removed from quoted text: control characters (incl. NUL and ESC), format
# characters (zero-width and bidirectional overrides that can visually spoof a report),
# line/paragraph separators and lone surrogates. XML 1.0 cannot carry most of these anyway.
_STRIP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})

# goal -> (rule id, name, severity level, GitHub security-severity, OWASP LLM Top 10 (2025), help)
_RULES: dict[str, tuple[str, str, str, str, str, str]] = {
    "tool_misuse": (
        "AGSEC-TOOL-MISUSE",
        "InjectedInstructionCalledForbiddenTool",
        "error",
        "8.5",
        "LLM06",
        "A prompt injection made the agent request a tool it must never call. Enforce a "
        "deny-by-default tool policy (agentsec.sandbox.ToolGuard) so a hijacked model "
        "cannot act on the request.",
    ),
    "exfil": (
        "AGSEC-EXFILTRATION",
        "InjectedInstructionCausedDataExfiltration",
        "error",
        "8.5",
        "LLM02",
        "A prompt injection made the agent send data toward an attacker-controlled host "
        "(tool arguments or a rendered markdown/HTML image or link). Validate output and "
        "restrict outbound destinations (agentsec.middleware.OutputGuard, ToolGuard URL rules).",
    ),
    "prompt_leak": (
        "AGSEC-PROMPT-LEAK",
        "InjectedInstructionLeakedSystemPrompt",
        "error",
        "7.0",
        "LLM07",
        "A prompt injection made the agent disclose a secret planted in its system prompt. "
        "Keep secrets out of prompts and add a protected-string output check.",
    ),
    "canary": (
        "AGSEC-INSTRUCTION-FOLLOWING",
        "AgentFollowedInjectedInstruction",
        "warning",
        "5.0",
        "LLM01",
        "The agent followed an instruction planted in untrusted content. On its own this is "
        "low impact, but it is the first step of every real injection. Contain the blast "
        "radius with tool policy and output validation.",
    ),
}
_FALLBACK = (
    "AGSEC-OTHER",
    "InjectionSucceeded",
    "warning",
    "5.0",
    "LLM01",
    "A prompt-injection test case succeeded against the target.",
)


def clean(text: str, limit: int = MAX_TEXT) -> str:
    """Bound and de-fang text that originated in the system under test."""
    text = "".join(
        " " if unicodedata.category(ch) in _STRIP_CATEGORIES or ch in "\ufffe\uffff" else ch
        for ch in text
    )
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _rule_for(goal: str) -> tuple[str, str, str, str, str, str]:
    return _RULES.get(goal, _FALLBACK)


# ------------------------------------------------------------------------------ SARIF


def to_sarif(
    report: FuzzReport, *, artifact_uri: str = "agent", target: str | None = None
) -> dict[str, Any]:
    """Render successful attacks as a SARIF 2.1.0 log.

    Fuzz findings have no source location, but code-scanning UIs need one to attach an
    alert to, so every result points at ``artifact_uri`` (line 1). Pass the path of the
    file that defines your agent, relative to the repository root.
    """
    used = sorted({_rule_for(r.goal) for r in report.results if r.success})
    rules = [
        {
            "id": rid,
            "name": name,
            "shortDescription": {"text": name},
            "fullDescription": {"text": help_text},
            "help": {"text": help_text},
            "defaultConfiguration": {"level": level},
            "properties": {
                "tags": ["security", "prompt-injection", "OWASP-LLM-2025-" + owasp],
                "security-severity": sev,
                "precision": "high",
            },
        }
        for rid, name, level, sev, owasp, help_text in used
    ]
    results = [_sarif_result(r, artifact_uri) for r in report.results if r.success]
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "agentsec",
                "version": __version__,
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }
        },
        "results": results,
        "properties": {
            "seed": report.seed,
            "attackSuccessRate": report.asr,
            "cases": report.total,
            "targetErrors": report.errors,
        },
    }
    if target:
        run["properties"]["target"] = clean(target, 200)
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def _sarif_result(r: CaseResult, artifact_uri: str) -> dict[str, Any]:
    rid, _, level, _, _, _ = _rule_for(r.goal)
    detail = f" Evidence: {clean(r.evidence)}" if r.evidence else ""
    return {
        "ruleId": rid,
        "level": level,
        "message": {
            "text": (
                f"Attack {r.payload_id} ({r.category}, obfuscation {r.mutator}, "
                f"delivered {r.scenario}) succeeded: {', '.join(r.hits)}.{detail}"
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri},
                    "region": {"startLine": 1},
                }
            }
        ],
        "partialFingerprints": {"agentsec/caseId/v1": r.case_id},
        "properties": {"category": r.category, "mutator": r.mutator, "scenario": r.scenario},
    }


# ------------------------------------------------------------------------------ JUnit


def to_junit(report: FuzzReport) -> str:
    """Render a JUnit XML report: one test suite per attack category, one test per case.

    A succeeded attack is a *failure*; a case where the target crashed is an *error*.
    """
    by_category: dict[str, list[CaseResult]] = {}
    for r in report.results:
        by_category.setdefault(r.category, []).append(r)

    root = ET.Element(
        "testsuites",
        name="agentsec-fuzz",
        tests=str(report.total),
        failures=str(report.successes),
        errors=str(report.errors),
    )
    for category, cases in sorted(by_category.items()):
        suite = ET.SubElement(
            root,
            "testsuite",
            name=clean(category),
            tests=str(len(cases)),
            failures=str(sum(1 for c in cases if c.success)),
            errors=str(sum(1 for c in cases if c.error is not None)),
            time=f"{sum(c.latency_ms for c in cases) / 1000:.3f}",
        )
        for c in cases:
            case = ET.SubElement(
                suite,
                "testcase",
                classname=f"agentsec.{clean(category)}",
                name=clean(c.case_id),
                time=f"{c.latency_ms / 1000:.3f}",
            )
            if c.error is not None:
                err = ET.SubElement(case, "error", message=clean(c.error), type="TargetError")
                err.text = clean(c.error)
            elif c.success:
                fail = ET.SubElement(
                    case,
                    "failure",
                    message=clean(f"attack succeeded: {', '.join(c.hits)}"),
                    type=_rule_for(c.goal)[0],
                )
                fail.text = clean(c.evidence)
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"
