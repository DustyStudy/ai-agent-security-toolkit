"""DLP custom detectors: operator patterns for their own token formats, checked at load."""

from __future__ import annotations

import hashlib
import json
import time

import pytest

from agentsec.gateway.policyset import group_policy
from agentsec.middleware.audit import AuditLogger, MemorySink
from agentsec.middleware.dlp import DlpConfigError, DlpPolicy
from agentsec.sandbox.policy import Policy
from tests.test_dlp_phase2 import app_with, chat_with, dlp_records
from tests.test_gateway import call

TOKEN = "acme_" + "live_" + "Q7xK2m" * 5 + "Zp"  # 32 chars after the prefix
PATTERN = r"acme_(?:live|test)_[A-Za-z0-9]{32}"


def detector(**over):
    return {
        "kind": "acme_service_token",
        "category": "nhi",
        "pattern": PATTERN,
        "examples": ["acme_test_" + "a" * 32],
        "counter_examples": ["acme_live_short"],
    } | over


def policy(*detectors, **extra):
    return DlpPolicy.from_dict({"detectors": list(detectors or [detector()]), **extra})


def test_a_custom_detector_uses_its_category_modes():
    p = policy()
    out = p.scan(f"your key is {TOKEN}.", "output")
    assert out.action == "redact" and out.text == "your key is [REDACTED:acme_service_token]."
    (m,) = out.matches
    assert (m.kind, m.category) == ("acme_service_token", "nhi")
    assert TOKEN not in json.dumps(m.audit())
    args = p.scan_args({"headers": {"X-Acme": TOKEN}}, "http_post")
    assert args.blocked and args.matches[0].location == "arguments.headers.X-Acme"
    assert p.scan(f"x {TOKEN}", "tool_results").action == "redact"


def test_a_custom_token_used_as_a_key_is_not_copied_into_the_path():
    res = policy().scan_args({TOKEN: {"k": f"x {TOKEN}"}}, "t")
    assert [m.location for m in res.matches] == [
        "arguments.<key>",
        "arguments.[REDACTED:acme_service_token].k",
    ]


def test_a_pii_custom_detector_and_per_kind_overrides():
    emp = detector(kind="employee_id", category="pii", pattern=r"\bE\d{6}\b",
                   examples=["E123456"], counter_examples=["E12345", "XE1234567"])  # fmt: skip
    p = DlpPolicy.from_dict(
        {
            "detectors": [emp],
            "categories": {"pii": {"kinds": {"employee_id": {"output": "block"}}}},
        }
    )
    assert p.scan("staff E654321", "output").blocked
    assert p.scan("staff E654321", "tool_args").action == "monitor"


def test_allowlisting_a_custom_kind_needs_sha256_for_credentials():
    entry = {
        "id": "fixture", "reason": "test fixture", "owner": "sec", "expires": "2026-12-31",
        "kinds": ["acme_service_token"],
        "match": {"sha256": hashlib.sha256(TOKEN.encode()).hexdigest()},
    }  # fmt: skip
    p = policy(allow=[entry])
    (m,) = p.scan(f"k {TOKEN}", "output").matches
    assert (m.action, m.allowed_by) == ("allowed", "fixture")
    with pytest.raises(DlpConfigError, match="pii kinds only"):
        policy(allow=[entry | {"match": {"pattern": "acme_.*"}}])


@pytest.mark.parametrize(
    ("over", "error"),
    [
        ({"kind": "aws_access_key_id"}, "built-in kind"),
        ({"kind": "scan_limit"}, "built-in kind"),
        ({"kind": "Bad-Name"}, "lowercase"),
        ({"category": "secret"}, "category must be one of"),
        ({"pattern": "a" * 513}, "longer than 512"),
        ({"pattern": "acme_(live"}, "pattern:"),
        ({"pattern": "x*", "examples": ["x"]}, "empty string"),
        ({"examples": ["nothing here"]}, "does not match example"),
        ({"examples": []}, "examples must be"),
        ({"counter_examples": ["acme_live_" + "b" * 32]}, "matches counter-example"),
        ({"flags": "i"}, "unknown keys"),
    ],
)
def test_detectors_are_validated_at_load(over, error):
    with pytest.raises(DlpConfigError, match=error):
        policy(detector(**over))


def test_a_kind_cannot_be_defined_twice():
    with pytest.raises(DlpConfigError, match="defined twice"):
        policy(detector(), detector())


@pytest.mark.parametrize(
    ("pattern", "example"),
    [
        (r"(a+)+$", "aaa"),  # exponential
        (r"(\w+\s?)+$", "ab cd"),  # exponential on a run of word characters
        (r"\d+\d+x", "12x"),  # quadratic: the scan restarts at every digit
    ],
)
def test_catastrophic_patterns_are_rejected_quickly(pattern, example):
    start = time.monotonic()
    with pytest.raises(DlpConfigError, match="adversarial"):
        policy(detector(pattern=pattern, examples=[example], counter_examples=[]))
    assert time.monotonic() - start < 5  # the child stops at the first slow probe


def test_custom_matches_never_reach_the_audit_log_and_the_actor_stays():
    p = policy()
    sink = MemorySink()
    log = AuditLogger(sink, actor="acme_test_" + "c" * 32).bind(detectors=p.detectors)
    log.log("tool_request", arguments={"token": f"use {TOKEN}", TOKEN: 1})
    raw = json.dumps(sink.records)
    assert TOKEN not in raw and "[REDACTED:acme_service_token]" in raw
    assert sink.records[0]["actor"] == "acme_test_" + "c" * 32


def test_holdback_must_cover_a_redacted_custom_detector():
    with pytest.raises(ValueError, match="custom detector"):
        group_policy("g", Policy(), stream_mode="holdback",
                     holdback_chars=64, dlp=policy())  # fmt: skip


def test_the_gateway_applies_custom_detectors_and_keeps_values_out_of_audit(tmp_path):
    extra = (
        "dlp:\n  detectors:\n    - kind: acme_service_token\n      category: nhi\n"
        f"      pattern: '{PATTERN}'\n      examples: ['acme_test_{'a' * 32}']\n"
        "  categories: {nhi: {upstream: block}}\n"
    )
    app, up, sink = app_with(tmp_path, extra)
    status, _ = call(app, body=chat_with(f"deploy with {TOKEN}"))
    assert status == 400 and up.requests == []
    (rec,) = dlp_records(sink, "upstream")
    assert rec["kind"] == "acme_service_token" and rec["action"] == "block"
    assert TOKEN not in json.dumps(sink.records)
