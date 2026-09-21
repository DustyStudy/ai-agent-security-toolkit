"""Regression tests for bugs the fuzz targets found. Each one failed before its fix."""

from __future__ import annotations

import pytest

from agentsec.middleware import AuditLogger, MemorySink, format_cef
from agentsec.sandbox import ArgRule, Policy, PolicyError
from agentsec.sandbox.validators import check_url
from tests.cef_reference import parse_cef

RULE = ArgRule(type="url", schemes=["https"], hosts=["api.example.com"])

# ------------------------------------------------------------- URL host normalization


def test_a_single_trailing_dot_is_still_accepted():
    assert check_url("https://api.example.com./x", RULE) == []


@pytest.mark.parametrize(
    "url",
    [
        "https://api.example.com../x",  # empty DNS label
        "https://api.example.com.../x",
        "https://.api.example.com/x",
        "https://api..example.com/x",
    ],
)
def test_hosts_with_empty_labels_are_rejected(url):
    assert check_url(url, RULE), url


@pytest.mark.parametrize(
    "char",
    [
        chr(0x2028),  # line separator
        chr(0x2029),  # paragraph separator
        chr(0x200B),  # zero-width space
        chr(0x202E),  # right-to-left override
        chr(0x00AD),  # soft hyphen
        chr(0x85),  # next line
        "\x1f",
        " ",
    ],
)
def test_hosts_with_whitespace_control_or_format_characters_are_rejected(char):
    """Trimming them would judge a different host than the fetcher connects to."""
    assert check_url(f"https://api.example.com.{char}/x", RULE)
    assert check_url(f"https://{char}api.example.com/x", RULE)
    assert check_url(f"https://api.example.com{char}/x", RULE)


def test_private_addresses_stay_blocked_with_extra_dots():
    rule = ArgRule(type="url", schemes=["http"], hosts=[])
    for host in ("127.0.0.1...", "127.0.0.1.", "169.254.169.254.."):
        assert check_url(f"http://{host}/", rule), host


# ------------------------------------------------------------------- policy loading


def _base() -> dict:
    return {"tools": {"t": {"args": {"a": {"type": "string"}}}}}


def _with(tool=None, arg=None, top=None) -> dict:
    raw = _base()
    raw["tools"]["t"].update(tool or {})
    raw["tools"]["t"]["args"]["a"].update(arg or {})
    raw.update(top or {})
    return raw


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (_with(tool={"allow": "false"}), "allow must be true or false"),
        (_with(tool={"side_effects": "no"}), "side_effects must be true or false"),
        (_with(tool={"require_approval": 1}), "require_approval must be true or false"),
        (_with(tool={"max_calls": -1}), "max_calls must be a non-negative integer"),
        (_with(tool={"max_calls": True}), "max_calls must be a non-negative integer"),
        (_with(arg={"pattern": 5}), "pattern must be a string"),
        (_with(arg={"pattern": ["a"]}), "pattern must be a string"),
        (_with(arg={"hosts": "api.example.com"}), "hosts must be a list of strings"),
        (_with(arg={"deny_patterns": None}), "deny_patterns must be a list of strings"),
        (_with(arg={"roots": [1]}), "roots must be a list of strings"),
        (_with(arg={"enum": "abc"}), "enum must be a list"),
        (_with(arg={"maximum": "10"}), "maximum must be a finite number"),
        (_with(arg={"maximum": float("nan")}), "maximum must be a finite number"),
        (_with(arg={"max_length": 1.5}), "max_length must be a non-negative integer"),
        (_with(arg={"block_private": "yes"}), "block_private must be true or false"),
        (_with(top={"taint": {"action": ["deny"]}}), "taint.action must be a string"),
        (_with(top={"taint": {"action": {"x": 1}}}), "taint.action must be a string"),
        (_with(top={"taint": {"enabled": "true"}}), "taint.enabled must be true or false"),
        (_with(top={"max_total_calls": "5"}), "max_total_calls must be a non-negative integer"),
        (_with(top={"max_total_calls": -3}), "max_total_calls must be a non-negative integer"),
        (_with(top={"version": "1"}), "version must be an integer"),
        (_with(top={"version": None}), "version must be an integer"),
        ({"tools": {1: {}}}, "tool names must be strings"),
    ],
)
def test_wrongly_typed_policy_values_raise_policy_error_not_a_crash(raw, message):
    with pytest.raises(PolicyError, match=message):
        Policy.from_dict(raw)


def test_a_quoted_false_no_longer_enables_a_tool():
    """`allow: "false"` is a truthy string; before validation it silently allowed the tool."""
    with pytest.raises(PolicyError):
        Policy.from_dict(_with(tool={"allow": "false"}))
    assert Policy.from_dict(_with(tool={"allow": False})).tools["t"].allow is False


def test_well_typed_policies_still_load():
    policy = Policy.from_dict(
        _with(
            tool={"max_calls": 0, "side_effects": True},
            arg={"maximum": 2.5, "pattern": "x+", "hosts": ["a.example"], "enum": ["a", 1, None]},
            top={"max_total_calls": 0, "version": 1, "taint": {"action": "approve"}},
        )
    )
    assert policy.max_total_calls == 0 and policy.taint.action == "approve"


# ------------------------------------------------------------------------ CEF header


def test_cef_header_fields_lose_unicode_line_separators():
    """U+2028 is not a control character but splits lines in several parsers."""
    sink = MemorySink()
    AuditLogger(sink).log("tool_request", tool="t")
    for sep in (chr(0x2028), chr(0x2029)):
        line = format_cef(sink.records[0], vendor=f"a{sep}b", product=f"c{sep}d", version=sep)
        assert len(line.splitlines()) == 1
        header, _ = parse_cef(line)
        assert header[1:4] == ["a b", "c d", " "]
