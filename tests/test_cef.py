"""CEF output for SIEMs, and TeeSink for feeding one alongside the tamper-evident file."""

from __future__ import annotations

import io
import logging
import re

import pytest

from agentsec import __version__
from agentsec.middleware import (
    AuditLogger,
    CefSink,
    FileSink,
    MemorySink,
    TeeSink,
    format_cef,
    verify_file,
)
from agentsec.middleware.cef import MAX_VALUE_CHARS, severity
from tests.cef_reference import parse_cef


def _record(**data) -> dict:
    sink = MemorySink()
    AuditLogger(sink, actor="agent", redact=False).log(data.pop("event", "tool_decision"), **data)
    return sink.records[0]


# ------------------------------------------------------------------------- structure


def test_a_decision_record_becomes_a_well_formed_cef_line():
    rec = _record(tool="search", verdict="deny", reasons=["tool not in policy"], tool_session="s1")
    header, ext = parse_cef(format_cef(rec))
    assert header == [
        "CEF:0", "agentsec", "ai-agent-security-toolkit", __version__,
        "tool_decision", "Tool call decision", "6",
    ]  # fmt: skip
    assert ext["act"] == "deny" and ext["cs1"] == "search" and ext["cs1Label"] == "tool"
    assert ext["cs2"] == "tool not in policy" and ext["cs5"] == "s1"
    assert ext["suser"] == "agent" and ext["externalId"] == "0"
    assert ext["cs3"] == rec["hash"] and ext["cs4"] == rec["prev_hash"]
    assert ext["rt"].isdigit() and int(ext["rt"]) > 1_600_000_000_000
    assert "tool_session" in ext["msg"]


def test_vendor_product_and_version_are_configurable_and_header_escaped():
    line = format_cef(_record(tool="t"), vendor="Acme|Corp", product="A\\B", version="9")
    header, _ = parse_cef(line)
    assert header[1:4] == ["Acme|Corp", "A\\B", "9"]
    assert line.startswith("CEF:0|Acme\\|Corp|A\\\\B|9|")


def test_unknown_events_and_odd_records_still_format():
    assert parse_cef(format_cef({"event": "brand_new", "data": None}))[0][4:6] == [
        "brand_new",
        "brand_new",
    ]
    header, ext = parse_cef(format_cef({}))
    assert header[4] == "unknown" and "msg" in ext
    _, ext = parse_cef(format_cef({"ts": "not-a-time", "event": "x"}))
    assert "rt" not in ext


# ------------------------------------------------- hostile values cannot forge structure

HOSTILE = [
    "x cs1Label=forged act=allow",
    "a=b=c",
    "back\\slash and trailing\\",
    "pipe|in|value",
    "line1\nline2\r\nCEF:0|evil|x|1|sig|Fake event|10|act=pwn",
    "tab\tand\x00nul\x1bescape",
    "\u2028separator and \u202ebidi",
    "ünïcödé 日本語 =\\=\\\\=",
    "= = = =",
]


@pytest.mark.parametrize("evil", HOSTILE)
def test_hostile_values_cannot_forge_fields_or_events(evil):
    rec = _record(tool=evil, reasons=[evil], verdict="deny", tool_session=evil, extra=evil)
    line = format_cef(rec)
    assert "\n" not in line and "\r" not in line and "\x00" not in line
    header, ext = parse_cef(line)
    assert len(header) == 7 and header[4] == "tool_decision"
    expected = {
        "rt", "externalId", "suser", "deviceExternalId", "act", "cs1", "cs1Label", "cs2",
        "cs2Label", "cs3", "cs3Label", "cs4", "cs4Label", "cs5", "cs5Label", "msg",
    }  # fmt: skip
    assert set(ext) == expected  # nothing forged, nothing swallowed
    assert ext["act"] == "deny" and ext["cs1Label"] == "tool"
    # The value survives a round trip: line breaks are kept (encoded as \n and \r), every other
    # control character and the Unicode line/paragraph separators become spaces.
    normal = re.sub(r"[\x00-\x09\x0b\x0c\x0e-\x1f\x7f-\x9f]", " ", evil)
    normal = normal.replace(chr(0x2028), " ").replace(chr(0x2029), " ")
    assert ext["cs1"] == normal


def test_hostile_header_fields_cannot_end_the_header():
    line = format_cef(_record(tool="t", event="ev|il\nx"), vendor="v|\\")
    header, _ = parse_cef(line)
    assert len(header) == 7 and header[4] == "ev|il x"


def test_long_values_are_bounded():
    line = format_cef(_record(tool="t" * 5000))
    _, ext = parse_cef(line)
    assert len(ext["cs1"]) == MAX_VALUE_CHARS and ext["cs1"].endswith("…")
    assert len(ext["msg"]) <= MAX_VALUE_CHARS


# --------------------------------------------------------------------------- severity


@pytest.mark.parametrize(
    ("event", "data", "expected"),
    [
        ("tool_decision", {"verdict": "allow"}, 3),
        ("tool_decision", {"verdict": "needs_approval"}, 5),
        ("tool_decision", {"verdict": "deny"}, 6),
        ("approval", {"approved": True}, 3),
        ("approval", {"approved": False}, 5),
        ("mcp_tool_finding", {"kind": "injection"}, 8),
        ("mcp_tool_finding", {"kind": "changed"}, 8),
        ("mcp_tool_finding", {"kind": "oversized"}, 6),
        ("mcp_tool_blocked", {}, 6),
        ("validation", {}, 5),
        ("error", {}, 5),
        ("prompt", {"blocked": True}, 7),
        ("prompt", {}, 1),
        ("tool_request", {}, 1),
    ],
)
def test_severity_ranks_denials_and_findings_above_routine_activity(event, data, expected):
    assert severity(event, data) == expected


# ------------------------------------------------------------------ sinks and TeeSink


def test_cef_sink_writes_lines_to_a_stream_and_to_a_callback():
    buf, seen = io.StringIO(), []
    for sink in (CefSink(buf), CefSink(seen.append, vendor="Acme")):
        AuditLogger(sink).log("tool_request", tool="search")
    assert buf.getvalue().count("\n") == 1 and buf.getvalue().startswith("CEF:0|agentsec|")
    assert seen[0].startswith("CEF:0|Acme|") and CefSink(io.StringIO()).last_record() is None


def test_tee_sink_keeps_the_tamper_evident_chain_and_feeds_a_siem(tmp_path):
    path, siem = tmp_path / "audit.jsonl", io.StringIO()
    audit = AuditLogger(TeeSink(FileSink(path), CefSink(siem)), actor="agent")
    audit.log("tool_request", tool="search")
    audit.log("tool_decision", tool="search", verdict="allow")
    audit.log("tool_result", tool="search", result="ok")

    assert verify_file(path).ok
    lines = siem.getvalue().splitlines()
    assert len(lines) == 3
    chain = [parse_cef(line)[1] for line in lines]
    assert chain[1]["cs4"] == chain[0]["cs3"] and chain[2]["cs4"] == chain[1]["cs3"]

    # a restart resumes the chain from the primary file
    again = AuditLogger(TeeSink(FileSink(path), CefSink(io.StringIO())))
    again.log("tool_request", tool="search")
    assert verify_file(path).ok


def test_a_failing_secondary_sink_never_breaks_the_chain(tmp_path, caplog):
    path = tmp_path / "audit.jsonl"

    class Down:
        def write(self, record):
            raise ConnectionError("siem unreachable")

        def last_record(self):
            return None

    audit = AuditLogger(TeeSink(FileSink(path), Down()))
    with caplog.at_level(logging.ERROR, logger="agentsec.audit"):
        audit.log("tool_request", tool="a")
        audit.log("tool_request", tool="b")
    assert verify_file(path).ok and len(path.read_text().splitlines()) == 2
    assert "Down failed" in caplog.text


def test_a_failing_primary_sink_propagates():
    class Broken:
        def write(self, record):
            raise OSError("disk full")

        def last_record(self):
            return None

    with pytest.raises(OSError):
        AuditLogger(TeeSink(Broken(), MemorySink())).log("tool_request", tool="a")
