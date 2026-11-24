from __future__ import annotations

import json
from datetime import UTC, datetime

from agentsec.cli import main
from agentsec.middleware import AuditLogger, FileSink, MemorySink, verify_file, verify_records
from agentsec.middleware.audit import compute_hash
from tests.conftest import fake_aws_key


def _clock():
    return datetime(2026, 1, 1, tzinfo=UTC)


def test_chain_links_and_verifies():
    sink = MemorySink()
    log = AuditLogger(sink, session_id="s1", clock=_clock)
    for i in range(3):
        log.log("prompt", n=i)
    assert [r["seq"] for r in sink.records] == [0, 1, 2]
    assert sink.records[1]["prev_hash"] == sink.records[0]["hash"]
    assert verify_records(sink.records).ok


def test_tampering_detected():
    sink = MemorySink()
    log = AuditLogger(sink)
    for i in range(4):
        log.log("tool_request", n=i)
    sink.records[2]["data"]["n"] = 999
    res = verify_records(sink.records)
    assert not res.ok and res.first_bad_seq == 2 and res.records_checked == 2


def test_deleted_record_detected():
    sink = MemorySink()
    log = AuditLogger(sink)
    for i in range(4):
        log.log("x", n=i)
    del sink.records[1]
    assert not verify_records(sink.records).ok


def test_secrets_are_redacted_before_hashing_and_writing():
    sink = MemorySink()
    AuditLogger(sink).log(
        "model_output", text=f"key {fake_aws_key()}", nested={"k": [fake_aws_key()]}
    )
    blob = json.dumps(sink.records[0])
    assert fake_aws_key() not in blob and "REDACTED" in blob
    assert verify_records(sink.records).ok


def test_log_content_false_stores_hash_only():
    sink = MemorySink()
    AuditLogger(sink, log_content=False).log("prompt", text="x" * 500)
    field = sink.records[0]["data"]["text"]
    assert set(field) == {"sha256", "length"} and field["length"] == 500


def test_keep_fields_stay_readable_but_redacted_and_truncated():
    sink = MemorySink()
    log = AuditLogger(sink, log_content=False, keep_fields=["reasons"], max_field_chars=200)
    secret = "AKIA" + "ABCDEFGHIJKLMNOP"
    log.log("deny", reasons=["r" * 100 + " " + secret, "z" * 300], text="x" * 500)
    data = sink.records[0]["data"]
    assert data["reasons"][0].startswith("r" * 100) and secret not in data["reasons"][0]
    assert data["reasons"][1]["length"] == 300 and "truncated" in data["reasons"][1]
    assert set(data["text"]) == {"sha256", "length"}  # other fields are still hashed
    assert verify_records(sink.records).ok


def test_long_fields_truncated_with_full_hash():
    sink = MemorySink()
    AuditLogger(sink, max_field_chars=10).log("prompt", text="y" * 50)
    f = sink.records[0]["data"]["text"]
    assert f["truncated"] == "y" * 10 and f["length"] == 50 and len(f["sha256"]) == 64


def test_file_sink_resumes_chain_across_restarts(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLogger(FileSink(path)).log("a")
    AuditLogger(FileSink(path)).log("b")
    res = verify_file(path)
    assert res.ok and res.records_checked == 2


def test_verify_file_flags_edited_line_and_garbage(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(FileSink(path))
    log.log("a", v=1)
    log.log("b", v=2)
    lines = path.read_text().splitlines()
    path.write_text(lines[0].replace('"v":1', '"v":7') + "\n" + lines[1] + "\n")
    assert not verify_file(path).ok
    path.write_text("not json\n")
    assert "not valid JSON" in verify_file(path).reason


def test_checkpoint_reports_head():
    log = AuditLogger(MemorySink())
    rec = log.log("a")
    assert log.checkpoint()["hash"] == rec["hash"]


# ---- agentsec audit summary


def _summary_log(path):
    """Six records, one per hour from 2026-01-01T00:00Z, by two actors."""
    hours = iter(range(24))
    log = AuditLogger(
        FileSink(path), actor="alice", clock=lambda: datetime(2026, 1, 1, next(hours), tzinfo=UTC)
    )
    bob = log.bind(actor="bob")
    log.log("tool_request", tool="read_file", arguments={})
    log.log("tool_decision", tool="read_file", verdict="allow", reasons=[])
    bob.log("tool_decision", tool="shell", verdict="deny", reasons=["not allowed"])
    bob.log("tool_decision", tool="shell", verdict="deny", reasons=["not allowed"])
    bob.log("gateway_mcp_call", tool="search", allowed=False, reason="no such tool")
    log.log("gateway_mcp_call", tool="search", allowed=True)
    return str(path)


def _summary(capsys, *argv):
    code = main(["audit", "summary", *argv])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_summary_counts_events_decisions_and_denials(tmp_path, capsys):
    path = _summary_log(tmp_path / "audit.jsonl")
    code, out, _ = _summary(capsys, path, "--json")
    assert code == 0
    assert json.loads(out) == {
        "verified": True,
        "records": 6,
        "matched": 6,
        "events": {"tool_decision": 3, "gateway_mcp_call": 2, "tool_request": 1},
        "decisions": {"deny": 3, "allow": 2},
        "denied_tools": {"shell": 2, "search": 1},
        "denied_actors": {"bob": 3},
    }
    code, out, _ = _summary(capsys, path)
    assert code == 0
    assert out.startswith("OK: chain intact, 6 record(s), 6 matched")
    assert "By decision:\n  deny   3\n  allow  2\n" in out
    assert "Top 10 denied tools:\n  shell   2\n  search  1\n" in out


def test_summary_filters(tmp_path, capsys):
    path = _summary_log(tmp_path / "audit.jsonl")

    def events(*flags):
        code, out, _ = _summary(capsys, path, "--json", *flags)
        assert code == 0
        return json.loads(out)["events"]

    assert events("--actor", "alice") == {
        "tool_request": 1,
        "tool_decision": 1,
        "gateway_mcp_call": 1,
    }
    assert events("--event", "tool_decision") == {"tool_decision": 3}
    # --since is inclusive, --until exclusive; a timestamp without an offset is UTC.
    assert events("--since", "2026-01-01T04:00:00") == {"gateway_mcp_call": 2}
    assert events("--until", "2026-01-01T01:00:00+00:00") == {"tool_request": 1}
    assert events("--since", "2026-01-01T03:00:00+02:00", "--until", "2026-01-01T02:00") == {
        "tool_decision": 1
    }
    assert events("--actor", "nobody") == {}


def test_summary_refuses_a_tampered_log_unless_no_verify(tmp_path, capsys):
    path = _summary_log(tmp_path / "audit.jsonl")
    text = (tmp_path / "audit.jsonl").read_text()
    (tmp_path / "audit.jsonl").write_text(text.replace('"verdict":"deny"', '"verdict":"allow"', 1))
    code, out, err = _summary(capsys, path)
    assert code == 1 and out == ""
    assert "TAMPERED" in err and "No summary" in err
    code, out, _ = _summary(capsys, path, "--no-verify", "--json")
    assert code == 0
    got = json.loads(out)
    assert got["verified"] is False and got["decisions"] == {"allow": 3, "deny": 2}
    code, out, _ = _summary(capsys, path, "--no-verify")
    assert out.startswith("UNVERIFIED (--no-verify), 6 record(s)")
    # A torn last line fails verification too, and --no-verify says where it stopped.
    (tmp_path / "audit.jsonl").write_text(text + '{"seq":')
    assert _summary(capsys, path)[0] == 1
    code, out, err = _summary(capsys, path, "--no-verify")
    assert code == 0 and "6 record(s)" in out and "line 7 is not valid JSON" in err
    # An integer too long for Python to convert is a bad line, not a crash.
    (tmp_path / "audit.jsonl").write_text('{"seq":' + "9" * 5000 + "}")
    code, out, err = _summary(capsys, path)
    assert code == 1 and out == "" and "line 1 is not valid JSON" in err
    assert main(["audit", "verify", path]) == 1


def test_summary_bounds_the_verification_reason(tmp_path, capsys):
    # A correctly hashed record with a huge seq puts that number in the next record's reason.
    path = tmp_path / "audit.jsonl"
    first = {"seq": 10**1000, "prev_hash": "0" * 64}
    first["hash"] = compute_hash(first)
    path.write_text(json.dumps(first) + "\n" + json.dumps({"seq": 0}) + "\n")
    code, out, err = _summary(capsys, str(path))
    assert code == 1 and out == "" and "sequence gap" in err
    assert max(map(len, err.splitlines())) < 400


def test_summary_of_empty_and_missing_logs(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    path.write_text("")
    assert _summary(capsys, str(path)) == (0, "OK: chain intact, 0 record(s), 0 matched\n", "")
    code, _, err = _summary(capsys, str(tmp_path / "missing.jsonl"))
    assert code == 2 and err.startswith("error:")


def test_summary_strips_control_characters_and_bounds_values(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(FileSink(path), actor="eve\x1b[31m\nOK: forged", redact=False)
    rlo = chr(0x202E)  # right-to-left override
    log.log("tool_decision", tool="t\x07" + rlo + "x" * 5000, verdict="deny", reasons=[])
    log.log("ev\rent", verdict="de\x00ny")
    code, out, _ = _summary(capsys, str(path))
    assert code == 0
    assert not any(ch in out for ch in "\x1b\x07\x00\r" + rlo)
    assert "\nOK: forged" not in out  # the actor's newline cannot start a line of its own
    assert max(map(len, out.splitlines())) < 400
    code, out, _ = _summary(capsys, str(path), "--json")
    got = json.loads(out)
    assert code == 0 and list(got["denied_actors"]) == ["eve [31m OK: forged"]
    # Filters match the value in the log, not its cleaned form.
    assert (
        json.loads(_summary(capsys, str(path), "--json", "--actor", log.actor)[1])["matched"] == 2
    )
    assert json.loads(_summary(capsys, str(path), "--json", "--event", "ev ent")[1])["matched"] == 0
    assert all(len(key) <= 300 for key in got["denied_tools"])


def test_credentials_are_removed_from_metadata_and_structured_fields():
    sink = MemorySink()
    token = "agt_" + "x" * 43
    logger = AuditLogger(sink, actor=token, session_id=token)
    logger.log(token, password=["sample-private-value"], headers={"Cookie": "sid=private"})
    serialized = json.dumps([sink.records, logger.checkpoint()])
    for private in (token, "sample-private-value", "sid=private"):
        assert private not in serialized
    assert verify_records(sink.records).ok
