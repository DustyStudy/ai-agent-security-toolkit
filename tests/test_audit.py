from __future__ import annotations

import json
from datetime import UTC, datetime

from agentsec.middleware import AuditLogger, FileSink, MemorySink, verify_file, verify_records
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
