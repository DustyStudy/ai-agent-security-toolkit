"""Credential key names, torn audit tails, and command-line secrets."""

from __future__ import annotations

import json
import logging
import time

import pytest

from agentsec.middleware.audit import AuditLogger, FileSink, MemorySink, verify_file
from agentsec.middleware.redact import redact_text

VALUE = "Zq7-sample-private-value"


@pytest.mark.parametrize(
    "key",
    [
        "SecretAccessKey",
        "SessionToken",
        "aws_secret_access_key",
        "AWS_SECRET_ACCESS_KEY",
        "secretKey",
        "secret_key",
        "private_key",
        "idToken",
        "sessionToken",
        "bearerToken",
        "apiToken",
        "appSecret",
        "signing_key",
        "signing-key",
        "db.password",
        "credential",
        "Credentials",
        "secretaccesskey",
        "sessiontoken",
    ],
)
def test_credential_named_keys_are_redacted_whatever_the_value_looks_like(key):
    sink = MemorySink()
    AuditLogger(sink).log("tool_request", args={key: VALUE}, **{key: "short"})
    blob = json.dumps(sink.records)
    assert VALUE not in blob and "short" not in blob


@pytest.mark.parametrize(
    "key", ["AccessKeyId", "access_key_id", "Key", "key", "public_key", "max_tokens", "keyboard"]
)
def test_keys_that_only_resemble_credentials_stay_readable(key):
    sink = MemorySink()
    AuditLogger(sink).log("tool_request", args={key: "plain-value"})
    assert sink.records[0]["data"]["args"] == {key: "plain-value"}


def _torn(path):
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"seq": 1, "ha')  # hook killed mid-write


def test_torn_final_line_is_set_aside_and_the_chain_resumes(tmp_path, caplog):
    path = tmp_path / "audit.jsonl"
    first = AuditLogger(FileSink(path)).log("prompt", text="hi")
    _torn(path)
    with caplog.at_level(logging.WARNING, logger="agentsec.audit"):
        resumed = AuditLogger(FileSink(path))
    record = resumed.log("prompt", text="again")
    assert record["seq"] == 1 and record["prev_hash"] == first["hash"]
    result = verify_file(path)
    assert result.ok and result.records_checked == 2
    (aside,) = tmp_path.glob("audit.jsonl.torn-*")
    assert aside.read_bytes() == b'{"seq": 1, "ha'
    assert "torn write" in caplog.text and aside.name in caplog.text


def test_a_file_holding_only_a_torn_line_starts_a_new_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text('{"seq": 0, "ev', encoding="utf-8")
    assert AuditLogger(FileSink(path)).log("prompt")["seq"] == 0
    assert verify_file(path).ok


def test_verify_stays_strict_about_a_torn_line(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLogger(FileSink(path)).log("prompt", text="hi")
    _torn(path)
    assert not verify_file(path).ok
    assert not list(tmp_path.glob("*.torn-*"))  # verifying never repairs


@pytest.mark.parametrize(
    "tail",
    [
        "not json\n",  # complete line: someone wrote it, no crash did
        '{"seq": 1}',  # valid JSON without a newline: cannot tell what it was
        'garbage\n{"seq": 2, "ha',  # torn line after other damage
    ],
)
def test_other_corruption_still_refuses_and_is_left_alone(tmp_path, tail):
    path = tmp_path / "audit.jsonl"
    AuditLogger(FileSink(path)).log("prompt", text="hi")
    with path.open("a", encoding="utf-8", newline="") as fh:
        fh.write(tail)
    with pytest.raises(ValueError, match="torn write"):
        AuditLogger(FileSink(path))
    if not tail.endswith("ha"):
        assert not list(tmp_path.glob("*.torn-*"))


def test_resume_reads_the_tail_not_the_whole_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(FileSink(path))
    last = [logger.log("prompt", text="x" * 3000) for _ in range(60)][-1]  # > one 64 KiB block
    # Damage at the start is verify's business; resuming must not have to read that far.
    raw = path.read_bytes()
    path.write_bytes(b"\xff" * 10 + raw[10:])
    assert FileSink(path).last_record() == last
    # A record larger than the first block is still found whole.
    big = AuditLogger(FileSink(path), max_field_chars=500_000).log("prompt", text="y " * 100_000)
    assert FileSink(path).last_record() == big


@pytest.mark.parametrize(
    "command",
    [
        f"curl -u alice:{VALUE} https://example.test",
        f"curl -s https://example.test/a?b=1&c=2 --user 'alice:{VALUE}'",
        f'curl -u "alice:{VALUE}" https://example.test',
        f"tool --password {VALUE} --verbose",
        f"tool --token {VALUE}",
        f"tool --secret '{VALUE}'",
        f"tool --api-key {VALUE}",
        f'tool --client-secret "{VALUE}"',
        f"mysql -u root -p{VALUE} shop",
        f"mysql -h db.internal -p {VALUE}",
        f"sshpass -p {VALUE} ssh ops@host",
        f"docker login registry.example.test -u alice -p {VALUE}",
        'curl --header "Authorization: Bearer Zq7-short"',
        "curl -H 'Authorization: Bearer Zq7-short'",
    ],
)
def test_command_line_secrets_are_redacted(command):
    redacted, findings = redact_text(command)
    assert "Zq7" not in redacted and findings
    assert "alice" in redacted or "alice" not in command  # the user name is context
    assert redact_text(redacted)[0] == redacted  # idempotent


@pytest.mark.parametrize(
    "command",
    [
        "mysql -P 3306 -h db.internal shop",
        "mysql -u root -p -h db.internal",
        "tool --password --verbose",
        "tool --token-file /run/secrets/token",
        "tool --max-tokens 1024",
        "curl -u alice https://example.test",
        "grep -p pattern file",
    ],
)
def test_lookalike_flags_are_left_alone(command):
    assert redact_text(command) == (command, [])


def test_command_names_repeated_many_times_stay_cheap():
    text = "curl mysql docker login " * 8000  # just under the scan limit
    start = time.perf_counter()
    redact_text(text)
    assert time.perf_counter() - start < 5
