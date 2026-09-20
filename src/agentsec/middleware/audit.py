"""Tamper-evident audit logging for agent activity.

Each record carries ``prev_hash`` and ``hash`` (SHA-256 over the canonical JSON
of the record plus the previous hash), forming a chain. Editing or deleting a
record in the middle of the log breaks verification from that point onward.

What this does *not* give you: protection against truncation of the log tail or
wholesale replacement of the file by someone with write access. For that, ship
records to an append-only / WORM store (for example S3 Object Lock or CloudWatch
Logs with a restricted resource policy) and periodically anchor
:meth:`AuditLogger.checkpoint` somewhere the agent host cannot write.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any, Protocol

from agentsec.middleware.redact import redact_text

GENESIS_HASH = "0" * 64

# Event type names. Free-form strings are allowed; these are the ones the
# built-in middleware emits.
PROMPT = "prompt"
UNTRUSTED_INPUT = "untrusted_input"
INJECTION_SIGNAL = "injection_signal"
MODEL_OUTPUT = "model_output"
TOOL_REQUEST = "tool_request"
TOOL_DECISION = "tool_decision"
TOOL_RESULT = "tool_result"
APPROVAL = "approval"
VALIDATION = "validation"
ERROR = "error"


class AuditSink(Protocol):
    def write(self, record: dict[str, Any]) -> None: ...

    def last_record(self) -> dict[str, Any] | None: ...


class MemorySink:
    """Keeps records in a list. Useful in tests and for the fuzzer."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def write(self, record: dict[str, Any]) -> None:
        self.records.append(record)

    def last_record(self) -> dict[str, Any] | None:
        return self.records[-1] if self.records else None


class StreamSink:
    """Writes JSON lines to a text stream (stdout by default)."""

    def __init__(self, stream: IO[str] | None = None) -> None:
        self._stream = stream or sys.stdout
        self._last: dict[str, Any] | None = None

    def write(self, record: dict[str, Any]) -> None:
        self._stream.write(json.dumps(record, sort_keys=True) + "\n")
        self._stream.flush()
        self._last = record

    def last_record(self) -> dict[str, Any] | None:
        return self._last


class FileSink:
    """Appends JSON lines to a file and resumes the hash chain on restart."""

    def __init__(self, path: str | Path, *, fsync: bool = False) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fsync = fsync
        self._lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            if self._fsync:
                os.fsync(fh.fileno())

    def last_record(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        last = None
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        return json.loads(last) if last else None


class CallbackSink:
    """Forwards each record to a function, e.g. a CloudWatch/SIEM shipper."""

    def __init__(self, fn: Callable[[dict[str, Any]], None]) -> None:
        self._fn = fn
        self._last: dict[str, Any] | None = None

    def write(self, record: dict[str, Any]) -> None:
        self._fn(record)
        self._last = record

    def last_record(self) -> dict[str, Any] | None:
        return self._last


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def compute_hash(record_without_hash: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(record_without_hash)).hexdigest()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


class AuditLogger:
    """Append-only, hash-chained structured logger.

    Args:
        sink: Where records go.
        session_id: Correlates all records from one agent session.
        actor: Free-form identity of the agent / end user for attribution.
        redact: Scrub secrets and PII from string fields before writing.
        log_content: If False, string fields longer than ``preview_chars`` are
            replaced by their SHA-256 and length only. Use this when prompts may
            hold regulated data you do not want at rest in the log.
        max_field_chars: Truncation limit for any single string field. The full
            content's SHA-256 is always recorded when truncation happens.
    """

    def __init__(
        self,
        sink: AuditSink,
        *,
        session_id: str | None = None,
        actor: str = "agent",
        redact: bool = True,
        log_content: bool = True,
        preview_chars: int = 64,
        max_field_chars: int = 4000,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.sink = sink
        self.session_id = session_id or uuid.uuid4().hex
        self.actor = actor
        self._redact = redact
        self._log_content = log_content
        self._preview_chars = preview_chars
        self._max_field_chars = max_field_chars
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()
        last = sink.last_record()
        self._seq = int(last["seq"]) + 1 if last else 0
        self._prev_hash = str(last["hash"]) if last else GENESIS_HASH

    # -- public API --------------------------------------------------------
    def log(self, event: str, **data: Any) -> dict[str, Any]:
        with self._lock:
            record: dict[str, Any] = {
                "seq": self._seq,
                "ts": self._clock().isoformat(),
                "session_id": self.session_id,
                "actor": self.actor,
                "event": event,
                "data": self._clean(data),
                "prev_hash": self._prev_hash,
            }
            record["hash"] = compute_hash(record)
            self.sink.write(record)
            self._seq += 1
            self._prev_hash = record["hash"]
            return record

    def checkpoint(self) -> dict[str, Any]:
        """Latest chain head. Anchor this outside the agent host's write reach."""
        return {"seq": self._seq - 1, "hash": self._prev_hash, "session_id": self.session_id}

    # -- internals ---------------------------------------------------------
    def _clean(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._clean_str(value)
        if isinstance(value, dict):
            return {str(k): self._clean(v) for k, v in value.items()}
        if isinstance(value, list | tuple | set | frozenset):
            return [self._clean(v) for v in value]
        if isinstance(value, int | float | bool) or value is None:
            return value
        return self._clean_str(repr(value))

    def _clean_str(self, text: str) -> Any:
        if self._redact:
            text, _ = redact_text(text)
        if not self._log_content and len(text) > self._preview_chars:
            return {"sha256": _sha256(text), "length": len(text)}
        if len(text) > self._max_field_chars:
            return {
                "truncated": text[: self._max_field_chars],
                "sha256": _sha256(text),
                "length": len(text),
            }
        return text


@dataclass
class VerifyResult:
    ok: bool
    records_checked: int
    first_bad_seq: int | None = None
    reason: str = ""


def verify_records(records: Iterable[dict[str, Any]]) -> VerifyResult:
    prev = GENESIS_HASH
    expected_seq: int | None = None
    checked = 0
    for rec in records:
        seq = rec.get("seq")
        if expected_seq is not None and seq != expected_seq:
            return VerifyResult(False, checked, seq, f"sequence gap: expected {expected_seq}")
        if rec.get("prev_hash") != prev:
            return VerifyResult(False, checked, seq, "prev_hash does not match previous record")
        claimed = rec.get("hash")
        body = {k: v for k, v in rec.items() if k != "hash"}
        if compute_hash(body) != claimed:
            return VerifyResult(False, checked, seq, "record contents do not match hash")
        prev = str(claimed)
        expected_seq = (seq + 1) if isinstance(seq, int) else None
        checked += 1
    return VerifyResult(True, checked)


def verify_file(path: str | Path) -> VerifyResult:
    """Verify a JSONL audit file. Malformed lines are reported as tampering."""
    records: list[dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                return VerifyResult(False, len(records), None, f"line {lineno} is not valid JSON")
    return verify_records(records)
