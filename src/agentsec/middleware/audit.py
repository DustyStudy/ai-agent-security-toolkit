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

import copy
import functools
import hashlib
import hmac
import json
import logging
import os
import re
import sys
import threading
import time
import uuid
import weakref
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any, Protocol

from agentsec.middleware.redact import _EMAIL, find_sensitive, redact_text

_LOG = logging.getLogger("agentsec.audit")

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
DLP_MATCH = "dlp_match"


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
        # Absolute now, so a later chdir neither moves the file nor splits its chain key.
        self.path = Path(os.path.abspath(path))
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

    def check_writable(self) -> None:
        """Raise OSError if the file cannot be opened for append (a /readyz probe, no record)."""
        with self._lock, self.path.open("a", encoding="utf-8"):
            pass

    @property
    def chain_key(self) -> str:
        """Identifies the file, so loggers writing to it share one chain head."""
        return os.path.normcase(os.path.realpath(self.path))

    def last_record(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        with self._lock:
            lines, torn_at = self._tail()
            if lines and torn_at is not None and _parse(lines[-1]) is _NOT_JSON:
                # A final line with no newline that is not JSON is a write cut short by a
                # crash. Refusing here blocked every later session until someone repaired the
                # file by hand; nothing can have chained onto the fragment, so set it aside.
                self._set_aside(lines.pop(), torn_at)
                torn_at = None
        if not lines:
            return None
        record = _parse(lines[-1])
        valid = (
            # No newline: the next append would glue onto this line ("}{...").
            torn_at is None
            and isinstance(record, dict)
            and type(record.get("seq")) is int
            and isinstance(record.get("hash"), str)
            and compute_hash({k: v for k, v in record.items() if k != "hash"}) == record["hash"]
        )
        if not valid:
            # Appending after it would chain onto a guess, so refuse to start; fail closed
            # rather than silently fork the chain.
            raise ValueError(
                f"last line of audit log {self.path} is not a valid record (torn write?). "
                "Run `agentsec audit verify` on it, then repair it or start a new file."
            )
        return record

    def _tail(self) -> tuple[list[bytes], int | None]:
        """The last two non-blank lines, and the offset of the last one if it has no newline.

        Reads backwards from the end: every hook invocation resumes the chain, and reading
        the whole of a growing log each time made every call slower than the one before.
        """
        block = 1 << 16
        with self.path.open("rb") as fh:
            size = fh.seek(0, os.SEEK_END)
            while True:
                start = max(0, size - block)
                fh.seek(start)
                parts = fh.read().split(b"\n")
                if start:
                    parts = parts[1:]  # may begin mid-line
                lines = [p for p in parts if p.strip()]
                if start == 0 or len(lines) >= 2:
                    break
                block *= 2
        unterminated = bool(parts and parts[-1].strip())
        return lines[-2:], size - len(parts[-1]) if unterminated else None

    def _set_aside(self, fragment: bytes, offset: int) -> None:
        aside = self.path.with_name(f"{self.path.name}.torn-{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}")
        # Copy first, then cut: a crash between the two leaves the fragment in both places.
        with aside.open("xb") as out:
            out.write(fragment)
            out.flush()
            os.fsync(out.fileno())
        os.truncate(self.path, offset)
        _LOG.warning(
            "audit log %s ended in a torn write (%d bytes); moved it to %s and resumed from "
            "the last complete record",
            self.path,
            len(fragment),
            aside,
        )


_NOT_JSON = object()


def _parse(line: bytes) -> Any:
    """The JSON value on ``line``, or ``_NOT_JSON``."""
    try:
        return json.loads(line.decode("utf-8", "replace"))
    except ValueError:  # JSONDecodeError, or an integer too long to convert
        return _NOT_JSON


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


class TeeSink:
    """Writes each record to several sinks; the first is the source of truth.

    The *primary* sink (typically a :class:`FileSink`) keeps the hash chain and is what
    ``AuditLogger`` resumes from, so its errors propagate. A failure in a *secondary* sink
    (a SIEM feed that is down) is logged to the ``agentsec.audit`` logger and does not
    interrupt the agent or the chain: raising after the primary write would leave the
    logger's sequence number behind the file.
    """

    def __init__(self, primary: AuditSink, *secondary: AuditSink) -> None:
        self._primary = primary
        self._secondary = secondary

    def write(self, record: dict[str, Any]) -> None:
        self._primary.write(record)
        for sink in self._secondary:
            try:
                sink.write(record)
            except Exception:  # noqa: BLE001 - see the class docstring
                _LOG.exception("secondary audit sink %s failed", type(sink).__name__)

    def last_record(self) -> dict[str, Any] | None:
        return self._primary.last_record()

    @property
    def chain_key(self) -> str | None:
        return getattr(self._primary, "chain_key", None)


class RetrySink:
    """Delivers records to a secondary sink in order, keeping the ones it could not deliver.

    ``write`` never raises. Undelivered records wait in ``backlog`` and go out, oldest first,
    on the next ``write`` or ``flush``. shortcut: the backlog is in memory and unbounded, so a
    restart loses it (the local file still has every record); bound it if outages run for hours.
    """

    def __init__(self, sink: AuditSink, clock: Callable[[], float] = time.time) -> None:
        self._sink = sink
        self._clock = clock
        self._lock = threading.Lock()
        self._pending: deque[dict[str, Any]] = deque()
        self._last_ok = clock()

    def write(self, record: dict[str, Any]) -> None:
        with self._lock:
            self._pending.append(record)
        self.flush()

    def flush(self) -> None:
        with self._lock:
            while self._pending:
                try:
                    self._sink.write(self._pending[0])
                except Exception:  # noqa: BLE001 - keep the record and retry on the next flush
                    _LOG.exception("secondary audit sink %s failed", type(self._sink).__name__)
                    return
                self._pending.popleft()
                self._last_ok = self._clock()

    @property
    def backlog(self) -> int:
        return len(self._pending)

    @property
    def last_delivery_age(self) -> float:
        """Seconds since the last delivery; since start-up if there has been none."""
        return self._clock() - self._last_ok

    def last_record(self) -> dict[str, Any] | None:
        return None


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def compute_hash(record_without_hash: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(record_without_hash)).hexdigest()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


@dataclass
class _ChainHead:
    seq: int = 0
    prev_hash: str = GENESIS_HASH
    lock: threading.Lock = field(default_factory=threading.Lock)


# Chain heads shared by every logger on one file in this process; an entry goes away with
# its last logger. Separate *processes* appending to one file still fork the chain: give
# each process its own file.
_HEADS: weakref.WeakValueDictionary[str, _ChainHead] = weakref.WeakValueDictionary()
_HEADS_LOCK = threading.Lock()


class AuditLogger:
    """Append-only, hash-chained structured logger.

    Any number of loggers in one process may write to the same :class:`FileSink` path;
    they share its chain. Several processes must not append to one file.

    Args:
        sink: Where records go.
        session_id: Correlates all records from one agent session.
        actor: Free-form identity of the agent / end user for attribution.
        redact: Scrub secrets and PII from string fields before writing.
        log_content: If False, string fields longer than ``preview_chars`` are
            replaced by their SHA-256 and length only. Use this when prompts may
            hold regulated data you do not want at rest in the log.
        keep_fields: Top-level ``data`` keys whose strings ``log_content=False`` leaves
            readable (still redacted and truncated), for decision metadata such as denial
            ``reasons`` that an analyst must be able to read. Never list a content field.
        max_field_chars: Truncation limit for any single string field. The full
            content's SHA-256 is always recorded when truncation happens.
        email_key: With ``redact``, email addresses in logged values become
            ``[EMAIL:hmac-sha256:<16 hex>]`` under this key (the same value and format as a
            DLP fingerprint), so repeats correlate. Without a key they become
            ``[REDACTED:email]``: an unkeyed hash of an address is reversed by guessing it.
            The actor, session id and event name are never changed.
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
        keep_fields: Iterable[str] = (),
        clock: Callable[[], datetime] | None = None,
        email_key: bytes | None = None,
    ) -> None:
        self.email_key = email_key
        self.sink = sink
        self.session_id = session_id or uuid.uuid4().hex
        self.actor = actor
        self._redact = redact
        self._log_content = log_content
        self._preview_chars = preview_chars
        self._max_field_chars = max_field_chars
        self._keep_fields = frozenset(keep_fields)
        self._clock = clock or (lambda: datetime.now(UTC))
        # Loggers on the same file (one per conversation, say) share one chain head, so
        # their records interleave into a single chain instead of forking it. A sink with no
        # file behind it (memory, stream, callback) is shared by object: two loggers on one
        # such sink each started at seq 0 and wrote two interleaved chains that never verify.
        # The id cannot be reused while the head lives, because every logger holding the
        # head also holds the sink.
        key = getattr(sink, "chain_key", None) or f"sink-object:{id(sink)}"
        with _HEADS_LOCK:
            head = _HEADS.get(key)
            if head is None:
                head = _ChainHead()
                _HEADS[key] = head
        with head.lock:
            last = sink.last_record()
            head.seq = int(last["seq"]) + 1 if last else 0
            head.prev_hash = str(last["hash"]) if last else GENESIS_HASH
        self._head = head

    # -- public API --------------------------------------------------------
    def log(self, event: str, **data: Any) -> dict[str, Any]:
        head = self._head
        with head.lock:
            record: dict[str, Any] = {
                "seq": head.seq,
                "ts": self._clock().isoformat(),
                "session_id": self._clean_key(self.session_id),
                "actor": self._clean_key(self.actor),
                "event": self._clean_key(event),
                "data": {
                    self._clean_key(k): self._clean_item(k, v, keep=k in self._keep_fields)
                    for k, v in data.items()
                },
                "prev_hash": head.prev_hash,
            }
            record["hash"] = compute_hash(record)
            self.sink.write(record)
            head.seq += 1
            head.prev_hash = record["hash"]
            return record

    def bind(self, *, actor: str | None = None, session_id: str | None = None) -> AuditLogger:
        """A logger with another actor or session that appends to this logger's chain.

        Cheaper than a new ``AuditLogger`` on the same sink, which re-reads the sink's last
        record: use it for one logger per request or user in a long-running service.
        """
        bound = copy.copy(self)  # shares the sink and the chain head
        if actor is not None:
            bound.actor = actor
        if session_id is not None:
            bound.session_id = session_id
        return bound

    def checkpoint(self) -> dict[str, Any]:
        """Latest chain head. Anchor this outside the agent host's write reach."""
        with self._head.lock:
            return {
                "seq": self._head.seq - 1,
                "hash": self._head.prev_hash,
                "session_id": self._clean_key(self.session_id),
            }

    # -- internals ---------------------------------------------------------
    def _clean(self, value: Any, keep: bool = False) -> Any:
        if isinstance(value, str):
            return self._clean_str(value, keep)
        if isinstance(value, dict):
            # Keys are redacted too: an agent can put a secret in a key as easily as a value.
            return {self._clean_key(k): self._clean_item(k, v, keep) for k, v in value.items()}
        if (
            self._redact
            and isinstance(value, list | tuple)
            and len(value) == 2
            and isinstance(value[0], str)
            and value[1] is not None
            and _credential_key(value[0][-200:]) is not None
        ):
            # A (name, value) pair, as in httpx/aiohttp header lists:
            # [("Authorization", "Bearer x")] is the assignment Authorization=...
            return [self._clean(value[0], keep), self._clean_item(value[0], value[1], keep)]
        if isinstance(value, list | tuple | set | frozenset):
            return [self._clean(v, keep) for v in value]
        if isinstance(value, int | float | bool) or value is None:
            return value
        return self._clean_str(repr(value), keep)

    def _clean_item(self, key: Any, value: Any, keep: bool) -> Any:
        if self._redact and value is not None:
            kind = _credential_key(str(key)[-200:])
            if kind is not None:
                # {"password": "x"} is the assignment password=x: the whole value goes,
                # whatever it looks like (short, spaced, or starting like something else).
                return f"[REDACTED:{kind}]"
        return self._clean(value, keep)

    def _clean_key(self, key: Any) -> str:
        text = str(key)
        return redact_text(text)[0] if self._redact else text

    def _email(self, m: re.Match[str]) -> str:
        if self.email_key is None:
            return "[REDACTED:email]"
        digest = hmac.new(self.email_key, m[0].encode(), hashlib.sha256).hexdigest()
        return f"[EMAIL:hmac-sha256:{digest[:16]}]"

    def _clean_str(self, text: str, keep: bool = False) -> Any:
        if self._redact:
            text, _ = redact_text(text)
            # Only values: the actor (often an address) goes through _clean_key and stays.
            text = _EMAIL.pattern.sub(self._email, text)
        if not self._log_content and not keep and len(text) > self._preview_chars:
            return {"sha256": _sha256(text), "length": len(text)}
        if len(text) > self._max_field_chars:
            return {
                "truncated": text[: self._max_field_chars],
                "sha256": _sha256(text),
                "length": len(text),
            }
        return text


# camelCase, snake_case, kebab-case and dotted names all split into the same words.
_KEY_WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+")
_PASSWORD_WORDS = frozenset({"password", "passwd", "pwd"})
_SECRET_WORDS = frozenset({"token", "secret", "key", "credential", "credentials", "private"})
# Names written with no word boundary, which the split cannot see into.
_SECRET_NAMES = frozenset(
    {
        "secretaccesskey",
        "awssecretaccesskey",
        "sessiontoken",
        "secretkey",
        "privatekey",
        "signingkey",
        "clientsecret",
        "appsecret",
        "apitoken",
        "idtoken",
        "bearertoken",
    }
)


@functools.lru_cache(maxsize=1024)
def _credential_key(key: str) -> str | None:
    """The redaction kind if ``key`` names a credential, else None."""
    if key.casefold() in {"authorization", "proxy-authorization", "cookie", "set-cookie"}:
        return "credential_header"
    prefix = f"{key}="
    for f in find_sensitive(prefix + "x" * 8):
        if f.category == "secret" and f.start == len(prefix):
            return f.kind
    # The probe only sees what the text rules find in an 8-character value, so it misses
    # SecretAccessKey, sessionToken, private_key and the like. Decide those by name.
    words = [w.lower() for w in _KEY_WORDS.findall(key)]
    if not words:
        return None
    if words[-1] in _PASSWORD_WORDS:
        return "password_assignment"
    if words[-1] == "auth":
        # requests' auth=("user", "password"), basic_auth, proxy_auth: the value is a credential.
        return "secret_assignment"
    # A bare "key" (an S3 object key, a keyboard key) and a public key are not secrets.
    plain_key = words[-1] == "key" and (len(words) == 1 or words[-2] == "public")
    if (words[-1] in _SECRET_WORDS and not plain_key) or "".join(words) in _SECRET_NAMES:
        return "secret_assignment"
    return None


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
        if not isinstance(rec, dict):
            return VerifyResult(False, checked, None, "record is not a JSON object")
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


def read_records(path: str | Path, bad: list[str]) -> Iterator[Any]:
    """Yield each JSON line of an audit file. Stops at an unreadable line, noting it in ``bad``."""
    # One record in memory at a time: a production log can be larger than RAM.
    lineno = 0
    try:
        with Path(path).open(encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):  # noqa: B007 - read in the except
                if not line.strip():
                    continue
                try:
                    yield json.loads(line)
                except ValueError:  # JSONDecodeError, or an integer too long to convert
                    bad.append(f"line {lineno} is not valid JSON")
                    return
    except UnicodeDecodeError:
        # The logger only writes ASCII-escaped JSON, so invalid UTF-8 was put there by hand.
        bad.append(f"line {lineno + 1} is not valid UTF-8")


def verify_file(
    path: str | Path, records: Callable[[Iterator[Any]], Iterator[Any]] | None = None
) -> VerifyResult:
    """Verify a JSONL audit file. Malformed lines are reported as tampering.

    ``records`` wraps the record stream, so a caller can read the records in the same pass.
    """
    bad: list[str] = []
    stream = read_records(path, bad)
    result = verify_records(records(stream) if records else stream)
    if result.ok and bad:
        return VerifyResult(False, result.records_checked, None, bad[0])
    return result
