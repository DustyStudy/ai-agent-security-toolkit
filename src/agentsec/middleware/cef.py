"""Format audit records as ArcSight Common Event Format (CEF) for SIEM ingestion.

CEF is understood by Splunk, Microsoft Sentinel, QRadar, Elastic, ArcSight and most syslog
pipelines. A line looks like::

    CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|key=value key=value ...

Audit records carry attacker-influenceable text (tool arguments, model output, tool results),
so every value is escaped per the CEF rules and bounded. A value cannot end its field, forge a
new ``key=value`` pair or start a new event:

* header fields: ``\\`` and ``|`` are escaped;
* extension values: ``\\`` and ``=`` are escaped, newlines become ``\\n`` and ``\\r``, and other
  control characters are replaced with a space.

Ship the hash-chained JSONL file as the evidence of record and use these lines as the live feed
to your SIEM (see :class:`~agentsec.middleware.audit.TeeSink`). The CEF lines include each
record's hash and its predecessor's, so a receiver can also check the chain.
"""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Callable
from datetime import datetime
from typing import IO, Any

from agentsec import __version__

CEF_VERSION = 0
MAX_VALUE_CHARS = 1023  # the CEF-recommended cap for free-text extension values


def _header(text: str) -> str:
    return _plain(text).replace("\\", "\\\\").replace("|", "\\|")


def _plain(text: str) -> str:
    """Replace control characters and Unicode line/paragraph separators with spaces.

    U+2028 and U+2029 are not control characters, but many parsers (Python's ``splitlines``,
    JavaScript, several log shippers) treat them as line breaks.
    """
    return "".join(" " if unicodedata.category(ch) in ("Cc", "Zl", "Zp") else ch for ch in text)


def _value(value: Any, limit: int = MAX_VALUE_CHARS) -> str:
    """Escape an extension value: backslash, equals and line breaks; bound its length."""
    text = value if isinstance(value, str) else json.dumps(value, default=str, sort_keys=True)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    out: list[str] = []
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch == "=":
            out.append("\\=")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif unicodedata.category(ch) in ("Cc", "Zl", "Zp"):
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


# event name -> human-readable name; severities are computed from the record's data
_EVENTS: dict[str, str] = {
    "prompt": "Prompt screened",
    "model_output": "Model output screened",
    "tool_request": "Tool call requested",
    "tool_decision": "Tool call decision",
    "tool_result": "Tool call result",
    "approval": "Human approval",
    "validation": "Output validation",
    "error": "Agent error",
    "mcp_tool_finding": "MCP tool definition finding",
    "mcp_tool_blocked": "MCP tool call blocked",
}


def severity(event: str, data: dict[str, Any]) -> int:
    """CEF severity 0-10: denials and injection findings rank above routine activity."""
    if event == "tool_decision":
        return {"deny": 6, "needs_approval": 5}.get(str(data.get("verdict")), 3)
    if event == "approval":
        return 3 if data.get("approved") is True else 5
    if event == "mcp_tool_finding":
        return 8 if data.get("kind") in ("injection", "changed") else 6
    if event == "mcp_tool_blocked":
        return 6
    if event in ("validation", "error"):
        return 5
    if data.get("blocked") is True:
        return 7
    return 1


def _epoch_ms(timestamp: Any) -> int | None:
    try:
        return int(datetime.fromisoformat(str(timestamp)).timestamp() * 1000)
    except ValueError:
        return None


def format_cef(
    record: dict[str, Any],
    *,
    vendor: str = "agentsec",
    product: str = "ai-agent-security-toolkit",
    version: str = __version__,
) -> str:
    """Render one audit record (as written by :class:`AuditLogger`) as a single CEF line."""
    event = str(record.get("event", "unknown"))
    data = record.get("data")
    data = data if isinstance(data, dict) else {}
    fields: list[tuple[str, Any]] = []

    epoch = _epoch_ms(record.get("ts"))
    if epoch is not None:
        fields.append(("rt", epoch))
    if "seq" in record:
        fields.append(("externalId", record["seq"]))
    if record.get("actor"):
        fields.append(("suser", record["actor"]))
    if record.get("session_id"):
        fields.append(("deviceExternalId", record["session_id"]))
    if "verdict" in data:
        fields.append(("act", data["verdict"]))
    if "tool" in data:
        fields += [("cs1", data["tool"]), ("cs1Label", "tool")]
    if data.get("reasons"):
        fields += [("cs2", "; ".join(map(str, data["reasons"]))), ("cs2Label", "reasons")]
    if record.get("hash"):
        fields += [("cs3", record["hash"]), ("cs3Label", "recordHash")]
    if record.get("prev_hash"):
        fields += [("cs4", record["prev_hash"]), ("cs4Label", "previousHash")]
    if data.get("tool_session"):
        fields += [("cs5", data["tool_session"]), ("cs5Label", "guardSession")]
    fields.append(("msg", data))

    head = "|".join(
        [
            f"CEF:{CEF_VERSION}",
            _header(vendor),
            _header(product),
            _header(version),
            _header(event),
            _header(_EVENTS.get(event, event)),
            str(severity(event, data)),
        ]
    )
    return head + "|" + " ".join(f"{key}={_value(value)}" for key, value in fields)


class CefSink:
    """An audit sink that writes each record as a CEF line to a stream or a callback.

    It keeps no chain state (``last_record`` is ``None``), so use it *alongside* a chain-keeping
    sink such as :class:`~agentsec.middleware.audit.FileSink` via
    :class:`~agentsec.middleware.audit.TeeSink`.
    """

    def __init__(self, target: IO[str] | Callable[[str], None], **format_options: str) -> None:
        self._target = target
        self._options = format_options

    def write(self, record: dict[str, Any]) -> None:
        line = format_cef(record, **self._options)
        if callable(self._target):
            self._target(line)
        else:
            self._target.write(line + "\n")
            self._target.flush()

    def last_record(self) -> dict[str, Any] | None:
        return None


__all__ = ["CefSink", "format_cef", "severity"]
