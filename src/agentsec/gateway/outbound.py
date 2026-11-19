"""Outbound screening: secrets in the request the gateway is about to send to a model upstream."""

from __future__ import annotations

from typing import Any

from agentsec.middleware import redact_text

MODES = ("off", "block", "redact")


def attachments(messages: list[dict[str, Any]]) -> list[str]:
    """Paths of message content parts that are not plain text (images, audio, files)."""
    return [
        f"messages[{i}].content[{j}]"
        for i, m in enumerate(messages)
        if isinstance(m.get("content"), list)
        for j, p in enumerate(m["content"])
        if not (isinstance(p, dict) and p.get("type") == "text")
    ]


def scrub(value: Any, path: str, hits: list[tuple[str, str]]) -> Any:
    """Copy of ``value`` with secrets in every string replaced; ``hits`` gets (path, kind).

    Walks the whole request: all roles, history, tool_calls arguments, tool results, tool
    definitions. Only PII-free secret rules apply; the secret itself is never recorded.
    """
    if isinstance(value, str):
        text, found = redact_text(value, include_pii=False)
        hits += [(path, f.kind) for f in found]
        return text
    if isinstance(value, list):
        return [scrub(v, f"{path}[{i}]", hits) for i, v in enumerate(value)]
    if isinstance(value, dict):
        return {k: scrub(v, f"{path}.{k}", hits) for k, v in value.items()}
    return value
