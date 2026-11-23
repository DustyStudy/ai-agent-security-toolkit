"""Outbound screening: sensitive data in the request the gateway is about to send upstream."""

from __future__ import annotations

import dataclasses
from typing import Any

from agentsec.middleware.dlp import DlpMatch, DlpPolicy

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


def upstream_policy(dlp: DlpPolicy, cred_mode: str, pii_mode: str) -> DlpPolicy:
    """``dlp`` with an upstream's ``outbound.on_secret`` / ``on_pii`` overriding the
    ``upstream`` surface ("off" keeps the group's own modes)."""
    if cred_mode == "off" and pii_mode == "off":
        return dlp
    modes = {k: dict(v) for k, v in dlp.modes.items()}
    kinds = {k: dict(v) for k, v in dlp.kind_modes.items()}
    if cred_mode != "off":
        modes["credentials"]["upstream"] = modes["nhi"]["upstream"] = cred_mode
    if pii_mode != "off":
        modes["pii"]["upstream"] = pii_mode
        for kind, override in kinds.items():
            if dlp.category(kind) == "pii":
                override.pop("upstream", None)
    return dataclasses.replace(dlp, modes=modes, kind_modes=kinds)


def screen(value: Any, path: str, policy: DlpPolicy, hits: list[DlpMatch]) -> Any:
    """Copy of ``value`` with every string scanned on the ``upstream`` surface and redacted
    where its mode says so; ``hits`` gets each match with its request path, never the value.

    Walks the whole request: all roles, history, tool_calls arguments, tool results, tool
    definitions.
    """
    if isinstance(value, str):
        result = policy.scan(value, "upstream")
        hits += [dataclasses.replace(m, location=path) for m in result.matches]
        return result.text
    if isinstance(value, list):
        return [screen(v, f"{path}[{i}]", policy, hits) for i, v in enumerate(value)]
    if isinstance(value, dict):
        return {k: screen(v, f"{path}.{k}", policy, hits) for k, v in value.items()}
    return value
