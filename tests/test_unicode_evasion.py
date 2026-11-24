"""Character-injection evasion (Mindgard, "Bypassing LLM Guardrails", 2025; AWS, "Defending
LLM applications against Unicode character smuggling", 2025-09-30).

Zero-width, tag, soft-hyphen and variation-selector characters, or fullwidth forms, inside a
secret hid it from every detector while the reader still saw the secret. Every secret-shaped
value is built at run time so no scanner trips on this file.
"""

from __future__ import annotations

import pytest

from agentsec.middleware import AuditLogger, MemorySink
from agentsec.middleware.dlp import DlpPolicy
from agentsec.middleware.redact import find_sensitive, fold, redact_text

AWS = "AKIA" + "IOSFODNN7" + "EXAMPLF"
GH = "ghp_" + "a1B2" * 9


def _fullwidth(s: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if c.isalnum() else c for c in s)


@pytest.mark.parametrize(
    "hidden",
    [
        AWS[:4] + "\u200b" + AWS[4:],  # zero-width space
        AWS[:4] + "\u2060" + AWS[4:8] + "\u200d" + AWS[8:],  # word joiner, zero-width joiner
        AWS[:4] + "\U000e0041" + AWS[4:],  # tag character
        AWS[:4] + "\u00ad" + AWS[4:],  # soft hyphen
        AWS[:4] + "\ufe0f" + AWS[4:],  # variation selector ("emoji smuggling")
        AWS[:4] + "\U000e0101" + AWS[4:],  # supplementary variation selector
        _fullwidth(AWS),
    ],
)
def test_obfuscated_secret_is_found_and_redacted(hidden: str) -> None:
    text = f"the key is {hidden} ok"
    (f,) = find_sensitive(text)
    assert f.kind == "aws_access_key_id"
    assert text[f.start : f.end] == hidden  # offsets are the caller's, not the folded text's
    out, _ = redact_text(text)
    assert out == "the key is [REDACTED:aws_access_key_id] ok"


def test_dlp_blocks_obfuscated_secret_in_tool_args() -> None:
    policy = DlpPolicy()
    r = policy.scan_args({"body": GH[:6] + "\u200b" + GH[6:]}, "send_email")
    assert r.action == "block"
    assert [m.kind for m in r.matches] == ["github_token"]


def test_dlp_fingerprint_ignores_invisible_characters() -> None:
    policy = DlpPolicy(fingerprint_key=b"k" * 32)
    plain = policy.scan(AWS, "output").matches[0].fingerprint
    hidden = policy.scan(AWS[:4] + "\u200b" + AWS[4:], "output").matches[0].fingerprint
    assert plain is not None and plain == hidden


def test_obfuscated_secret_is_redacted_in_the_audit_log() -> None:
    sink = MemorySink()
    AuditLogger(sink).log("tool_result", text="key " + AWS[:4] + "\u200c" + AWS[4:])
    assert AWS[4:] not in str(sink.records)


def test_fold_keeps_ordinary_text() -> None:
    assert fold("plain ascii") == "plain ascii"
    assert fold("café, naïve, 東京") == "café, naïve, 東京"
    assert fold("a\u200bb") == "ab"
