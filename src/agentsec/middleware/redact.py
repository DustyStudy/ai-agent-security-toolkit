"""Secret and PII detection/redaction used by both audit logging and output validation."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

# Same rationale as agentsec.middleware.injection.DEFAULT_MAX_SCAN_CHARS: this runs over
# attacker-influenceable text of unbounded size (audit log fields, tool output, tool-call
# exception text) across a dozen regex rules, so it needs a cost ceiling. Findings beyond the
# cutoff are missed and that portion of ``redact_text``'s output is returned unredacted -- bound
# how much untrusted content reaches this in the first place where you can.
DEFAULT_MAX_SCAN_CHARS = 200_000


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int
    category: str  # "secret" or "pii"

    def preview(self, text: str) -> str:
        """A safe preview: never echoes more than the first 4 characters."""
        return text[self.start : self.start + 4] + "…"


def _luhn_ok(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass(frozen=True)
class _Rule:
    kind: str
    category: str
    pattern: re.Pattern[str]
    check: Callable[[str], bool] | None = None
    group: int = 0


# PGPASSWORD / SSHPASS / MYSQL_PWD: the tool-specific prefix is part of the word, so the
# lookbehind alone would skip them.
_PW_KEY = (
    r"(?i)(?<![a-z])(?:pg|ssh|mysql_?)?(?:password|passphrase|passwd|pwd|pass|pw)"
    r"[\"']?\s*[=:]\s*"
)
# api_key=..., client_secret: ..., "access_token": "...", AccountKey=... (Azure). The key must
# sit right before the separator, so max_tokens: 1024 or secretary=x do not match.
_CREDENTIAL_FIELD = (
    r"(?i)(?<![a-z])(?:api[_-]?key|client[_-]?secret|secret|(?:access|auth|refresh)?[_-]?token"
    r"|account[_-]?key|shared[_-]?access[_-]?key|sig)[\"']?\s*[=:]\s*"  # sig=: Azure SAS
)


def _assignment_rules(kind: str, key: str) -> tuple[_Rule, ...]:
    """Unquoted, double-quoted and single-quoted values after ``key``.

    Quoted values may hold spaces and escapes, so they get their own rules.
    """
    return (
        _Rule(
            kind, "secret", re.compile(key + r"(?![\"'])(?!\[REDACTED:)([^\s\"'&,;]{4,})"), group=1
        ),
        _Rule(
            kind,
            "secret",
            re.compile(key + r"\"(?!\[REDACTED:[a-z_]+\]\")((?:[^\"\\\n]|\\.){1,4096})\"?"),
            group=1,
        ),
        _Rule(
            kind,
            "secret",
            re.compile(key + r"'(?!\[REDACTED:[a-z_]+\]')((?:[^'\\\n]|\\.){1,4096})'?"),
            group=1,
        ),
    )


_RULES: tuple[_Rule, ...] = (
    _Rule(
        "aws_access_key_id",
        "secret",
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b"),
    ),
    _Rule(
        "aws_secret_access_key",
        "secret",
        # Also keyed on the STS/boto field names, which have no "aws" before them. The end
        # is a lookahead, not \b: a key ending in "/" or "+" has no word boundary after it.
        re.compile(
            r"(?i)(?:aws.{0,30}?(?:secret|sk)|secret_?access_?key).{0,20}?[\"'=:\s]+"
            r"([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
        ),
        group=1,
    ),
    _Rule(
        "url_credentials",
        "secret",
        # postgres://user:PASSWORD@host and redis://:PASSWORD@host - redact the password,
        # keep the rest for context. The scheme is bounded: unbounded, "a.a.a.a..." retries
        # from every "." (quadratic). Skipping our own placeholder keeps redaction idempotent,
        # so OutputGuard's recheck does not mistake a redacted value for a leftover secret.
        re.compile(
            r"\b[a-z][a-z0-9+.-]{0,31}://[^\s:/@]*:(?!\[REDACTED:)([^\s/@]+)@", re.IGNORECASE
        ),
        group=1,
    ),
    # password=..., DB_PASSWORD=..., PWD: ..., "password": "..." (JSON/YAML/env/connection
    # strings). A lookbehind, not \b: "_" before PASSWORD is a word character.
    *_assignment_rules("password_assignment", _PW_KEY),
    *_assignment_rules("secret_assignment", _CREDENTIAL_FIELD),
    # Stripe secret/restricted keys use "_", which the OpenAI-style sk- rule does not cover.
    _Rule("stripe_api_key", "secret", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}")),
    _Rule(
        "basic_auth",
        "secret",
        re.compile(r"(?i)\bauthorization[\"']?\s*[=:]\s*[\"']?basic\s+([A-Za-z0-9+/]{8,}={0,2})"),
        group=1,
    ),
    _Rule(
        "authorization_header",
        "secret",
        # Any other scheme ("Token", "ApiKey", custom) and a bare credential with no scheme.
        re.compile(
            r"(?i)\bauthorization[\"']?\s*[=:]\s*[\"']?(?:[a-z][a-z0-9-]*\s+)?"
            r"(?!\[REDACTED:)([A-Za-z0-9._~+/=:-]{12,})"
        ),
        group=1,
    ),
    _Rule("github_token", "secret", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    _Rule("gitlab_token", "secret", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    _Rule("npm_token", "secret", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    _Rule("huggingface_token", "secret", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    _Rule("github_fine_grained_pat", "secret", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    _Rule("slack_token", "secret", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    _Rule("anthropic_api_key", "secret", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    # Current OpenAI keys are sk-proj-/sk-svcacct-/sk-admin- with "-" and "_" in the body.
    _Rule(
        "openai_style_api_key",
        "secret",
        re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}"),
    ),
    _Rule("google_api_key", "secret", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    _Rule(
        "private_key_block",
        "secret",
        # The whole block, not just the BEGIN line: matching only the header would leave the
        # base64 key material itself in the log/output. An unterminated block (truncated
        # output) is redacted to the end of the text rather than left exposed.
        re.compile(
            r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
            r"[\s\S]*?"
            r"(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|\Z)"
        ),
    ),
    _Rule(
        "jwt",
        "secret",
        # One start per run of token characters ("-" included in the lookbehind): with \b,
        # "eyJ-eyJ-eyJ-..." restarted at every "eyJ" and rescanned the rest of the run.
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}+\.[A-Za-z0-9_-]{8,}+\.[A-Za-z0-9_-]{8,}\b"
        ),
    ),
    _Rule("bearer_token", "secret", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    _Rule(
        "us_ssn",
        "pii",
        re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    ),
    _Rule(
        "payment_card",
        "pii",
        re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
        check=_luhn_ok,
    ),
)


def find_sensitive(
    text: str, *, include_pii: bool = True, max_scan_chars: int = DEFAULT_MAX_SCAN_CHARS
) -> list[Finding]:
    """Return non-overlapping findings, ordered by position.

    Only the first ``max_scan_chars`` characters are scanned; pass ``max_scan_chars=len(text)``
    (or ``math.inf``) to scan all of it regardless of size.
    """
    scanned = text if len(text) <= max_scan_chars else text[:max_scan_chars]
    found: list[Finding] = []
    for rule in _RULES:
        if rule.category == "pii" and not include_pii:
            continue
        for m in rule.pattern.finditer(scanned):
            if rule.check and not rule.check(m.group(rule.group)):
                continue
            found.append(Finding(rule.kind, m.start(rule.group), m.end(rule.group), rule.category))
    found.sort(key=lambda f: (f.start, -(f.end - f.start)))
    merged: list[Finding] = []
    for f in found:
        if merged and f.start < merged[-1].end:
            continue
        merged.append(f)
    return merged


def redact_text(
    text: str, *, include_pii: bool = True, max_scan_chars: int = DEFAULT_MAX_SCAN_CHARS
) -> tuple[str, list[Finding]]:
    """Replace sensitive spans with ``[REDACTED:<kind>]``.

    Text beyond ``max_scan_chars`` is not scanned and is returned unredacted (see
    :func:`find_sensitive`).
    """
    findings = find_sensitive(text, include_pii=include_pii, max_scan_chars=max_scan_chars)
    if not findings:
        return text, []
    out: list[str] = []
    cursor = 0
    for f in findings:
        out.append(text[cursor : f.start])
        out.append(f"[REDACTED:{f.kind}]")
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out), findings
