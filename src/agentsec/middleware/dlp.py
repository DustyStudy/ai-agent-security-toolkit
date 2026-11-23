"""Data-loss prevention: one policy for credentials, non-human identities and PII.

The detectors are the ones in :mod:`agentsec.middleware.redact`; this module groups them into
categories and decides, per surface, whether a finding is monitored, redacted or blocked.
Design: docs/design/DATA_LOSS_PREVENTION.md.

Nothing here records a matched value. A match is described by its kind, position, length and,
when a key is configured, a keyed fingerprint.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from agentsec.middleware.redact import _EMAIL, _RULES, DEFAULT_MAX_SCAN_CHARS, find_sensitive

SURFACES = ("output", "tool_args", "tool_results", "upstream")
CATEGORIES = ("credentials", "nhi", "pii")
MODES = ("monitor", "redact", "block")
_RANK = {"monitor": 0, "redact": 1, "block": 2}

# Secrets recognised by their context; everything else in the secret category is recognised
# by its issuer's own format (a non-human identity).
_CREDENTIAL_KINDS = frozenset(
    {
        "password_assignment",
        "secret_assignment",
        "cli_credential",
        "url_credentials",
        "authorization_header",
        "basic_auth",
        "bearer_token",
        "cookie_header",
        "jwt",
        "private_key_block",
    }
)
CATEGORY_OF: dict[str, str] = {
    r.kind: (
        "pii" if r.category == "pii" else "credentials" if r.kind in _CREDENTIAL_KINDS else "nhi"
    )
    for r in (*_RULES, _EMAIL)
}

_DEFAULT_MODES: dict[str, dict[str, str]] = {
    "credentials": {
        "output": "redact",
        "tool_args": "block",
        "tool_results": "redact",
        "upstream": "monitor",
    },
    "nhi": {
        "output": "redact",
        "tool_args": "block",
        "tool_results": "redact",
        "upstream": "monitor",
    },
    "pii": {
        "output": "redact",
        "tool_args": "monitor",
        "tool_results": "monitor",
        "upstream": "monitor",
    },
}
_DEFAULT_KIND_MODES: dict[str, dict[str, str]] = {"email": dict.fromkeys(SURFACES, "monitor")}

MAX_ALLOW_DAYS = 180
MAX_UNIT_CHARS = 1_000_000  # all strings in one tool call
MAX_UNIT_STRINGS = 10_000
MAX_MATCH_RECORDS = 50  # per unit; the rest are counted, not described

# $TOKEN, ${TOKEN}, %TOKEN%, {{ secrets.X }}: a reference to a secret, not the secret.
_REFERENCE = re.compile(r"\$\{?[A-Za-z_]\w*\}?|%[A-Za-z_]\w*%|\{\{[^{}]{1,200}\}\}")

# Published example values that are never real credentials or people. Matches are still
# recorded (allowed_by="builtin"), so a real value next to an example one is still caught.
_BUILTIN_VALUES = frozenset(
    {
        "AKIA" + "IOSFODNN7EXAMPLE",  # AWS documentation access key id
        "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY",  # its documented secret key
        # Card networks' and processors' published test numbers.
        "4242424242424242",
        "4000056655665556",
        "4111111111111111",
        "5555555555554444",
        "2223003122003222",
        "5200828282828210",
        "5105105105105100",
        "378282246310005",
        "371449635398431",
        "6011111111111117",
        "6011000990139424",
        "3056930009020004",
        "36227206271667",
        "3566002020360505",
        "6200000000000005",
        "078051120",  # SSN printed on a 1938 wallet insert, voided
    }
)
_BUILTIN_EMAIL_DOMAINS = ("example.com", "example.org", "example.net")
_BUILTIN_EMAIL_TLDS = (".test", ".invalid", ".example", ".localhost")


class DlpConfigError(ValueError):
    """Raised when a ``dlp`` section is malformed."""


@dataclass(frozen=True)
class DlpMatch:
    """One finding, described without its value."""

    kind: str
    category: str
    surface: str
    offset: int
    length: int
    action: str  # monitor | redact | block | allowed
    fingerprint: str | None = None
    allowed_by: str | None = None
    location: str | None = None  # JSON path inside tool arguments
    tool: str | None = None

    def audit(self) -> dict[str, Any]:
        """Fields for a ``dlp_match`` audit record. Never the value or any part of it."""
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass(frozen=True)
class DlpResult:
    text: str  # redacted text (for tool arguments: unchanged; they are never rewritten)
    action: str | None  # strictest action taken, None when nothing matched
    matches: tuple[DlpMatch, ...] = ()
    overflow: int = 0  # matches past MAX_MATCH_RECORDS

    @property
    def blocked(self) -> bool:
        return self.action == "block"


@dataclass(frozen=True)
class AllowEntry:
    id: str
    reason: str
    owner: str
    expires: date
    kinds: frozenset[str]
    surfaces: frozenset[str] = frozenset(SURFACES)
    tools: frozenset[str] | None = None
    email_domain: str | None = None
    sha256: str | None = None
    pattern: re.Pattern[str] | None = None

    def matches(self, value: str, kind: str, surface: str, tool: str | None, today: date) -> bool:
        if today > self.expires or kind not in self.kinds or surface not in self.surfaces:
            return False
        if self.tools is not None and tool not in self.tools:
            return False
        if self.email_domain is not None:
            return value.rpartition("@")[2].lower() == self.email_domain
        if self.sha256 is not None:
            return hmac.compare_digest(hashlib.sha256(value.encode()).hexdigest(), self.sha256)
        return self.pattern is not None and self.pattern.fullmatch(value) is not None


@dataclass(frozen=True)
class DlpPolicy:
    """Modes per category and surface, per-kind overrides, allowlist, fingerprint key.

    ``DlpPolicy()`` is the default policy: secrets redacted in answers and blocked in tool
    arguments, SSNs and cards redacted in answers, everything else monitored.
    """

    modes: dict[str, dict[str, str]] = field(default_factory=lambda: _copy(_DEFAULT_MODES))
    kind_modes: dict[str, dict[str, str]] = field(
        default_factory=lambda: _copy(_DEFAULT_KIND_MODES)
    )
    allow: tuple[AllowEntry, ...] = ()
    fingerprint_key: bytes | None = None
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC), compare=False)

    # ------------------------------------------------------------------ loading
    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any] | None,
        *,
        resolve_secret: Callable[[str], str] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> DlpPolicy:
        """Strict: unknown keys, categories, surfaces, kinds or modes are errors.

        ``fingerprint_key`` is a reference (``env:NAME`` or ``file:/path``), resolved with
        ``resolve_secret`` (default: environment variable or file contents).
        """
        clock = clock or (lambda: datetime.now(UTC))
        data = data or {}
        _only(data, {"categories", "allow", "fingerprint_key"}, "dlp")
        modes, kind_modes = _copy(_DEFAULT_MODES), _copy(_DEFAULT_KIND_MODES)
        cats = data.get("categories") or {}
        if not isinstance(cats, dict):
            raise DlpConfigError("dlp.categories must be a mapping")
        for cat, section in cats.items():
            where = f"dlp.categories.{cat}"
            if cat not in CATEGORIES:
                raise DlpConfigError(f"{where}: category must be one of {', '.join(CATEGORIES)}")
            if not isinstance(section, dict):
                raise DlpConfigError(f"{where} must be a mapping")
            _only(section, {*SURFACES, "kinds"}, where)
            explicit = _surface_modes({k: v for k, v in section.items() if k != "kinds"}, where)
            modes[cat].update(explicit)
            # A category mode set here beats a built-in per-kind default (email: monitor).
            for kind in _DEFAULT_KIND_MODES:
                if CATEGORY_OF[kind] == cat:
                    for surface in explicit:
                        kind_modes[kind].pop(surface, None)
            kinds = section.get("kinds") or {}
            if not isinstance(kinds, dict):
                raise DlpConfigError(f"{where}.kinds must be a mapping")
            for kind, override in kinds.items():
                if CATEGORY_OF.get(kind) != cat:
                    raise DlpConfigError(f"{where}.kinds: {kind!r} is not a {cat} kind")
                if not isinstance(override, dict):
                    raise DlpConfigError(f"{where}.kinds.{kind} must be a mapping")
                kind_modes.setdefault(kind, {}).update(
                    _surface_modes(override, f"{where}.kinds.{kind}")
                )
        raw_allow = data.get("allow") or []
        if not isinstance(raw_allow, list):
            raise DlpConfigError("dlp.allow must be a list")
        today = clock().date()
        allow = tuple(_allow_entry(e, i, today) for i, e in enumerate(raw_allow))
        ids = [e.id for e in allow]
        if len(set(ids)) != len(ids):
            raise DlpConfigError("dlp.allow: entry ids must be unique")
        key = None
        ref = data.get("fingerprint_key")
        if ref is not None:
            if not isinstance(ref, str):
                raise DlpConfigError("dlp.fingerprint_key must be 'env:NAME' or 'file:/path'")
            key = (resolve_secret or _resolve)(ref).encode()
            if len(key) < 32:
                raise DlpConfigError("dlp.fingerprint_key must be at least 32 bytes")
        return cls(modes, kind_modes, allow, key, clock)

    # ------------------------------------------------------------------ checks
    def mode(self, kind: str, surface: str) -> str:
        category = CATEGORY_OF.get(kind, "credentials")
        mode = self.kind_modes.get(kind, {}).get(surface) or self.modes[category][surface]
        # A rewritten argument changes the action (a payment to "[REDACTED:...]"), so redact
        # in tool arguments means block.
        return "block" if surface == "tool_args" and mode == "redact" else mode

    def strictest(self, surface: str) -> str:
        """The strictest mode any kind can get on ``surface``."""
        return max((self.mode(k, surface) for k in CATEGORY_OF), key=_RANK.__getitem__)

    def scan(self, text: str, surface: str, *, tool: str | None = None) -> DlpResult:
        """Find, decide and (for ``redact``) rewrite. One pass over the detectors."""
        if surface not in SURFACES:
            raise ValueError(f"unknown surface {surface!r}")
        if len(text) > DEFAULT_MAX_SCAN_CHARS:
            return self._too_big(surface, text, tool)
        return self._result(text, list(self._matches(text, surface, tool, None)))

    def scan_args(self, arguments: Any, tool: str | None) -> DlpResult:
        """Every string (keys included) in a tool call's arguments. Never rewrites them."""
        matches: list[DlpMatch] = []
        total = count = 0
        for path, text in _strings(arguments, "arguments"):
            total += len(text)
            count += 1
            if (
                total > MAX_UNIT_CHARS
                or count > MAX_UNIT_STRINGS
                or len(text) > DEFAULT_MAX_SCAN_CHARS
            ):
                return self._too_big("tool_args", "", tool, total)
            matches += self._matches(text, "tool_args", tool, path)
        return DlpResult("", _strictest(matches), *_cap(matches))

    # ------------------------------------------------------------------ internals
    def _matches(
        self, text: str, surface: str, tool: str | None, location: str | None
    ) -> Iterator[DlpMatch]:
        today = self.clock().date()
        for f in find_sensitive(text, max_scan_chars=len(text), include_email=True):
            value = text[f.start : f.end]
            if _REFERENCE.fullmatch(value):
                continue
            allowed_by = self._allowed_by(value, f.kind, surface, tool, today)
            yield DlpMatch(
                kind=f.kind,
                category=CATEGORY_OF.get(f.kind, "credentials"),
                surface=surface,
                offset=f.start,
                length=f.end - f.start,
                action="allowed" if allowed_by else self.mode(f.kind, surface),
                fingerprint=self._fingerprint(value),
                allowed_by=allowed_by,
                location=location,
                tool=tool,
            )

    def _allowed_by(
        self, value: str, kind: str, surface: str, tool: str | None, today: date
    ) -> str | None:
        if _builtin(value, kind):
            return "builtin"
        for entry in self.allow:
            if entry.matches(value, kind, surface, tool, today):
                return entry.id
        return None

    def _fingerprint(self, value: str) -> str | None:
        if self.fingerprint_key is None:
            return None
        digest = hmac.new(self.fingerprint_key, value.encode(), hashlib.sha256).hexdigest()
        return "hmac-sha256:" + digest[:16]

    def _too_big(
        self, surface: str, text: str, tool: str | None, length: int | None = None
    ) -> DlpResult:
        # Fail closed: a secret can sit past any limit. Only an all-monitor surface delivers.
        action = "block" if self.strictest(surface) != "monitor" else "monitor"
        size = len(text) if length is None else length
        match = DlpMatch("scan_limit", "unscanned", surface, 0, size, action, tool=tool)
        return DlpResult("[REDACTED:scan_limit]" if action == "block" else text, action, (match,))

    def _result(self, text: str, matches: list[DlpMatch]) -> DlpResult:
        action = _strictest(matches)
        out: list[str] = []
        cursor = 0
        for m in matches:
            if m.action != "redact":
                continue
            out.append(text[cursor : m.offset])
            out.append(f"[REDACTED:{m.kind}]")
            cursor = m.offset + m.length
        out.append(text[cursor:])
        return DlpResult("".join(out), action, *_cap(matches))


# ---------------------------------------------------------------------- helpers
def _copy(modes: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    return {k: dict(v) for k, v in modes.items()}


def _strictest(matches: list[DlpMatch]) -> str | None:
    acted = [m.action for m in matches if m.action in _RANK]
    return max(acted, key=_RANK.__getitem__) if acted else None


def _cap(matches: list[DlpMatch]) -> tuple[tuple[DlpMatch, ...], int]:
    return tuple(matches[:MAX_MATCH_RECORDS]), max(0, len(matches) - MAX_MATCH_RECORDS)


def _only(section: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = set(section) - allowed
    if unknown:
        raise DlpConfigError(f"{where}: unknown keys {sorted(map(str, unknown))}")


def _surface_modes(section: dict[str, Any], where: str) -> dict[str, str]:
    _only(section, set(SURFACES), where)
    for surface, mode in section.items():
        if mode not in MODES:
            raise DlpConfigError(f"{where}.{surface} must be monitor, redact or block")
    return dict(section)


def _text(entry: dict[str, Any], key: str, where: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise DlpConfigError(f"{where}.{key} is required")
    return value


def _names(value: Any, where: str, allowed: Any = None) -> frozenset[str]:
    if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value):
        raise DlpConfigError(f"{where} must be a non-empty list of names")
    if allowed is not None and set(value) - set(allowed):
        raise DlpConfigError(f"{where}: unknown {sorted(set(value) - set(allowed))}")
    return frozenset(value)


def _allow_entry(entry: Any, i: int, today: date) -> AllowEntry:
    where = f"dlp.allow[{i}]"
    if not isinstance(entry, dict):
        raise DlpConfigError(f"{where} must be a mapping")
    _only(entry, {"id", "reason", "owner", "expires", "kinds", "surfaces", "tools", "match"}, where)
    expires = entry.get("expires")
    if isinstance(expires, str):
        try:
            expires = date.fromisoformat(expires)
        except ValueError:
            raise DlpConfigError(f"{where}.expires must be a date (YYYY-MM-DD)") from None
    if not isinstance(expires, date) or isinstance(expires, datetime):
        raise DlpConfigError(f"{where}.expires must be a date (YYYY-MM-DD)")
    if expires > today + timedelta(days=MAX_ALLOW_DAYS):
        # A forgotten exception must not become a permanent hole.
        raise DlpConfigError(f"{where}.expires is more than {MAX_ALLOW_DAYS} days away")
    kinds = _names(entry.get("kinds"), f"{where}.kinds", CATEGORY_OF)
    surfaces = _names(entry.get("surfaces", list(SURFACES)), f"{where}.surfaces", SURFACES)
    tools = None if entry.get("tools") is None else _names(entry["tools"], f"{where}.tools")
    match = entry.get("match")
    if not isinstance(match, dict) or len(match) != 1:
        raise DlpConfigError(f"{where}.match takes exactly one of email_domain, sha256, pattern")
    ((how, value),) = match.items()
    if not isinstance(value, str) or not value:
        raise DlpConfigError(f"{where}.match.{how} must be a non-empty string")
    fields: dict[str, Any] = {}
    if how == "email_domain":
        if kinds != {"email"}:
            raise DlpConfigError(f"{where}: email_domain only applies to kinds [email]")
        fields["email_domain"] = value.lower().rstrip(".")
    elif how == "sha256":
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise DlpConfigError(f"{where}.match.sha256 must be 64 lowercase hex characters")
        fields["sha256"] = value
    elif how == "pattern":
        # A pattern broad enough to be useful for a credential is an off switch.
        if any(CATEGORY_OF[k] != "pii" for k in kinds):
            raise DlpConfigError(f"{where}: pattern is for pii kinds only; use sha256")
        try:
            fields["pattern"] = re.compile(value)
        except re.error as e:
            raise DlpConfigError(f"{where}.match.pattern: {e}") from None
    else:
        raise DlpConfigError(f"{where}.match takes exactly one of email_domain, sha256, pattern")
    return AllowEntry(
        id=_text(entry, "id", where),
        reason=_text(entry, "reason", where),
        owner=_text(entry, "owner", where),
        expires=expires,
        kinds=kinds,
        surfaces=surfaces,
        tools=tools,
        **fields,
    )


def _builtin(value: str, kind: str) -> bool:
    if kind == "email":
        domain = value.rpartition("@")[2].lower()
        return domain in _BUILTIN_EMAIL_DOMAINS or domain.endswith(_BUILTIN_EMAIL_TLDS)
    if kind in ("payment_card", "us_ssn"):
        value = "".join(c for c in value if c.isdigit())
    return value in _BUILTIN_VALUES


def _strings(value: Any, path: str, depth: int = 0) -> Iterator[tuple[str, str]]:
    """(path, string) for every string and key, depth-first. Deep nesting is scanned as text."""
    if depth > 64:
        yield path, repr(value)
    elif isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for k, v in value.items():
            key = str(k)
            yield f"{path}.<key>", key
            yield from _strings(v, f"{path}.{_safe_key(key)}", depth + 1)
    elif isinstance(value, list | tuple):
        for i, v in enumerate(value):
            yield from _strings(v, f"{path}[{i}]", depth + 1)


def _safe_key(key: str) -> str:
    # The path is audited: a key that is itself a secret must not be copied into it.
    return (
        f"[REDACTED:{find[0].kind}]" if (find := find_sensitive(key, include_email=True)) else key
    )


def _resolve(ref: str) -> str:
    kind, _, value = ref.partition(":")
    if kind == "env":
        secret = os.environ.get(value)
        if not secret:
            raise DlpConfigError(f"environment variable {value!r} is not set")
        return secret
    if kind == "file":
        return Path(value).read_text(encoding="utf-8").strip()
    raise DlpConfigError("dlp.fingerprint_key must be 'env:NAME' or 'file:/path'")


DEFAULT_DLP = DlpPolicy()
