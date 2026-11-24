"""Secret and PII detection/redaction used by both audit logging and output validation."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass

# Same rationale as agentsec.middleware.injection.DEFAULT_MAX_SCAN_CHARS: this runs over
# attacker-influenceable text of unbounded size (audit log fields, tool output, tool-call
# exception text) across a dozen regex rules, so it needs a cost ceiling.
DEFAULT_MAX_SCAN_CHARS = 200_000

# Invisible characters outside category Cf (combining grapheme joiner, Hangul fillers,
# variation selectors, which carry "emoji smuggling"): dropped like Cf before matching.
_INVISIBLE_NON_CF = frozenset(
    "\u034f\u115f\u1160\u3164\uffa0"
    + "".join(map(chr, range(0xFE00, 0xFE10)))
    + "".join(map(chr, range(0xE0100, 0xE01F0)))
)


def _fold_char(ch: str) -> str:
    if unicodedata.category(ch) == "Cf" or ch in _INVISIBLE_NON_CF:
        return ""
    return unicodedata.normalize("NFKC", ch)


def fold(text: str) -> str:
    """``text`` as a reader sees it: invisible characters dropped, compatibility forms
    (fullwidth, circled, math alphanumerics) folded to their plain form."""
    return text if text.isascii() else "".join(map(_fold_char, text))


def _folded(text: str) -> tuple[str, list[int] | None]:
    """``fold(text)`` plus, for each folded character, the index it came from in ``text``.

    A zero-width space or a fullwidth letter inside a key ("AKIA\u200b...") hides it from every
    detector but not from the person or program that reads it, so detectors run on this.
    """
    if text.isascii():
        return text, None
    out: list[str] = []
    origin: list[int] = []
    for i, ch in enumerate(text):
        folded = _fold_char(ch)
        out.append(folded)
        origin += [i] * len(folded)
    return "".join(out), origin


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


# (first digits, valid lengths) per card network. A Luhn-valid run of digits with no network
# prefix is an order number or a timestamp one time in ten, not a card.
_CARD_NETWORKS: tuple[tuple[tuple[int, int], tuple[int, ...]], ...] = (
    ((4, 4), (13, 16, 19)),  # Visa
    ((51, 55), (16,)),  # Mastercard
    ((2221, 2720), (16,)),  # Mastercard 2-series
    ((34, 34), (15,)),  # Amex
    ((37, 37), (15,)),
    ((6011, 6011), (16, 17, 18, 19)),  # Discover
    ((644, 649), (16, 17, 18, 19)),
    ((65, 65), (16, 17, 18, 19)),
    ((35, 35), (16, 17, 18, 19)),  # JCB
    ((30, 30), (14, 15, 16, 17, 18, 19)),  # Diners
    ((36, 36), (14, 15, 16, 17, 18, 19)),
    ((38, 39), (14, 15, 16, 17, 18, 19)),
    ((62, 62), (16, 17, 18, 19)),  # UnionPay
)


def _card_ok(candidate: str) -> bool:
    """Luhn, a known network prefix and length, and one consistent grouping."""
    if not _luhn_ok(candidate):
        return False
    digits = "".join(c for c in candidate if c.isdigit())
    seps = set(candidate) - set(digits)
    if len(seps) > 1:
        return False
    if seps:
        groups = [len(g) for g in candidate.split(seps.pop())]
        if not (
            all(n == 4 for n in groups[:-1])
            and 1 <= groups[-1] <= 4  # 4-4-4-4(-3)
            or groups in ([4, 6, 5], [4, 6, 4])  # Amex, Diners
        ):
            return False
    for (low, high), lengths in _CARD_NETWORKS:
        width = len(str(low))
        if low <= int(digits[:width]) <= high and len(digits) in lengths:
            return True
    return False


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
    r"|account[_-]?key|shared[_-]?access[_-]?key|sig"  # sig=: Azure SAS
    # SECRET_KEY (Django), private_key, signing_key, aws_secret_access_key, access_key ...
    r"|(?:private|secret|signing|encryption|master|(?:secret[_-]?)?access)[_-]?key"
    r")[\"']?\s*[=:]\s*"
)

# Command lines give the secret after a space, with no "=" or ":" for the rules above to key
# on: --password X, sshpass -p X, mysql -pX, docker login -p X. "-p" stays case-sensitive
# (mysql -P is the port), and a following "-" is the next flag, not a value. The gap after
# the command name is bounded so a long run of command names cannot go quadratic.
_CLI_FLAG = (
    r"(?:(?<![\w-])--(?i:(?:[a-z0-9]+[-_])*(?:password|passwd|token|secret|api[-_]?key))[ \t]+"
    r"|\bsshpass[ \t]+-p[ \t]*"
    r"|\bmysql(?:dump|admin)?\b[^\n]{0,200}?\s-p[ \t]*"
    r"|\bdocker[ \t]+login\b[^\n]{0,200}?\s-p[ \t]+"
    r")(?!-)"
)
# curl -u user:PASSWORD - the user name stays for context.
_CURL_USER = r"\bcurl\b[^\n]{0,200}?\s(?:-u|--user)[ \t]*"


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
    # Azure storage connection strings. Before the assignment rules, which match the same span
    # as a generic secret_assignment: the named kind wins a tie.
    _Rule(
        "azure_storage_key",
        "secret",
        re.compile(r"(?i)\bAccountKey\s*=\s*([A-Za-z0-9+/]{86}==)(?![A-Za-z0-9+/=])"),
        group=1,
    ),
    # password=..., DB_PASSWORD=..., PWD: ..., "password": "..." (JSON/YAML/env/connection
    # strings). A lookbehind, not \b: "_" before PASSWORD is a word character.
    *_assignment_rules("password_assignment", _PW_KEY),
    *_assignment_rules("secret_assignment", _CREDENTIAL_FIELD),
    *_assignment_rules("cli_credential", _CLI_FLAG),
    _Rule(
        "cli_credential",
        "secret",
        re.compile(_CURL_USER + r"[^\s:\"']+:(?!\[REDACTED:)([^\s\"']+)"),
        group=1,
    ),
    _Rule(
        "cli_credential",
        "secret",
        re.compile(_CURL_USER + r"\"[^\":\n]*:(?!\[REDACTED:)((?:[^\"\\\n]|\\.)+)"),
        group=1,
    ),
    _Rule(
        "cli_credential",
        "secret",
        re.compile(_CURL_USER + r"'[^':\n]*:(?!\[REDACTED:)([^'\n]+)"),
        group=1,
    ),
    _Rule(
        "authorization_header",
        "secret",
        # -H "Authorization: Bearer X" with a token shorter than the general rules accept.
        re.compile(
            r"(?:-H|--header)[ \t]*[\"']?(?i:(?:proxy-)?authorization):[ \t]*"
            r"(?:[A-Za-z][A-Za-z0-9-]*[ \t]+)?+(?!\[REDACTED:)([^\s\"']+)"
        ),
        group=1,
    ),
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
        # A known scheme marks what follows as the credential, however short it is:
        # "Authorization: Bearer abc.def" was left whole by the 12-character rule below.
        re.compile(
            r"(?i)\b(?:proxy-)?authorization[\"']?\s*[=:]\s*[\"']?"
            r"(?:bearer|token|apikey|api-key|key|dpop|digest|hmac|negotiate|ntlm|sso-key)\s+"
            r"(?!\[REDACTED:)([A-Za-z0-9._~+/=:-]+)"
        ),
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
    _Rule("gateway_access_token", "secret", re.compile(r"agt_[A-Za-z0-9_-]{43}")),
    _Rule("github_token", "secret", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    # Personal access, runner, deploy and feed tokens.
    _Rule("gitlab_token", "secret", re.compile(r"\bgl(?:pat|rt|dt|ft)-[A-Za-z0-9_-]{20,}")),
    _Rule(
        "sendgrid_api_key",
        "secret",
        re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])"),
    ),
    _Rule("digitalocean_token", "secret", re.compile(r"\bdo[opr]_v1_[a-f0-9]{64}\b")),
    _Rule("shopify_token", "secret", re.compile(r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b")),
    _Rule("databricks_token", "secret", re.compile(r"\bdapi[a-f0-9]{32}(?:-\d)?\b")),
    _Rule("npm_token", "secret", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    _Rule("huggingface_token", "secret", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    _Rule("github_fine_grained_pat", "secret", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    # xoxe-: refresh tokens, xapp-: app-level tokens. Possessive, not \b: a token ending in
    # "-" kept its last character in the output.
    _Rule("slack_token", "secret", re.compile(r"\b(?:xox[abeprs]|xapp)-[A-Za-z0-9-]{10,}+")),
    # The path of an incoming webhook is its credential: anyone holding it can post.
    _Rule(
        "slack_webhook",
        "secret",
        re.compile(
            r"\bhooks\.slack(?:-gov)?\.com/((?:services|workflows|triggers)/[A-Za-z0-9/_-]+)"
        ),
        group=1,
    ),
    _Rule("anthropic_api_key", "secret", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}+")),
    _Rule("google_oauth_token", "secret", re.compile(r"\bya29\.[A-Za-z0-9_-]{20,}+")),
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
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}+\.[A-Za-z0-9_-]{8,}+\.[A-Za-z0-9_-]{8,}+"
        ),
    ),
    _Rule("bearer_token", "secret", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    _Rule(
        "cookie_header",
        "secret",
        # Cookie: sid=...; csrftoken=... and Set-Cookie: sid=...: session cookies are bearer
        # credentials. Only name=value lists match, so prose such as "Cookie: oatmeal" stays.
        re.compile(
            r"(?i)\b(?:set-)?cookie[\"']?[ \t]*:[ \t]*[\"']?(?!\[REDACTED:)"
            r"([^\s=;,\"']{1,256}=[^\r\n\"']{0,4096})"
        ),
        group=1,
    ),
    _Rule(
        "us_ssn",
        "pii",
        # 123-45-6789 or 123 45 6789, with the same separator twice.
        re.compile(r"\b(?!000|666|9\d\d)\d{3}([- ])(?!00)\d{2}\1(?!0000)\d{4}\b"),
    ),
    _Rule(
        "us_ssn",
        "pii",
        # A bare 9-digit run only right after a label: bare 9-digit numbers are everywhere.
        re.compile(
            r"(?i)\b(?:ssn|social security(?: number| no\.?)?|tin)\b[^\d\n]{0,20}?"
            r"(?<!\d)((?!000|666|9\d\d)\d{3}(?!00)\d{2}(?!0000)\d{4})(?!\d)"
        ),
        group=1,
    ),
    _Rule(
        "payment_card",
        "pii",
        # Lazy: the shortest run that ends at a boundary, so a number written right after a
        # card ("<card> 2 items") does not make one too-long candidate.
        # shortcut: a 19-digit card written in groups is read as its first 16 digits; widen
        # the search if 19-digit cards in 4-4-4-4-3 form show up in practice.
        re.compile(r"\b(?:\d[ -]?){12,18}?\d\b"),
        check=_card_ok,
    ),
)

# Not in _RULES: the audit log redacts _RULES everywhere, and an email address is often the
# actor's own name there. DLP asks for it with include_email=True.
_EMAIL = _Rule(
    "email",
    "pii",
    # One start per run of address characters, bounded parts: linear on "a@a@a@...".
    re.compile(
        r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@"
        r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,8}[A-Za-z]{2,63}(?![A-Za-z0-9-])"
    ),
)


def find_sensitive(
    text: str,
    *,
    include_pii: bool = True,
    max_scan_chars: int = DEFAULT_MAX_SCAN_CHARS,
    include_email: bool = False,
    extra: tuple[_Rule, ...] = (),
) -> list[Finding]:
    """Return non-overlapping findings, ordered by position. ``extra``: more rules (DLP's
    custom detectors), run after the built-in ones.

    Only the first ``max_scan_chars`` characters are scanned; pass ``max_scan_chars=len(text)``
    (or ``math.inf``) to scan all of it regardless of size.
    """
    prefix = text if len(text) <= max_scan_chars else text[:max_scan_chars]
    scanned, origin = _folded(prefix)
    found: list[Finding] = []
    rules = (*((*_RULES, _EMAIL) if include_email and include_pii else _RULES), *extra)
    for rule in rules:
        if rule.category == "pii" and not include_pii:
            continue
        pos = 0
        while (m := rule.pattern.search(scanned, pos)) is not None:
            if rule.check and not rule.check(m.group(rule.group)):
                # Retry from the next start, not past the rejected span: "ref 12 <card>" would
                # otherwise hide the card inside a longer candidate that fails the check.
                pos = m.start() + 1
                continue
            start, end = m.start(rule.group), m.end(rule.group)
            if origin is not None:  # back to positions in the caller's text
                start, end = origin[start], origin[end - 1] + 1
            found.append(Finding(rule.kind, start, end, rule.category))
            pos = max(m.end(), m.start() + 1)
    found.sort(key=lambda f: (f.start, -(f.end - f.start)))
    merged: list[Finding] = []
    for f in found:
        if merged and f.start < merged[-1].end:
            previous = merged[-1]
            if f.end > previous.end:
                merged[-1] = Finding(previous.kind, previous.start, f.end, previous.category)
            continue
        merged.append(f)
    return merged


def redact_text(
    text: str, *, include_pii: bool = True, max_scan_chars: int = DEFAULT_MAX_SCAN_CHARS
) -> tuple[str, list[Finding]]:
    """Replace sensitive spans with ``[REDACTED:<kind>]``.

    Oversized fields are withheld whole because a credential can cross the scan boundary.
    """
    if len(text) > max_scan_chars:
        return "[REDACTED:scan_limit]", [Finding("scan_limit", 0, len(text), "unscanned")]
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
