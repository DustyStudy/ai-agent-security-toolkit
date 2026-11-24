"""Which accounts may use the gateway: approved email domains, and no personal mailboxes.

A user name is the identity the proxy or the OIDC ``user_claim`` gave. With either rule on, it
must be an email address: ``local@domain`` with exactly one ``@``, ASCII domain only (an IDN
look-alike such as ``corp.exаmple`` with a Cyrillic ``а`` is refused rather than compared).
"""

from __future__ import annotations

import re

# Consumer mail providers. An account there is a person's own, not one the company manages.
PERSONAL_DOMAINS = frozenset(
    {
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
        "yahoo.com", "ymail.com", "rocketmail.com", "aol.com", "icloud.com", "me.com", "mac.com",
        "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net", "gmx.de", "web.de",
        "mail.com", "zoho.com", "yandex.com", "yandex.ru", "mail.ru", "qq.com", "163.com",
        "126.com", "fastmail.com", "tutanota.com", "tuta.io", "hey.com", "hotmail.co.uk",
        "yahoo.co.uk", "outlook.de", "hotmail.de", "hotmail.fr", "yahoo.fr", "orange.fr",
        "free.fr", "libero.it", "naver.com", "daum.net", "rediffmail.com",
    }
)  # fmt: skip
_DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")


def _domain(user: str) -> str | None:
    if user.count("@") != 1:
        return None  # "a@evil@corp": systems disagree on which part is the domain
    local, _, domain = user.partition("@")
    domain = domain.lower().rstrip(".")
    if not local or not domain.isascii() or not _DOMAIN.fullmatch(domain):
        return None
    return domain


def _matches(domain: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        return domain.endswith(pattern[1:])
    return domain == pattern


def account_refusal(
    user: str, allowed_domains: tuple[str, ...], block_personal: bool
) -> str | None:
    """Why ``user`` may not use the gateway, or None. Domains are already lowercase."""
    if not allowed_domains and not block_personal:
        return None
    domain = _domain(user)
    if domain is None:
        return "not an email address"
    if block_personal and domain in PERSONAL_DOMAINS:
        return "personal email domain"
    if allowed_domains and not any(_matches(domain, p) for p in allowed_domains):
        return "email domain not approved"
    return None
