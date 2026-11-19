"""OIDC bearer-token identity for the gateway: verify a JWT against the IdP's JWKS.

Verification is PyJWT's (``pyjwt[crypto]``, in the ``gateway`` extra); this module only decides
which key and which rules apply. Fail closed: any doubt is a 401.
"""

from __future__ import annotations

import json
import logging
import math
import threading
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

# Asymmetric only. HS* would let anyone holding the (public) JWKS mint tokens if a key were ever
# loaded as an HMAC secret, and "none" is not a signature.
SUPPORTED_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)
MAX_TOKEN_CHARS = 8192
MAX_JWKS_BYTES = 256 * 1024
REFRESH_COOLDOWN_S = 60.0  # at most one JWKS fetch attempt a minute, for any reason
_LOG = logging.getLogger("agentsec.gateway")


class TokenRejected(Exception):
    """The reason is for the audit log only; the client always gets a plain 401."""


@dataclass(frozen=True)
class OidcSettings:
    issuer: str
    audience: str
    jwks_url: str
    algorithms: tuple[str, ...] = ("RS256", "ES256")
    user_claim: str = "sub"
    groups_claim: str = "groups"
    jwks_cache_s: float = 600.0
    leeway_s: float = 60.0


def fetch_jwks(url: str, timeout: float = 5.0) -> dict[str, Any]:
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310 - URL from config, checked https
    # A total deadline, not just a per-read socket timeout: a server dripping bytes would
    # otherwise hold the verifier's lock (and every login behind it) indefinitely.
    deadline = time.monotonic() + timeout
    buf = bytearray()
    with opener.open(req, timeout=timeout) as resp:
        while len(buf) <= MAX_JWKS_BYTES:
            if time.monotonic() > deadline:
                raise TimeoutError("JWKS fetch exceeded its deadline")
            chunk = resp.read1(65536)
            if not chunk:
                break
            buf.extend(chunk)
    data = bytes(buf)
    if len(data) > MAX_JWKS_BYTES:
        raise ValueError("JWKS document too large")
    doc = json.loads(data)
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
        raise ValueError("JWKS document has no keys list")
    return doc


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class OidcVerifier:
    """Verifies tokens and caches the IdP's signing keys.

    Keys are refreshed after half of ``jwks_cache_s``, or when a token names an unknown ``kid``.
    Fetch attempts, for either reason, are at most one a minute, so a flood of made-up kids or an
    IdP outage cannot turn logins into a stream of fetches. If the IdP is unreachable the cached
    keys stay usable until ``jwks_cache_s``, then every token is refused.
    """

    def __init__(
        self,
        settings: OidcSettings,
        *,
        fetch: Callable[[str], dict[str, Any]] = fetch_jwks,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        import jwt  # the gateway extra; imported here so the base install never needs it

        self._jwt = jwt
        self.settings = settings
        self._fetch = fetch
        self._clock = clock
        self._lock = threading.Lock()
        self._keys: dict[str, tuple[Any, Any]] = {}  # kid -> (PyJWK, the JWK's own "alg")
        self._fetched_at: float | None = None
        self._last_attempt = -math.inf

    # ------------------------------------------------------------------ keys
    def _refresh(self) -> None:
        doc = self._fetch(self.settings.jwks_url)
        keys: dict[str, tuple[Any, Any]] = {}
        for raw in doc["keys"]:
            if not isinstance(raw, dict) or raw.get("use", "sig") != "sig":
                continue
            ops = raw.get("key_ops", ["verify"])
            if not isinstance(ops, list) or "verify" not in ops:
                continue
            kid = raw.get("kid")
            if not isinstance(kid, str) or not kid:
                continue  # keyless selection is ambiguous; require a kid
            try:
                keys[kid] = (self._jwt.PyJWK(raw), raw.get("alg"))
            except self._jwt.PyJWTError:
                continue  # an unsupported key type in the set is skipped, not fatal
        self._keys, self._fetched_at = keys, self._clock()

    def _key_for(self, kid: str) -> tuple[Any, Any]:
        ttl = self.settings.jwks_cache_s
        with self._lock:
            now = self._clock()
            stale = self._fetched_at is None or now - self._fetched_at > ttl / 2
            wanted = stale or kid not in self._keys
            if wanted and now - self._last_attempt >= REFRESH_COOLDOWN_S:
                self._last_attempt = now
                try:
                    self._refresh()
                except Exception:  # noqa: BLE001 - network, JSON or shape errors: no fresh keys
                    _LOG.warning("JWKS refresh failed", exc_info=True)
            # Judged after the fetch attempt, against the clock now: a slow failed fetch must
            # not let keys past their lifetime through.
            if self._fetched_at is None or self._clock() - self._fetched_at > ttl:
                raise TokenRejected("signing keys unavailable")
            key = self._keys.get(kid)
        if key is None:
            raise TokenRejected("unknown signing key")
        return key

    # ---------------------------------------------------------------- tokens
    def verify(self, token: str) -> tuple[str, tuple[str, ...]]:
        """Return ``(user, groups)`` for a valid token, or raise :class:`TokenRejected`."""
        jwt, s = self._jwt, self.settings
        if len(token) > MAX_TOKEN_CHARS:
            raise TokenRejected("token too long")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise TokenRejected("malformed token") from None
        alg, kid = header.get("alg"), header.get("kid")
        if alg not in s.algorithms:
            raise TokenRejected(f"algorithm {alg!r} not allowed")
        if not isinstance(kid, str) or not kid:
            raise TokenRejected("token has no kid")
        key, key_alg = self._key_for(kid)
        if key_alg is not None and key_alg != alg:
            # A JWK that declares its algorithm may only verify that algorithm. (PyJWK infers
            # one from the key type when "alg" is absent, so read the JWK's own field.)
            raise TokenRejected("token algorithm does not match the key")
        try:
            claims = jwt.decode(
                token,
                key.key,
                algorithms=[alg],
                audience=s.audience,
                issuer=s.issuer,
                leeway=s.leeway_s,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except Exception as e:  # noqa: BLE001 - PyJWTError, and TypeError for a key/alg mismatch
            raise TokenRejected(f"invalid token: {type(e).__name__}") from None
        user = claims.get(s.user_claim)
        if (
            not isinstance(user, str)
            or not user
            or user != user.strip()
            or not user.isprintable()
            or len(user) > 256
        ):
            raise TokenRejected(f"claim {s.user_claim!r} is missing or not a usable string")
        raw_groups = claims.get(s.groups_claim, [])
        if not isinstance(raw_groups, list) or not all(isinstance(g, str) for g in raw_groups):
            raise TokenRejected(f"claim {s.groups_claim!r} must be a list of strings")
        return user, tuple(g for g in raw_groups if g)
