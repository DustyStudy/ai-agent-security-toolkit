"""Gateway access tokens: for clients that only take a fixed header (IDE MCP configs).

A token is issued to a user who signed in through SSO (``POST /tokens``) and stands in for
that sign-in until it expires or is revoked. Only a SHA-256 hash is stored: a token is 256
random bits, so the hash cannot be reversed and a slow password hash would add nothing.
The user's groups are recorded at issue time, which is one reason lifetimes are short.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PREFIX = "agt_"
ID_PREFIX = "tok_"
_TOKEN_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
TOUCH_INTERVAL_S = 60.0  # last_used is written at most this often per token
PRUNE_AFTER_S = 7 * 86400.0  # expired and revoked rows are deleted this long afterwards

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens (
    id TEXT PRIMARY KEY,
    user TEXT NOT NULL,
    groups TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created REAL NOT NULL,
    expires REAL NOT NULL,
    revoked REAL,
    last_used REAL
);
CREATE INDEX IF NOT EXISTS tokens_user ON tokens (user);
"""


class TokenError(ValueError):
    pass


@dataclass(frozen=True)
class TokenSettings:
    store: str
    default_ttl_s: float = 7 * 86400.0
    max_ttl_s: float = 30 * 86400.0
    max_per_user: int = 20


@dataclass(frozen=True)
class TokenInfo:
    id: str
    user: str
    groups: tuple[str, ...]
    name: str
    created: float
    expires: float
    revoked: float | None
    last_used: float | None

    def public(self) -> dict[str, Any]:
        """What a listing shows: never the hash."""
        return {
            "id": self.id,
            "name": self.name,
            "created": self.created,
            "expires": self.expires,
            "revoked": self.revoked,
            "last_used": self.last_used,
        }


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def looks_like_token(value: str) -> bool:
    return value.startswith(PREFIX)


class TokenStore:
    def __init__(self, path: str | Path, *, clock: Callable[[], float] = time.time) -> None:
        path = Path(path)
        if not path.exists():
            # Created owner-only before SQLite opens it (POSIX; Windows uses the folder's ACL).
            fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        self._db = sqlite3.connect(str(path), check_same_thread=False, timeout=5.0)
        self._db.executescript(_SCHEMA)
        self._lock = threading.Lock()
        self._clock = clock

    # ---------------------------------------------------------------- issue/revoke
    def issue(
        self, user: str, groups: tuple[str, ...], name: str, ttl_s: float, max_per_user: int
    ) -> tuple[TokenInfo, str]:
        """A new token for ``user``; the plain token is returned once and never stored."""
        now = self._clock()
        token = PREFIX + secrets.token_urlsafe(32)
        info = TokenInfo(
            # The prefix keeps an id that happens to be 16 digits from reading as a payment
            # card number, which the audit log would redact (about one id in 18,000).
            id=ID_PREFIX + secrets.token_hex(8),
            user=user,
            groups=groups,
            name=name,
            created=now,
            expires=now + ttl_s,
            revoked=None,
            last_used=None,
        )
        with self._lock:
            # One write-locked transaction for count and insert: the lock above covers one
            # process, this covers every process sharing the file (a second gateway, the CLI).
            self._db.execute("BEGIN IMMEDIATE")
            try:
                # Without this, issue-and-revoke in a loop grows the table and every listing.
                self._db.execute(
                    "DELETE FROM tokens WHERE MIN(expires, COALESCE(revoked, expires)) < ?",
                    (now - PRUNE_AFTER_S,),
                )
                live = self._db.execute(
                    "SELECT COUNT(*) FROM tokens WHERE user = ? AND revoked IS NULL "
                    "AND expires > ?",
                    (user, now),
                ).fetchone()[0]
                if live >= max_per_user:
                    raise TokenError(f"at most {max_per_user} live tokens per user; revoke one")
                self._db.execute(
                    "INSERT INTO tokens (id, user, groups, hash, name, created, expires) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (info.id, user, json.dumps(list(groups)), _hash(token), name, now,
                     info.expires),
                )  # fmt: skip
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")
        return info, token

    def revoke(self, token_id: str, *, user: str | None = None) -> bool:
        """Revoke one token; with ``user``, only if it is theirs. False if nothing changed."""
        now = self._clock()
        with self._lock, self._db:
            if user is None:
                cur = self._db.execute(
                    "UPDATE tokens SET revoked = ? WHERE id = ? AND revoked IS NULL",
                    (now, token_id),
                )
            else:
                cur = self._db.execute(
                    "UPDATE tokens SET revoked = ? WHERE id = ? AND user = ? AND revoked IS NULL",
                    (now, token_id, user),
                )
            return cur.rowcount > 0

    def revoke_user(self, user: str) -> int:
        with self._lock, self._db:
            return self._db.execute(
                "UPDATE tokens SET revoked = ? WHERE user = ? AND revoked IS NULL",
                (self._clock(), user),
            ).rowcount

    # ---------------------------------------------------------------- lookups
    def verify(self, token: str) -> TokenInfo:
        """The live token behind ``token``. Raises TokenError (reason for the audit log)."""
        body = token[len(PREFIX) :]
        if not looks_like_token(token) or not 40 <= len(body) <= 64 or set(body) - _TOKEN_CHARS:
            raise TokenError("malformed token")
        now = self._clock()
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM tokens WHERE hash = ?", (_hash(token),)
            ).fetchone()
            if row is None:
                raise TokenError("unknown token")
            info = _info(row)
            if info.revoked is not None:
                raise TokenError(f"token {info.id} is revoked")
            if info.expires <= now:
                raise TokenError(f"token {info.id} has expired")
            if info.last_used is None or now - info.last_used > TOUCH_INTERVAL_S:
                with self._db:
                    self._db.execute("UPDATE tokens SET last_used = ? WHERE id = ?", (now, info.id))
        return info

    def list(self, *, user: str | None = None) -> list[TokenInfo]:
        with self._lock:
            if user is None:
                rows = self._db.execute("SELECT * FROM tokens ORDER BY created").fetchall()
            else:
                rows = self._db.execute(
                    "SELECT * FROM tokens WHERE user = ? ORDER BY created", (user,)
                ).fetchall()
        return [_info(r) for r in rows]

    def close(self) -> None:
        self._db.close()


def _info(row: tuple[Any, ...]) -> TokenInfo:
    token_id, user, groups, _hash_, name, created, expires, revoked, last_used = row
    return TokenInfo(
        id=token_id,
        user=user,
        groups=tuple(json.loads(groups)),
        name=name,
        created=created,
        expires=expires,
        revoked=revoked,
        last_used=last_used,
    )
