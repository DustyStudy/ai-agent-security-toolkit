"""Offboarding: revoke gateway access tokens when the identity provider disables a user or
removes a user from a group, on every token store, with a durable retry ledger.

An IdP automation (Okta, Entra, Keycloak) posts one JSON document to ``agentsec token offboard``:
``{"disabled_users": ["a@x"], "removed_groups": [{"user": "b@x", "group": "admins"}]}``.
Each (event, store) pair is a ledger row that stays pending until that store's revoke succeeds,
so a store that is down is retried on the next run and cannot be silently skipped.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentsec.gateway.tokens import TokenStore

DEFAULT_DEADLINE_S = 3600.0

_SCHEMA = """
CREATE TABLE IF NOT EXISTS offboarding (
    kind TEXT NOT NULL,          -- 'user' or 'group'
    user TEXT NOT NULL,
    grp TEXT NOT NULL,           -- '' for kind 'user'
    store TEXT NOT NULL,
    first_seen REAL NOT NULL,
    done REAL,                   -- NULL while pending
    error TEXT,
    PRIMARY KEY (kind, user, grp, store)
);
"""


class OffboardError(ValueError):
    pass


@dataclass(frozen=True)
class Pending:
    kind: str
    user: str
    group: str
    store: str
    first_seen: float
    error: str | None


@dataclass(frozen=True)
class Outcome:
    revoked: int
    pending: list[Pending]
    overdue: list[Pending]


def parse_events(text: str) -> list[tuple[str, str, str]]:
    """(kind, user, group) triples from the IdP document; strict, since it is a trust boundary."""
    try:
        doc = json.loads(text)
    except ValueError as e:
        raise OffboardError(f"events are not valid JSON: {e}") from None
    if not isinstance(doc, dict) or set(doc) - {"disabled_users", "removed_groups"}:
        raise OffboardError(
            'events must be an object with "disabled_users" and/or "removed_groups"'
        )
    out: list[tuple[str, str, str]] = []
    users = doc.get("disabled_users", [])
    if not isinstance(users, list) or not all(isinstance(u, str) and u for u in users):
        raise OffboardError('"disabled_users" must be a list of non-empty strings')
    out += [("user", u, "") for u in users]
    pairs = doc.get("removed_groups", [])
    if not isinstance(pairs, list):
        raise OffboardError('"removed_groups" must be a list of {"user", "group"} objects')
    for p in pairs:
        if (
            not isinstance(p, dict)
            or set(p) != {"user", "group"}
            or not all(isinstance(v, str) and v for v in p.values())
        ):
            raise OffboardError('"removed_groups" must be a list of {"user", "group"} objects')
        out.append(("group", p["user"], p["group"]))
    return out


def run(
    ledger: str | Path,
    stores: list[str],
    events: list[tuple[str, str, str]],
    *,
    deadline_s: float = DEFAULT_DEADLINE_S,
    clock: Callable[[], float] = time.time,
    open_store: Callable[[str], TokenStore] = TokenStore,
) -> Outcome:
    """Record ``events`` for every store, then try every pending row (new and old)."""
    now = clock()
    db = sqlite3.connect(str(ledger), timeout=5.0)
    try:
        db.executescript(_SCHEMA)
        with db:
            for kind, user, group in events:
                for store in stores:
                    # A finished row reopens: the same user can be disabled a second time after
                    # being re-enabled and given new tokens. A pending row keeps its first_seen.
                    db.execute(
                        "INSERT INTO offboarding (kind, user, grp, store, first_seen) "
                        "VALUES (?, ?, ?, ?, ?) ON CONFLICT (kind, user, grp, store) DO UPDATE "
                        "SET first_seen = excluded.first_seen, done = NULL, error = NULL "
                        "WHERE done IS NOT NULL",
                        (kind, user, group, store, now),
                    )
        revoked = 0
        rows = db.execute(
            "SELECT kind, user, grp, store FROM offboarding WHERE done IS NULL"
        ).fetchall()
        for kind, user, group, store in rows:
            try:
                ts = open_store(store)
                try:
                    revoked += (
                        ts.revoke_user(user) if kind == "user" else ts.revoke_group(user, group)
                    )
                finally:
                    ts.close()
            except Exception as e:  # noqa: BLE001 - any failure leaves the row pending for retry
                err = f"{type(e).__name__}: {e}"[:200]
                with db:
                    db.execute(
                        "UPDATE offboarding SET error = ? WHERE kind=? AND user=? AND grp=? "
                        "AND store=?",
                        (err, kind, user, group, store),
                    )
            else:
                with db:
                    db.execute(
                        "UPDATE offboarding SET done = ?, error = NULL WHERE kind=? AND user=? "
                        "AND grp=? AND store=?",
                        (now, kind, user, group, store),
                    )
        pending = [
            Pending(*r)
            for r in db.execute(
                "SELECT kind, user, grp, store, first_seen, error FROM offboarding "
                "WHERE done IS NULL ORDER BY first_seen"
            )
        ]
    finally:
        db.close()
    overdue = [p for p in pending if now - p.first_seen > deadline_s]
    return Outcome(revoked, pending, overdue)


def metrics_text(out: Outcome) -> str:
    """Prometheus text format, for node_exporter's textfile collector."""
    return (
        "# TYPE agentsec_offboarding_pending gauge\n"
        f"agentsec_offboarding_pending {len(out.pending)}\n"
        "# TYPE agentsec_offboarding_overdue gauge\n"
        f"agentsec_offboarding_overdue {len(out.overdue)}\n"
    )


def audit_events(out: Outcome) -> list[dict[str, Any]]:
    return [
        {"event": "offboarding_overdue", "kind": p.kind, "user": p.user, "group": p.group,
         "store": p.store, "since": p.first_seen, "error": p.error}
        for p in out.overdue
    ]  # fmt: skip
