"""Offboarding: revoke gateway access tokens when the identity provider disables a user or
removes a user from a group, on every token store, with a durable retry ledger.

An IdP automation (Okta, Entra, Keycloak) posts one JSON document to ``agentsec token offboard``:
``{"disabled_users": ["a@x"], "removed_groups": [{"user": "b@x", "group": "admins"}]}``.
Each (event, store) pair is a ledger row that stays pending until that store's revoke succeeds,
so a store that is down is retried on the next run and cannot be silently skipped. A disabled
user is also recorded in each store, so no new token can be minted for them afterwards.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass, field
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
CREATE TABLE IF NOT EXISTS inbox (   -- events not yet turned into rows for every store
    kind TEXT NOT NULL,
    user TEXT NOT NULL,
    grp TEXT NOT NULL,
    first_seen REAL NOT NULL,
    PRIMARY KEY (kind, user, grp)
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
    # Per (kind, user, group) with a row finished in this run: tokens revoked by this run.
    counts: dict[tuple[str, str, str], int] = field(default_factory=dict)
    # Events whose every row finished in this run with no token revoked: likely a wrong name.
    unmatched: list[tuple[str, str, str]] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)  # stores whose file does not exist here


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


def _open_existing(path: str) -> TokenStore:
    return TokenStore(path, create=False)


def record(
    ledger: str | Path,
    events: list[tuple[str, str, str]],
    *,
    clock: Callable[[], float] = time.time,
) -> None:
    """Make ``events`` durable. Needs no store and no config, so it runs before either is read."""
    now = clock()
    with closing(sqlite3.connect(str(ledger), timeout=5.0)) as db:
        db.executescript(_SCHEMA)
        with db:
            for ev in events:
                # An event already waiting keeps its first_seen: the deadline runs from then.
                db.execute("INSERT OR IGNORE INTO inbox VALUES (?, ?, ?, ?)", (*ev, now))
                # A finished row reopens: the same user can be disabled a second time after
                # being re-enabled and given new tokens. A pending row keeps its first_seen.
                db.execute(
                    "UPDATE offboarding SET first_seen = ?, done = NULL, error = NULL "
                    "WHERE kind = ? AND user = ? AND grp = ? AND done IS NOT NULL",
                    (now, *ev),
                )


def run(
    ledger: str | Path,
    stores: list[str],
    events: list[tuple[str, str, str]],
    *,
    deadline_s: float = DEFAULT_DEADLINE_S,
    clock: Callable[[], float] = time.time,
    open_store: Callable[[str], TokenStore] = _open_existing,
    unread: Mapping[str, str] | None = None,
) -> Outcome:
    """Record ``events`` for every store, then try every pending row (new and old).

    ``unread`` maps a gateway config that could not be read to the error: its store is unknown,
    so the events wait in the inbox, and count as pending, until a run reads every config.
    """
    now = clock()
    unread = unread or {}
    record(ledger, events, clock=clock)
    db = sqlite3.connect(str(ledger), timeout=5.0)
    try:
        with db:
            waiting = db.execute("SELECT kind, user, grp, first_seen FROM inbox").fetchall()
            for kind, user, group, seen in waiting:
                for store in stores:
                    db.execute(
                        "INSERT INTO offboarding (kind, user, grp, store, first_seen) "
                        "VALUES (?, ?, ?, ?, ?) ON CONFLICT (kind, user, grp, store) DO NOTHING",
                        (kind, user, group, store, seen),
                    )
            if not unread:
                db.execute("DELETE FROM inbox")
                waiting = []
        revoked = 0
        counts: dict[tuple[str, str, str], int] = {}
        finished: dict[tuple[str, str, str], int] = {}
        missing: set[str] = set()
        rows = db.execute(
            "SELECT kind, user, grp, store FROM offboarding WHERE done IS NULL"
        ).fetchall()
        for kind, user, group, store in rows:
            try:
                ts = open_store(store)
                try:
                    # Disabling also blocks new tokens, so a user with none yet is still covered.
                    n = ts.disable_user(user) if kind == "user" else ts.revoke_group(user, group)
                finally:
                    ts.close()
                revoked += n
                counts[kind, user, group] = counts.get((kind, user, group), 0) + n
                finished[kind, user, group] = finished.get((kind, user, group), 0) + 1
            except Exception as e:  # noqa: BLE001 - any failure leaves the row pending for retry
                if isinstance(e, FileNotFoundError):
                    missing.add(store)
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
        pending += [
            Pending(kind, user, group, config, seen, error)
            for kind, user, group, seen in waiting
            for config, error in unread.items()
        ]
        # Only when all of the event's rows finished in this run: an earlier run may have
        # revoked its tokens on another store, and that count is not kept.
        unmatched = [
            ev
            for ev, n in counts.items()
            if n == 0
            and ev not in {(k, u, g) for k, u, g, _ in waiting}
            and finished[ev]
            == db.execute(
                "SELECT COUNT(*) FROM offboarding WHERE kind = ? AND user = ? AND grp = ?", ev
            ).fetchone()[0]
        ]
    finally:
        db.close()
    overdue = [p for p in pending if now - p.first_seen > deadline_s]
    return Outcome(revoked, pending, overdue, counts, unmatched, sorted(missing))


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
