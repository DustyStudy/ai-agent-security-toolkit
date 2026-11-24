"""SCIM 2.0 user provisioning (RFC 7643/7644), the subset Entra ID, Okta and OneLogin use.

The IdP creates, updates, deactivates and deletes users at ``/scim/v2/Users``. The directory is
stored next to the access tokens. What it changes at the gateway:

* deactivating (``active: false``) or deleting a user ends their sessions now and refuses them
  until they are active again, whatever case their sign-in name arrives in;
* with ``scim.require_provisioned``, only users the IdP provisioned and left active get in.

Groups are not provisioned: groups come from the sign-in (token or header), as before.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
MAX_PAGE = 200
_FIELDS = ("userName", "externalId", "displayName", "active", "emails", "name")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scim_users (
    id TEXT PRIMARY KEY,
    user_name TEXT NOT NULL,
    user_key TEXT NOT NULL UNIQUE,
    active INTEGER NOT NULL,
    doc TEXT NOT NULL,
    created REAL NOT NULL,
    modified REAL NOT NULL
);
"""


class ScimError(Exception):
    def __init__(self, status: int, detail: str, scim_type: str | None = None) -> None:
        super().__init__(detail)
        self.status, self.detail, self.scim_type = status, detail, scim_type

    def body(self) -> dict[str, Any]:
        out: dict[str, Any] = {"schemas": [ERROR_SCHEMA], "status": str(self.status)}
        if self.scim_type:
            out["scimType"] = self.scim_type
        out["detail"] = self.detail
        return out


def _key(user_name: str) -> str:
    return user_name.casefold()  # SCIM userName is case-insensitive (RFC 7643 section 4.1.1)


def _bool(value: Any) -> bool:
    # Entra ID sends "True"/"False" strings in PATCH operations.
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    raise ScimError(400, "active must be a boolean", "invalidValue")


def _user_name(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ScimError(400, "userName must be a non-empty string", "invalidValue")
    if not value.isprintable() or value != value.strip():
        raise ScimError(400, "userName must be printable with no outer spaces", "invalidValue")
    return value


def _stamp(t: float) -> str:
    return datetime.fromtimestamp(t, UTC).isoformat().replace("+00:00", "Z")


class ScimDirectory:
    def __init__(self, path: str | Path, *, clock: Callable[[], float] = time.time) -> None:
        self._db = sqlite3.connect(str(path), check_same_thread=False, timeout=5.0)
        self._db.executescript(_SCHEMA)
        self._lock = threading.RLock()  # patch holds it across read, change and write
        self._clock = clock

    # ------------------------------------------------------------------ the gateway's view
    def status(self, user: str) -> bool | None:
        """True: provisioned and active. False: deactivated. None: not in the directory."""
        with self._lock:
            row = self._db.execute(
                "SELECT active FROM scim_users WHERE user_key = ?", (_key(user),)
            ).fetchone()
        return None if row is None else bool(row[0])

    # ------------------------------------------------------------------ SCIM operations
    def _resource(self, row: tuple[Any, ...], base: str) -> dict[str, Any]:
        rid, user_name, _key_, active, doc, created, modified = row
        return {
            **json.loads(doc),
            "schemas": [USER_SCHEMA],
            "id": rid,
            "userName": user_name,
            "active": bool(active),
            "meta": {
                "resourceType": "User",
                "created": _stamp(created),
                "lastModified": _stamp(modified),
                "location": f"{base}/Users/{rid}",
            },
        }

    def _row(self, rid: str) -> tuple[Any, ...]:
        row = self._db.execute("SELECT * FROM scim_users WHERE id = ?", (rid,)).fetchone()
        if row is None:
            raise ScimError(404, "no such user")
        return tuple(row)

    @staticmethod
    def _clean(data: Any) -> tuple[str, bool, dict[str, Any]]:
        if not isinstance(data, dict):
            raise ScimError(400, "body must be a JSON object", "invalidSyntax")
        user_name = _user_name(data.get("userName"))
        active = _bool(data.get("active", True))
        doc = {k: data[k] for k in _FIELDS if k in data and k not in ("userName", "active")}
        for k in ("externalId", "displayName"):
            if k in doc and not isinstance(doc[k], str):
                raise ScimError(400, f"{k} must be a string", "invalidValue")
        return user_name, active, doc

    def create(self, data: Any, base: str) -> tuple[dict[str, Any], str, bool]:
        user_name, active, doc = self._clean(data)
        now, rid = self._clock(), uuid.uuid4().hex
        with self._lock, self._db:
            try:
                self._db.execute(
                    "INSERT INTO scim_users VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (rid, user_name, _key(user_name), int(active), json.dumps(doc), now, now),
                )
            except sqlite3.IntegrityError:
                raise ScimError(409, "userName already exists", "uniqueness") from None
            return self._resource(self._row(rid), base), user_name, active

    def get(self, rid: str, base: str) -> dict[str, Any]:
        with self._lock:
            return self._resource(self._row(rid), base)

    def search(self, filter_: str | None, start: int, count: int, base: str) -> dict[str, Any]:
        where: str = ""
        args: tuple[str, ...] = ()
        if filter_:
            where, args = "WHERE user_key = ?", (_key(_parse_filter(filter_)),)
        count = max(0, min(count, MAX_PAGE))
        with self._lock:
            total = self._db.execute(f"SELECT COUNT(*) FROM scim_users {where}", args).fetchone()[0]  # noqa: S608 - fixed text
            rows = self._db.execute(
                f"SELECT * FROM scim_users {where} ORDER BY created LIMIT ? OFFSET ?",  # noqa: S608
                (*args, count, max(start, 1) - 1),
            ).fetchall()
        return {
            "schemas": [LIST_SCHEMA],
            "totalResults": total,
            "startIndex": max(start, 1),
            "itemsPerPage": len(rows),
            "Resources": [self._resource(tuple(r), base) for r in rows],
        }

    def replace(self, rid: str, data: Any, base: str) -> tuple[dict[str, Any], str, bool, str]:
        """PUT: returns (resource, userName, active, the userName before)."""
        user_name, active, doc = self._clean(data)
        return self._store(rid, user_name, active, doc, base)

    def patch(self, rid: str, data: Any, base: str) -> tuple[dict[str, Any], str, bool, str]:
        if not isinstance(data, dict) or PATCH_SCHEMA not in data.get("schemas", []):
            raise ScimError(400, "expected a PatchOp", "invalidSyntax")
        ops = data.get("Operations")
        if not isinstance(ops, list) or not ops:
            raise ScimError(400, "Operations must be a non-empty list", "invalidSyntax")
        with self._lock:
            return self._patch_locked(rid, ops, base)

    def _patch_locked(
        self, rid: str, ops: list[Any], base: str
    ) -> tuple[dict[str, Any], str, bool, str]:
        _id, user_name, _k, active, doc_text, _c, _m = self._row(rid)
        current = {**json.loads(doc_text), "userName": user_name, "active": bool(active)}
        for op in ops:
            if not isinstance(op, dict):
                raise ScimError(400, "each operation must be an object", "invalidSyntax")
            kind = str(op.get("op", "")).lower()
            path, value = op.get("path"), op.get("value")
            if kind not in ("add", "replace", "remove"):
                raise ScimError(400, f"unsupported op {kind!r}", "invalidSyntax")
            if path is None:
                if kind == "remove" or not isinstance(value, dict):
                    raise ScimError(400, "an operation without path needs an object", "noTarget")
                changes = value
            else:
                changes = {path: None if kind == "remove" else value}
            for attr, v in changes.items():
                name = next((f for f in _FIELDS if f.lower() == str(attr).lower()), None)
                if name is None:
                    raise ScimError(400, f"unsupported attribute {attr!r}", "invalidPath")
                if v is None:
                    if name in ("userName", "active"):
                        raise ScimError(400, f"{name} cannot be removed", "mutability")
                    current.pop(name, None)
                else:
                    current[name] = v
        user_name, active_now, doc = self._clean(current)
        return self._store(rid, user_name, active_now, doc, base)

    def _store(
        self, rid: str, user_name: str, active: bool, doc: dict[str, Any], base: str
    ) -> tuple[dict[str, Any], str, bool, str]:
        with self._lock, self._db:
            before = self._row(rid)[1]
            try:
                self._db.execute(
                    "UPDATE scim_users SET user_name = ?, user_key = ?, active = ?, doc = ?,"
                    " modified = ? WHERE id = ?",
                    (user_name, _key(user_name), int(active), json.dumps(doc), self._clock(), rid),
                )
            except sqlite3.IntegrityError:
                raise ScimError(409, "userName already exists", "uniqueness") from None
            return self._resource(self._row(rid), base), user_name, active, before

    def delete(self, rid: str) -> str:
        with self._lock, self._db:
            user_name = self._row(rid)[1]
            self._db.execute("DELETE FROM scim_users WHERE id = ?", (rid,))
        return str(user_name)

    def close(self) -> None:
        self._db.close()


def _parse_filter(text: str) -> str:
    """The one filter IdPs send: ``userName eq "value"``. Anything else is refused."""
    attr, _, rest = text.strip().partition(" ")
    op, _, value = rest.strip().partition(" ")
    value = value.strip()
    if attr.lower() != "username" or op.lower() != "eq" or len(value) < 2:
        raise ScimError(400, 'only the filter userName eq "..." is supported', "invalidFilter")
    if not (value[0] == value[-1] == '"'):
        raise ScimError(400, "the filter value must be quoted", "invalidFilter")
    try:
        parsed = json.loads(value)  # SCIM string literals are JSON strings
    except ValueError:
        raise ScimError(400, "the filter value is not a valid string", "invalidFilter") from None
    return _user_name(parsed)


SERVICE_PROVIDER_CONFIG = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    "patch": {"supported": True},
    "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
    "filter": {"supported": True, "maxResults": MAX_PAGE},
    "changePassword": {"supported": False},
    "sort": {"supported": False},
    "etag": {"supported": False},
    "authenticationSchemes": [
        {"type": "oauthbearertoken", "name": "Bearer token", "description": "scim.token"}
    ],
}

__all__ = ["SERVICE_PROVIDER_CONFIG", "ScimDirectory", "ScimError"]
