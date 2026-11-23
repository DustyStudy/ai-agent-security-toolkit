"""Signed blocklist feeds for the gateway's egress check (docs/design/EGRESS_BLOCKLIST.md).

The gateway only reads feed files. An operator job downloads each feed, signs it with
``agentsec egress sign-feed`` (a feed key, never the policy bundle key) and renames the file
and its ``.sig`` into place. ``FILE.sig`` is JSON::

    {"format": "agentsec-feed-v1", "name": "...", "sha256": "...", "issued_at": 1700000000,
     "signature": "<base64 Ed25519 over the other four fields>"}

Feed age is taken from the signed ``issued_at``, never from the file's mtime, and a feed older
than the one already loaded is refused (rollback).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentsec.sandbox.blocklist import Blocklist, Feed, parse_feed

FORMAT = "agentsec-feed-v1"
MAX_FEED_BYTES = 64 * 1024 * 1024
MAX_SIG_BYTES = 4096
CLOCK_SKEW_S = 300  # an issued_at further in the future than this is refused
STALE_LOG_INTERVAL_S = 3600


class FeedError(ValueError):
    pass


@dataclass(frozen=True)
class FeedConfig:
    name: str
    kind: str  # ip | domain
    file: str
    max_age_s: float = 48 * 3600


@dataclass(frozen=True)
class EgressSettings:
    feeds: tuple[FeedConfig, ...]
    public_key: Any  # Ed25519PublicKey
    except_hosts: tuple[str, ...] = ()
    on_stale: str = "warn"  # warn | deny
    check_model_links: bool = True
    state_file: str | None = (
        None  # highest accepted issued_at per list, so restarts cannot roll back
    )
    reload_interval_s: float = 10.0


def _payload(name: str, sha256: str, issued_at: int) -> bytes:
    doc = {"format": FORMAT, "name": name, "sha256": sha256, "issued_at": issued_at}
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def _read(path: Path, limit: int) -> bytes:
    try:
        with path.open("rb") as fh:
            data = fh.read(limit + 1)  # bounded: whoever writes the folder cannot exhaust memory
    except OSError as e:
        raise FeedError(f"cannot read {path.name}: {type(e).__name__}") from None
    if len(data) > limit:
        raise FeedError(f"{path.name} is over {limit} bytes")
    return data


def sign_feed(
    path: str | Path, private_key_pem: bytes, name: str, issued_at: int | None = None
) -> Path:
    """Write ``path.sig``. Run it where the feed key lives, never on the gateway host."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    key = load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise FeedError("the feed signing key must be an Ed25519 private key")
    path = Path(path)
    sha = hashlib.sha256(_read(path, MAX_FEED_BYTES)).hexdigest()
    issued = int(time.time()) if issued_at is None else issued_at
    sig = {
        "format": FORMAT,
        "name": name,
        "sha256": sha,
        "issued_at": issued,
        "signature": base64.b64encode(key.sign(_payload(name, sha, issued))).decode(),
    }
    out = path.with_name(path.name + ".sig")
    out.write_text(json.dumps(sig, sort_keys=True) + "\n", encoding="utf-8")
    return out


def verify_feed(path: str | Path, name: str, public_key: Any, now: float) -> tuple[bytes, int]:
    """The feed bytes and signed ``issued_at``, after checking signature, name and hash."""
    from cryptography.exceptions import InvalidSignature

    path = Path(path)
    sig_path = path.with_name(path.name + ".sig")
    try:
        sig = json.loads(_read(sig_path, MAX_SIG_BYTES))
        signed_name, sha, issued = sig["name"], sig["sha256"], sig["issued_at"]
        signature = base64.b64decode(sig["signature"], validate=True)
    except FeedError:
        raise FeedError(f"feed {name!r}: signature file {sig_path.name} is missing") from None
    except (ValueError, KeyError, TypeError):
        raise FeedError(f"feed {name!r}: signature file {sig_path.name} is malformed") from None
    if (
        sig.get("format") != FORMAT
        or not isinstance(signed_name, str)
        or not isinstance(sha, str)
        or not isinstance(issued, int)
        or isinstance(issued, bool)
    ):
        raise FeedError(f"feed {name!r}: signature file {sig_path.name} is malformed")
    try:
        public_key.verify(signature, _payload(signed_name, sha, issued))
    except InvalidSignature:
        raise FeedError(f"feed {name!r}: signature does not verify") from None
    # Checked after the signature, so these messages never describe forged contents.
    if signed_name != name:
        raise FeedError(f"feed {name!r}: signed for list {signed_name!r}")
    if issued > now + CLOCK_SKEW_S:
        raise FeedError(f"feed {name!r}: issued_at is in the future")
    data = _read(path, MAX_FEED_BYTES)
    if hashlib.sha256(data).hexdigest() != sha:
        raise FeedError(f"feed {name!r}: file does not match its signed hash")
    return data, issued


def _stat(path: Path) -> tuple[Any, ...]:
    out: list[Any] = []
    for p in (path, path.with_name(path.name + ".sig")):
        try:
            st = p.stat()
            out.append((st.st_mtime_ns, st.st_size, st.st_ino))
        except OSError:
            out.append(None)
    return tuple(out)


def read_state(path: str | None) -> dict[str, int]:
    if path is None:
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        raise FeedError(f"egress state file is unreadable: {type(e).__name__}") from None
    if not isinstance(data, dict) or not all(
        isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool)
        for k, v in data.items()
    ):
        raise FeedError("egress state file is malformed")
    return data


def write_state(path: str, state: dict[str, int]) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


class FeedSet:
    """Loads the configured feeds and keeps the current :class:`Blocklist`.

    ``current`` is swapped as one reference, so a request keeps the list it started with.
    ``refresh()`` returns audit events (name, fields) for the caller to log.
    """

    def __init__(
        self,
        settings: EgressSettings,
        *,
        wall_clock: Callable[[], float] = time.time,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self._wall = wall_clock
        self._clock = clock
        self._lock = threading.Lock()
        self._seen: dict[str, tuple[Any, ...]] = {}
        self._feeds: dict[str, Feed] = {}
        self._last_error: dict[str, str] = {}
        self._stale_logged: dict[str, float] = {}
        self._next = clock() + settings.reload_interval_s
        self._state = read_state(settings.state_file)
        now = wall_clock()
        for fc in settings.feeds:  # startup: any failure refuses to start
            self._seen[fc.name] = _stat(Path(fc.file))
            self._feeds[fc.name] = self._load(fc, now)
        self._save_state()
        self.current = self._build()

    def _load(self, fc: FeedConfig, now: float) -> Feed:
        data, issued = verify_feed(fc.file, fc.name, self.settings.public_key, now)
        floor = self._state.get(fc.name)
        loaded = self._feeds.get(fc.name)
        if loaded is not None and loaded.issued_at is not None:
            floor = max(floor or 0, int(loaded.issued_at))
        if floor is not None and issued < floor:
            raise FeedError(
                f"feed {fc.name!r}: issued_at {issued} is older than {floor} (rollback refused)"
            )
        try:
            feed = parse_feed(
                data, fc.kind, fc.name, issued_at=float(issued), max_age_s=fc.max_age_s,
                on_stale=self.settings.on_stale,
            )  # fmt: skip
        except ValueError as e:
            raise FeedError(str(e)) from None
        self._state[fc.name] = max(issued, self._state.get(fc.name, 0))
        return feed

    def _save_state(self) -> None:
        if self.settings.state_file is not None:
            write_state(self.settings.state_file, self._state)

    def _build(self) -> Blocklist:
        return Blocklist(
            [self._feeds[fc.name] for fc in self.settings.feeds],
            except_hosts=self.settings.except_hosts,
            clock=self._wall,
        )

    def loaded_events(self) -> list[tuple[str, dict[str, Any]]]:
        return [("gateway_blocklist_loaded", _describe(f)) for f in self.current.feeds]

    def stale(self) -> list[str]:
        now = self._wall()
        return [f.name for f in self.current.feeds if f.stale(now)]

    def status(self) -> list[dict[str, Any]]:
        now = self._wall()
        return [
            {"list": f.name, "kind": f.kind, "entries": f.entries, "age_s": f.age(now) or 0.0,
             "stale": f.stale(now), "on_stale": f.on_stale}
            for f in self.current.feeds
        ]  # fmt: skip

    def ages(self) -> dict[str, float]:
        now = self._wall()
        return {f.name: f.age(now) or 0.0 for f in self.current.feeds}

    def refresh(self, force: bool = False) -> list[tuple[str, dict[str, Any]]]:
        """Re-read changed feeds (when due). Never raises: a bad feed keeps the last good one."""
        now_m = self._clock()
        if (not force and now_m < self._next) or not self._lock.acquire(blocking=False):
            return []
        events: list[tuple[str, dict[str, Any]]] = []
        try:
            self._next = now_m + self.settings.reload_interval_s
            now = self._wall()
            changed = False
            for fc in self.settings.feeds:
                seen = _stat(Path(fc.file))
                if seen == self._seen.get(fc.name):
                    continue
                try:
                    feed = self._load(fc, now)
                    self._save_state()  # before enforcing, as for bundles
                except Exception as e:  # noqa: BLE001 - any failure keeps the last good list
                    # Retried every interval (a half-swapped pair settles), logged once per error.
                    if str(e) != self._last_error.get(fc.name):
                        self._last_error[fc.name] = str(e)
                        events.append(
                            ("gateway_blocklist_reload_failed", {"list": fc.name, "reason": str(e)})
                        )
                    continue
                self._seen[fc.name] = seen
                self._last_error.pop(fc.name, None)
                self._feeds[fc.name] = feed
                changed = True
                events.append(("gateway_blocklist_loaded", _describe(feed)))
            if changed:
                self.current = self._build()
            for f in self.current.feeds:
                age = f.age(now)
                if (
                    f.stale(now)
                    and now - self._stale_logged.get(f.name, -1e18) >= STALE_LOG_INTERVAL_S
                ):
                    self._stale_logged[f.name] = now
                    events.append(
                        ("gateway_blocklist_stale",
                         {"list": f.name, "age_s": int(age or 0), "on_stale": f.on_stale})
                    )  # fmt: skip
        finally:
            self._lock.release()
        return events


def _describe(f: Feed) -> dict[str, Any]:
    return {
        "list": f.name,
        "kind": f.kind,
        "entries": f.entries,
        "list_sha256": f.sha256,
        "issued_at": int(f.issued_at or 0),
    }
