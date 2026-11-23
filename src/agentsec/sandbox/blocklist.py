"""Deny lists of known-bad IP networks and domains for URL arguments (docs/design/EGRESS_BLOCKLIST.md).

Parsing and matching only. Fetching, signing and refreshing feeds belong to the caller (the
gateway does it in ``agentsec.gateway.feeds``); this module never touches the network.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
KINDS = ("ip", "domain")
_DOMAIN = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*")
_COMMENT = re.compile(r"\s[;#]")


@dataclass(frozen=True)
class Feed:
    """One parsed list. ``issued_at`` (UNIX seconds) is when the feed was signed, if known."""

    name: str
    kind: str  # ip | domain
    domains: frozenset[str] = frozenset()
    # (ip version, prefix length) -> network addresses as integers shifted to the prefix
    networks: dict[tuple[int, int], frozenset[int]] = field(default_factory=dict)
    entries: int = 0
    sha256: str = ""
    issued_at: float | None = None
    max_age_s: float | None = None
    on_stale: str = "warn"  # warn | deny

    def age(self, now: float) -> float | None:
        return None if self.issued_at is None else max(0.0, now - self.issued_at)

    def stale(self, now: float) -> bool:
        age = self.age(now)
        return age is not None and self.max_age_s is not None and age > self.max_age_s


def parse_feed(data: bytes, kind: str, name: str, **meta: Any) -> Feed:
    """Parse a feed file. Any malformed line rejects the whole file (ValueError)."""
    if kind not in KINDS:
        raise ValueError(f"feed {name!r}: kind must be 'ip' or 'domain'")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(f"feed {name!r} is not UTF-8") from None
    domains: set[str] = set()
    nets: dict[tuple[int, int], set[int]] = {}
    count = 0
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = _COMMENT.split(raw, maxsplit=1)[0].strip()
        if not line or line[0] in "#;":
            continue
        where = f"feed {name!r} line {lineno}"
        if kind == "ip":
            try:
                net = ipaddress.ip_network(line, strict=True)
            except ValueError:
                raise ValueError(f"{where}: not an IP address or network: {line[:80]!r}") from None
            shift = net.max_prefixlen - net.prefixlen
            nets.setdefault((net.version, net.prefixlen), set()).add(
                int(net.network_address) >> shift
            )
        else:
            host = line.split()[-1]  # a hosts-file line "0.0.0.0 evil.example" names the last field
            host = host.lower().removesuffix(".")
            if not host.isascii() or not _DOMAIN.fullmatch(host):
                raise ValueError(f"{where}: not an ASCII domain name: {host[:80]!r}")
            domains.add(host)
        count += 1
    return Feed(
        name=name,
        kind=kind,
        domains=frozenset(domains),
        networks={k: frozenset(v) for k, v in nets.items()},
        entries=count,
        sha256=meta.pop("sha256", None) or hashlib.sha256(data).hexdigest(),
        **meta,
    )


@dataclass(frozen=True)
class Hit:
    feed: Feed
    matched: str  # domain | ip
    value: str  # what was looked up
    entry: str  # the feed entry that matched


class Blocklist:
    """Immutable set of feeds. Swap the whole object to refresh; never mutate one in use."""

    def __init__(
        self,
        feeds: Sequence[Feed],
        *,
        except_hosts: Iterable[str] = (),
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.feeds = tuple(feeds)
        self.except_hosts = tuple(h.lower() for h in except_hosts)
        self.clock = clock
        self.needs_dns = any(f.kind == "ip" for f in self.feeds)

    @classmethod
    def from_entries(
        cls, *, domains: Iterable[str] = (), networks: Iterable[str] = (), name: str = "inline"
    ) -> Blocklist:
        """For library users and tests: lists built in code, never stale."""
        feeds = []
        if domains:
            feeds.append(parse_feed("\n".join(domains).encode(), "domain", f"{name}-domains"))
        if networks:
            feeds.append(parse_feed("\n".join(networks).encode(), "ip", f"{name}-ips"))
        return cls(feeds)

    def excepted(self, host: str) -> bool:
        from agentsec.sandbox.validators import _host_matches

        return bool(self.except_hosts) and _host_matches(host, self.except_hosts)

    def match_domain(self, host: str) -> list[Hit]:
        """``host`` must be normalised (lowercase, ASCII, no trailing dot)."""
        labels = host.split(".")
        suffixes = [".".join(labels[i:]) for i in range(len(labels))]
        for f in self.feeds:
            for s in suffixes:
                if f.kind == "domain" and s in f.domains:
                    return [Hit(f, "domain", host, s)]
        return []

    def match_ip(self, ip: IPAddress) -> list[Hit]:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        value = int(ip)
        for f in self.feeds:
            if f.kind != "ip":
                continue
            for (version, plen), nets in f.networks.items():
                if version != ip.version:
                    continue
                shift = ip.max_prefixlen - plen
                if value >> shift in nets:
                    cls = ipaddress.IPv4Network if version == 4 else ipaddress.IPv6Network
                    entry = cls(((value >> shift) << shift, plen))
                    return [Hit(f, "ip", str(ip), str(entry))]
        return []

    def stale_errors(self) -> list[str]:
        """Reasons to deny every URL: feeds past ``max_age_s`` whose ``on_stale`` is ``deny``."""
        now = self.clock()
        return [
            f"blocklist {f.name!r} is stale"
            for f in self.feeds
            if f.on_stale == "deny" and f.stale(now)
        ]

    def record(self, hit: Hit, host: str, resolved: Sequence[str] | None) -> dict[str, Any]:
        """Audit fields for one hit (no URL: the caller adds ``url_sha256``)."""
        age = hit.feed.age(self.clock())
        return {
            "host": host,
            "matched": hit.matched,
            "match_value": hit.value,
            "entry": hit.entry,
            "list": hit.feed.name,
            "list_sha256": hit.feed.sha256,
            "list_age_s": None if age is None else int(age),
            "resolved": list(resolved) if resolved is not None else None,
        }


def reason(hit: Hit, host: str) -> str:
    return f"host {host!r} is on blocklist {hit.feed.name!r} (matched {hit.entry!r})"
