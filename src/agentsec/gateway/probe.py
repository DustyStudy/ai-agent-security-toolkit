"""Check that upstreams refuse direct connections: run it from a client, not the gateway host."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

from agentsec.gateway.config import GatewayConfig, _is_loopback


def _is_unspecified(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_unspecified  # 0.0.0.0, ::
    except ValueError:
        return False


def probe_isolation(
    config: GatewayConfig, timeout: float = 3.0, gateway_host: str | None = None
) -> list[dict[str, str | int]]:
    """One row per upstream; ``status`` is ``reachable`` (a finding), ``isolated`` or ``unchecked``.

    Only a TCP connect to the host and port of each URL: no request is sent, and the secret
    references (``api_key_ref``, ``auth_ref``) are never read.
    """
    targets = [("model", u.name, u.url) for u in config.upstreams.values()]
    targets += [("mcp", m.name, m.url) for m in config.mcp_upstreams.values()]
    seen: dict[tuple[str, int], tuple[str, str]] = {}  # many models share one server
    rows: list[dict[str, str | int]] = []
    for kind, name, url in targets:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if _is_loopback(host) or _is_unspecified(host):
            # Loopback here is this machine, not the gateway host: probing it proves nothing.
            if gateway_host is None:
                rows.append(
                    {"kind": kind, "name": name, "host": host, "port": port, "status": "unchecked",
                     "detail": "loopback URL: pass --gateway-host to probe this port there"}
                )  # fmt: skip
                continue
            host = gateway_host
        if (host, port) not in seen:
            # shortcut: one connect at a time, so N dead hosts take N * timeout; thread it if slow.
            try:
                socket.create_connection((host, port), timeout=timeout).close()
                seen[host, port] = ("reachable", "TCP connect succeeded: not isolated")
            except OSError as e:
                seen[host, port] = ("isolated", str(e) or type(e).__name__)
        status, detail = seen[host, port]
        rows.append(
            {"kind": kind, "name": name, "host": host, "port": port, "status": status,
             "detail": detail}
        )  # fmt: skip
    return rows
