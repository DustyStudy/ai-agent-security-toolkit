"""Argument validation primitives: paths, URLs (SSRF), and scalar constraints."""

from __future__ import annotations

import ipaddress
import math
import os
import re
import socket
from collections.abc import Callable, Sequence
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from agentsec.sandbox.policy import ArgRule

Resolver = Callable[[str], list[str]]


def _default_resolver(host: str) -> list[str]:
    return sorted({str(info[4][0]) for info in socket.getaddrinfo(host, None)})


# --------------------------------------------------------------------------- paths
def path_within_roots(value: str, roots: Sequence[str]) -> tuple[bool, str]:
    """Resolve ``value`` (following symlinks) and require it to live under a root.

    Relative paths are interpreted relative to the first root. Returns
    ``(ok, resolved_path)``.
    """
    if not roots:
        return False, value
    if "\x00" in value:
        return False, value
    base = os.path.realpath(roots[0])
    candidate = value if os.path.isabs(value) else os.path.join(base, value)
    resolved = os.path.realpath(candidate)
    for root in roots:
        real_root = os.path.realpath(root)
        try:
            common = os.path.commonpath([os.path.normcase(resolved), os.path.normcase(real_root)])
        except ValueError:  # different drives on Windows
            continue
        if common == os.path.normcase(real_root):
            return True, resolved
    return False, resolved


# --------------------------------------------------------------------------- urls
def _host_matches(host: str, patterns: Sequence[str]) -> bool:
    host = host.lower().rstrip(".")
    for pattern in patterns:
        p = pattern.lower()
        if p.startswith("*."):
            if host.endswith(p[1:]) and host != p[2:]:
                return True
        elif host == p:
            return True
    return False


def _is_nonpublic(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local  # includes 169.254.169.254 cloud metadata
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _ascii_host(host: str) -> str | None:
    """The host as a normalising fetcher would see it, or None if it is not a valid name.

    URL libraries fold Unicode look-alikes (fullwidth digits, etc.) to ASCII via IDNA and
    ignore a trailing dot, so a fullwidth "127.0.0.1" and ``https://127.0.0.1./`` both reach
    loopback. Checking the raw string would let both through; check this form instead.
    """
    host = host.strip()
    try:
        ascii_form = host if host.isascii() else host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return ascii_form.rstrip(".").lower()


def _parse_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    # Legacy forms like 2130706433, 0x7f000001, 0177.0.0.1 that URL fetchers accept.
    if re.fullmatch(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}", host, re.IGNORECASE):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            return None
    return None


def check_url(value: str, rule: ArgRule, resolver: Resolver | None = None) -> list[str]:
    errors: list[str] = []
    try:
        parts = urlsplit(value)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        return ["not a valid URL"]
    if parts.scheme.lower() not in {s.lower() for s in rule.schemes}:
        errors.append(f"scheme {parts.scheme!r} not allowed")
    if parts.username is not None or parts.password is not None:
        errors.append("credentials in URL are not allowed")
    if not host:
        errors.append("URL has no host")
        return errors
    ascii_host = _ascii_host(host)
    if ascii_host is None:
        errors.append(f"host {host!r} is not a valid hostname")
        return errors
    if rule.hosts and not _host_matches(ascii_host, rule.hosts):
        errors.append(f"host {host!r} not in allowlist")
    literal = _parse_ip_literal(ascii_host)
    if rule.block_private:
        if literal is not None:
            if _is_nonpublic(literal):
                errors.append(f"host {host!r} is a non-public address")
        elif rule.resolve_dns:
            try:
                addrs = (resolver or _default_resolver)(ascii_host)
            except OSError:
                errors.append(f"host {host!r} did not resolve")
                addrs = []
            for addr in addrs:
                ip = _parse_ip_literal(addr)
                if ip is not None and _is_nonpublic(ip):
                    errors.append(f"host {host!r} resolves to non-public address {addr}")
                    break
    return errors


# --------------------------------------------------------------------------- args
def check_arg(value: Any, rule: ArgRule, *, resolver: Resolver | None = None) -> list[str]:
    """Return a list of human-readable violations (empty means the value is acceptable)."""
    errors: list[str] = []
    t = rule.type

    if t == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
        return ["expected integer"]
    if t == "number" and (not isinstance(value, int | float) or isinstance(value, bool)):
        return ["expected number"]
    if t == "boolean" and not isinstance(value, bool):
        return ["expected boolean"]
    if t in {"string", "path", "url"} and not isinstance(value, str):
        return ["expected string"]
    if isinstance(value, float) and not math.isfinite(value):
        # NaN compares false to everything, so it would sail past every minimum/maximum
        # below (and json.loads accepts it by default). Infinity is rejected for symmetry.
        return ["non-finite number (NaN/Infinity) is not allowed"]

    if rule.enum is not None and value not in rule.enum:
        errors.append(f"value not in allowed set {rule.enum}")
    if isinstance(value, int | float) and not isinstance(value, bool):
        if rule.minimum is not None and value < rule.minimum:
            errors.append(f"below minimum {rule.minimum}")
        if rule.maximum is not None and value > rule.maximum:
            errors.append(f"above maximum {rule.maximum}")
    if isinstance(value, str):
        if rule.max_length is not None and len(value) > rule.max_length:
            errors.append(f"longer than {rule.max_length} characters")
        if rule.pattern is not None and not re.fullmatch(rule.pattern, value):
            errors.append("does not match required pattern")
        for pat in rule.deny_patterns:
            if re.search(pat, value):
                errors.append(f"matches denied pattern {pat!r}")
        if t == "path":
            ok, resolved = path_within_roots(value, rule.roots)
            if not ok:
                errors.append("path escapes allowed roots")
            else:
                normalized = PurePosixPath(resolved.replace("\\", "/")).as_posix()
                for pat in rule.deny_patterns:
                    if re.search(pat, normalized):
                        errors.append(f"resolved path matches denied pattern {pat!r}")
        elif t == "url":
            errors.extend(check_url(value, rule, resolver))
    return errors
