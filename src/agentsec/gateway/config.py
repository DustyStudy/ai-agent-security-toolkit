"""Strict loader for the gateway's YAML config. Unknown keys and unsafe settings are errors."""

from __future__ import annotations

import hashlib
import ipaddress
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from agentsec.gateway.oidc import SUPPORTED_ALGORITHMS, OidcSettings
from agentsec.sandbox.policy import Policy


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Upstream:
    name: str  # what clients put in "model"
    url: str  # base URL ending before /chat/completions, e.g. http://ollama.internal:11434/v1
    model: str  # the model name the upstream expects
    api_key_ref: str | None = None  # "env:NAME" or "file:/path"; never a literal

    def api_key(self) -> str | None:
        """Resolved on every call, so a rotated secret file is picked up without a restart."""
        return resolve_secret(self.api_key_ref) if self.api_key_ref else None


@dataclass(frozen=True)
class GatewayConfig:
    policy: Policy
    # First 128 bits of the policy file's sha256: under the 64 characters that log_content=False
    # would replace with a hash.
    policy_rev: str
    upstreams: dict[str, Upstream]
    audit_file: str
    trusted_proxies: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    user_header: str = "x-auth-request-user"
    groups_header: str = "x-auth-request-groups"
    allowed_groups: tuple[str, ...] = ()  # empty: any authenticated user
    oidc: OidcSettings | None = None  # set: identity comes from bearer tokens, not headers
    host: str = "127.0.0.1"
    port: int = 8443
    tls_cert_file: str | None = None
    tls_key_file: str | None = None
    tls_terminated_by_proxy: bool = False
    mode: str = "enforce"  # enforce | monitor
    allowed_hosts: tuple[str, ...] = ()
    protected: tuple[str, ...] = ()
    block_on_injection: bool = True
    spotlight_tool_results: bool = False
    log_content: bool = False
    cef_file: str | None = None
    max_body_bytes: int = 1024 * 1024
    max_response_bytes: int = 5 * 1024 * 1024
    max_tokens_cap: int = 4096
    upstream_timeout_s: float = 120.0
    requests_per_min: int = 60
    concurrent_requests: int = 4
    body_timeout_s: float = 30.0


def resolve_secret(ref: str) -> str:
    kind, _, value = ref.partition(":")
    if kind == "env":
        secret = os.environ.get(value)
        if not secret:
            raise ConfigError(f"environment variable {value!r} is not set")
        return secret
    if kind == "file":
        return Path(value).read_text(encoding="utf-8").strip()
    raise ConfigError("secrets must be references: 'env:NAME' or 'file:/path'")


_TOP = {"listen", "identity", "policy", "mode", "output", "input", "limits", "upstreams", "audit"}
_SECTIONS: dict[str, set[str]] = {
    "listen": {"host", "port", "tls", "tls_terminated_by_proxy"},
    "tls": {"cert_file", "key_file"},
    "identity": {
        "mode",
        "user_header",
        "groups_header",
        "trusted_proxies",
        "allowed_groups",
        "oidc",
    },
    "oidc": {
        "issuer",
        "audience",
        "jwks_url",
        "algorithms",
        "user_claim",
        "groups_claim",
        "jwks_cache_s",
        "leeway_s",
    },
    "output": {"allowed_hosts", "protected"},
    "input": {"block_on_injection", "spotlight_tool_results"},
    "limits": {
        "max_body_bytes",
        "max_response_bytes",
        "max_tokens_cap",
        "upstream_timeout_s",
        "requests_per_min",
        "concurrent_requests",
        "body_timeout_s",
    },
    "audit": {"file", "log_content", "cef_file"},
    "upstream": {"url", "model", "api_key"},
}


def _section(data: dict[str, Any], key: str, kind: str | None = None) -> dict[str, Any]:
    value = data.get(key) or {}
    if not isinstance(value, dict):
        raise ConfigError(f"{key!r} must be a mapping")
    unknown = set(value) - _SECTIONS[kind or key]
    if unknown:
        raise ConfigError(f"unknown keys in {key!r}: {sorted(unknown)}")
    return value


def _typed(value: Any, kind: type, where: str) -> Any:
    ok = isinstance(value, kind) and not (kind is not bool and isinstance(value, bool))
    if kind is float:
        ok = isinstance(value, int | float) and not isinstance(value, bool)
    if not ok:
        raise ConfigError(f"{where} must be {kind.__name__}")
    return value


def _strs(value: Any, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where} must be a list of strings")
    return tuple(value)


def _positive(section: dict[str, Any], key: str, default: Any, kind: type = int) -> Any:
    value = _typed(section.get(key, default), kind, key)
    # YAML has .nan and .inf: NaN passes "<= 0", and infinity disables a limit or an expiry.
    if not math.isfinite(value) or value <= 0:
        raise ConfigError(f"{key} must be a positive finite number")
    return value


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _oidc(section: dict[str, Any]) -> OidcSettings:
    issuer = _typed(section.get("issuer"), str, "identity.oidc.issuer")
    audience = _typed(section.get("audience"), str, "identity.oidc.audience")
    jwks_url = _typed(section.get("jwks_url"), str, "identity.oidc.jwks_url")
    parts = urlsplit(jwks_url)
    loopback = parts.hostname is not None and _is_loopback(parts.hostname)
    if not (parts.scheme == "https" or (parts.scheme == "http" and loopback)):
        # The keys decide who is anyone: fetching them over plain HTTP lets the network forge users.
        raise ConfigError("identity.oidc.jwks_url must be https (http only for a loopback host)")
    algorithms = _strs(section.get("algorithms", ["RS256", "ES256"]), "identity.oidc.algorithms")
    bad = set(algorithms) - SUPPORTED_ALGORITHMS
    if bad or not algorithms:
        raise ConfigError(
            f"identity.oidc.algorithms must be asymmetric algorithms from "
            f"{sorted(SUPPORTED_ALGORITHMS)}; refused: {sorted(bad)}"
        )
    leeway = _typed(section.get("leeway_s", 60.0), float, "identity.oidc.leeway_s")
    if not 0 <= leeway <= 300:
        raise ConfigError("identity.oidc.leeway_s must be between 0 and 300 seconds")
    return OidcSettings(
        issuer=issuer,
        audience=audience,
        jwks_url=jwks_url,
        algorithms=algorithms,
        user_claim=_typed(section.get("user_claim", "sub"), str, "identity.oidc.user_claim"),
        groups_claim=_typed(
            section.get("groups_claim", "groups"), str, "identity.oidc.groups_claim"
        ),
        jwks_cache_s=_positive(section, "jwks_cache_s", 600.0, float),
        leeway_s=float(leeway),
    )


def load_config(path: str | Path) -> GatewayConfig:
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ConfigError("config must be a mapping")
    unknown = set(data) - _TOP
    if unknown:
        raise ConfigError(f"unknown top-level keys: {sorted(unknown)}")
    base = path.parent

    listen = _section(data, "listen")
    tls = _section(listen, "tls")
    host = _typed(listen.get("host", "127.0.0.1"), str, "listen.host")
    port = _typed(listen.get("port", 8443), int, "listen.port")
    cert, key = tls.get("cert_file"), tls.get("key_file")
    if (cert is None) != (key is None):
        raise ConfigError("listen.tls needs both cert_file and key_file")
    behind_proxy = _typed(listen.get("tls_terminated_by_proxy", False), bool, "listen.tls_...")
    if not _is_loopback(host) and cert is None and not behind_proxy:
        raise ConfigError(
            "a non-loopback listen.host needs listen.tls, or tls_terminated_by_proxy: true"
        )

    identity = _section(data, "identity")
    identity_mode = identity.get("mode", "trusted_header")
    proxies_raw = _strs(identity.get("trusted_proxies", []), "identity.trusted_proxies")
    oidc = None
    if identity_mode == "trusted_header":
        if not proxies_raw:
            raise ConfigError("identity.trusted_proxies must list the auth proxy's addresses")
        if "oidc" in identity:
            raise ConfigError("identity.oidc is only read with mode: oidc")
    elif identity_mode == "oidc":
        if proxies_raw or "user_header" in identity or "groups_header" in identity:
            # One listener, one identity source: a header path next to tokens is a bypass.
            raise ConfigError("identity mode oidc takes no trusted_proxies or identity headers")
        oidc = _oidc(_section(identity, "oidc"))
    else:
        raise ConfigError("identity.mode must be 'trusted_header' or 'oidc'")
    try:
        proxies = tuple(ipaddress.ip_network(p, strict=False) for p in proxies_raw)
    except ValueError as e:
        raise ConfigError(f"identity.trusted_proxies: {e}") from e

    policy_section = data.get("policy")
    if not isinstance(policy_section, str):
        raise ConfigError("policy must be the path of a tool policy YAML file")
    raw_policy = (base / policy_section).read_bytes()  # one read: the hash covers what is parsed
    policy = Policy.from_dict(yaml.safe_load(raw_policy))

    mode = data.get("mode", "enforce")
    if mode not in {"enforce", "monitor"}:
        raise ConfigError("mode must be 'enforce' or 'monitor'")

    upstreams_raw = data.get("upstreams")
    if not isinstance(upstreams_raw, dict) or not upstreams_raw:
        raise ConfigError("upstreams must map at least one model name to an upstream")
    upstreams = {}
    for name in upstreams_raw:
        u = _section(upstreams_raw, name, "upstream")
        url = _typed(u.get("url"), str, f"upstreams.{name}.url")
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ConfigError(f"upstreams.{name}.url must be an http(s) URL")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ConfigError(f"upstreams.{name}.url must not hold credentials, query or fragment")
        api_key = u.get("api_key")
        if api_key is not None and (
            not isinstance(api_key, str) or not api_key.startswith(("env:", "file:"))
        ):
            raise ConfigError(f"upstreams.{name}.api_key must be 'env:NAME' or 'file:/path'")
        upstreams[str(name)] = Upstream(
            name=str(name),
            url=url.rstrip("/"),
            model=_typed(u.get("model", name), str, f"upstreams.{name}.model"),
            api_key_ref=api_key,
        )

    output, inp, limits = (
        _section(data, "output"),
        _section(data, "input"),
        _section(data, "limits"),
    )
    audit = _section(data, "audit")
    audit_file = _typed(audit.get("file"), str, "audit.file")
    cef_file = audit.get("cef_file")

    return GatewayConfig(
        policy=policy,
        policy_rev="sha256:" + hashlib.sha256(raw_policy).hexdigest()[:32],
        upstreams=upstreams,
        audit_file=str(base / audit_file),
        trusted_proxies=proxies,
        user_header=_typed(
            identity.get("user_header", "X-Auth-Request-User"), str, "user_header"
        ).lower(),
        groups_header=_typed(
            identity.get("groups_header", "X-Auth-Request-Groups"), str, "groups_header"
        ).lower(),
        allowed_groups=_strs(identity.get("allowed_groups", []), "identity.allowed_groups"),
        oidc=oidc,
        host=host,
        port=port,
        tls_cert_file=None if cert is None else str(base / cert),
        tls_key_file=None if key is None else str(base / key),
        tls_terminated_by_proxy=behind_proxy,
        mode=mode,
        allowed_hosts=_strs(output.get("allowed_hosts", []), "output.allowed_hosts"),
        protected=_strs(output.get("protected", []), "output.protected"),
        block_on_injection=_typed(inp.get("block_on_injection", True), bool, "block_on_injection"),
        spotlight_tool_results=_typed(
            inp.get("spotlight_tool_results", False), bool, "spotlight_tool_results"
        ),
        log_content=_typed(audit.get("log_content", False), bool, "audit.log_content"),
        cef_file=None if cef_file is None else str(base / _typed(cef_file, str, "cef_file")),
        max_body_bytes=_positive(limits, "max_body_bytes", 1024 * 1024),
        max_response_bytes=_positive(limits, "max_response_bytes", 5 * 1024 * 1024),
        max_tokens_cap=_positive(limits, "max_tokens_cap", 4096),
        upstream_timeout_s=_positive(limits, "upstream_timeout_s", 120.0, float),
        requests_per_min=_positive(limits, "requests_per_min", 60),
        concurrent_requests=_positive(limits, "concurrent_requests", 4),
        body_timeout_s=_positive(limits, "body_timeout_s", 30.0, float),
    )
