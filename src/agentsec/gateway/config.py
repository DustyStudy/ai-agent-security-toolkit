"""Strict loader for the gateway's YAML config. Unknown keys and unsafe settings are errors."""

from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agentsec.gateway.feeds import EgressSettings, FeedConfig
from agentsec.gateway.oidc import SUPPORTED_ALGORITHMS, OidcSettings
from agentsec.gateway.policyset import ANY_GROUP, PolicySet, group_policy, stream_settings
from agentsec.gateway.tokens import TokenSettings
from agentsec.middleware.dlp import DlpConfigError, DlpPolicy
from agentsec.sandbox.policy import Policy, load_yaml_strict


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Upstream:
    name: str  # what clients put in "model"
    url: str  # base URL ending before /chat/completions, e.g. https://models.internal/v1
    model: str  # the model name the upstream expects
    api_key_ref: str | None = None  # "env:NAME" or "file:/path"; never a literal
    outbound_on_secret: str = "off"  # noqa: S105  # off | block | redact: secrets in the request sent here
    outbound_on_pii: str = (
        "off"  # off | block | redact: PII in the request sent here; off: group dlp
    )

    def api_key(self) -> str | None:
        """Resolved on every call, so a rotated secret file is picked up without a restart."""
        return resolve_secret(self.api_key_ref) if self.api_key_ref else None


@dataclass(frozen=True)
class McpUpstream:
    name: str  # tools appear to clients as "<name>__<tool>"
    url: str  # the upstream's streamable HTTP endpoint, e.g. https://mcp-jira.internal/mcp
    auth_ref: str | None = None  # "env:NAME" or "file:/path": sent as a bearer token

    def auth(self) -> str | None:
        return resolve_secret(self.auth_ref) if self.auth_ref else None


@dataclass(frozen=True)
class BundleSettings:
    dir: str
    public_key: Any  # Ed25519PublicKey
    min_revision: int = 0  # refuse older bundles, also across restarts
    reload_interval_s: float = 10.0  # 0: never reload
    state_file: str | None = None  # highest accepted revision, so a restart cannot roll back


@dataclass(frozen=True)
class GatewayConfig:
    policies: PolicySet  # what is enforced at startup; a bundle may replace it on reload
    upstreams: dict[str, Upstream]
    audit_file: str
    trusted_proxies: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    user_header: str = "x-auth-request-user"
    groups_header: str = "x-auth-request-groups"
    allowed_groups: tuple[str, ...] = ()  # empty: any authenticated user
    allowed_domains: tuple[str, ...] = ()  # set: the user must be an address in one of these
    block_personal_domains: bool = False  # set: gmail.com, outlook.com etc. are refused
    oidc: OidcSettings | None = None  # set: identity comes from bearer tokens, not headers
    host: str = "127.0.0.1"
    port: int = 8443
    tls_cert_file: str | None = None
    tls_key_file: str | None = None
    tls_terminated_by_proxy: bool = False
    # Host header names (no port) the main listener accepts. Empty: the loopback names when host is
    # loopback, otherwise the configuration must supply explicit names.
    allowed_hosts: tuple[str, ...] = ()
    allowed_origins: tuple[str, ...] = ()  # an Origin header outside this list is refused
    # Peer addresses the main listener serves. Empty: any address (identity still applies).
    allowed_clients: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    admin_port: int | None = None  # set: /metrics and /readyz on admin_host:admin_port
    admin_host: str = "127.0.0.1"
    admin_fuzz_report: str | None = None  # an `agentsec fuzz --json` file shown on /dashboard
    admin_evidence_dir: str | None = None  # docs/evidence-style folder linked from /dashboard
    # env:/file: reference to the bearer secret for POST /sessions/revoke on the admin listener
    admin_revoke_token_ref: str | None = None
    bundle: BundleSettings | None = None  # set: policies come from a signed bundle
    log_content: bool = False
    cef_file: str | None = None
    max_body_bytes: int = 1024 * 1024
    max_response_bytes: int = 5 * 1024 * 1024
    max_tokens_cap: int = 4096
    tokens_per_user_per_day: int | None = None  # set: model tokens a user may use per 24 hours
    upstream_timeout_s: float = 120.0
    requests_per_min: int = 60
    concurrent_requests: int = 4
    body_timeout_s: float = 30.0
    max_connections: int = 1000  # open connections and requests in flight; above it, 503
    header_timeout_s: float = 10.0  # a connection must send a whole request head within this
    shutdown_timeout_s: float = 30.0  # on SIGTERM, how long requests in flight may finish
    mcp_upstreams: dict[str, McpUpstream] = field(default_factory=dict)
    mcp_session_idle_s: float = 3600.0
    mcp_require_pins: bool = False  # set: every mcp_upstream needs reviewed pins, or no start
    tokens: TokenSettings | None = None  # set: users may mint access tokens (POST /tokens)
    egress: EgressSettings | None = None  # set: URL arguments are checked against signed feeds
    policy_hook: PolicyHookSettings | None = None  # set: an external service vets each tool call


@dataclass(frozen=True)
class PolicyHookSettings:
    url: str
    timeout_s: float = 5.0
    auth_ref: str | None = None  # env:/file: reference; sent as "Authorization: Bearer <it>"


MAX_SECRET_FILE_BYTES = 65536  # keys and tokens; a bigger file is a wrong path


def resolve_secret(ref: str) -> str:
    kind, _, value = ref.partition(":")
    if kind == "env":
        secret = os.environ.get(value)
        if not secret:
            raise ConfigError(f"environment variable {value!r} is not set")
        return secret
    if kind == "file":
        with open(value, "rb") as fh:
            data = fh.read(MAX_SECRET_FILE_BYTES + 1)
        if len(data) > MAX_SECRET_FILE_BYTES:
            raise ConfigError(f"secret file {value!r} is over {MAX_SECRET_FILE_BYTES} bytes")
        return data.decode("utf-8").strip()
    raise ConfigError("secrets must be references: 'env:NAME' or 'file:/path'")


_TOP = {
    "listen",
    "admin",
    "identity",
    "policy",
    "bundle",
    "mode",
    "output",
    "input",
    "limits",
    "upstreams",
    "mcp_upstreams",
    "mcp",
    "tokens",
    "audit",
    "dlp",
    "egress",
    "policy_hook",
}
_SECTIONS: dict[str, set[str]] = {
    "listen": {
        "host",
        "port",
        "tls",
        "tls_terminated_by_proxy",
        "allowed_hosts",
        "allowed_origins",
        "allowed_clients",
    },
    "admin": {"host", "port", "fuzz_report", "evidence_dir", "revoke_token"},
    "tls": {"cert_file", "key_file"},
    "identity": {
        "mode",
        "user_header",
        "groups_header",
        "trusted_proxies",
        "allowed_groups",
        "allowed_domains",
        "block_personal_domains",
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
    "output": {"allowed_hosts", "protected", "stream_mode", "holdback_chars"},
    "input": {"block_on_injection", "spotlight_tool_results"},
    "dlp": {"categories", "detectors", "allow", "fingerprint_key"},
    "limits": {
        "max_body_bytes",
        "max_response_bytes",
        "max_tokens_cap",
        "tokens_per_user_per_day",
        "upstream_timeout_s",
        "requests_per_min",
        "concurrent_requests",
        "body_timeout_s",
        "mcp_session_idle_s",
        "max_connections",
        "header_timeout_s",
        "shutdown_timeout_s",
    },
    "audit": {"file", "log_content", "cef_file"},
    "upstream": {"url", "model", "api_key", "outbound"},
    "outbound": {"on_secret", "on_pii"},
    "mcp_upstream": {"url", "auth", "pins"},
    "mcp": {"require_pins"},
    "tokens": {
        "store",
        "default_ttl_days",
        "max_ttl_days",
        "max_per_user",
        "offboarding_deadline_s",
    },
    "bundle": {"dir", "public_key_file", "min_revision", "reload_interval_s", "state_file"},
    "egress": {
        "blocklists",
        "except_hosts",
        "on_stale",
        "public_key_file",
        "check_model_links",
        "state_file",
        "reload_interval_s",
    },
    "blocklist": {"name", "kind", "file", "max_age_h"},
    "policy_hook": {"url", "timeout_s", "auth"},
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


def loopback_hosts(host: str) -> frozenset[str] | None:
    """Host header names for a loopback listener, or None when ``host`` is not loopback."""
    if not _is_loopback(host):
        return None
    return frozenset(
        {"localhost", "127.0.0.1", "[::1]", f"[{host}]" if ":" in host else host.lower()}
    )


def _require_secure_upstream(where: str, url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme == "http" and not _is_loopback(parts.hostname or ""):
        raise ConfigError(f"{where}.url requires https for a non-loopback upstream")


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


MCP_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")  # no "_": "__" separates upstream and tool
NAMESPACE = "__"


def _mcp_upstreams(data: dict[str, Any], base: Path) -> tuple[dict[str, McpUpstream], dict]:
    """``mcp_upstreams`` and, for single-policy configs, each upstream's pin file."""
    raw = data.get("mcp_upstreams") or {}
    if not isinstance(raw, dict):
        raise ConfigError("mcp_upstreams must be a mapping")
    upstreams, pins = {}, {}
    for name in raw:
        if not isinstance(name, str) or not MCP_NAME.fullmatch(name):
            raise ConfigError(f"mcp_upstreams name {name!r} must be lowercase letters, digits, '-'")
        u = _section(raw, name, "mcp_upstream")
        url = _typed(u.get("url"), str, f"mcp_upstreams.{name}.url")
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ConfigError(f"mcp_upstreams.{name}.url must be an http(s) URL")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ConfigError(
                f"mcp_upstreams.{name}.url must not hold credentials, query or fragment"
            )
        auth = u.get("auth")
        if auth is not None and (
            not isinstance(auth, str) or not auth.startswith(("env:", "file:"))
        ):
            raise ConfigError(f"mcp_upstreams.{name}.auth must be 'env:NAME' or 'file:/path'")
        if "pins" in u:
            if "bundle" in data:
                raise ConfigError(f"with bundle, mcp_upstreams.{name}.pins goes in the bundle")
            pins[name] = _pin_file(base / _typed(u["pins"], str, f"mcp_upstreams.{name}.pins"))
        _require_secure_upstream(f"mcp_upstreams.{name}", url)
        upstreams[name] = McpUpstream(name=name, url=url, auth_ref=auth)
    return upstreams, pins


MAX_TOKEN_TTL_DAYS = 90


def unpinned(policies: PolicySet, mcp_upstreams: Iterable[str]) -> list[str]:
    """MCP upstreams with no reviewed pins: their tools are only pinned on first use."""
    return sorted(n for n in mcp_upstreams if n not in policies.mcp_pins)


def _tokens(data: dict[str, Any], base: Path) -> TokenSettings | None:
    if "tokens" not in data:
        return None
    section = _section(data, "tokens")
    store = _typed(section.get("store"), str, "tokens.store")
    default = _positive(section, "default_ttl_days", 7.0, float)
    longest = _positive(section, "max_ttl_days", 30.0, float)
    if not default <= longest <= MAX_TOKEN_TTL_DAYS:
        raise ConfigError(
            f"tokens: default_ttl_days <= max_ttl_days <= {MAX_TOKEN_TTL_DAYS} is required"
        )
    return TokenSettings(
        store=str(base / store),
        default_ttl_s=default * 86400,
        max_ttl_s=longest * 86400,
        max_per_user=_positive(section, "max_per_user", 20),
        offboarding_deadline_s=_positive(section, "offboarding_deadline_s", 3600.0, float),
    )


def _domains(identity: dict[str, Any]) -> tuple[str, ...]:
    out = []
    for d in _strs(identity.get("allowed_domains", []), "identity.allowed_domains"):
        d = d.lower()
        bare = d[2:] if d.startswith("*.") else d
        if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", bare):
            raise ConfigError(f"identity.allowed_domains: {d!r} is not a domain (or *.domain)")
        out.append(d)
    return tuple(out)


def _policy_hook(data: dict[str, Any]) -> PolicyHookSettings | None:
    if "policy_hook" not in data:
        return None
    section = _section(data, "policy_hook")
    url = _typed(section.get("url"), str, "policy_hook.url")
    auth = section.get("auth")
    if auth is not None:
        auth = _typed(auth, str, "policy_hook.auth")
        if not auth.startswith(("env:", "file:")):
            raise ConfigError("policy_hook.auth must be a reference: 'env:NAME' or 'file:/path'")
    settings = PolicyHookSettings(
        url=url, timeout_s=_positive(section, "timeout_s", 5.0, float), auth_ref=auth
    )
    try:
        from agentsec.sandbox.policy_hook import HttpPolicyHook

        HttpPolicyHook(url)  # same URL rules as at run time
    except ValueError as e:
        raise ConfigError(f"policy_hook.url: {e}") from e
    return settings


def _pin_file(path: Path) -> dict[str, str]:
    from agentsec.integrations.mcp import ToolPins  # no mcp SDK needed for pins

    try:
        return ToolPins.load(path).pins
    except (OSError, ValueError) as e:
        raise ConfigError(f"{path.name}: {e}") from None


def _single_policy(
    data: dict[str, Any], base: Path, mcp_pins: dict[str, dict[str, str]] | None = None
) -> PolicySet:
    """One policy for every authenticated user, from ``policy``, ``mode``, ``output``, ``input``
    and ``dlp``."""
    policy_section = data.get("policy")
    if not isinstance(policy_section, str):
        raise ConfigError("policy must be the path of a tool policy YAML file (or use bundle)")
    raw_policy = (base / policy_section).read_bytes()  # one read: the hash covers what is parsed
    policy = Policy.from_dict(load_yaml_strict(raw_policy))
    mode = data.get("mode", "enforce")
    if mode not in {"enforce", "monitor"}:
        raise ConfigError("mode must be 'enforce' or 'monitor'")
    output, inp = _section(data, "output"), _section(data, "input")
    try:
        stream_mode, holdback_chars = stream_settings(output, "output")
    except ValueError as e:
        raise ConfigError(str(e)) from None
    try:
        dlp = DlpPolicy.from_dict(_section(data, "dlp"), resolve_secret=resolve_secret)
    except DlpConfigError as e:
        raise ConfigError(str(e)) from None
    flags = {
        "block_on_injection": _typed(
            inp.get("block_on_injection", True), bool, "block_on_injection"
        ),
        "spotlight_tool_results": _typed(
            inp.get("spotlight_tool_results", False), bool, "spotlight_tool_results"
        ),
    }
    try:
        entry = group_policy(
            ANY_GROUP,
            policy,
            mode=mode,
            allowed_hosts=_strs(output.get("allowed_hosts", []), "output.allowed_hosts"),
            protected=_strs(output.get("protected", []), "output.protected"),
            stream_mode=stream_mode,
            holdback_chars=holdback_chars,
            mcp=None,  # one policy for everyone: every configured MCP upstream, gated by its keys
            dlp=dlp,
            **flags,
        )
    except ValueError as e:  # settings that are fine alone but not together
        raise ConfigError(str(e)) from None
    # First 128 bits of the file's sha256: under the 64 characters log_content=False hashes.
    return PolicySet(
        revision="sha256:" + hashlib.sha256(raw_policy).hexdigest()[:32],
        groups=(entry,),
        mcp_pins=mcp_pins or {},
    )


def _egress(data: dict[str, Any], base: Path) -> EgressSettings | None:
    from agentsec.gateway.bundle import BundleError, load_public_key

    if "egress" not in data:
        return None
    section = _section(data, "egress")
    raw = section.get("blocklists")
    if not isinstance(raw, list) or not raw:
        raise ConfigError("egress.blocklists must be a non-empty list")
    feeds: list[FeedConfig] = []
    for i, entry in enumerate(raw):
        where = f"egress.blocklists[{i}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where} must be a mapping")
        unknown = set(entry) - _SECTIONS["blocklist"]
        if unknown:
            raise ConfigError(f"unknown keys in {where}: {sorted(unknown)}")
        name = _typed(entry.get("name"), str, f"{where}.name")
        if not MCP_NAME.fullmatch(name) or name in {f.name for f in feeds}:
            raise ConfigError(f"{where}.name must be unique, lowercase letters, digits and '-'")
        kind = _typed(entry.get("kind"), str, f"{where}.kind")
        if kind not in ("ip", "domain"):
            raise ConfigError(f"{where}.kind must be 'ip' or 'domain'")
        file = _typed(entry.get("file"), str, f"{where}.file")
        max_age_h = _positive(entry, "max_age_h", 48.0, float)
        feeds.append(FeedConfig(name, kind, str(base / file), float(max_age_h) * 3600))
    on_stale = section.get("on_stale", "warn")
    if on_stale not in ("warn", "deny"):
        raise ConfigError("egress.on_stale must be 'warn' or 'deny'")
    key_file = _typed(section.get("public_key_file"), str, "egress.public_key_file")
    try:
        key = load_public_key((base / key_file).read_bytes())
    except (BundleError, OSError, ValueError) as e:
        raise ConfigError(f"egress.public_key_file: {e}") from e
    state = section.get("state_file")
    return EgressSettings(
        feeds=tuple(feeds),
        public_key=key,
        except_hosts=_strs(section.get("except_hosts", []), "egress.except_hosts"),
        on_stale=on_stale,
        check_model_links=_typed(
            section.get("check_model_links", True), bool, "egress.check_model_links"
        ),
        state_file=None if state is None else str(base / _typed(state, str, "egress.state_file")),
        reload_interval_s=float(_positive(section, "reload_interval_s", 10.0, float)),
    )


def _bundle(
    section: dict[str, Any], base: Path, upstreams: set[str], mcp_upstreams: set[str]
) -> tuple[BundleSettings, PolicySet]:
    from agentsec.gateway.bundle import (
        BundleError,
        check_state,
        load_bundle,
        load_public_key,
        read_state,
    )

    root = _typed(section.get("dir"), str, "bundle.dir")
    key_file = _typed(section.get("public_key_file"), str, "bundle.public_key_file")
    min_revision = _typed(section.get("min_revision", 0), int, "bundle.min_revision")
    interval = _typed(section.get("reload_interval_s", 10.0), float, "bundle.reload_interval_s")
    if min_revision < 0 or not math.isfinite(interval) or interval < 0:
        raise ConfigError("bundle.min_revision and bundle.reload_interval_s must be >= 0")
    state = section.get("state_file")
    state_file = None if state is None else str(base / _typed(state, str, "bundle.state_file"))
    try:
        key = load_public_key((base / key_file).read_bytes())
        settings = BundleSettings(str(base / root), key, min_revision, float(interval), state_file)
        # No valid bundle, no gateway: never start without a verified policy.
        policies = load_bundle(settings.dir, key, upstreams=upstreams, mcp_upstreams=mcp_upstreams)
        if policies.numeric_revision is not None and policies.numeric_revision < min_revision:
            raise BundleError(f"bundle revision is below bundle.min_revision ({min_revision})")
        if state_file is not None:
            # Checked here, recorded only by `serve`: a token command, `serve --check` or
            # `probe-isolation` reading the config must not advance the accepted revision.
            check_state(policies, read_state(state_file))
    except (BundleError, OSError, ValueError) as e:
        raise ConfigError(f"bundle: {e}") from e
    return settings, policies


def load_config(path: str | Path) -> GatewayConfig:
    path = Path(path)
    data = load_yaml_strict(path.read_text(encoding="utf-8"))
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
    allowed_hosts = tuple(
        h.lower() for h in _strs(listen.get("allowed_hosts", []), "listen.allowed_hosts")
    )
    for h in allowed_hosts:
        # The name in a Host header: a DNS name, an IPv4 address or [IPv6]. No port, no wildcards.
        if not re.fullmatch(r"\[[0-9a-f:.]+\]|[a-z0-9.-]+", h):
            raise ConfigError(f"listen.allowed_hosts: {h!r} is not a host name (without a port)")
    if not allowed_hosts and not _is_loopback(host):
        raise ConfigError("listen.allowed_hosts is required for a non-loopback listener")
    allowed_origins = tuple(
        o.lower() for o in _strs(listen.get("allowed_origins", []), "listen.allowed_origins")
    )
    for o in allowed_origins:
        parts = urlsplit(o)
        if parts.scheme not in {"http", "https"} or o != f"{parts.scheme}://{parts.netloc}":
            raise ConfigError(
                f"listen.allowed_origins: {o!r} is not an origin such as https://chat.corp.example"
            )

    admin = _section(data, "admin")
    admin_host = _typed(admin.get("host", "127.0.0.1"), str, "admin.host")
    admin_port = None if not admin else _typed(admin.get("port"), int, "admin.port")
    fuzz_report = admin.get("fuzz_report")
    evidence_dir = admin.get("evidence_dir")
    revoke_ref = admin.get("revoke_token")
    if revoke_ref is not None and not (
        isinstance(revoke_ref, str) and revoke_ref.startswith(("env:", "file:"))
    ):
        raise ConfigError("admin.revoke_token must be a reference: 'env:NAME' or 'file:/path'")
    try:
        # An IP literal, not "localhost": a resolver could map that name to another interface.
        admin_loopback = ipaddress.ip_address(admin_host).is_loopback
    except ValueError:
        admin_loopback = False
    if admin and not admin_loopback:
        # The admin listener has no authentication: reachable from this host only.
        raise ConfigError("admin.host must be a loopback IP address such as 127.0.0.1")
    if revoke_ref is not None and admin_port is None:
        raise ConfigError("admin.revoke_token needs admin.port: the endpoint is on that listener")
    if admin_port is not None and admin_port == port:
        # Whatever the hosts: 0.0.0.0 and 127.0.0.1 on one port overlap.
        raise ConfigError("admin.port must differ from listen.port")

    try:
        allowed_clients = tuple(
            ipaddress.ip_network(c, strict=True)
            for c in _strs(listen.get("allowed_clients", []), "listen.allowed_clients")
        )
    except ValueError as e:
        raise ConfigError(f"listen.allowed_clients: {e}") from e
    if any(c.prefixlen == 0 for c in allowed_clients):
        raise ConfigError("listen.allowed_clients must not allow every address (/0); omit it")

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
        # strict: 172.28.0.10/16 written where a /32 was meant would trust the whole /16.
        proxies = tuple(ipaddress.ip_network(p, strict=True) for p in proxies_raw)
    except ValueError as e:
        raise ConfigError(f"identity.trusted_proxies: {e}") from e
    if any(p.prefixlen == 0 for p in proxies):
        # Every peer could then name any user in a header.
        raise ConfigError("identity.trusted_proxies must not trust every address (/0)")
    if allowed_clients and any(
        not any(p.version == c.version and p.subnet_of(c) for c in allowed_clients)  # type: ignore[arg-type]
        for p in proxies
    ):
        # Every request would be refused: the auth proxy is the peer the listener sees.
        raise ConfigError("listen.allowed_clients must include every identity.trusted_proxies net")
    for p in proxies:
        floor = 16 if p.version == 4 else 48
        if p.prefixlen < floor:
            # A proxy list is a few hosts or one subnet; a wider net is usually a typo.
            raise ConfigError(
                f"identity.trusted_proxies: {p} is too broad; use /{floor} or a longer prefix"
            )

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
        _require_secure_upstream(f"upstreams.{name}", url)
        outbound = _section(u, "outbound")
        on_secret, on_pii = outbound.get("on_secret", "off"), outbound.get("on_pii", "off")
        for option, value in (("on_secret", on_secret), ("on_pii", on_pii)):
            if value not in ("off", "block", "redact"):
                raise ConfigError(
                    f"upstreams.{name}.outbound.{option} must be off, block or redact"
                )
        upstreams[str(name)] = Upstream(
            outbound_on_secret=on_secret,
            outbound_on_pii=on_pii,
            name=str(name),
            url=url.rstrip("/"),
            model=_typed(u.get("model", name), str, f"upstreams.{name}.model"),
            api_key_ref=api_key,
        )

    mcp_upstreams, mcp_pins = _mcp_upstreams(data, base)
    limits = _section(data, "limits")
    bundle = None
    if "bundle" in data:
        if any(k in data for k in ("policy", "mode", "output", "input", "dlp")):
            # With a bundle every group carries its own; a second source would be ambiguous.
            raise ConfigError("with bundle, put policy, mode, output, input and dlp in the bundle")
        bundle, policies = _bundle(
            _section(data, "bundle"), base, set(upstreams), set(mcp_upstreams)
        )
    else:
        policies = _single_policy(data, base, mcp_pins)
    require_pins = _typed(
        _section(data, "mcp").get("require_pins", False), bool, "mcp.require_pins"
    )
    if require_pins and (missing := unpinned(policies, mcp_upstreams)):
        where = "the bundle's mcp_pins" if bundle else "mcp_upstreams.<name>.pins"
        raise ConfigError(f"mcp.require_pins: no pins for {missing} (set {where})")
    audit = _section(data, "audit")
    audit_file = _typed(audit.get("file"), str, "audit.file")
    cef_file = audit.get("cef_file")

    return GatewayConfig(
        policies=policies,
        bundle=bundle,
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
        allowed_domains=_domains(identity),
        block_personal_domains=_typed(
            identity.get("block_personal_domains", False), bool, "identity.block_personal_domains"
        ),
        oidc=oidc,
        host=host,
        port=port,
        tls_cert_file=None if cert is None else str(base / cert),
        tls_key_file=None if key is None else str(base / key),
        tls_terminated_by_proxy=behind_proxy,
        allowed_hosts=allowed_hosts,
        allowed_clients=allowed_clients,
        allowed_origins=allowed_origins,
        admin_host=admin_host,
        admin_port=admin_port,
        admin_revoke_token_ref=revoke_ref,
        admin_fuzz_report=None
        if fuzz_report is None
        else str(base / _typed(fuzz_report, str, "admin.fuzz_report")),
        admin_evidence_dir=None
        if evidence_dir is None
        else str(base / _typed(evidence_dir, str, "admin.evidence_dir")),
        log_content=_typed(audit.get("log_content", False), bool, "audit.log_content"),
        cef_file=None if cef_file is None else str(base / _typed(cef_file, str, "cef_file")),
        max_body_bytes=_positive(limits, "max_body_bytes", 1024 * 1024),
        max_response_bytes=_positive(limits, "max_response_bytes", 5 * 1024 * 1024),
        max_tokens_cap=_positive(limits, "max_tokens_cap", 4096),
        tokens_per_user_per_day=None
        if limits.get("tokens_per_user_per_day") is None
        else _positive(limits, "tokens_per_user_per_day", None),
        upstream_timeout_s=_positive(limits, "upstream_timeout_s", 120.0, float),
        requests_per_min=_positive(limits, "requests_per_min", 60),
        concurrent_requests=_positive(limits, "concurrent_requests", 4),
        body_timeout_s=_positive(limits, "body_timeout_s", 30.0, float),
        max_connections=_positive(limits, "max_connections", 1000),
        header_timeout_s=_positive(limits, "header_timeout_s", 10.0, float),
        shutdown_timeout_s=_positive(limits, "shutdown_timeout_s", 30.0, float),
        mcp_upstreams=mcp_upstreams,
        mcp_session_idle_s=_positive(limits, "mcp_session_idle_s", 3600.0, float),
        mcp_require_pins=require_pins,
        tokens=_tokens(data, base),
        egress=_egress(data, base),
        policy_hook=_policy_hook(data),
    )
