"""What the gateway enforces for one request: the policy of the first group that matches."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from agentsec.middleware.dlp import DEFAULT_DLP, DlpPolicy
from agentsec.middleware.validators import (
    OutputGuard,
    OutputValidator,
    ProtectedStringValidator,
    SecretLeakValidator,
)
from agentsec.sandbox.policy import Policy

ANY_GROUP = "*"
STREAM_MODES = {"buffer", "holdback"}
HOLDBACK_MIN, HOLDBACK_MAX = 32, 8192


@dataclass(frozen=True)
class GroupPolicy:
    group: str  # a group name, or "*" for every authenticated user
    policy: Policy
    mode: str  # enforce | monitor
    models: frozenset[str] | None  # upstream names this group may use; None: all of them
    output_guard: OutputGuard
    argument_guard: OutputGuard
    block_on_injection: bool
    spotlight_tool_results: bool
    stream_mode: str = "buffer"  # holdback: stream text that is held_chars behind and checked
    holdback_chars: int = 256
    mcp: frozenset[str] | None = frozenset()  # MCP upstreams this group may reach; None: all
    dlp: DlpPolicy = DEFAULT_DLP  # credentials, NHI and PII: answers here, arguments in ToolGuard


def stream_settings(output: dict[str, Any], where: str) -> tuple[str, int]:
    """``stream_mode`` and ``holdback_chars`` from an ``output`` section. Raises ValueError."""
    mode = output.get("stream_mode", "buffer")
    if not isinstance(mode, str) or mode not in STREAM_MODES:
        raise ValueError(f"{where}.stream_mode must be 'buffer' or 'holdback'")
    chars = output.get("holdback_chars", 256)
    if (
        not isinstance(chars, int)
        or isinstance(chars, bool)
        or not HOLDBACK_MIN <= chars <= HOLDBACK_MAX
    ):
        raise ValueError(
            f"{where}.holdback_chars must be an integer from {HOLDBACK_MIN} to {HOLDBACK_MAX}"
        )
    return mode, chars


def group_policy(
    group: str,
    policy: Policy,
    *,
    mode: str = "enforce",
    models: Iterable[str] | None = None,
    allowed_hosts: Iterable[str] = (),
    protected: Iterable[str] = (),
    block_on_injection: bool = True,
    spotlight_tool_results: bool = False,
    stream_mode: str = "buffer",
    holdback_chars: int = 256,
    mcp: Iterable[str] | None = (),
    dlp: DlpPolicy = DEFAULT_DLP,
) -> GroupPolicy:
    protected = tuple(protected)
    if (
        stream_mode == "holdback"
        and holdback_chars < 256
        and dlp.mode("email", "output") != "monitor"
    ):
        # An address can be 254 characters: a shorter window could release half of one.
        raise ValueError("holdback_chars must be at least 256 when email is redacted or blocked")
    # Tool arguments: secrets and protected strings only. PII and links are normal in
    # arguments (an email address for send_email); the policy's argument rules cover those.
    arg_validators: list[OutputValidator] = [SecretLeakValidator()]
    if protected:
        arg_validators.append(ProtectedStringValidator(protected))
    return GroupPolicy(
        group=group,
        policy=policy,
        mode=mode,
        models=None if models is None else frozenset(models),
        output_guard=OutputGuard.default(
            allowed_hosts=tuple(allowed_hosts), protected=protected, dlp=dlp
        ),
        argument_guard=OutputGuard(arg_validators),
        block_on_injection=block_on_injection,
        spotlight_tool_results=spotlight_tool_results,
        stream_mode=stream_mode,
        holdback_chars=holdback_chars,
        mcp=None if mcp is None else frozenset(mcp),
        dlp=dlp,
    )


@dataclass(frozen=True)
class PolicySet:
    """Immutable, so a reload swaps one reference and in-flight requests keep their revision."""

    revision: str  # recorded as policy_rev on every request
    groups: tuple[GroupPolicy, ...]
    expires: datetime | None = None
    numeric_revision: int | None = None  # bundles only: refuses rollbacks on reload
    # MCP upstream name -> {namespaced tool: fingerprint}. An upstream with pins only offers
    # tools whose definition matches its pin; without pins, the gateway pins each tool on first use.
    mcp_pins: Mapping[str, Mapping[str, str]] = field(default_factory=dict)

    def resolve(self, user_groups: Iterable[str]) -> GroupPolicy | None:
        """First entry that names one of the user's groups, or "*". None means 403."""
        mine = set(user_groups)
        for entry in self.groups:
            if entry.group == ANY_GROUP or entry.group in mine:
                return entry
        return None
