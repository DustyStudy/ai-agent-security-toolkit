"""What the gateway enforces for one request: the policy of the first group that matches."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from agentsec.middleware.validators import (
    OutputGuard,
    OutputValidator,
    ProtectedStringValidator,
    SecretLeakValidator,
)
from agentsec.sandbox.policy import Policy

ANY_GROUP = "*"


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
) -> GroupPolicy:
    protected = tuple(protected)
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
        output_guard=OutputGuard.default(allowed_hosts=tuple(allowed_hosts), protected=protected),
        argument_guard=OutputGuard(arg_validators),
        block_on_injection=block_on_injection,
        spotlight_tool_results=spotlight_tool_results,
    )


@dataclass(frozen=True)
class PolicySet:
    """Immutable, so a reload swaps one reference and in-flight requests keep their revision."""

    revision: str  # recorded as policy_rev on every request
    groups: tuple[GroupPolicy, ...]
    expires: datetime | None = None
    numeric_revision: int | None = None  # bundles only: refuses rollbacks on reload

    def resolve(self, user_groups: Iterable[str]) -> GroupPolicy | None:
        """First entry that names one of the user's groups, or "*". None means 403."""
        mine = set(user_groups)
        for entry in self.groups:
            if entry.group == ANY_GROUP or entry.group in mine:
                return entry
        return None
