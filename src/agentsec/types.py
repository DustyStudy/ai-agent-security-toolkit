"""Shared value types used across the fuzzer, sandbox and middleware."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolCall:
    """A tool invocation requested by a model."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    id: str = ""


@dataclass
class AttackInput:
    """One adversarial test input handed to a target.

    ``user_message`` is what the (trusted) user typed. ``untrusted_content`` is
    text the attacker controls but the user did not type: a retrieved document,
    web page, email body or tool output. Indirect-injection scenarios put the
    payload there.
    """

    user_message: str
    untrusted_content: str | None = None
    system_secret: str | None = None
    available_tools: tuple[str, ...] = ()


@dataclass
class TargetResponse:
    """What a target produced for one :class:`AttackInput`."""

    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    blocked: bool = False
    notes: list[str] = field(default_factory=list)


Target = Callable[[AttackInput], TargetResponse]


def coerce_response(value: str | TargetResponse | None) -> TargetResponse:
    """Accept a bare string from simple targets."""
    if value is None:
        return TargetResponse()
    if isinstance(value, TargetResponse):
        return value
    return TargetResponse(text=str(value))
