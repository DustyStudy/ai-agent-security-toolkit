"""Glue for the two common tool-calling wire formats.

Both helpers are duck-typed on plain dicts, so they work with the raw API
responses and add no SDK dependency. They implement the loop body of "model
asked for tools -> run them -> hand results back", with the guard in the middle.

Each has a sync form and an ``arun_*`` async form. The async forms run the calls
of one model turn **one after another, in the order the model gave them**, so
their audit trail and taint effects match the sync forms exactly. If you want
concurrency, call :meth:`ToolGuard.aexecute` yourself.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from typing import Any

from agentsec.middleware.redact import redact_text
from agentsec.sandbox.guard import Decision, Session, ToolDenied, ToolGuard
from agentsec.types import ToolCall

ToolRegistry = Mapping[str, Callable[..., Any]]


def _to_text(result: Any) -> str:
    return result if isinstance(result, str) else json.dumps(result, default=str)


def _refusal(exc: ToolDenied) -> tuple[str, bool]:
    return f"Tool call refused by security policy: {exc.decision.message()}", True


def _failure(exc: Exception) -> tuple[str, bool]:
    # The model (and so anything that can steer it) reads this text: an exception message
    # can carry connection strings, tokens or internal paths. Redact and bound it.
    detail, _ = redact_text(str(exc))
    return f"Tool raised {type(exc).__name__}: {detail[:300]}", True


def _unregistered(decision: Decision) -> tuple[str, bool]:
    reason = decision.message() if not decision.allowed else "no implementation registered"
    return f"Tool call refused: {reason}", True


def _run(
    guard: ToolGuard,
    session: Session,
    registry: ToolRegistry,
    call: ToolCall,
) -> tuple[str, bool]:
    """Return ``(content, is_error)``. Denials become error text the model can read."""
    fn = registry.get(call.name)
    if fn is None:
        # Still authorize so unknown tools are audited and denied by policy.
        return _unregistered(guard.authorize(call, session))
    try:
        return _to_text(guard.execute(call, fn, session)), False
    except ToolDenied as exc:
        return _refusal(exc)
    except Exception as exc:  # noqa: BLE001 - tool failures are reported to the model, not raised
        return _failure(exc)


async def _arun(
    guard: ToolGuard,
    session: Session,
    registry: ToolRegistry,
    call: ToolCall,
) -> tuple[str, bool]:
    """Async form of :func:`_run`."""
    fn = registry.get(call.name)
    if fn is None:
        return _unregistered(await guard.aauthorize(call, session))
    try:
        return _to_text(await guard.aexecute(call, fn, session)), False
    except ToolDenied as exc:
        return _refusal(exc)
    except Exception as exc:  # noqa: BLE001 - tool failures are reported to the model, not raised
        return _failure(exc)


# ------------------------------------------------------------------------ Anthropic


def _anthropic_calls(content_blocks: list[dict[str, Any]]) -> Iterator[ToolCall]:
    for block in content_blocks:
        if block.get("type") != "tool_use":
            continue
        raw_input: Any = block.get("input")
        # dict() on a malformed (non-object) input would raise and crash the whole agent loop.
        # Pass it through instead: the guard denies non-object arguments and audits the attempt.
        arguments: Any = dict(raw_input) if isinstance(raw_input, dict) else raw_input
        yield ToolCall(
            name=block["name"],
            arguments={} if arguments is None else arguments,
            id=block.get("id", ""),
        )


def _anthropic_result(call: ToolCall, content: str, is_error: bool) -> dict[str, Any]:
    item: dict[str, Any] = {"type": "tool_result", "tool_use_id": call.id, "content": content}
    if is_error:
        item["is_error"] = True
    return item


def run_anthropic_tool_uses(
    guard: ToolGuard,
    session: Session,
    content_blocks: list[dict[str, Any]],
    registry: ToolRegistry,
) -> list[dict[str, Any]]:
    """Turn ``tool_use`` content blocks into ``tool_result`` blocks for the next user turn."""
    return [
        _anthropic_result(call, *_run(guard, session, registry, call))
        for call in _anthropic_calls(content_blocks)
    ]


async def arun_anthropic_tool_uses(
    guard: ToolGuard,
    session: Session,
    content_blocks: list[dict[str, Any]],
    registry: ToolRegistry,
) -> list[dict[str, Any]]:
    """Async :func:`run_anthropic_tool_uses`. Registry functions may be sync or ``async def``."""
    results: list[dict[str, Any]] = []
    for call in _anthropic_calls(content_blocks):
        results.append(_anthropic_result(call, *await _arun(guard, session, registry, call)))
    return results


# --------------------------------------------------------------------------- OpenAI


def _openai_call(tc: dict[str, Any]) -> tuple[ToolCall, str | None]:
    """Parse one ``tool_calls`` entry. The second item is a refusal message, or ``None``."""
    fn = tc.get("function", {})
    try:
        args = json.loads(fn.get("arguments") or "{}")
    except json.JSONDecodeError:
        args = None
    call = ToolCall(
        name=fn.get("name", ""),
        arguments=args if isinstance(args, dict) else {},
        id=tc.get("id", ""),
    )
    if args is None:
        return call, "Tool call refused: arguments were not valid JSON"
    if not isinstance(args, dict):
        return call, "Tool call refused: arguments must be a JSON object"
    return call, None


def _openai_message(call: ToolCall, content: str) -> dict[str, Any]:
    return {"role": "tool", "tool_call_id": call.id, "content": content}


def run_openai_tool_calls(
    guard: ToolGuard,
    session: Session,
    tool_calls: list[dict[str, Any]],
    registry: ToolRegistry,
) -> list[dict[str, Any]]:
    """Turn chat-completions ``tool_calls`` into ``role: tool`` messages."""
    messages: list[dict[str, Any]] = []
    for tc in tool_calls:
        call, refusal = _openai_call(tc)
        content = refusal if refusal is not None else _run(guard, session, registry, call)[0]
        messages.append(_openai_message(call, content))
    return messages


async def arun_openai_tool_calls(
    guard: ToolGuard,
    session: Session,
    tool_calls: list[dict[str, Any]],
    registry: ToolRegistry,
) -> list[dict[str, Any]]:
    """Async :func:`run_openai_tool_calls`. Registry functions may be sync or ``async def``."""
    messages: list[dict[str, Any]] = []
    for tc in tool_calls:
        call, refusal = _openai_call(tc)
        if refusal is not None:
            content = refusal
        else:
            content = (await _arun(guard, session, registry, call))[0]
        messages.append(_openai_message(call, content))
    return messages


__all__ = [
    "ToolRegistry",
    "arun_anthropic_tool_uses",
    "arun_openai_tool_calls",
    "run_anthropic_tool_uses",
    "run_openai_tool_calls",
]
