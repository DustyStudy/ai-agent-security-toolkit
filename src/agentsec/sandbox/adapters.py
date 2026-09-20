"""Glue for the two common tool-calling wire formats.

Both helpers are duck-typed on plain dicts, so they work with the raw API
responses and add no SDK dependency. They implement the loop body of "model
asked for tools -> run them -> hand results back", with the guard in the middle.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

from agentsec.sandbox.guard import Session, ToolDenied, ToolGuard
from agentsec.types import ToolCall

ToolRegistry = Mapping[str, Callable[..., Any]]


def _to_text(result: Any) -> str:
    return result if isinstance(result, str) else json.dumps(result, default=str)


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
        decision = guard.authorize(call, session)
        reason = decision.message() if not decision.allowed else "no implementation registered"
        return f"Tool call refused: {reason}", True
    try:
        return _to_text(guard.execute(call, fn, session)), False
    except ToolDenied as exc:
        return f"Tool call refused by security policy: {exc.decision.message()}", True
    except Exception as exc:  # noqa: BLE001 - tool failures are reported to the model, not raised
        return f"Tool raised {type(exc).__name__}: {exc}", True


def run_anthropic_tool_uses(
    guard: ToolGuard,
    session: Session,
    content_blocks: list[dict[str, Any]],
    registry: ToolRegistry,
) -> list[dict[str, Any]]:
    """Turn ``tool_use`` content blocks into ``tool_result`` blocks for the next user turn."""
    results: list[dict[str, Any]] = []
    for block in content_blocks:
        if block.get("type") != "tool_use":
            continue
        call = ToolCall(
            name=block["name"], arguments=dict(block.get("input") or {}), id=block.get("id", "")
        )
        content, is_error = _run(guard, session, registry, call)
        item: dict[str, Any] = {
            "type": "tool_result",
            "tool_use_id": call.id,
            "content": content,
        }
        if is_error:
            item["is_error"] = True
        results.append(item)
    return results


def run_openai_tool_calls(
    guard: ToolGuard,
    session: Session,
    tool_calls: list[dict[str, Any]],
    registry: ToolRegistry,
) -> list[dict[str, Any]]:
    """Turn chat-completions ``tool_calls`` into ``role: tool`` messages."""
    messages: list[dict[str, Any]] = []
    for tc in tool_calls:
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
            content = "Tool call refused: arguments were not valid JSON"
        elif not isinstance(args, dict):
            content = "Tool call refused: arguments must be a JSON object"
        else:
            content, _ = _run(guard, session, registry, call)
        messages.append({"role": "tool", "tool_call_id": call.id, "content": content})
    return messages
