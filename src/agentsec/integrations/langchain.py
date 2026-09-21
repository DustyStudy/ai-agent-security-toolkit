"""Guard LangChain and LangGraph tools with a :class:`~agentsec.sandbox.ToolGuard`.

``guard_tool`` returns a new tool with the same name, description and argument schema whose
every call goes through the guard (allowlist, argument checks, limits, approval, taint, audit)
before the original tool runs. Use it for both sync (``invoke``) and async (``ainvoke``)
code paths, and hand the result to any agent runtime, including LangGraph's ``ToolNode``
and ``create_react_agent``::

    guarded = guard_tools([search, send_email], guard, session)
    agent = create_react_agent(model, guarded)

A refused call is returned to the model as a readable message (a ``ToolException``, which the
returned tool reports as its output) instead of crashing the run.

Requires ``pip install "ai-agent-security-toolkit[langchain]"``. The caller's run configuration
(callbacks, tags, ``configurable``) reaches the original tool through LangChain's own context
propagation, so tracing and per-run settings keep working.

Not supported: tools with *injected* arguments (``InjectedState``, ``InjectedToolCallId``).
Those values would reach the guard as ordinary arguments, so wrap such tools by hand.
"""

from collections.abc import Iterable
from typing import Any

try:
    from langchain_core.tools import BaseTool, StructuredTool, ToolException
except ImportError as exc:  # pragma: no cover - exercised only without the optional extra
    raise ImportError(
        'agentsec.integrations.langchain needs LangChain: pip install "ai-agent-security-toolkit[langchain]"'
    ) from exc

from agentsec.sandbox.guard import Session, ToolDenied, ToolGuard
from agentsec.types import ToolCall

__all__ = ["guard_tool", "guard_tools"]


def _refusal(exc: ToolDenied) -> ToolException:
    return ToolException(f"Tool call refused by security policy: {exc.decision.message()}")


def guard_tool(
    tool: BaseTool,
    guard: ToolGuard,
    session: Session | None = None,
    *,
    name: str | None = None,
) -> StructuredTool:
    """Return ``tool`` guarded as policy tool ``name`` (default: the tool's own name).

    The guard sees the arguments the model supplied after LangChain's own validation, including
    defaults LangChain fills in, so the policy must allow every argument in the tool's schema.
    Tool artifacts (``response_format="content_and_artifact"``) are not passed through.
    """
    policy_name = name or tool.name

    def run(**kwargs: Any) -> Any:
        def call(**arguments: Any) -> Any:
            return tool.invoke(arguments)

        try:
            return guard.execute(ToolCall(name=policy_name, arguments=kwargs), call, session)
        except ToolDenied as exc:
            raise _refusal(exc) from None

    async def arun(**kwargs: Any) -> Any:
        async def call(**arguments: Any) -> Any:
            return await tool.ainvoke(arguments)

        try:
            return await guard.aexecute(ToolCall(name=policy_name, arguments=kwargs), call, session)
        except ToolDenied as exc:
            raise _refusal(exc) from None

    return StructuredTool.from_function(
        func=run,
        coroutine=arun,
        name=tool.name,
        description=tool.description,
        args_schema=tool.args_schema,
        infer_schema=False,
        return_direct=tool.return_direct,
        handle_tool_error=True,
        metadata=tool.metadata,
        tags=tool.tags,
    )


def guard_tools(
    tools: Iterable[BaseTool], guard: ToolGuard, session: Session | None = None
) -> list[StructuredTool]:
    """Guard every tool in ``tools``. See :func:`guard_tool`."""
    return [guard_tool(t, guard, session) for t in tools]
