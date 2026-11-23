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
    from langchain_core.tools import BaseTool, StructuredTool, Tool, ToolException
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover - exercised only without the optional extra
    raise ImportError(
        'agentsec.integrations.langchain needs LangChain: pip install "ai-agent-security-toolkit[langchain]"'
    ) from exc

from agentsec.sandbox.guard import Session, ToolDenied, ToolGuard
from agentsec.types import ToolCall

__all__ = ["guard_tool", "guard_tools"]


_SINGLE_INPUT = "tool_input"


def _refusal(exc: ToolDenied) -> ToolException:
    return ToolException(f"Tool call refused by security policy: {exc.decision.message()}")


def _by_alias(schema: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    """Rename validated fields back to the names the tool's schema accepts as input.

    LangChain hands the guard (and so the tool) field names, but a field declared
    ``Field(alias="recipient")`` only validates under its alias: every call the guard allowed
    failed in the original tool with a ValidationError.
    """
    if not (isinstance(schema, type) and issubclass(schema, BaseModel)):
        return arguments
    if schema.model_config.get("populate_by_name") or schema.model_config.get("validate_by_name"):
        return arguments
    out: dict[str, Any] = {}
    for key, value in arguments.items():
        info = schema.model_fields.get(key)
        alias = None
        if info is not None:
            alias = info.validation_alias if isinstance(info.validation_alias, str) else info.alias
        out[alias or key] = value
    return out


def guard_tool(
    tool: BaseTool,
    guard: ToolGuard,
    session: Session | None = None,
    *,
    name: str | None = None,
) -> BaseTool:
    """Return ``tool`` guarded as policy tool ``name`` (default: the tool's own name).

    The guard sees the arguments the model supplied after LangChain's own validation, including
    defaults LangChain fills in, so the policy must allow every argument in the tool's schema.
    The original tool then validates them once more: a schema validator that changes its input
    (dollars to cents, say) must give the same result when run twice.
    Tool artifacts (``response_format="content_and_artifact"``) are not passed through.
    The policy names arguments by field name, also for a field with an alias.

    A single-input ``Tool`` (no ``args_schema``) keeps its one-string schema; the policy
    names its argument ``tool_input``.
    """
    policy_name = name or tool.name
    if tool.args_schema is None:
        return _guard_single_input(tool, guard, session, policy_name)
    schema = tool.args_schema

    def run(**kwargs: Any) -> Any:
        def call(**arguments: Any) -> Any:
            return tool.invoke(_by_alias(schema, arguments))

        try:
            return guard.execute(ToolCall(name=policy_name, arguments=kwargs), call, session)
        except ToolDenied as exc:
            raise _refusal(exc) from None

    async def arun(**kwargs: Any) -> Any:
        async def call(**arguments: Any) -> Any:
            return await tool.ainvoke(_by_alias(schema, arguments))

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


def _guard_single_input(
    tool: BaseTool, guard: ToolGuard, session: Session | None, policy_name: str
) -> Tool:
    """Guard a legacy single-input tool as a ``Tool`` with the same one-string schema.

    A ``StructuredTool`` built from it advertised a schema of ``args``/``config``/``kwargs``
    to the model and raised TypeError on the string input such tools take.
    """

    def run(tool_input: Any) -> Any:
        def call(**arguments: Any) -> Any:
            return tool.invoke(arguments[_SINGLE_INPUT])

        try:
            return guard.execute(
                ToolCall(name=policy_name, arguments={_SINGLE_INPUT: tool_input}), call, session
            )
        except ToolDenied as exc:
            raise _refusal(exc) from None

    async def arun(tool_input: Any) -> Any:
        async def call(**arguments: Any) -> Any:
            return await tool.ainvoke(arguments[_SINGLE_INPUT])

        try:
            return await guard.aexecute(
                ToolCall(name=policy_name, arguments={_SINGLE_INPUT: tool_input}), call, session
            )
        except ToolDenied as exc:
            raise _refusal(exc) from None

    return Tool(
        name=tool.name,
        func=run,
        coroutine=arun,
        description=tool.description,
        return_direct=tool.return_direct,
        handle_tool_error=True,
        metadata=tool.metadata,
        tags=tool.tags,
    )


def guard_tools(
    tools: Iterable[BaseTool], guard: ToolGuard, session: Session | None = None
) -> list[BaseTool]:
    """Guard every tool in ``tools``. See :func:`guard_tool`."""
    return [guard_tool(t, guard, session) for t in tools]
