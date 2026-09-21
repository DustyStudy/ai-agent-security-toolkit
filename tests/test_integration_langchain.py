"""guard_tool / guard_tools against real langchain-core (and LangGraph when installed).

Skipped unless ``langchain-core`` is installed (``pip install "ai-agent-security-toolkit[langchain]"``).
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("langchain_core")

from langchain_core.callbacks import BaseCallbackHandler  # noqa: E402
from langchain_core.tools import tool  # noqa: E402

from agentsec.integrations.langchain import guard_tool, guard_tools  # noqa: E402
from agentsec.middleware import AuditLogger, MemorySink  # noqa: E402
from agentsec.sandbox import Policy, Session, ToolGuard  # noqa: E402

RAN: list[str] = []


@tool
def add(a: int, b: int) -> int:
    """Add two integers."""
    RAN.append("add")
    return a + b


@tool
def search(query: str) -> str:
    """Search the knowledge base."""
    RAN.append("search")
    return f"result for {query}"


@tool
def send_email(to: str) -> str:
    """Send an email."""
    RAN.append("send_email")
    return f"sent to {to}"


@tool
def unlisted(x: str) -> str:
    """A tool the policy does not list."""
    RAN.append("unlisted")
    return x


@tool
async def lookup(customer: str) -> str:
    """Look up a customer (async only)."""
    RAN.append("lookup")
    return f"record for {customer}"


def _guard():
    policy = Policy.from_dict(
        {
            "tools": {
                "add": {
                    "args": {
                        "a": {"type": "integer", "maximum": 10},
                        "b": {"type": "integer", "maximum": 10},
                    }
                },
                "search": {"returns_untrusted": True, "args": {"query": {"type": "string"}}},
                "send_email": {"side_effects": True, "args": {"to": {"type": "string"}}},
                "lookup": {"args": {"customer": {"type": "string"}}},
            }
        }
    )
    sink = MemorySink()
    return ToolGuard(policy, audit=AuditLogger(sink)), sink


@pytest.fixture(autouse=True)
def _reset():
    RAN.clear()


def test_guarded_tool_keeps_name_description_and_argument_schema():
    guard, _ = _guard()
    guarded = guard_tool(add, guard)
    assert (guarded.name, guarded.description) == (add.name, add.description)
    assert guarded.tool_call_schema.model_json_schema() == add.tool_call_schema.model_json_schema()


def test_allowed_calls_run_the_original_tool():
    guard, sink = _guard()
    guarded = guard_tool(add, guard)
    assert guarded.invoke({"a": 2, "b": 3}) == 5
    assert RAN == ["add"]
    assert [r["event"] for r in sink.records] == ["tool_request", "tool_decision", "tool_result"]


def test_policy_denials_become_readable_output_and_never_run_the_tool():
    guard, _ = _guard()
    out = guard_tool(add, guard).invoke({"a": 100, "b": 1})  # a exceeds the policy maximum
    assert "refused by security policy" in out and RAN == []

    out = guard_tool(unlisted, guard).invoke({"x": "hi"})  # not in the policy
    assert "default deny" in out and RAN == []


def test_async_path_and_async_only_tools_work():
    guard, _ = _guard()

    async def go():
        a = await guard_tool(add, guard).ainvoke({"a": 1, "b": 2})
        b = await guard_tool(lookup, guard).ainvoke({"customer": "acme"})
        c = await guard_tool(add, guard).ainvoke({"a": 99, "b": 2})
        return a, b, c

    a, b, c = asyncio.run(go())
    assert (a, b) == (3, "record for acme") and "refused" in c
    assert RAN == ["add", "lookup"]


def test_taint_from_an_untrusted_tool_blocks_a_later_side_effecting_tool():
    guard, _ = _guard()
    session = Session()
    tools = {t.name: t for t in guard_tools([search, send_email], guard, session)}
    assert "result for q3" in tools["search"].invoke({"query": "q3"})
    out = tools["send_email"].invoke({"to": "a@b.example"})
    assert "untrusted content" in out
    assert RAN == ["search"] and session.tainted


def test_run_configuration_reaches_the_original_tool():
    """Callbacks in the caller's config must still fire for the wrapped tool."""

    class Counter(BaseCallbackHandler):
        def __init__(self):
            self.starts: list[str] = []

        def on_tool_start(self, serialized, input_str, **kwargs):
            self.starts.append(kwargs.get("name") or (serialized or {}).get("name", ""))

    guard, _ = _guard()
    handler = Counter()
    guard_tool(add, guard).invoke({"a": 1, "b": 1}, config={"callbacks": [handler]})
    assert handler.starts.count("add") == 2  # the guarded wrapper and the original tool


def test_langgraph_tool_node_round_trip():
    pytest.importorskip("langgraph")
    from langchain_core.messages import AIMessage
    from langgraph.graph import END, START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode

    guard, _ = _guard()
    graph = StateGraph(MessagesState)
    graph.add_node("tools", ToolNode(guard_tools([add], guard)))
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    app = graph.compile()

    def call(a):
        msg = AIMessage(
            content="", tool_calls=[{"name": "add", "args": {"a": a, "b": 1}, "id": "c1"}]
        )
        return app.invoke({"messages": [msg]})["messages"][-1]

    ok, denied = call(4), call(500)
    assert ok.content == "5"
    assert "refused by security policy" in denied.content
    assert RAN == ["add"]
