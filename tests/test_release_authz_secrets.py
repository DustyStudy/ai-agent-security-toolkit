"""Release review of tool-call authorization, output validation and secret handling.

Each test pins one gap found in that review: the failure it describes was reproduced on the
code before the fix.
"""

from __future__ import annotations

import asyncio
import dataclasses
import sys
import threading
from typing import Any

import pytest

from agentsec.integrations.mcp import GuardedMCPClient
from agentsec.middleware import AuditLogger, MemorySink
from agentsec.middleware.audit import verify_records
from agentsec.middleware.redact import redact_text
from agentsec.middleware.validators import (
    MAX_JSON_DEPTH,
    JsonSchemaValidator,
    OutputGuard,
    SecretLeakValidator,
)
from agentsec.sandbox import Policy, Session, ToolDenied, ToolGuard
from agentsec.sandbox.guard import Verdict
from agentsec.types import ToolCall


def _approval_policy() -> Policy:
    return Policy.from_dict(
        {
            "tools": {
                "send": {"side_effects": True, "require_approval": True, "allow_extra_args": True}
            }
        }
    )


def _events(sink: MemorySink, event: str) -> list[dict[str, Any]]:
    return [r["data"] for r in sink.records if r["event"] == event]


# ------------------------------------------------------------------------ approvers


@pytest.mark.parametrize("answer", ["n", "no", "false", 1, [False], object()])
def test_only_a_boolean_true_from_the_approver_approves(answer):
    # approver=lambda call, d: input("approve? ") returned "n", which bool() read as a yes.
    sink = MemorySink()
    guard = ToolGuard(_approval_policy(), approver=lambda c, d: answer, audit=AuditLogger(sink))
    decision = guard.authorize(ToolCall("send", {}), Session())
    assert decision.verdict == Verdict.DENY
    assert "non-boolean" in decision.message()
    assert _events(sink, "approval")[-1]["approved"] is False


def test_a_non_boolean_answer_is_refused_on_the_async_path_too():
    async def async_no(call, decision):
        return "no"

    for approver in (lambda c, d: "no", async_no):
        guard = ToolGuard(_approval_policy(), approver=approver)
        decision = asyncio.run(guard.aauthorize(ToolCall("send", {}), Session()))
        assert decision.verdict == Verdict.DENY


def test_boolean_answers_still_work():
    yes = ToolGuard(_approval_policy(), approver=lambda c, d: True)
    no = ToolGuard(_approval_policy(), approver=lambda c, d: False)
    assert yes.authorize(ToolCall("send", {}), Session()).allowed
    assert not no.authorize(ToolCall("send", {}), Session()).allowed


def test_an_approver_that_raises_refuses_the_call_and_the_refusal_is_audited():
    # The exception used to escape authorize() with only a tool_request in the audit log.
    def timed_out(call, decision):
        raise TimeoutError("nobody answered; token=abcd1234")

    sink = MemorySink()
    guard = ToolGuard(_approval_policy(), approver=timed_out, audit=AuditLogger(sink))
    session = Session()
    ran: list[str] = []
    with pytest.raises(ToolDenied) as info:
        guard.execute(ToolCall("send", {}), lambda: ran.append("send"), session)
    assert ran == []
    assert "approver failed (TimeoutError)" in info.value.decision.message()
    assert "abcd1234" not in info.value.decision.message()
    assert _events(sink, "tool_decision")[-1]["verdict"] == "deny"
    assert _events(sink, "approval")[-1]["approved"] is False
    assert session.total_calls == 0


def test_an_async_approver_that_raises_refuses_the_call():
    async def broken(call, decision):
        raise ConnectionError("approval service down")

    for approver in (broken, lambda c, d: 1 / 0):
        guard = ToolGuard(_approval_policy(), approver=approver)
        decision = asyncio.run(guard.aauthorize(ToolCall("send", {}), Session()))
        assert decision.verdict == Verdict.DENY
        assert "approver failed" in decision.message()


def test_cancelling_the_approver_still_cancels_the_call():
    async def waits(call, decision):
        await asyncio.sleep(3600)
        return True

    guard = ToolGuard(_approval_policy(), approver=waits)
    session = Session()

    async def main():
        task = asyncio.create_task(guard.aauthorize(ToolCall("send", {}), session))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(main())
    assert session.total_calls == 0


# ----------------------------------------------------------------- evaluate / args


def test_a_non_string_tool_name_is_denied_not_a_crash():
    guard = ToolGuard(_approval_policy())
    for name in (["send"], {"a": 1}, None):
        call = ToolCall(name=name, arguments={})  # type: ignore[arg-type]
        assert guard.authorize(call, Session()).verdict == Verdict.DENY
        assert asyncio.run(guard.aauthorize(call, Session())).verdict == Verdict.DENY


def _enum_guard(enum: list[Any]) -> ToolGuard:
    return ToolGuard(
        Policy.from_dict({"tools": {"pick": {"args": {"v": {"type": "any", "enum": enum}}}}})
    )


@pytest.mark.parametrize(
    ("enum", "value"),
    [
        ([0, 1], True),
        ([0, 1], False),
        ([True], 1),
        ([1.0], True),
        ([{"admin": False}], {"admin": 0}),
        ([[0, 1]], [False, True]),
        ([[1, 2]], (1, 2)),
    ],
)
def test_enum_membership_does_not_equate_booleans_and_numbers(enum, value):
    # True == 1 in Python, so `true` passed enum [0, 1] on an untyped argument.
    assert _enum_guard(enum).evaluate(ToolCall("pick", {"v": value})).verdict == Verdict.DENY


@pytest.mark.parametrize(
    ("enum", "value"),
    [([0, 1], 1), ([1.0], 1), ([True, False], False), (["a"], "a"), ([{"k": [1]}], {"k": [1]})],
)
def test_enum_membership_still_accepts_equal_values(enum, value):
    assert _enum_guard(enum).evaluate(ToolCall("pick", {"v": value})).allowed


def test_a_session_shared_by_two_guards_keeps_its_total_cap_under_threads():
    # The commit lock was per guard, so two guards (one per MCP server, say) sharing one
    # session could both pass the cap check before either counted.
    policy = Policy.from_dict({"tools": {"t": {}}, "max_total_calls": 40})
    guards = [ToolGuard(policy), ToolGuard(policy)]
    assert guards[0]._lock is guards[1]._lock
    session = Session()
    allowed: list[bool] = []
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:

        def worker(guard: ToolGuard) -> None:
            for _ in range(60):
                allowed.append(guard.authorize(ToolCall("t", {}), session).allowed)

        threads = [threading.Thread(target=worker, args=(guards[i % 2],)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(old)
    assert sum(allowed) == 40
    assert session.total_calls == 40


# ------------------------------------------------------------- structured output


@pytest.mark.parametrize("text", ["1e400", "-1e400", '{"amount": 1e999}'])
def test_json_schema_validator_refuses_numbers_that_parse_to_infinity(text):
    validator = JsonSchemaValidator({"type": ["number", "object"]})
    violations = validator.check(text)
    assert violations and "not valid JSON" in violations[0].message


def test_json_schema_validator_reports_deep_nesting_instead_of_raising():
    validator = JsonSchemaValidator({"type": "array"})
    deep = "[" * 100_000 + "]" * 100_000
    assert validator.check(deep)
    result = OutputGuard([validator]).process(deep)
    assert not result.allowed


def test_json_schema_validator_depth_limit_does_not_depend_on_the_python_version():
    # Python 3.14's json parses 100,000 levels that 3.13 refused with RecursionError; the
    # explicit limit keeps the verdict the same on every supported version.
    validator = JsonSchemaValidator({"type": "array"})
    limit = MAX_JSON_DEPTH
    assert validator.check("[" * limit + "]" * limit) == []
    over = validator.check("[" * (limit + 1) + "]" * (limit + 1))
    assert over and "nested too deeply" in over[0].message


def test_json_schema_validator_reports_nesting_too_deep_for_the_schema_check():
    # Parses fine, but a recursive schema walks it a few stack frames per level.
    validator = JsonSchemaValidator(
        {"$ref": "#/$defs/n", "$defs": {"n": {"items": {"$ref": "#/$defs/n"}}}}
    )
    assert validator.check("[" * 50 + "]" * 50) == []
    violations = validator.check("[" * 900 + "]" * 900)
    assert violations and "too deeply" in violations[0].message


def test_json_schema_validator_refuses_duplicate_keys():
    # The schema saw the last "role"; a consumer keeping the first would act on "admin".
    validator = JsonSchemaValidator(
        {"type": "object", "properties": {"role": {"enum": ["user"]}}, "required": ["role"]}
    )
    violations = validator.check('{"role": "admin", "role": "user"}')
    assert violations and "duplicate key" in violations[0].message
    assert validator.check('{"role": "user", "nested": {"a": 1, "b": 2}}') == []


# ------------------------------------------------------------------------ redaction

_SECRETS = [
    ("Authorization: Bearer abc.def-ghi", "abc.def-ghi"),
    ("Authorization: token ghx123", "ghx123"),
    ("Proxy-Authorization: Bearer s3cr3t", "s3cr3t"),
    (
        "xa" + "pp-1-A0123456789-1234567890123-0123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcdef",
    ),
    ("xo" + "xe-1-My0xLTEyMzQ1Njc4OTAtMTIzNDU2Nzg5MC0x", "My0xLTEyMzQ1Njc4OTAtMTIzNDU2Nzg5MC0x"),
    (
        "https://hooks.slack" + ".com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
        "XXXXXXXXXXXXXXXXXXXXXXXX",
    ),
    ("ya" + "29.a0AfH6SMBx3abcdefghijklmnopqrstuvwxyz0123456789", "a0AfH6SMBx3abcdefghij"),
    ("SECRET_KEY=django-insecure-abc123", "django-insecure-abc123"),
    ("private_" + "key: " + "abcdefgh" + "12345678", "abcdefgh12345678"),
    ("signing" + "Key='" + "abcdefgh" + "12345678'", "abcdefgh12345678"),
    ("access_" + "key=" + "abcd1234" + "efgh", "abcd1234efgh"),
    ("aws_secret_access_key=" + "A" * 44, "A" * 44),
    ("Cookie: sessionid=abcdef0123456789; csrftoken=zyx987", "abcdef0123456789"),
    ("Set-Cookie: sid=abcdef0123456789; HttpOnly", "abcdef0123456789"),
    ("Cfg(private_key='PK1234567')", "PK1234567"),
]


@pytest.mark.parametrize(("text", "secret"), _SECRETS)
def test_common_secret_formats_are_redacted(text, secret):
    redacted, findings = redact_text(text)
    assert findings
    assert secret not in redacted
    # Idempotent, so OutputGuard's recheck does not take the placeholder for a leftover.
    assert redact_text(redacted)[0] == redacted
    result = OutputGuard([SecretLeakValidator()]).process(text)
    assert result.allowed and secret not in result.text


@pytest.mark.parametrize(
    "token",
    [
        "ey"
        + "JhbGciOiJIUzI1NiJ9.ey"
        + "JzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR-",
        "sk-" + "ant-api03-" + "A" * 40 + "-",
        "xo" + "xb-123456789012-1234567890123-abcdefghij-",
    ],
)
def test_a_token_ending_in_a_dash_is_redacted_whole(token):
    # \b at the end stopped before a trailing "-", which was left in the output.
    redacted, _ = redact_text(f"value {token} end")
    assert redacted.startswith("value [REDACTED:") and redacted.endswith("] end")


@pytest.mark.parametrize(
    "text",
    ["Cookie: oatmeal raisin", "Authorization: required", "the access key rotation", "key=value"],
)
def test_prose_near_the_new_rules_is_left_alone(text):
    assert redact_text(text) == (text, [])


# --------------------------------------------------------------------------- audit


def test_audit_redacts_auth_tuples_and_header_pairs():
    sink = MemorySink()
    log = AuditLogger(sink)
    log.log(
        "tool_request",
        arguments={
            "auth": ("alice", "hunter2"),
            "headers": [("Authorization", "Bearer abc"), ["X-Api-Key", "k1"], ("Accept", "json")],
            "basic_auth": ["bob", "pw2"],
        },
    )
    text = repr(sink.records[-1])
    for secret in ("hunter2", "Bearer abc", "k1", "pw2"):
        assert secret not in text
    assert "Accept" in text and "json" in text


def test_pair_handling_keeps_log_content_false_hashing():
    sink = MemorySink()
    log = AuditLogger(sink, log_content=False, preview_chars=8)
    log.log("prompt", parts=["a long prompt that must not be stored", "second part here"])
    parts = sink.records[-1]["data"]["parts"]
    assert all(isinstance(p, dict) and "sha256" in p for p in parts)


def test_two_loggers_on_one_memory_sink_share_one_chain():
    # Each started at seq 0, so the sink held two interleaved chains that never verified.
    sink = MemorySink()
    first, second = AuditLogger(sink), AuditLogger(sink)
    for i in range(6):
        (first if i % 2 else second).log("event", i=i)
    assert verify_records(sink.records).ok
    assert [r["seq"] for r in sink.records] == list(range(6))


def test_loggers_on_different_memory_sinks_keep_separate_chains():
    a, b = MemorySink(), MemorySink()
    AuditLogger(a).log("x")
    AuditLogger(b).log("y")
    assert a.records[0]["seq"] == b.records[0]["seq"] == 0


def test_dataclass_arguments_do_not_leak_key_fields():
    @dataclasses.dataclass
    class Creds:
        private_key: str
        signing_key: str

    sink = MemorySink()
    AuditLogger(sink).log("tool_request", arguments={"creds": Creds("PKVALUE123", "SKVALUE456")})
    text = repr(sink.records[-1])
    assert "PKVALUE123" not in text and "SKVALUE456" not in text


# ----------------------------------------------------------------------------- MCP


class _Tool:
    def __init__(self, name: str) -> None:
        self.name = name
        self.description = f"{name} tool"
        self.inputSchema = {"type": "object"}


class _Listing:
    def __init__(self, tools: list[Any]) -> None:
        self.tools = tools
        self.nextCursor = None


class _SlowClient:
    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.started = asyncio.Event()
        self.calls: list[str] = []

    async def list_tools(self, **kwargs: Any) -> _Listing:
        return _Listing([_Tool("fetch"), _Tool("send")])

    async def call_tool(self, name: str, arguments: dict[str, Any], **kwargs: Any) -> str:
        self.calls.append(name)
        if name == "fetch":
            self.started.set()
            await self.release.wait()
        return f"{name} done"


def test_mcp_taints_before_the_request_so_an_overlapping_side_effect_is_refused():
    # The session was tainted only after the result came back, so a side-effecting call made
    # while an untrusted fetch was in flight (or after one that raised) went through.
    policy = Policy.from_dict({"tools": {"fetch": {}, "send": {"side_effects": True}}})
    guard = ToolGuard(policy)
    session = Session()

    async def main() -> None:
        client = _SlowClient()
        guarded = GuardedMCPClient(client, guard, session)
        await guarded.list_tools()
        fetch = asyncio.create_task(guarded.call_tool("fetch", {}))
        await client.started.wait()
        assert session.tainted
        with pytest.raises(ToolDenied):
            await guarded.call_tool("send", {})
        client.release.set()
        assert await fetch == "fetch done"
        assert client.calls == ["fetch"]

    asyncio.run(main())


def test_mcp_refused_call_does_not_taint():
    policy = Policy.from_dict({"tools": {"fetch": {"args": {"q": {"type": "string"}}}}})
    guard = ToolGuard(policy)
    session = Session()

    async def main() -> None:
        guarded = GuardedMCPClient(_SlowClient(), guard, session)
        await guarded.list_tools()
        with pytest.raises(ToolDenied):
            await guarded.call_tool("fetch", {"q": 1})

    asyncio.run(main())
    assert not session.tainted


# ------------------------------------------------------------------------ LangChain


def test_langchain_single_input_tool_keeps_its_schema_and_is_guarded():
    # A legacy Tool was wrapped as a StructuredTool advertising args/config/kwargs, and its
    # string input raised TypeError.
    pytest.importorskip("langchain_core")
    from langchain_core.tools import Tool
    from langchain_core.utils.function_calling import convert_to_openai_tool

    from agentsec.integrations.langchain import guard_tool

    ran: list[str] = []
    legacy = Tool(name="lookup", func=lambda q: ran.append(q) or f"found {q}", description="d")
    policy = Policy.from_dict(
        {"tools": {"lookup": {"args": {"tool_input": {"type": "string", "max_length": 5}}}}}
    )
    guarded = guard_tool(legacy, ToolGuard(policy), Session())
    assert (
        convert_to_openai_tool(guarded)["function"]["parameters"]
        == (convert_to_openai_tool(legacy)["function"]["parameters"])
    )
    assert guarded.invoke("abc") == "found abc"
    assert guarded.invoke({"__arg1": "xyz"}) == "found xyz"
    assert "refused by security policy" in guarded.invoke("too long for policy")
    assert asyncio.run(guarded.ainvoke("def")) == "found def"
    assert ran == ["abc", "xyz", "def"]


def test_langchain_tool_with_an_aliased_field_runs_when_allowed():
    # The guard saw field names and passed them on, but the tool validates the alias only:
    # every allowed call failed with a ValidationError.
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool
    from pydantic import BaseModel, Field

    from agentsec.integrations.langchain import guard_tool

    class Args(BaseModel):
        to: str = Field(alias="recipient")

    @tool(args_schema=Args)
    def notify(to: str) -> str:
        """Notify someone."""
        return f"sent to {to}"

    policy = Policy.from_dict(
        {"tools": {"notify": {"args": {"to": {"type": "string", "pattern": r"[a-z]+@corp\.com"}}}}}
    )
    guarded = guard_tool(notify, ToolGuard(policy), Session())
    assert guarded.invoke({"recipient": "bob@corp.com"}) == "sent to bob@corp.com"
    assert "refused" in guarded.invoke({"recipient": "eve@evil.example"})
    assert asyncio.run(guarded.ainvoke({"recipient": "bob@corp.com"})) == "sent to bob@corp.com"


@pytest.mark.filterwarnings("ignore::UserWarning")  # pydantic.v1 warns on Python 3.14
def test_langchain_tool_with_a_pydantic_v1_aliased_field_runs_when_allowed():
    pytest.importorskip("langchain_core")
    v1 = pytest.importorskip("pydantic.v1")
    from langchain_core.tools import tool

    from agentsec.integrations.langchain import guard_tool

    class Args(v1.BaseModel):
        to: str = v1.Field(alias="recipient")

    class ByName(v1.BaseModel):
        to: str = v1.Field(alias="recipient")

        class Config:
            allow_population_by_field_name = True

    policy = Policy.from_dict(
        {"tools": {"notify": {"args": {"to": {"type": "string", "pattern": r"[a-z]+@corp\.com"}}}}}
    )
    for schema in (Args, ByName):

        @tool(args_schema=schema)
        def notify(to: str) -> str:
            """Notify someone."""
            return f"sent to {to}"

        guarded = guard_tool(notify, ToolGuard(policy), Session())
        assert guarded.invoke({"recipient": "bob@corp.com"}) == "sent to bob@corp.com"
        assert "refused" in guarded.invoke({"recipient": "eve@evil.example"})
        assert asyncio.run(guarded.ainvoke({"recipient": "bob@corp.com"})) == "sent to bob@corp.com"
