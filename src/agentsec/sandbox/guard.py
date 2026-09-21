"""Enforcement point between a model's tool requests and the code that runs them."""

from __future__ import annotations

import asyncio
import copy
import functools
import inspect
import threading
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from agentsec.sandbox.policy import Policy
from agentsec.sandbox.validators import Resolver, check_arg
from agentsec.types import ToolCall

if TYPE_CHECKING:
    from agentsec.middleware.audit import AuditLogger


class Verdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVE = "needs_approval"


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    tool: str
    reasons: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.verdict == Verdict.ALLOW

    def message(self) -> str:
        return "; ".join(self.reasons) or self.verdict.value


class ToolDenied(PermissionError):
    def __init__(self, decision: Decision) -> None:
        super().__init__(f"tool {decision.tool!r} denied: {decision.message()}")
        self.decision = decision


@dataclass
class Session:
    """Per-conversation state: call counters and the untrusted-content taint flag.

    The taint flag is the core of the "lethal trifecta" mitigation. Once an
    agent has read attacker-influenceable content (web page, email, retrieved
    document, another tool's output) the model's next actions can no longer be
    trusted to reflect the user's intent, so side-effecting tools are denied or
    sent for human approval for the rest of the session.
    """

    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    calls: Counter[str] = field(default_factory=Counter)
    total_calls: int = 0
    tainted: bool = False
    taint_sources: list[str] = field(default_factory=list)

    def mark_untrusted(self, source: str) -> None:
        self.tainted = True
        if source not in self.taint_sources:
            self.taint_sources.append(source)


Approver = Callable[[ToolCall, Decision], bool | Awaitable[bool]]

_ASYNC_APPROVER_REASON = "approver is async; use aauthorize()/aexecute() instead of the sync API"


class ToolGuard:
    """Evaluate, gate, and optionally execute tool calls under a :class:`Policy`."""

    def __init__(
        self,
        policy: Policy,
        *,
        approver: Approver | None = None,
        audit: AuditLogger | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        self.policy = policy
        self.approver = approver
        self.audit = audit
        self._resolver = resolver
        # A DNS-resolving URL rule (or a custom resolver) does blocking I/O inside evaluate(),
        # so the async API runs evaluation in a worker thread instead of on the event loop.
        self._blocking_eval = resolver is not None or any(
            arg.resolve_dns for rule in policy.tools.values() for arg in rule.args.values()
        )
        self._lock = threading.Lock()
        self.default_session = Session()

    # ------------------------------------------------------------- evaluation
    def evaluate(self, call: ToolCall, session: Session | None = None) -> Decision:
        """Pure policy check. Does not consume rate limits or contact the approver."""
        session = session or self.default_session
        rule = self.policy.tools.get(call.name)
        if rule is None:
            return Decision(Verdict.DENY, call.name, ("tool not in policy (default deny)",))
        if not rule.allow:
            return Decision(Verdict.DENY, call.name, ("tool explicitly disabled",))

        reasons: list[str] = []
        args = call.arguments
        if not isinstance(args, dict):
            return Decision(Verdict.DENY, call.name, ("arguments must be an object",))

        for arg_name in args:
            if arg_name not in rule.args and not rule.allow_extra_args:
                reasons.append(f"unexpected argument {arg_name!r}")
        for arg_name, arg_rule in rule.args.items():
            if arg_name not in args:
                if arg_rule.required:
                    reasons.append(f"missing required argument {arg_name!r}")
                continue
            for err in check_arg(args[arg_name], arg_rule, resolver=self._resolver):
                reasons.append(f"argument {arg_name!r}: {err}")

        if rule.max_calls is not None and session.calls[call.name] >= rule.max_calls:
            reasons.append(f"per-session limit of {rule.max_calls} calls reached")
        cap = self.policy.max_total_calls
        if cap is not None and session.total_calls >= cap:
            reasons.append(f"session total limit of {cap} tool calls reached")
        if reasons:
            return Decision(Verdict.DENY, call.name, tuple(reasons))

        needs_approval: list[str] = []
        if rule.require_approval:
            needs_approval.append("policy requires human approval")
        if self.policy.taint.enabled and session.tainted and rule.side_effects:
            why = (
                "session has ingested untrusted content ("
                + ", ".join(session.taint_sources)
                + ") and this tool has side effects"
            )
            if self.policy.taint.action == "deny":
                return Decision(Verdict.DENY, call.name, (why,))
            needs_approval.append(why)
        if needs_approval:
            return Decision(Verdict.APPROVE, call.name, tuple(needs_approval))
        return Decision(Verdict.ALLOW, call.name)

    # ---------------------------------------------------------- authorization
    def authorize(self, call: ToolCall, session: Session | None = None) -> Decision:
        """Evaluate, run approval if required, record the call, and audit."""
        session = session or self.default_session
        decision = self._begin(call, session)
        if decision.verdict == Verdict.APPROVE:
            if self.approver is None:
                decision = self._resolve_approval(call, session, decision, None)
            else:
                answer = self.approver(call, decision)
                if inspect.isawaitable(answer):
                    # An un-awaited coroutine is truthy: treating it as an answer would
                    # approve every request. Discard it and refuse.
                    if inspect.iscoroutine(answer):
                        answer.close()
                    decision = Decision(
                        Verdict.DENY, call.name, (*decision.reasons, _ASYNC_APPROVER_REASON)
                    )
                    self._audit("approval", session, tool=call.name, approved=False)
                else:
                    decision = self._resolve_approval(call, session, decision, bool(answer))
        return self._commit(call, session, decision)

    async def aauthorize(self, call: ToolCall, session: Session | None = None) -> Decision:
        """Async :meth:`authorize`. The approver may be a plain function or a coroutine function."""
        session = session or self.default_session
        decision = await self._abegin(call, session)
        if decision.verdict == Verdict.APPROVE:
            if self.approver is None:
                decision = self._resolve_approval(call, session, decision, None)
            else:
                answer = self.approver(call, decision)
                if inspect.isawaitable(answer):
                    answer = await answer
                decision = self._resolve_approval(call, session, decision, bool(answer))
        return self._commit(call, session, decision)

    def _begin(self, call: ToolCall, session: Session) -> Decision:
        self._audit("tool_request", session, tool=call.name, arguments=call.arguments)
        return self.evaluate(call, session)

    async def _abegin(self, call: ToolCall, session: Session) -> Decision:
        self._audit("tool_request", session, tool=call.name, arguments=call.arguments)
        if self._blocking_eval:
            return await asyncio.to_thread(self.evaluate, call, session)
        return self.evaluate(call, session)

    def _resolve_approval(
        self, call: ToolCall, session: Session, decision: Decision, approved: bool | None
    ) -> Decision:
        """Turn an approver's answer (``None`` = no approver configured) into a final decision."""
        if approved is None:
            return Decision(Verdict.DENY, call.name, (*decision.reasons, "no approver configured"))
        self._audit("approval", session, tool=call.name, approved=approved)
        if approved:
            return Decision(Verdict.ALLOW, call.name, decision.reasons)
        return Decision(Verdict.DENY, call.name, (*decision.reasons, "approval refused"))

    def _commit(self, call: ToolCall, session: Session, decision: Decision) -> Decision:
        if decision.allowed:
            with self._lock:
                # evaluate() ran without the lock (and an approver may have blocked for a
                # long time), so concurrent calls could all have passed the limit check.
                # Re-check and count atomically so a limit really is a limit. This section
                # never awaits, so it is equally atomic for asyncio tasks.
                over = self._over_limit(call.name, session)
                if over is not None:
                    decision = Decision(Verdict.DENY, call.name, (over,))
                else:
                    session.calls[call.name] += 1
                    session.total_calls += 1
        self._audit(
            "tool_decision",
            session,
            tool=call.name,
            verdict=decision.verdict.value,
            reasons=list(decision.reasons),
        )
        return decision

    def execute(
        self, call: ToolCall, fn: Callable[..., Any], session: Session | None = None
    ) -> Any:
        """Authorize then run ``fn(**call.arguments)``. Raises :class:`ToolDenied`."""
        session = session or self.default_session
        call = self._snapshot(call)
        decision = self.authorize(call, session)
        if not decision.allowed:
            raise ToolDenied(decision)
        rule = self.policy.tools[call.name]
        try:
            result = fn(**call.arguments)
            if inspect.isawaitable(result):
                # Calling an async tool from the sync path would hand the model a coroutine
                # object as if it were the tool's output, and the tool would never run.
                if inspect.iscoroutine(result):
                    result.close()
                raise TypeError(f"tool {call.name!r} is async; use aexecute()/awrap()")
        finally:
            # Taint even if the tool raised: it may already have fetched attacker-controlled
            # content before failing, and the model is shown the error either way.
            if rule.returns_untrusted:
                session.mark_untrusted(call.name)
        self._audit("tool_result", session, tool=call.name, result=result)
        return result

    async def aexecute(
        self, call: ToolCall, fn: Callable[..., Any], session: Session | None = None
    ) -> Any:
        """Async :meth:`execute`.

        ``fn`` may be a coroutine function or an ordinary function. Ordinary functions run in
        a worker thread so a blocking tool cannot stall the event loop.
        """
        session = session or self.default_session
        call = self._snapshot(call)
        decision = await self.aauthorize(call, session)
        if not decision.allowed:
            raise ToolDenied(decision)
        rule = self.policy.tools[call.name]
        try:
            if _is_coroutine_callable(fn):
                result = await fn(**call.arguments)
            else:
                result = await asyncio.to_thread(fn, **call.arguments)
                if inspect.isawaitable(result):
                    result = await result
        finally:
            # Also runs on cancellation: a worker thread cannot be interrupted, so the tool
            # may still have read untrusted content even though this task was cancelled.
            if rule.returns_untrusted:
                session.mark_untrusted(call.name)
        self._audit("tool_result", session, tool=call.name, result=result)
        return result

    @staticmethod
    def _snapshot(call: ToolCall) -> ToolCall:
        # Judge and run the SAME snapshot: the caller (or another thread/task) still holds the
        # original dict and could change it between authorization and execution.
        return ToolCall(name=call.name, arguments=copy.deepcopy(call.arguments), id=call.id)

    def wrap(
        self, name: str, fn: Callable[..., Any], session: Session | None = None
    ) -> Callable[..., Any]:
        """Return ``fn`` guarded as tool ``name``. Keyword arguments only."""

        @functools.wraps(fn)
        def guarded(**kwargs: Any) -> Any:
            return self.execute(ToolCall(name=name, arguments=kwargs), fn, session)

        return guarded

    def awrap(
        self, name: str, fn: Callable[..., Any], session: Session | None = None
    ) -> Callable[..., Awaitable[Any]]:
        """Return ``fn`` guarded as tool ``name`` for use from async code. Keyword arguments only."""

        @functools.wraps(fn)
        async def guarded(**kwargs: Any) -> Any:
            return await self.aexecute(ToolCall(name=name, arguments=kwargs), fn, session)

        return guarded

    def _over_limit(self, name: str, session: Session) -> str | None:
        rule = self.policy.tools[name]
        if rule.max_calls is not None and session.calls[name] >= rule.max_calls:
            return f"per-session limit of {rule.max_calls} calls reached"
        cap = self.policy.max_total_calls
        if cap is not None and session.total_calls >= cap:
            return f"session total limit of {cap} tool calls reached"
        return None

    def _audit(self, event: str, session: Session, **data: Any) -> None:
        if self.audit is not None:
            self.audit.log(event, tool_session=session.id, **data)


def _is_coroutine_callable(fn: Callable[..., Any]) -> bool:
    """True for ``async def`` functions, including partials and objects with ``async __call__``."""
    return inspect.iscoroutinefunction(fn) or inspect.iscoroutinefunction(
        getattr(fn, "__call__", None)  # noqa: B004 - deliberate: detect an async __call__
    )
