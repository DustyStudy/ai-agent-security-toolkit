"""Enforcement point between a model's tool requests and the code that runs them."""

from __future__ import annotations

import functools
import threading
import uuid
from collections import Counter
from collections.abc import Callable
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


Approver = Callable[[ToolCall, Decision], bool]


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
        """Evaluate, run approval if required, record the call, and audit. Never raises."""
        session = session or self.default_session
        self._audit("tool_request", session, tool=call.name, arguments=call.arguments)
        decision = self.evaluate(call, session)

        if decision.verdict == Verdict.APPROVE:
            if self.approver is None:
                decision = Decision(
                    Verdict.DENY, call.name, (*decision.reasons, "no approver configured")
                )
            else:
                approved = bool(self.approver(call, decision))
                self._audit("approval", session, tool=call.name, approved=approved)
                decision = (
                    Decision(Verdict.ALLOW, call.name, decision.reasons)
                    if approved
                    else Decision(Verdict.DENY, call.name, (*decision.reasons, "approval refused"))
                )

        if decision.allowed:
            with self._lock:
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
        decision = self.authorize(call, session)
        if not decision.allowed:
            raise ToolDenied(decision)
        result = fn(**call.arguments)
        rule = self.policy.tools[call.name]
        if rule.returns_untrusted:
            session.mark_untrusted(call.name)
        self._audit("tool_result", session, tool=call.name, result=result)
        return result

    def wrap(
        self, name: str, fn: Callable[..., Any], session: Session | None = None
    ) -> Callable[..., Any]:
        """Return ``fn`` guarded as tool ``name``. Keyword arguments only."""

        @functools.wraps(fn)
        def guarded(**kwargs: Any) -> Any:
            return self.execute(ToolCall(name=name, arguments=kwargs), fn, session)

        return guarded

    def _audit(self, event: str, session: Session, **data: Any) -> None:
        if self.audit is not None:
            self.audit.log(event, tool_session=session.id, **data)
