"""One object that wires scanner + tool guard + output guard + audit log together."""

from __future__ import annotations

from dataclasses import dataclass, field

from agentsec.middleware import audit as ev
from agentsec.middleware.audit import AuditLogger
from agentsec.middleware.injection import InjectionScanner, ScanResult, spotlight
from agentsec.middleware.validators import GuardResult, OutputGuard
from agentsec.sandbox.guard import Decision, Session, ToolGuard
from agentsec.types import ToolCall


@dataclass
class InputScreen:
    text: str
    scan: ScanResult
    blocked: bool = False
    reasons: list[str] = field(default_factory=list)


class AgentMiddleware:
    """The three hook points an agent loop needs.

    * :meth:`screen_input` - before text reaches the model. Untrusted content
      taints the session and (optionally) is wrapped by :func:`spotlight`.
    * :meth:`authorize_tool` - before a tool runs.
    * :meth:`screen_output` - before model text reaches a user or downstream system.

    Every hook writes to the audit log when one is configured.
    """

    def __init__(
        self,
        *,
        guard: ToolGuard | None = None,
        output_guard: OutputGuard | None = None,
        scanner: InjectionScanner | None = None,
        audit: AuditLogger | None = None,
        block_on_injection: bool = True,
        spotlight_untrusted: bool = True,
    ) -> None:
        self.guard = guard
        self.output_guard = output_guard
        self.scanner = scanner
        self.audit = audit
        self.block_on_injection = block_on_injection
        self.spotlight_untrusted = spotlight_untrusted
        if guard is not None and guard.audit is None:
            guard.audit = audit

    def screen_input(
        self,
        text: str,
        *,
        source: str = "user",
        untrusted: bool = False,
        session: Session | None = None,
    ) -> InputScreen:
        scan = self.scanner.scan(text) if self.scanner else ScanResult(score=0.0)
        if untrusted and session is not None:
            session.mark_untrusted(source)
        self._log(ev.UNTRUSTED_INPUT if untrusted else ev.PROMPT, source=source, text=text)
        blocked = bool(scan.flagged and self.block_on_injection)
        if scan.signals:
            self._log(
                ev.INJECTION_SIGNAL,
                source=source,
                score=round(scan.score, 2),
                signals=scan.signals,
                blocked=blocked,
            )
        out = spotlight(text, source=source) if untrusted and self.spotlight_untrusted else text
        reasons = [f"injection signals: {', '.join(scan.signals)}"] if blocked else []
        return InputScreen(text=out, scan=scan, blocked=blocked, reasons=reasons)

    def authorize_tool(self, call: ToolCall, session: Session | None = None) -> Decision:
        if self.guard is None:
            raise RuntimeError("AgentMiddleware was created without a ToolGuard")
        return self.guard.authorize(call, session)

    def screen_output(self, text: str) -> GuardResult:
        if self.output_guard is None:
            return GuardResult(text=text, allowed=True)
        result = self.output_guard.process(text)
        self._log(ev.MODEL_OUTPUT, text=text, delivered=result.allowed)
        if result.violations:
            self._log(
                ev.VALIDATION,
                violations=[
                    {"validator": v.validator, "message": v.message, "action": v.action.value}
                    for v in result.violations
                ],
                allowed=result.allowed,
            )
        return result

    def _log(self, event: str, **data: object) -> None:
        if self.audit is not None:
            self.audit.log(event, **data)
