"""Apply a tool policy and taint tracking to a coding agent's own tools, as a hook.

The gateway enforces policy on the calls it makes itself. A coding agent's shell, file and
fetch tools run on the developer's machine and never pass through it, so an instruction
planted in a tool result (a forged error event, a fetched web page) can go straight to a shell
command. Which tools count as untrusted is the policy's choice: a file read taints the session
only if the policy marks the read tool ``returns_untrusted``. Claude Code runs a ``PreToolUse`` hook before every tool call; ``agentsec hook`` is
that hook. It evaluates the call against a :class:`~agentsec.sandbox.Policy` and answers:

* allowed: says nothing, so the agent's normal permission prompts still apply;
* denied: exit code 2, which blocks the call and shows the model the reason;
* needs approval (``require_approval``, or taint with ``action: approve``): asks the human
  through the agent's own permission prompt. With ``block_approvals`` (``--block-approvals``)
  it is exit code 2 instead: for runs with nobody to answer, and for Claude Code versions
  where a hook's ``ask`` was reported to displace a ``permissions.deny`` rule.

Each invocation is a new process, so the session's taint flag and call counts are kept in an
append-only file per session under ``state_dir``. A call to a tool marked ``returns_untrusted``
taints the session when the call is let through, not when it returns: one hook event is then
enough, and a missing ``PostToolUse`` registration cannot silently turn taint off. A call the
human then declines has still tainted the session.

Limits. The agent runs as the same user as the hook, so a shell command can delete the state
file; keep ``state_dir`` outside every path the policy lets the agent write, and expect the
control to hold only while shell access is itself side-effecting under the policy. Anything
but exit code 2 lets the call through, including a hook that times out: register it with
``"onFailure": "block"``.
"""

from __future__ import annotations

import hashlib
import json
import sys
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentsec.middleware.audit import AuditLogger, FileSink
from agentsec.sandbox import Policy, Session, ToolGuard
from agentsec.sandbox.guard import Decision, Verdict
from agentsec.sandbox.validators import Resolver, _default_resolver, check_arg
from agentsec.types import ToolCall

BLOCK = 2  # the only exit code Claude Code treats as "do not run the tool"
# Events that name a tool but have nothing left to gate: the tool has already run.
NOT_GATED = frozenset({"PostToolUse", "PostToolUseFailure"})
DNS_TIMEOUT = 5.0  # seconds per host


@dataclass(frozen=True)
class HookResult:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    """Serialise hook processes: parallel tool calls each start one.

    Without it two calls could both pass a call limit, and two audit records could chain off
    the same predecessor. The lock dies with the process, so a crash cannot leave it held.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as fh:
        if sys.platform == "win32":
            import msvcrt

            fh.seek(0)
            # Retries for about ten seconds, then raises OSError: the call is blocked.
            msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(fh, fcntl.LOCK_EX)
        yield


def _state_file(state_dir: Path, session_id: str) -> Path:
    # Hashed: the id comes from the hook input and must not be able to name a path.
    return state_dir / (hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:32] + ".jsonl")


def load_session(path: Path, session_id: str) -> Session:
    """Rebuild a session from its record of calls. A corrupt record raises, which blocks."""
    session = Session(id=session_id)
    if not path.exists():
        return session
    for line in path.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        name = record["call"]
        if not isinstance(name, str):
            raise ValueError("session state: 'call' must be a string")
        session.calls[name] += 1
        session.total_calls += 1
        untrusted = record["untrusted"]
        if not isinstance(untrusted, bool):
            # "true" or a missing field must not read as "not tainted".
            raise ValueError("session state: 'untrusted' must be true or false")
        if untrusted:
            session.mark_untrusted(name)
    return session


def _resolve(host: str) -> list[str]:
    """Resolve ``host`` within DNS_TIMEOUT, or raise OSError, which the URL check denies on.

    getaddrinfo has no timeout of its own, so it runs in a daemon thread that is abandoned
    when it is late; the hook process exits right after.
    """
    found: list[list[str]] = []

    def work() -> None:
        try:
            found.append(_default_resolver(host))
        except (OSError, UnicodeError):
            pass  # reported below as "did not resolve"

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(DNS_TIMEOUT)
    if not found:
        raise OSError(f"{host} did not resolve within {DNS_TIMEOUT:g}s")
    return found[0]


def _resolve_urls(policy: Policy, name: str, args: Any) -> Resolver:
    """Resolve the call's URL hosts now, and return a resolver that only replays the answers.

    A slow DNS server would otherwise stall every other hook process behind the lock. A host
    that failed or timed out is absent from the answers and fails again on replay: denied.
    """
    answers: dict[str, list[str]] = {}

    def lookup(host: str) -> list[str]:
        answers[host] = _resolve(host)
        return answers[host]

    def replay(host: str) -> list[str]:
        if host not in answers:
            raise OSError(f"{host} did not resolve")
        return answers[host]

    rule = policy.tools.get(name)
    if rule is not None and isinstance(args, dict):
        for arg_name, arg_rule in rule.args.items():
            if arg_rule.type == "url" and arg_name in args:
                check_arg(args[arg_name], arg_rule, resolver=lookup)  # for its DNS lookups only
    return replay


def handle(
    event: Mapping[str, Any],
    policy: Policy,
    state_dir: str | Path,
    *,
    audit: str | Path | None = None,
    block_approvals: bool = False,
) -> HookResult:
    """Decide one hook event. Raises on malformed input; the caller must turn that into BLOCK.

    ``audit`` is a path, not a logger: the logger reads the chain's last record when it is
    made, so it has to be made inside the lock or two parallel hooks would chain off the same
    record.
    """
    event_name = event.get("hook_event_name")
    # Fail closed: an input that names a tool is a call to gate unless its event is known not
    # to be one. A missing or misspelt event name must not wave a tool call through unaudited.
    if event_name != "PreToolUse" and (event_name in NOT_GATED or "tool_name" not in event):
        return HookResult()  # registered on another event by mistake: nothing to decide
    name, session_id = event.get("tool_name"), event.get("session_id")
    if not (isinstance(name, str) and isinstance(session_id, str) and session_id):
        raise ValueError("hook input lacks tool_name or session_id")
    state_dir = Path(state_dir)
    path = _state_file(state_dir, session_id)
    resolver = _resolve_urls(policy, name, event.get("tool_input", {}))
    with _locked(state_dir / ".lock"):
        logger = AuditLogger(FileSink(audit), actor="claude-code") if audit else None
        guard = ToolGuard(policy, audit=logger, resolver=resolver)
        session = load_session(path, session_id)
        call = ToolCall(name, event.get("tool_input", {}), id=str(event.get("tool_use_id", "")))
        guard._audit("tool_request", session, tool=name, arguments=call.arguments)
        if event_name == "PreToolUse":
            decision = guard.evaluate(call, session)
        else:
            reason = f"hook event {event_name!r} is not PreToolUse"
            decision = Decision(Verdict.DENY, name, (reason,))
        guard._audit(
            "tool_decision",
            session,
            tool=name,
            verdict=decision.verdict.value,
            reasons=list(decision.reasons),
        )
        if decision.verdict == Verdict.DENY:
            return HookResult(BLOCK, stderr=f"agentsec policy: {decision.message()}")
        if block_approvals and decision.verdict == Verdict.APPROVE:
            # Blocked like a denial, so not counted and not tainted: the tool does not run.
            reason = f"agentsec policy: {decision.message()} (approval is blocked)"
            return HookResult(BLOCK, stderr=reason)
        # Counted and tainted now, before the human answers a prompt and before the tool runs.
        untrusted = guard.policy.tools[name].returns_untrusted
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"call": name, "untrusted": untrusted}) + "\n")
    if decision.verdict == Verdict.APPROVE:
        output = {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": f"agentsec policy: {decision.message()}",
        }
        return HookResult(stdout=json.dumps({"hookSpecificOutput": output}))
    return HookResult()
