"""Guard a Model Context Protocol (MCP) client: tool pinning, poisoning scan, guarded calls.

MCP servers are third-party code that tells your model what its tools do (the tool
*descriptions*) and returns content the model then reads (the tool *results*). Both are
attacker-influenceable:

* **Tool poisoning** hides instructions in a tool's description or parameter schema.
* **Rug pull**: a server shows a harmless description when you approve it and swaps it later.
* **Poisoned results**: anything a tool returns is untrusted input to the next model call.

:class:`GuardedMCPClient` wraps an MCP client so that

1. ``list_tools`` hides tools the :class:`~agentsec.sandbox.Policy` does not allow, drops tools
   whose definition changed since it was pinned, and drops tools whose text looks like an
   injection (:class:`ToolPins`, :func:`scan_tool_definitions`);
2. ``call_tool`` goes through :meth:`ToolGuard.aexecute` (allowlist, argument checks, limits,
   approval, audit), and taints the session because the result is untrusted.

Nothing here imports the ``mcp`` package. It is duck-typed on the small surface that both
SDK 1.x and 2.x share (``list_tools()`` returning an object with ``.tools``; ``call_tool(name,
arguments)``) and reads both the camelCase (1.x) and snake_case (2.x) attribute spellings.
Unknown attributes are deliberately **not** forwarded to the wrapped client, so the guarded
object cannot be used to reach an unguarded ``call_tool``.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from agentsec.middleware.injection import InjectionScanner
from agentsec.sandbox.guard import Decision, Session, ToolDenied, ToolGuard, Verdict
from agentsec.types import ToolCall

PIN_FILE_VERSION = 1
DEFAULT_MAX_DESCRIPTION_CHARS = 2000
MAX_SCANNED_CHARS = 50_000

FindingKind = Literal["changed", "new", "removed", "injection", "oversized"]


class ToolManifestError(RuntimeError):
    """Raised (with ``on_finding="raise"``) when a listed tool fails a check."""

    def __init__(self, findings: list[ToolFinding]) -> None:
        super().__init__("; ".join(f"{f.tool}: {f.kind} ({f.detail})" for f in findings))
        self.findings = findings


@dataclass(frozen=True)
class ToolFinding:
    tool: str
    kind: FindingKind
    detail: str = ""


# ----------------------------------------------------------------------- reading tools


def _get(obj: Any, *names: str, default: Any = None) -> Any:
    """First present attribute or key among ``names`` (camelCase and snake_case spellings)."""
    for name in names:
        if isinstance(obj, Mapping):
            if name in obj:
                return obj[name]
        elif hasattr(obj, name):
            return getattr(obj, name)
    return default


def _plain(value: Any) -> Any:
    """Reduce SDK objects to JSON-compatible data so hashing and scanning are stable."""
    if hasattr(value, "model_dump"):
        return _plain(value.model_dump(mode="json"))
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [_plain(v) for v in value]
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return repr(value)


def tool_name(tool: Any) -> str:
    return str(_get(tool, "name", default=""))


def _definition(tool: Any) -> dict[str, Any]:
    return {
        "name": tool_name(tool),
        "title": _plain(_get(tool, "title")),
        "description": _plain(_get(tool, "description")),
        "input_schema": _plain(_get(tool, "inputSchema", "input_schema")),
        "output_schema": _plain(_get(tool, "outputSchema", "output_schema")),
        "annotations": _plain(_get(tool, "annotations")),
    }


def tool_fingerprint(tool: Any) -> str:
    """SHA-256 over the parts of a tool definition that shape model behavior.

    Stable across MCP SDK versions: the same definition hashes the same whether the SDK exposes
    ``inputSchema`` or ``input_schema``.
    """
    canonical = json.dumps(_definition(tool), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _strings(value: Any) -> Iterable[str]:
    """Every string in a nested structure, including mapping keys (hiding places for payloads)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for k, v in value.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _strings(v)


# ---------------------------------------------------------------------------- scanning


def scan_tool_definitions(
    tools: Iterable[Any],
    scanner: InjectionScanner | None = None,
    *,
    max_description_chars: int = DEFAULT_MAX_DESCRIPTION_CHARS,
) -> list[ToolFinding]:
    """Flag tool definitions that look like tool poisoning.

    Scans the name, title, description and every string in the parameter schema (descriptions,
    enums, defaults, property names), where injected instructions are usually hidden. This is a
    heuristic tripwire, not a guarantee: pin definitions and review them as well.
    """
    scanner = scanner or InjectionScanner()
    findings: list[ToolFinding] = []
    for tool in tools:
        name = tool_name(tool)
        definition = _definition(tool)
        text = "\n".join(_strings(definition))[:MAX_SCANNED_CHARS]
        result = scanner.scan(text)
        if result.flagged:
            findings.append(
                ToolFinding(
                    name, "injection", f"score {result.score:.2f}: {', '.join(result.signals)}"
                )
            )
        description = definition["description"]
        if isinstance(description, str) and len(description) > max_description_chars:
            findings.append(
                ToolFinding(
                    name,
                    "oversized",
                    f"description is {len(description)} chars (max {max_description_chars})",
                )
            )
    return findings


# ------------------------------------------------------------------------------ pinning


class ToolPins:
    """Trust-on-first-use fingerprints of tool definitions, to catch rug pulls.

    Pin the tools once a human has reviewed them, save the pins somewhere the agent cannot
    write, and load them on later runs. A tool whose definition changes is reported as
    ``changed`` instead of being silently trusted.
    """

    def __init__(self, pins: Mapping[str, str] | None = None) -> None:
        self._pins: dict[str, str] = dict(pins or {})

    @property
    def pins(self) -> dict[str, str]:
        return dict(self._pins)

    def pin(self, tools: Iterable[Any]) -> None:
        for tool in tools:
            self._pins[tool_name(tool)] = tool_fingerprint(tool)

    def check(self, tools: Iterable[Any], *, complete: bool = True) -> list[ToolFinding]:
        """Compare against the pins. ``complete`` says ``tools`` is the full listing.

        Pass ``complete=False`` for a single page of a paginated listing so tools on other pages
        are not reported as removed.
        """
        findings: list[ToolFinding] = []
        seen: set[str] = set()
        for tool in tools:
            name = tool_name(tool)
            seen.add(name)
            pinned = self._pins.get(name)
            if pinned is None:
                findings.append(ToolFinding(name, "new", "no pin recorded"))
            elif pinned != tool_fingerprint(tool):
                findings.append(ToolFinding(name, "changed", "definition differs from its pin"))
        if complete:
            findings += [
                ToolFinding(n, "removed", "pinned tool is gone")
                for n in self._pins
                if n not in seen
            ]
        return findings

    def save(self, path: str | Path) -> None:
        payload = {"version": PIN_FILE_VERSION, "tools": self._pins}
        Path(path).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
        )

    @classmethod
    def load(cls, path: str | Path) -> ToolPins:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("version") != PIN_FILE_VERSION:
            raise ValueError(f"unsupported tool pin file (expected version {PIN_FILE_VERSION})")
        tools = raw.get("tools")
        if not isinstance(tools, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in tools.items()
        ):
            raise ValueError("tool pin file must map tool names to fingerprint strings")
        return cls(tools)


# ------------------------------------------------------------------------------- client


class GuardedMCPClient:
    """An MCP client whose tool listing and tool calls pass through a :class:`ToolGuard`.

    Args:
        client: an MCP client/session exposing ``async list_tools()`` and
            ``async call_tool(name, arguments)`` (e.g. ``mcp.ClientSession`` or ``mcp.Client``).
        guard: the policy enforcement point. Tools not in its policy are denied and hidden.
        session: per-conversation guard state; defaults to the guard's default session.
        pins: fingerprints from :class:`ToolPins`. Without it, definitions are only scanned.
        scanner: injection scanner used on tool definitions.
        pin_new: when ``pins`` is given, record tools seen for the first time (trust on first
            use). Set ``False`` to treat unpinned tools as findings.
        on_finding: ``"drop"`` (default) hides flagged tools and records the finding, ``"raise"``
            raises :class:`ToolManifestError` from ``list_tools``.
        taint_results: mark the session untrusted after every call (default), because MCP tool
            results are third-party content. Side-effecting tools are then denied or sent for
            approval per the policy's taint rules.
    """

    def __init__(
        self,
        client: Any,
        guard: ToolGuard,
        session: Session | None = None,
        *,
        pins: ToolPins | None = None,
        scanner: InjectionScanner | None = None,
        pin_new: bool = True,
        on_finding: Literal["drop", "raise"] = "drop",
        taint_results: bool = True,
    ) -> None:
        if on_finding not in ("drop", "raise"):
            raise ValueError("on_finding must be 'drop' or 'raise'")
        self._client = client
        self._guard = guard
        self._session = session or guard.default_session
        self._pins = pins
        self._scanner = scanner or InjectionScanner()
        self._pin_new = pin_new
        self._on_finding = on_finding
        self._taint = taint_results
        self._blocked: dict[str, str] = {}
        self.findings: list[ToolFinding] = []

    # ------------------------------------------------------------------- listing
    async def list_tools(self, **kwargs: Any) -> Any:
        """List the server's tools, minus disallowed, changed and suspicious ones."""
        listing = await self._client.list_tools(**kwargs)
        tools = list(_get(listing, "tools", default=[]))
        # A cursor means more pages exist, so do not call unseen pinned tools "removed".
        paged = bool(_get(listing, "nextCursor", "next_cursor")) or bool(kwargs.get("cursor"))

        found = scan_tool_definitions(tools, self._scanner)
        suspicious = {f.tool for f in found}
        if self._pins is not None:
            found += self._pins_findings(tools, suspicious, complete=not paged)
        # "removed" is informational: there is no listed tool to hide or refuse.
        blocking = [f for f in found if f.kind != "removed"]
        for f in found:
            self.findings.append(f)
            self._audit("mcp_tool_finding", tool=f.tool, kind=f.kind, detail=f.detail)
        if blocking and self._on_finding == "raise":
            raise ToolManifestError(blocking)

        # Recompute the block list from this listing so a tool that is fixed is usable again.
        bad = {f.tool: f"{f.kind}: {f.detail}" for f in blocking}
        for tool in tools:
            name = tool_name(tool)
            if name in bad:
                self._blocked[name] = bad[name]
            else:
                self._blocked.pop(name, None)
        kept = [t for t in tools if tool_name(t) not in bad and self._allowed(tool_name(t))]
        return _with_tools(listing, kept)

    def _pins_findings(
        self, tools: list[Any], suspicious: set[str], *, complete: bool
    ) -> list[ToolFinding]:
        assert self._pins is not None  # noqa: S101 - narrowing for the type checker
        found = self._pins.check(tools, complete=complete)
        if self._pin_new:
            # Trust on first use, but never pin a definition that just failed the scan: a saved
            # pin would make a poisoned description look reviewed.
            new = {f.tool for f in found if f.kind == "new"}
            self._pins.pin(
                t for t in tools if tool_name(t) in new and tool_name(t) not in suspicious
            )
            found = [f for f in found if f.kind != "new"]
        return found

    def _allowed(self, name: str) -> bool:
        rule = self._guard.policy.tools.get(name)
        return rule is not None and rule.allow

    # ------------------------------------------------------------------- calling
    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None, **kwargs: Any
    ) -> Any:
        """Call an MCP tool through the guard. Raises :class:`ToolDenied` when refused."""
        if name in self._blocked:
            reason = f"tool definition failed a check ({self._blocked[name]})"
            self._audit("mcp_tool_blocked", tool=name, reason=reason)
            raise ToolDenied(Decision(Verdict.DENY, name, (reason,)))

        reached_server = False

        async def invoke(**args: Any) -> Any:
            nonlocal reached_server
            reached_server = True
            return await self._client.call_tool(name, args, **kwargs)

        try:
            return await self._guard.aexecute(
                ToolCall(name=name, arguments=dict(arguments or {})), invoke, self._session
            )
        finally:
            # Taint only if the call was actually made: a call the guard refused fetched nothing.
            if self._taint and reached_server:
                self._session.mark_untrusted(f"mcp:{name}")

    def _audit(self, event: str, **data: Any) -> None:
        if self._guard.audit is not None:
            self._guard.audit.log(event, tool_session=self._session.id, **data)


def _with_tools(listing: Any, tools: list[Any]) -> Any:
    """A copy of ``listing`` whose tools are replaced, keeping its type where possible."""
    if hasattr(listing, "model_copy"):
        return listing.model_copy(update={"tools": tools})
    if isinstance(listing, dict):
        return {**listing, "tools": tools}
    clone = copy.copy(listing)
    clone.tools = tools
    return clone


def result_text(result: Any) -> str:
    """Concatenate the text blocks of an MCP tool result (empty if it has none)."""
    parts = [
        str(_get(block, "text"))
        for block in (_get(result, "content", default=None) or [])
        if isinstance(_get(block, "text"), str)
    ]
    return "\n".join(parts)


def result_is_error(result: Any) -> bool:
    return bool(_get(result, "isError", "is_error", default=False))
