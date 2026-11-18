"""The gateway's MCP endpoint: one sanctioned ``/mcp`` in front of approved upstream servers.

The MCP SDK speaks the protocol (both the 2025 handshake and the 2026 stateless revision);
this module decides what each request may do. Every ``tools/list`` and ``tools/call`` is
checked under the identity and group policy of the HTTP request that carried it:

- an upstream is reachable only if the caller's group lists it (``mcp``);
- its tools appear as ``<upstream>__<tool>``, and policy keys use that name;
- :class:`GuardedMCPClient` scans definitions, applies pins, the tool policy and taint, and
  refuses any tool that did not pass a listing first;
- taint and listing state live per user, shared by all their sessions and upstreams, so
  they cannot be dropped by opening a new session; a session id is bound to its opener;
- a tool result is scanned for injection, has secrets redacted, and is withheld if it is
  flagged, too large or impossible to scan, before the client sees it.

Requires the ``mcp`` extra (``pip install "ai-agent-security-toolkit[gateway,mcp]"``).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import AsyncIterator, Callable, MutableMapping
from dataclasses import dataclass, field
from typing import Any

from agentsec.gateway.config import NAMESPACE, GatewayConfig, McpUpstream
from agentsec.gateway.policyset import GroupPolicy, PolicySet
from agentsec.integrations.mcp import GuardedMCPClient, ToolPins, _strings
from agentsec.middleware.audit import AuditLogger
from agentsec.middleware.injection import InjectionScanner, spotlight
from agentsec.middleware.validators import Action, OutputGuard, Violation
from agentsec.sandbox.guard import Session, ToolDenied, ToolGuard

_LOG = logging.getLogger("agentsec.gateway.mcp")

SCOPE_KEY = "agentsec.mcp"  # where the gateway puts the caller's identity in the ASGI scope
MAX_STATES = 1000  # users with MCP state kept; the least recently used go first
MAX_SESSIONS = 10000  # open MCP sessions, across all users
MAX_TOOLS = 1000  # tools one upstream may list, across pages
MAX_PAGES = 20  # tools/list pages fetched from one upstream

Connector = Callable[[McpUpstream, float, int], contextlib.AbstractAsyncContextManager[Any]]


@dataclass(frozen=True)
class Caller:
    user: str
    groups: tuple[str, ...]
    policies: PolicySet
    gp: GroupPolicy
    request_id: str
    token_id: str | None = None  # the access token used, if any (recorded on audit records)


@contextlib.asynccontextmanager
async def connect_upstream(
    upstream: McpUpstream, timeout: float, max_bytes: int
) -> AsyncIterator[Any]:
    """An MCP client session to one upstream over streamable HTTP."""
    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    token = upstream.auth()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    headers["Accept-Encoding"] = "identity"  # the cap counts bytes as parsed, not compressed
    # Every response is capped as it streams in: the SDK reads a JSON answer whole.
    capped = _capped_transport(httpx2, httpx2.AsyncHTTPTransport(), max_bytes)
    # The SDK follows redirects only within the endpoint's origin, so the token stays there.
    async with httpx2.AsyncClient(
        headers=headers, timeout=httpx2.Timeout(timeout), transport=capped
    ) as http:
        transport = streamable_http_client(upstream.url, http_client=http)
        async with Client(transport, read_timeout_seconds=timeout) as client:
            yield client


def _capped_transport(httpx2: Any, inner: Any, max_bytes: int) -> Any:
    class CappedStream(httpx2.AsyncByteStream):
        def __init__(self, stream: Any) -> None:
            self._stream = stream

        async def __aiter__(self) -> AsyncIterator[bytes]:
            total = 0
            async for chunk in self._stream:
                total += len(chunk)
                if total > max_bytes:
                    raise UpstreamTooLarge(f"upstream response over {max_bytes} bytes")
                yield chunk

        async def aclose(self) -> None:
            await self._stream.aclose()

    class CappedTransport(httpx2.AsyncBaseTransport):
        async def handle_async_request(self, request: Any) -> Any:
            response = await inner.handle_async_request(request)
            encoding = response.headers.get("content-encoding", "identity").strip().lower()
            if encoding not in {"", "identity"}:
                # A small gzip body can expand far past the cap after the check has run.
                await response.aclose()
                raise UpstreamTooLarge("compressed upstream responses are refused")
            response.stream = CappedStream(response.stream)
            return response

        async def aclose(self) -> None:
            await inner.aclose()

    return CappedTransport()


class UpstreamTooLarge(Exception):
    pass


class _Namespaced:
    """One upstream seen through ``<upstream>__<tool>`` names, so policy keys are unambiguous."""

    def __init__(self, client: Any, prefix: str) -> None:
        self._client = client
        self._prefix = prefix + NAMESPACE
        self._listed = 0  # tools received in the current listing, across its pages

    async def list_tools(self, **kwargs: Any) -> Any:
        listing = await self._client.list_tools(**kwargs)
        self._listed = (self._listed if kwargs.get("cursor") else 0) + len(listing.tools)
        if self._listed > MAX_TOOLS:  # counted before the guard filters anything out
            raise UpstreamTooLarge(f"upstream lists more than {MAX_TOOLS} tools")
        tools = [t.model_copy(update={"name": self._prefix + t.name}) for t in listing.tools]
        return listing.model_copy(update={"tools": tools})

    async def call_tool(self, name: str, arguments: dict[str, Any], **kwargs: Any) -> Any:
        if not name.startswith(self._prefix):
            raise ValueError("tool is not on this upstream")
        return await self._client.call_tool(name[len(self._prefix) :], arguments, **kwargs)


class _Connection:
    """A long-lived upstream session, opened and closed in its own task (anyio's rule)."""

    def __init__(self, cm: contextlib.AbstractAsyncContextManager[Any]) -> None:
        self._cm = cm
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._error: BaseException | None = None
        self.client: Any = None
        self._task: asyncio.Task[None] | None = None
        self._entered = False

    async def open(self, timeout: float) -> Any:
        self._task = asyncio.create_task(self._run())
        try:
            await asyncio.wait_for(self._ready.wait(), timeout)
        except BaseException:
            self.close()  # timed out or cancelled: never leave the task holding a connection
            raise
        if self._error is not None:
            raise self._error
        return self.client

    async def _run(self) -> None:
        try:
            async with self._cm as client:
                self.client = client
                self._entered = True
                self._ready.set()
                await self._stop.wait()
        except BaseException as e:  # noqa: BLE001 - reported through open(), never swallowed there
            self._error = e
            self._ready.set()

    def close(self) -> None:
        self._stop.set()
        if self._task is not None and not self._entered:
            self._task.cancel()  # still connecting: the stop event is never reached


Rev = tuple[str, str]  # (policy revision, group): the rules a guard was built from


@dataclass
class _State:
    """What one user has seen over MCP: taint, and the tools that passed a listing.

    Per user, not per MCP session: the client is what the policy guards against, and it
    can always open a new session, so a session must not be a way to drop taint.
    """

    user: str
    session: Session
    audit: AuditLogger
    last_used: float
    clients: dict[tuple[Rev, str], GuardedMCPClient] = field(default_factory=dict)
    connections: dict[tuple[Rev, str], _Connection] = field(default_factory=dict)
    locks: dict[tuple[Rev, str], asyncio.Lock] = field(default_factory=dict)

    def drop(self, key: tuple[Rev, str]) -> None:
        self.clients.pop(key, None)
        conn = self.connections.pop(key, None)
        if conn is not None:
            conn.close()

    def prune(self, rev: Rev) -> None:
        """Close guards built from other rules: a request only ever uses its own revision."""
        for key in [k for k in self.connections if k[0] != rev]:
            self.drop(key)
            self.locks.pop(key, None)

    def close(self) -> None:
        for key in list(self.connections):
            self.drop(key)


class McpGateway:
    def __init__(
        self,
        config: GatewayConfig,
        audit: AuditLogger,
        scanner: InjectionScanner,
        *,
        connector: Connector = connect_upstream,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        require_sdk()
        from mcp import types
        from mcp.server.lowlevel import Server
        from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

        self._types = types
        self._config = config
        self._audit = audit
        self._scanner = scanner
        self._connector = connector
        self._clock = clock
        self._states: dict[str, _State] = {}
        self._first_seen: dict[str, ToolPins] = {}  # per upstream without reviewed pins
        # MCP session id -> (the user who opened it, last seen). Kept until the SDK would have
        # expired the session too, so an id never becomes usable by someone else while alive.
        self._owners: dict[str, tuple[str, float]] = {}
        self._inflight: dict[str, int] = {}  # session id -> requests being served
        server = Server(
            "agentsec-gateway",
            on_list_tools=self._list_tools,
            on_call_tool=self._call_tool,
        )
        self._manager = StreamableHTTPSessionManager(
            app=server,
            json_response=True,  # one JSON answer per request: no server-initiated streams
            stateless=False,
            max_request_body_size=config.max_body_bytes,
            session_idle_timeout=config.mcp_session_idle_s,
            max_sessions=MAX_SESSIONS,
        )
        self._running: asyncio.Future[None] | None = None
        self._run_task: asyncio.Task[None] | None = None

    # ---------------------------------------------------------------------- HTTP
    async def handle(self, scope: Any, receive: Any, send: Any, caller: Caller) -> None:
        """Serve one /mcp request for an authenticated caller."""
        await self._ensure_running()
        self._sweep()
        session_id = _header(scope, b"mcp-session-id")
        if session_id is not None:
            owner = self._owners.get(session_id)
            if owner is not None and owner[0] != caller.user:
                # Another user's session id: answer exactly as for an unknown one.
                await _plain(send, 404, b"Session not found")
                return
            if owner is not None:
                self._owners[session_id] = (caller.user, self._clock())
        if scope["method"] == "GET":
            await _plain(send, 405, b"server-initiated streams are not offered")
            return
        method = scope["method"]
        scope = dict(scope)
        scope[SCOPE_KEY] = caller

        async def recording_send(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                status = message.get("status", 0)
                if method == "DELETE" and session_id is not None and 200 <= status < 300:
                    self._owners.pop(session_id, None)  # only once the SDK ended it
                opened = _header({"headers": message.get("headers", [])}, b"mcp-session-id")
                if opened is not None and session_id is None and 200 <= status < 300:
                    self._owners.setdefault(opened, (caller.user, self._clock()))
            await send(message)

        if session_id is not None:
            self._inflight[session_id] = self._inflight.get(session_id, 0) + 1
        try:
            await self._manager.handle_request(scope, receive, recording_send)
        finally:
            if session_id is not None:
                left = self._inflight.pop(session_id) - 1
                if left:
                    self._inflight[session_id] = left
                if session_id in self._owners:
                    self._owners[session_id] = (caller.user, self._clock())

    async def _ensure_running(self) -> None:
        if self._running is not None:
            await asyncio.shield(self._running)
            return
        loop = asyncio.get_running_loop()
        self._running = loop.create_future()

        async def run() -> None:
            async with self._manager.run():
                assert self._running is not None  # noqa: S101 - set just above
                self._running.set_result(None)
                await asyncio.Event().wait()  # the manager lives as long as the process

        self._run_task = asyncio.create_task(run())
        await asyncio.shield(self._running)

    def _sweep(self) -> None:
        now = self._clock()
        idle = self._config.mcp_session_idle_s
        stale = [u for u, s in self._states.items() if now - s.last_used > idle]
        # Over capacity, only untainted state goes: evicting a tainted user would reset
        # their taint. Users are authenticated, so tainted state is bounded by the users.
        clean = sorted(
            (u for u, st in self._states.items() if u not in stale and not st.session.tainted),
            key=lambda u: self._states[u].last_used,
        )
        excess = len(self._states) - len(stale) - MAX_STATES
        stale += clean[: max(excess, 0)]
        for user in stale:
            self._states.pop(user).close()
        # The SDK ends a session after ``idle`` without traffic; keep its owner a while longer.
        for sid, (_, seen) in list(self._owners.items()):
            # The SDK does not expire a session while it serves a request; neither do we.
            if now - seen > idle + 60 and sid not in self._inflight:
                del self._owners[sid]

    # ------------------------------------------------------------------ handlers
    def _caller(self, ctx: Any) -> tuple[Caller, _State, Rev]:
        scope = getattr(getattr(ctx, "request", None), "scope", None) or {}
        caller = scope.get(SCOPE_KEY)
        if not isinstance(caller, Caller):
            # Only the gateway's handle() reaches the manager, so this is a bug: fail closed.
            raise PermissionError("MCP request without a gateway identity")
        state = self._states.get(caller.user)
        if state is None:
            label = f"mcp:{caller.request_id}"
            state = _State(
                user=caller.user,
                session=Session(id=label),
                audit=self._audit.bind(actor=caller.user, session_id=label),
                last_used=self._clock(),
            )
            self._states[caller.user] = state
        state.last_used = self._clock()
        return caller, state, (caller.policies.revision, caller.gp.group)

    def _reachable(self, caller: Caller) -> list[str]:
        allowed = caller.gp.mcp
        return [n for n in self._config.mcp_upstreams if allowed is None or n in allowed]

    async def _client(self, caller: Caller, state: _State, rev: Rev, name: str) -> GuardedMCPClient:
        key = (rev, name)
        # One connect at a time per guard: concurrent first requests share one connection.
        async with state.locks.setdefault(key, asyncio.Lock()):
            client = state.clients.get(key)
            if client is not None:
                return client
            upstream = self._config.mcp_upstreams[name]
            timeout = self._config.upstream_timeout_s
            conn = _Connection(self._connector(upstream, timeout, self._config.max_response_bytes))
            raw = await conn.open(timeout)
            state.prune(rev)
            pins = caller.policies.mcp_pins.get(name)
            # No reviewed pins: trust on first use, shared by every user until the process ends,
            # so a definition that changes after its first clean listing is blocked like a pin
            # mismatch. shortcut: these pins only grow (an upstream that keeps renaming tools
            # leaks memory); cap them if such an upstream turns up.
            first_seen = self._first_seen.setdefault(name, ToolPins())
            client = GuardedMCPClient(
                _Namespaced(raw, name),
                ToolGuard(caller.gp.policy, audit=state.audit),  # this request's rules only
                state.session,  # one session across upstreams: what one returns taints the rest
                pins=first_seen if pins is None else ToolPins(pins),
                pin_new=pins is None,  # with pins, an unpinned tool is a finding, never trusted
                scanner=self._scanner,
            )
            state.connections[key] = conn
            state.clients[key] = client
            return client

    async def _list_tools(self, ctx: Any, params: Any) -> Any:
        caller, state, rev = self._caller(ctx)
        tools: list[Any] = []
        for name in self._reachable(caller):
            found: list[Any] = []
            try:
                client = await self._client(caller, state, rev, name)
                cursor = None
                for _ in range(MAX_PAGES):
                    page = await asyncio.wait_for(
                        client.list_tools(**({"cursor": cursor} if cursor else {})),
                        self._config.upstream_timeout_s,
                    )
                    found.extend(page.tools)
                    cursor = page.next_cursor
                    if not cursor:
                        break
            except Exception as e:  # noqa: BLE001 - one bad upstream must not hide the others
                state.drop((rev, name))
                state.audit.log("gateway_mcp_upstream_error", upstream=name, error=_reason(e))
                continue
            tools.extend(found)
        state.audit.log("gateway_mcp_list", upstreams=self._reachable(caller), tools=len(tools))
        return self._types.ListToolsResult(tools=tools)

    async def _call_tool(self, ctx: Any, params: Any) -> Any:
        caller, state, rev = self._caller(ctx)
        name = params.name
        upstream = name.split(NAMESPACE, 1)[0] if NAMESPACE in name else ""
        if upstream not in self._reachable(caller):
            state.audit.log("gateway_mcp_call", tool=name, allowed=False, reason="no such tool")
            return self._error(f"unknown tool {name!r}")
        try:
            client = await self._client(caller, state, rev, upstream)
            result = await asyncio.wait_for(
                client.call_tool(name, dict(params.arguments or {})),
                self._config.upstream_timeout_s,
            )
        except ToolDenied as e:
            state.audit.log(
                "gateway_mcp_call",
                tool=name,
                allowed=False,
                reason=str(e),
                token_id=caller.token_id,
            )
            return self._error(f"denied by policy: {e}")
        except Exception as e:  # noqa: BLE001 - an MCP error result, never a crash or a leak
            state.drop((rev, upstream))  # reconnect, and list again, before the next call
            state.audit.log("gateway_mcp_upstream_error", upstream=upstream, error=_reason(e))
            return self._error("upstream error")
        state.audit.log("gateway_mcp_call", tool=name, allowed=True, token_id=caller.token_id)
        return self._screen(result, caller.gp, name, state.audit)

    def _screen(self, result: Any, gp: GroupPolicy, name: str, log: AuditLogger) -> Any:
        """What the client gets for an upstream result: scanned, redacted, or withheld.

        The model path's rules for ``role: tool`` messages, applied where the result enters the
        client: ``block_on_injection`` withholds a flagged result, ``spotlight_tool_results``
        marks text as data, and ``mode: monitor`` records what enforce would have done.
        """
        enforce = gp.mode == "enforce"
        # Secrets and protected strings only, as for tool arguments: PII, links and markup are
        # what a search or a file read normally returns.
        guard = gp.argument_guard
        try:
            text, as_json, binary = _scannable(result)
            scan = self._scanner.scan(text)
            why = ["binary resource cannot be scanned"] if binary else []
            found: list[Violation] = []
            if scan.truncated:
                why.append("result too large to scan")
            else:
                found = guard.process(text + "\n" + as_json).violations
            if scan.flagged and gp.block_on_injection:
                why.append(f"injection signals: {', '.join(scan.signals)}")
            if any(v.action == Action.BLOCK for v in found):
                why.append("output policy")
            out = result
            if not (why and enforce):
                redact = enforce and bool(found)
                out = self._rewritten(result, guard if redact else None, gp.spotlight_tool_results)
                clean, clean_json, _ = _scannable(out)
                # A secret where nothing is rewritten (a key, a URI, _meta) is still there.
                if redact and guard.process(clean + "\n" + clean_json).violations:
                    why.append("could not be fully redacted")
        except Exception as e:  # noqa: BLE001 - fail closed, in monitor mode too: nothing was checked
            log.log("gateway_mcp_result", tool=name, withheld=True, error=_reason(e), enforced=True)
            return self._error("tool result withheld: it could not be scanned")
        log.log(
            "gateway_mcp_result",
            tool=name,
            score=round(scan.score, 2),
            signals=scan.signals,
            truncated=scan.truncated,
            validators=sorted({v.validator for v in found}),
            withheld=bool(why),
            reasons=why,
            enforced=enforce,
        )
        if why and enforce:
            return self._error(f"tool result withheld by policy: {'; '.join(why)}")
        return out

    def _rewritten(self, result: Any, guard: OutputGuard | None, mark: bool) -> Any:
        """A copy with secrets redacted (when ``guard`` is given) and text blocks spotlighted."""
        t = self._types

        def clean(text: str) -> str:
            return guard.process(text).text if guard else text

        content = []
        for block in result.content:
            if isinstance(block, t.TextContent):
                text = clean(block.text)
                text = spotlight(text, source="a tool result") if mark else text
                block = block.model_copy(update={"text": text})
            elif isinstance(block, t.EmbeddedResource) and isinstance(
                block.resource, t.TextResourceContents
            ):
                resource = block.resource.model_copy(update={"text": clean(block.resource.text)})
                block = block.model_copy(update={"resource": resource})
            content.append(block)
        structured = result.structured_content
        if guard and structured is not None:
            # Redacted as JSON text, where "password": "..." is one assignment; a redaction
            # that breaks the JSON raises, and the result is withheld.
            structured = json.loads(clean(json.dumps(structured, ensure_ascii=False)))
        return result.model_copy(update={"content": content, "structured_content": structured})

    def _error(self, text: str) -> Any:
        t = self._types
        return t.CallToolResult(content=[t.TextContent(type="text", text=text)], is_error=True)


MIN_SDK = (2, 3)  # the session manager, MCPServer and 2026 protocol support this relies on


def require_sdk(installed: str | None = None) -> None:
    """Refuse an MCP SDK older than the one this endpoint was built and tested against."""
    from importlib.metadata import version

    raw = installed or version("mcp")
    parts = tuple(int(p) for p in raw.split(".")[:2] if p.isdigit())
    if parts < MIN_SDK:
        need = ".".join(map(str, MIN_SDK))
        raise RuntimeError(
            f"mcp_upstreams needs the MCP SDK {need} or newer (installed: {raw}); "
            f'pip install -U "mcp>={need}"'
        )


def _scannable(result: Any) -> tuple[str, str, bool]:
    """A result's strings (text, resource text, structuredContent, _meta, keys), the same as
    JSON, and whether it embeds a binary resource, which nothing here can read."""
    dump = result.model_dump(mode="json", exclude_none=True)
    binary = False
    for block in dump["content"]:
        if block["type"] in {"image", "audio"}:
            block.pop("data", None)  # media passes unscanned, like a data: image on the model path
        elif "blob" in block.get("resource", {}):
            del block["resource"]["blob"]
            binary = True
    return "\n".join(_strings(dump)), json.dumps(dump, ensure_ascii=False), binary


def _header(scope: Any, name: bytes) -> str | None:
    for k, v in scope.get("headers", []):
        if k.lower() == name:
            return v.decode("latin-1")
    return None


def _reason(e: BaseException) -> str:
    # Names, not messages: an upstream's error text is untrusted and may echo secrets.
    return type(e).__name__


async def _plain(send: Any, status: int, body: bytes) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"text/plain"), (b"cache-control", b"no-store")],
        }
    )
    await send({"type": "http.response.body", "body": body})
