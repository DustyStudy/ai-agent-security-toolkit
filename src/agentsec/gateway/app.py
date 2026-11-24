"""The gateway's ASGI app: an OpenAI-compatible chat-completions proxy that enforces policy.

It controls what reaches and leaves the model, not what the client runs (docs/design/GATEWAY.md).
Requests are rebuilt from an allowlist of fields, never forwarded as bytes. Streaming is served
in ``buffer`` mode: the upstream is always called without streaming, the whole answer is checked,
and only then sent to the client as SSE chunks.
"""

from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import hashlib
import http.client
import ipaddress
import json
import logging
import math
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable, Generator, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentsec.gateway.bundle import (
    MANIFEST,
    MAX_FILE_BYTES,
    SIGNATURE,
    BundleError,
    load_bundle,
    write_state,
)
from agentsec.gateway.config import GatewayConfig, Upstream, loopback_hosts, unpinned
from agentsec.gateway.dashboard import (
    DASHBOARD_HEADERS,
    list_evidence,
    load_fuzz_summary,
    read_evidence,
    render_dashboard,
)
from agentsec.gateway.feeds import FeedSet
from agentsec.gateway.holdback import Holdback
from agentsec.gateway.metrics import CountingSink, Metrics
from agentsec.gateway.oidc import OidcVerifier, TokenRejected, fetch_jwks
from agentsec.gateway.outbound import attachments, screen, upstream_policy
from agentsec.gateway.policyset import GroupPolicy, PolicySet
from agentsec.gateway.tokens import (
    TokenError,
    TokenSettings,
    TokenStore,
    looks_like_token,
)
from agentsec.integrations.mcp import scan_tool_definitions
from agentsec.middleware.audit import AuditLogger, AuditSink, FileSink, RetrySink, TeeSink
from agentsec.middleware.cef import CefSink
from agentsec.middleware.dlp import MAX_MATCH_RECORDS, DlpMatch
from agentsec.middleware.injection import InjectionScanner
from agentsec.middleware.pipeline import AgentMiddleware
from agentsec.middleware.validators import BlocklistLinkValidator, OutputGuard
from agentsec.sandbox.adapters import parse_openai_tool_call
from agentsec.sandbox.blocklist import Blocklist
from agentsec.sandbox.guard import Session, ToolGuard
from agentsec.sandbox.policy import Policy

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
# (upstream, JSON body, timeout seconds, max response bytes) -> parsed JSON response
Transport = Callable[[Upstream, bytes, float, int], Any]
StreamTransport = Callable[[Upstream, bytes, float, int], Generator[dict[str, Any], None, None]]

_REQUEST_FIELDS = {
    "model", "messages", "tools", "tool_choice", "parallel_tool_calls", "temperature",
    "top_p", "max_tokens", "stop", "seed", "response_format", "presence_penalty",
    "frequency_penalty",
}  # fmt: skip
_MESSAGE_FIELDS = {"role", "content", "name", "tool_calls", "tool_call_id"}
_ROLES = {"system", "developer", "user", "assistant", "tool"}
_FINISH = {"stop", "length", "tool_calls", "content_filter"}
WITHHELD_NOTICE = "A tool call was withheld by policy."
MAX_CONCURRENT_AUTH = 8  # token verifications in flight, across all clients
# Model calls in flight, across all users (limits.concurrent_requests is per user). Each holds a
# thread for up to twice upstream_timeout_s, so they get their own pool and a 503 when it is full.
MAX_CONCURRENT_UPSTREAM = 32
# Audit records one peer can cause before it is authenticated: a burst, then a slow refill.
PREAUTH_AUDIT_BURST = 10
PREAUTH_AUDIT_PER_MIN = 6
_TOKEN_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "agentsec_token_id", default=None
)
MAX_STREAM_TOOL_CALLS = 64  # tool-call indexes accepted in one streamed answer
_LOG = logging.getLogger("agentsec.gateway")
# Decision metadata stays readable with log_content off; prompts and answers are still hashed.
# These hold policy reasons, names and error kinds, never message text.
AUDIT_KEEP_FIELDS = frozenset(
    {
        "reasons",
        "reason",
        "error",
        "tools",
        "validators",
        "signals",
        "policy_rev",
        "groups",
        "token_id",
    }  # fmt: skip
)


class HttpError(Exception):
    def __init__(self, status: int, message: str, code: str, *, audited: bool = False) -> None:
        super().__init__(message)
        self.status, self.message, self.code = status, message, code
        self.audited = audited  # already has its own audit record; do not log it twice


class UpstreamError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would replay the upstream API key to whatever host answers."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


# The deadline of the upstream call running on this thread: the connection classes below hand
# it their socket, so it can cut a call that is still waiting at the deadline.
_DEADLINE = threading.local()


def _shut(sock: socket.socket) -> None:
    try:
        # The plain socket's shutdown, also for TLS: a read blocked in another thread returns.
        socket.socket.shutdown(sock, socket.SHUT_RDWR)
    except OSError:
        pass  # already closed


class _Deadline:
    """A total deadline for one upstream call, headers and connect included.

    The socket timeout bounds each read, not the call: an upstream that sends its status line
    and headers a byte at a time, or a chunked body's size lines, would hold a worker thread
    for as long as it liked. At the deadline the call's socket is shut down, so the blocked
    read returns and the caller sees ``expired``.
    """

    def __init__(self, timeout: float) -> None:
        self.at = time.monotonic() + timeout
        self.expired = False
        self._socks: list[socket.socket] = []
        self._lock = threading.Lock()
        self._timer = threading.Timer(timeout, self._expire)
        self._timer.daemon = True
        self._timer.start()

    def watch(self, sock: socket.socket) -> None:
        with self._lock:
            self._socks.append(sock)
            expired = self.expired
        if expired:
            _shut(sock)

    def _expire(self) -> None:
        with self._lock:
            self.expired = True
            socks = list(self._socks)
        for sock in socks:
            _shut(sock)

    def cancel(self) -> None:
        self._timer.cancel()

    def check(self) -> None:
        if self.expired or time.monotonic() > self.at:
            raise TimeoutError


def _watch(sock: socket.socket | None) -> None:
    deadline = getattr(_DEADLINE, "current", None)
    if deadline is not None and sock is not None:
        deadline.watch(sock)


class _WatchedHTTPConnection(http.client.HTTPConnection):
    def connect(self) -> None:
        super().connect()
        _watch(self.sock)


class _WatchedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self) -> None:
        super().connect()  # self.sock is the TLS socket from here on
        _watch(self.sock)


class _HTTPHandler(urllib.request.HTTPHandler):
    def do_open(self, http_class: Any, req: Any, **kw: Any) -> Any:
        return super().do_open(_WatchedHTTPConnection, req, **kw)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def do_open(self, http_class: Any, req: Any, **kw: Any) -> Any:
        return super().do_open(_WatchedHTTPSConnection, req, **kw)


# No proxies: HTTP(S)_PROXY from the environment would send prompts and the upstream key through
# the corporate proxy, even for a 127.0.0.1 upstream.
_OPENER = urllib.request.build_opener(
    _NoRedirect, urllib.request.ProxyHandler({}), _HTTPHandler, _HTTPSHandler
)
# What an API key may hold to be sent as a header: visible ASCII. http.client refuses anything
# else with an error that quotes the header, key included, into the gateway's own log.
_KEY_CHARS = re.compile(r"[\x21-\x7e]+")


def _upstream_request(upstream: Upstream, body: bytes, accept: str) -> urllib.request.Request:
    headers = {"Content-Type": "application/json", "Accept": accept}
    try:
        key = upstream.api_key()
    except (OSError, ValueError) as e:  # ConfigError is a ValueError; neither names the key
        raise UpstreamError(f"upstream api key unavailable: {type(e).__name__}") from None
    if key:
        if not _KEY_CHARS.fullmatch(key):
            raise UpstreamError("upstream api key is not a valid header value")
        headers["Authorization"] = f"Bearer {key}"
    return urllib.request.Request(  # noqa: S310 - URL is from config and checked as http(s)
        upstream.url + "/chat/completions", data=body, headers=headers, method="POST"
    )


def _open(req: urllib.request.Request, timeout: float, deadline: _Deadline) -> Any:
    _DEADLINE.current = deadline
    try:
        return _OPENER.open(req, timeout=timeout)
    finally:
        _DEADLINE.current = None


def _upstream_failure(e: Exception, deadline: _Deadline) -> Exception:
    """The error to raise for a failed upstream call: never the upstream's own text.

    Messages from urllib and http.client can quote what the upstream sent or the request
    headers (the API key), so only the exception type is kept.
    """
    if deadline.expired:
        return TimeoutError()  # the watchdog cut the call; whatever broke next is its doing
    if isinstance(e, TimeoutError | UpstreamError):
        return e
    if isinstance(e, urllib.error.HTTPError):
        e.close()  # the error body is never read; release the connection
        return UpstreamError(f"upstream returned HTTP {e.code}")
    if isinstance(e, urllib.error.URLError):
        reason = e.reason
        if isinstance(reason, TimeoutError):
            return TimeoutError()  # a connect timeout is a timeout, not an unreachable host
        kind = type(reason).__name__ if isinstance(reason, BaseException) else type(e).__name__
        return UpstreamError(f"upstream unreachable: {kind}")
    if isinstance(e, http.client.HTTPException):
        # A bad status line, a cut chunked body (IncompleteRead), an oversized header line.
        return UpstreamError(f"upstream protocol error: {type(e).__name__}")
    if isinstance(e, OSError):
        return UpstreamError(f"upstream unreachable: {type(e).__name__}")
    if isinstance(e, ValueError):
        return UpstreamError(f"upstream request failed: {type(e).__name__}")
    return e


def http_transport(upstream: Upstream, body: bytes, timeout: float, max_bytes: int) -> Any:
    # shortcut: blocking urllib in a worker thread; a client disconnect does not cancel the
    # upstream call. Move to an async client when streaming passthrough modes arrive.
    req = _upstream_request(upstream, body, "application/json")
    # Each read is bounded by the socket timeout and the whole call by the deadline, which
    # shuts the socket when it passes (worst case about ``timeout`` plus one read).
    deadline = _Deadline(timeout)
    try:
        with _open(req, timeout, deadline) as resp:
            if resp.status != 200:
                raise UpstreamError(f"upstream returned HTTP {resp.status}")
            buf = bytearray()
            while len(buf) <= max_bytes:
                deadline.check()
                chunk = resp.read1(65536)
                if not chunk:
                    break
                buf.extend(chunk)
            if deadline.expired:  # an EOF caused by the watchdog is not the end of the answer
                raise TimeoutError
            data = bytes(buf)
    except Exception as e:
        failure = _upstream_failure(e, deadline)
        if failure is e:
            raise
        raise failure from None
    finally:
        deadline.cancel()
    if len(data) > max_bytes:
        raise UpstreamError("upstream response too large")
    try:
        return json.loads(data)
    except (ValueError, RecursionError):  # RecursionError: nesting deeper than the parser goes
        raise UpstreamError("upstream response is not JSON") from None


def http_stream_transport(
    upstream: Upstream, body: bytes, timeout: float, max_bytes: int
) -> Generator[dict[str, Any], None, None]:
    """Yield the upstream's SSE ``data:`` events as JSON. The same deadline and size cap."""
    req = _upstream_request(upstream, body, "text/event-stream")
    deadline = _Deadline(timeout)
    try:
        # Closing this generator (client gone) closes the connection: the upstream stops.
        with _open(req, timeout, deadline) as resp:
            if resp.status != 200:
                raise UpstreamError(f"upstream returned HTTP {resp.status}")
            total, buf, data = 0, b"", []
            while True:
                deadline.check()
                chunk = resp.read1(65536)
                total += len(chunk)
                if total > max_bytes:
                    raise UpstreamError("upstream response too large")
                if not chunk:
                    if deadline.expired:  # the watchdog's EOF, not the upstream's
                        raise TimeoutError
                    if not buf.endswith(b"\r"):
                        # A cut connection must not pass for a finished answer.
                        raise UpstreamError("upstream stream ended without [DONE]")
                    chunk = b"\n"  # the CR kept below ended the last line (not counted)
                buf += chunk
                # SSE lines end in CRLF, CR or LF. A final CR may be half a CRLF: keep it.
                keep = b"\r" if buf.endswith(b"\r") else b""
                head = buf[:-1] if keep else buf
                *lines, rest = head.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
                buf = rest + keep
                for line in lines:
                    if line.startswith(b"data:"):
                        value = line[5:]
                        data.append(value[1:] if value.startswith(b" ") else value)
                        continue
                    if line or not data:
                        continue  # comments, other fields, or a blank line with no event
                    event, data = b"\n".join(data), []  # a blank line ends the event
                    if event.strip() == b"[DONE]":
                        return
                    try:
                        parsed = json.loads(event)
                    except (ValueError, RecursionError):
                        raise UpstreamError("upstream stream event is not JSON") from None
                    yield parsed
    except Exception as e:
        failure = _upstream_failure(e, deadline)
        if failure is e:
            raise
        raise failure from None
    finally:
        deadline.cancel()


class _Limiter:
    """Per-user request rate and concurrency, in memory: limits are per gateway process."""

    def __init__(self, per_min: int, concurrent: int, clock: Callable[[], float]) -> None:
        self._per_min, self._concurrent, self._clock = per_min, concurrent, clock
        self._recent: defaultdict[str, deque[float]] = defaultdict(deque)
        self._active: defaultdict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
        self._swept = clock()

    @contextmanager
    def slot(self, user: str) -> Iterator[None]:
        with self._lock:
            now = self._clock()
            if now - self._swept >= 60:
                # Forget users idle for a whole window, or every user ever seen stays in memory.
                self._swept = now
                for idle in [u for u, d in self._recent.items() if not d or now - d[-1] >= 60]:
                    del self._recent[idle]
            recent = self._recent[user]
            while recent and now - recent[0] >= 60:
                recent.popleft()
            if len(recent) >= self._per_min or self._active[user] >= self._concurrent:
                raise HttpError(429, "rate limit exceeded", "rate_limited")
            recent.append(now)
            self._active[user] += 1
        try:
            yield
        finally:
            with self._lock:
                self._active[user] -= 1
                if not self._active[user]:
                    del self._active[user]


class _AuditBudget:
    """Per-peer token bucket for audit records written before authentication.

    Without it a peer looping bad tokens fills the audit volume, and a full volume fails every
    user's request closed. Suppressed records are counted in a log line instead.
    """

    def __init__(self, burst: int, per_min: float, clock: Callable[[], float]) -> None:
        self._burst, self._rate, self._clock = burst, per_min / 60, clock
        self._peers: dict[str, list[float]] = {}  # peer -> [tokens, last refill, suppressed]
        self._lock = threading.Lock()
        self._swept = clock()

    def allow(self, peer: str) -> bool:
        with self._lock:
            now = self._clock()
            if now - self._swept >= 60:
                # Forget peers whose bucket has refilled, or every peer ever seen stays in memory.
                self._swept = now
                full = self._burst / self._rate
                for idle in [p for p, b in self._peers.items() if now - b[1] >= full]:
                    self._summary(idle, self._peers.pop(idle))
            bucket = self._peers.setdefault(peer, [self._burst, now, 0])
            bucket[0] = min(self._burst, bucket[0] + (now - bucket[1]) * self._rate)
            bucket[1] = now
            if bucket[0] < 1:
                bucket[2] += 1
                return False
            bucket[0] -= 1
            self._summary(peer, bucket)
            return True

    @staticmethod
    def _summary(peer: str, bucket: list[float]) -> None:
        if bucket[2]:
            _LOG.warning("suppressed %d pre-auth audit records from peer %r", int(bucket[2]), peer)
            bucket[2] = 0


def _peer(scope: Scope) -> str | None:
    client = scope.get("client")
    return str(client[0]) if client else None


def _content_part(part: Any) -> dict[str, Any]:
    """One message content part, rebuilt: text or an image. Nothing else is forwarded.

    A model server may fetch whatever a ``video_url`` or ``audio_url`` part names (SSRF), and no
    check here reads audio or files. Remote image URLs are refused in ``_screen_messages``.
    """
    kind = part.get("type") if isinstance(part, dict) else None
    if kind == "text" and isinstance(part.get("text"), str):
        return {"type": "text", "text": part["text"]}
    if kind == "image_url" and part.get("image_url") is not None:
        return {"type": "image_url", "image_url": part["image_url"]}
    raise HttpError(400, "unsupported message content part", "bad_request")


def _texts(content: Any) -> list[str]:
    if isinstance(content, str):
        return [content]
    if isinstance(content, list):
        return [
            p["text"] for p in content if isinstance(p, dict) and isinstance(p.get("text"), str)
        ]
    return []


def _replace_texts(content: Any, new: list[str]) -> Any:
    if isinstance(content, str):
        return new[0]
    it = iter(new)
    return [
        {**p, "text": next(it)} if isinstance(p, dict) and isinstance(p.get("text"), str) else p
        for p in content
    ]


def _scannable(tool: dict[str, Any]) -> dict[str, Any]:
    """An OpenAI tool in the shape scan_tool_definitions reads (``parameters`` is the schema)."""
    fn = tool["function"]
    return {
        "name": fn.get("name"),
        "description": fn.get("description"),
        "input_schema": fn.get("parameters"),
    }


class Gateway:
    """ASGI app. ``transport`` is replaceable so tests can stand in for the upstream."""

    def __init__(
        self,
        config: GatewayConfig,
        *,
        transport: Transport = http_transport,
        stream_transport: StreamTransport = http_stream_transport,
        sink: AuditSink | None = None,
        clock: Callable[[], float] = time.monotonic,
        jwks_fetch: Callable[[str], dict[str, Any]] = fetch_jwks,
        mcp_connector: Any = None,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self._transport = transport
        self._stream_transport = stream_transport
        delivery: RetrySink | None = None
        self._audit_probe: Callable[[], None] | None = None
        if sink is None:
            sink = FileSink(config.audit_file)
            # Created owner-only, like the token store (POSIX; Windows uses the folder's ACL).
            os.close(os.open(sink.path, os.O_CREAT | os.O_WRONLY, 0o600))
            self._audit_probe = sink.check_writable
            if config.cef_file:
                # The hash-chained file is the record; CEF is a copy for the SIEM, and TeeSink
                # carries on (and logs) if that copy fails.
                cef = open(config.cef_file, "a", encoding="utf-8")  # noqa: SIM115 - lives with the app
                delivery = RetrySink(CefSink(cef))
                sink = TeeSink(sink, delivery)
        self.metrics = Metrics()
        self.metrics.delivery = delivery
        sink = CountingSink(sink, self.metrics)  # counts a record only once it was written
        # The chain head is read once here; bind() gives each request a logger on that chain.
        self._audit = AuditLogger(
            sink,
            actor="gateway",
            log_content=config.log_content,
            keep_fields=AUDIT_KEEP_FIELDS,
        )
        self._policies = config.policies
        self._reload_lock = threading.Lock()
        self._reload_clock = clock
        self._next_reload = clock() + (config.bundle.reload_interval_s if config.bundle else 0)
        # None: the first due check does a full load. The files may have changed between
        # load_config and here, so a fingerprint taken now could describe another bundle.
        self._bundle_seen: str | None = None
        self._last_reject: str | None = None
        self._scanner = InjectionScanner()
        self._oidc = None if config.oidc is None else OidcVerifier(config.oidc, fetch=jwks_fetch)
        self._auth_slots = asyncio.Semaphore(MAX_CONCURRENT_AUTH)
        self._limiter = _Limiter(config.requests_per_min, config.concurrent_requests, clock)
        self._preauth_audit = _AuditBudget(PREAUTH_AUDIT_BURST, PREAUTH_AUDIT_PER_MIN, clock)
        # Two pools, so slow generations cannot starve auth and policy lookups of threads. A
        # request holds at most one upstream thread, and _upstream_active (event loop only) keeps
        # requests within the pool, so nothing queues there.
        self._upstream_pool = ThreadPoolExecutor(
            MAX_CONCURRENT_UPSTREAM, thread_name_prefix="agentsec-upstream"
        )
        self._upstream_active = 0
        # Auth holds at most MAX_CONCURRENT_AUTH of these; the rest serve policy and token work.
        self._control_pool = ThreadPoolExecutor(
            2 * MAX_CONCURRENT_AUTH, thread_name_prefix="agentsec-control"
        )
        self._tokens = (
            None if config.tokens is None else TokenStore(config.tokens.store, clock=wall_clock)
        )
        self._origins = frozenset(config.allowed_origins)
        # None: a non-loopback bind with no listen.allowed_hosts; the Host header is not checked.
        self._hosts = frozenset(config.allowed_hosts) or loopback_hosts(config.host)
        # The admin listener is for scrapers and probes on this host: no Origin is ever allowed.
        self._admin_hosts = loopback_hosts(config.admin_host)
        # Verified and parsed at startup: a missing, unsigned or invalid feed refuses to start.
        self._feeds = (
            None
            if config.egress is None
            else FeedSet(config.egress, wall_clock=wall_clock, clock=clock)
        )
        self._mcp = None
        if config.mcp_upstreams:
            try:
                from agentsec.gateway.mcp import McpGateway
            except ImportError as e:  # pragma: no cover - depends on the install
                raise RuntimeError(
                    'mcp_upstreams needs the mcp extra: pip install "ai-agent-security-toolkit'
                    '[gateway,mcp]"'
                ) from e
            extra = {} if mcp_connector is None else {"connector": mcp_connector}
            self._mcp = McpGateway(
                config, self._audit, self._scanner, clock=clock, blocklist=self._blocklist, **extra
            )
        self._audit.log(
            "gateway_start",
            policy_rev=config.policies.revision,
            groups=[g.group for g in config.policies.groups],
            # Holdback can deliver text the final check later objects to: say who opted in.
            holdback_groups=[
                g.group for g in config.policies.groups if g.stream_mode == "holdback"
            ],
            # No reviewed pins: these upstreams' tools are trusted as first listed.
            unpinned_mcp_upstreams=unpinned(config.policies, config.mcp_upstreams),
        )
        for event, data in self._feeds.loaded_events() if self._feeds else ():
            self._audit.log(event, **data)
        self._log_allow_expiry(config.policies)

    def _log_allow_expiry(self, policies: PolicySet) -> None:
        """At start and on each bundle load: allowlist entries that no longer match, and
        those about to stop, so an operator renews or drops them before traffic changes."""
        for gp in policies.groups:
            expired, soon = gp.dlp.allow_expiry()
            for event, entries in (("dlp_allow_expired", expired), ("dlp_allow_expiring", soon)):
                if entries:
                    self._audit.log(
                        event,
                        policy_group=gp.group,
                        policy_rev=policies.revision,
                        entries=[{"id": e.id, "expires": e.expires.isoformat()} for e in entries],
                    )

    def _blocklist(self) -> Blocklist | None:
        return None if self._feeds is None else self._feeds.current

    def _refresh_feeds(self) -> None:
        if self._feeds is not None:
            for event, data in self._feeds.refresh():
                self._audit.log(event, **data)

    # ------------------------------------------------------------------ ASGI
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return  # lifespan is turned off in serve(); websockets are not served
        send = self._counted(send)
        request_id = uuid.uuid4().hex
        user, peer = None, _peer(scope)
        try:
            path, method = scope["path"], scope["method"]
            if path == "/healthz" and method == "GET":
                await self._json(send, 200, {"status": "ok"}, request_id)
                return  # exempt: a container probe sends the pod address as Host
            _check_origin_host(scope, self._origins, self._hosts)
            user, groups, token_id = await self._identify(scope, request_id)
            _TOKEN_ID.set(token_id)  # recorded on this request's audit records
            # A reload reads and verifies files: off the event loop.
            policies, gp = await self._off_loop(self._control_pool, self._group_policy, groups)
            if path == "/v1/models" and method == "GET":
                self._log_request("gateway_models_listed", user, groups, policies, gp, request_id)
                data = [
                    {"id": n, "object": "model", "owned_by": "agentsec"}
                    for n in self.config.upstreams
                    if gp.models is None or n in gp.models
                ]
                await self._json(send, 200, {"object": "list", "data": data}, request_id)
                return
            if self._tokens is not None and (path == "/tokens" or path.startswith("/tokens/")):
                with self._limiter.slot(user):
                    await self._serve_tokens(
                        scope, receive, send, user, groups, token_id, request_id, policies, gp
                    )
                return
            if path == "/mcp" and self._mcp is not None:
                if method not in {"POST", "GET", "DELETE"}:
                    raise HttpError(405, "method not allowed", "method_not_allowed")
                with self._limiter.slot(user):
                    await self._serve_mcp(
                        scope, receive, send, user, groups, policies, gp, request_id
                    )
                return
            if path != "/v1/chat/completions":
                raise HttpError(404, "not found", "not_found")
            if method != "POST":
                raise HttpError(405, "method not allowed", "method_not_allowed")
            # The slot covers the body read, so stalled uploads count against the user's limits.
            with self._limiter.slot(user):
                try:
                    body = await asyncio.wait_for(
                        self._read_body(receive), self.config.body_timeout_s
                    )
                except TimeoutError:
                    raise HttpError(408, "request body timed out", "body_timeout") from None
                # Policy checks may resolve DNS and the upstream call blocks: keep both off the loop.
                if self._upstream_active >= MAX_CONCURRENT_UPSTREAM:
                    raise HttpError(503, "busy", "busy")  # rather than queue behind slow calls
                self._upstream_active += 1
                try:
                    status, payload, stream = await self._off_loop(
                        self._upstream_pool,
                        self._complete, body, user, groups, request_id, policies, gp,
                    )  # fmt: skip
                    if not isinstance(payload, dict):  # holdback: released as it is checked
                        await self._stream_events(send, payload, request_id)
                        return
                finally:
                    self._upstream_active -= 1
        except HttpError as e:
            if not e.audited:
                self._log_rejection(e, request_id, user, peer)
            await self._error(send, e, request_id)
            return
        except OSError as e:
            # Most likely the audit file: an unaudited model call is a gap in the evidence.
            self._log_failure(e, request_id, user, peer)
            await self._error(send, HttpError(503, "unavailable", "unavailable"), request_id)
            return
        except Exception as e:  # noqa: BLE001 - fail closed, never leak internals to the client
            self._log_failure(e, request_id, user, peer)
            await self._error(send, HttpError(500, "internal error", "internal_error"), request_id)
            return
        if stream:
            await self._sse(send, payload, request_id)
        else:
            await self._json(send, status, payload, request_id)

    # ------------------------------------------------------------------ tokens
    async def _serve_tokens(
        self, scope: Scope, receive: Receive, send: Send, user: str, groups: tuple[str, ...],
        token_id: str | None, request_id: str, policies: PolicySet, gp: GroupPolicy,
    ) -> None:  # fmt: skip
        """POST /tokens, GET /tokens, DELETE /tokens/<id>: a user's own access tokens."""
        tokens = self._tokens
        assert tokens is not None  # noqa: S101 - the route checks it
        settings = self.config.tokens
        assert settings is not None  # noqa: S101 - set together with the store
        if token_id is not None:
            # Only an SSO sign-in manages tokens: a leaked token must not mint or keep others.
            raise HttpError(403, "tokens cannot be managed with a token", "forbidden")
        path, method = scope["path"], scope["method"]
        log = self._audit.bind(actor=user, session_id=request_id)
        if path == "/tokens" and method == "GET":
            listed = await self._off_loop(self._control_pool, lambda: tokens.list(user=user))
            self._log_request("gateway_tokens_listed", user, groups, policies, gp, request_id)
            await self._json(send, 200, {"data": [t.public() for t in listed]}, request_id)
            return
        if path == "/tokens" and method == "POST":
            ctype = dict(scope.get("headers", [])).get(b"content-type", b"")
            if ctype.split(b";")[0].strip().lower() != b"application/json":
                # A cross-site form post cannot send this type without a CORS preflight.
                raise HttpError(415, "content-type must be application/json", "bad_request")
            try:
                body = await asyncio.wait_for(self._read_body(receive), self.config.body_timeout_s)
            except TimeoutError:
                raise HttpError(408, "request body timed out", "body_timeout") from None
            name, ttl_s = self._token_request(body, settings)
            try:
                info, token = await self._off_loop(
                    self._control_pool,
                    tokens.issue, user, groups, name, ttl_s, settings.max_per_user,
                )  # fmt: skip
            except TokenError as e:
                # Disabled after this request was identified: not the per-user limit.
                if await self._off_loop(self._control_pool, tokens.is_user_disabled, user):
                    raise HttpError(403, "user disabled", "user_disabled") from None
                raise HttpError(409, str(e), "too_many_tokens") from None
            log.log("gateway_token_issued", token_id=info.id, name=name, expires=info.expires)
            await self._json(
                send, 201, {**info.public(), "token": token}, request_id
            )  # shown once: only its hash is kept
            return
        if path.startswith("/tokens/") and method == "DELETE":
            target = path[len("/tokens/") :]
            done = await self._off_loop(
                self._control_pool, lambda: tokens.revoke(target, user=user)
            )
            if not done:
                raise HttpError(404, "no such token", "not_found")  # also someone else's
            log.log("gateway_token_revoked", token_id=target, by="owner")
            await self._json(send, 200, {"id": target, "revoked": True}, request_id)
            return
        raise HttpError(405 if path == "/tokens" else 404, "not found", "not_found")

    @staticmethod
    def _token_request(body: bytes, settings: TokenSettings) -> tuple[str, float]:
        try:
            data = json.loads(body or b"{}")
        except ValueError:
            raise HttpError(400, "body is not valid JSON", "bad_request") from None
        if not isinstance(data, dict) or set(data) - {"name", "ttl_days"}:
            raise HttpError(400, "body takes name and ttl_days", "bad_request")
        name = data.get("name", "")
        if not isinstance(name, str) or len(name) > 64 or not name.isprintable():
            raise HttpError(
                400, "name must be printable text of at most 64 characters", "bad_request"
            )
        ttl = data.get("ttl_days")
        if ttl is None:
            return name, settings.default_ttl_s
        if not isinstance(ttl, int | float) or isinstance(ttl, bool):
            raise HttpError(400, "ttl_days must be a number", "bad_request")
        try:
            ttl_s = float(ttl) * 86400  # a huge JSON integer overflows a float
        except OverflowError:
            ttl_s = math.inf
        if not math.isfinite(ttl_s):
            raise HttpError(400, "ttl_days is above the allowed maximum", "bad_request")
        if not 0 < ttl_s <= settings.max_ttl_s:
            raise HttpError(400, "ttl_days is above the allowed maximum", "bad_request")
        return name, ttl_s

    def _from_access_token(
        self, token: str, request_id: str, peer: str | None
    ) -> tuple[str, tuple[str, ...], str]:
        assert self._tokens is not None  # noqa: S101 - callers check it
        try:
            info = self._tokens.verify(token)
        except TokenError as e:
            # The store's reasons are a fixed set; the only variable part is its own token id.
            self._log_auth_failed(request_id, str(e), peer)
            raise HttpError(401, "unauthenticated", "unauthenticated", audited=True) from None
        return info.user, info.groups, info.id

    async def _serve_mcp(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        user: str,
        groups: tuple[str, ...],
        policies: PolicySet,
        gp: GroupPolicy,
        request_id: str,
    ) -> None:
        from agentsec.gateway.mcp import Caller

        assert self._mcp is not None  # noqa: S101 - the route checks it
        started = False

        async def tracked(message: dict[str, Any]) -> None:
            nonlocal started
            started = started or message["type"] == "http.response.start"
            await send(message)

        caller = Caller(user, groups, policies, gp, request_id, _TOKEN_ID.get())
        # Initialize, session delete and the like leave no record of their own in McpGateway.
        self._log_request(
            "gateway_mcp_request", user, groups, policies, gp, request_id,
            method=scope["method"],
            session=any(k.lower() == b"mcp-session-id" for k, _ in scope.get("headers", [])),
        )  # fmt: skip
        # One deadline for the whole exchange: a stalled body or upstream holds a slot otherwise.
        deadline = self.config.body_timeout_s + 2 * self.config.upstream_timeout_s
        try:
            await asyncio.wait_for(self._mcp.handle(scope, receive, tracked, caller), deadline)
        except TimeoutError:
            if started:
                return  # the answer was on its way; nothing more can be said
            raise HttpError(504, "mcp request timed out", "upstream_timeout") from None

    def _counted(self, send: Send) -> Send:
        async def counted(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                self.metrics.response(message["status"])
            await send(message)

        return counted

    # ------------------------------------------------------------------ admin
    async def admin(self, scope: Scope, receive: Receive, send: Send) -> None:
        """The admin listener: /healthz, /readyz, /metrics, /dashboard, /evidence/. Loopback only.

        Every route is a GET that changes nothing: there is no write endpoint here by design.
        """
        if scope["type"] != "http":
            return
        request_id = uuid.uuid4().hex
        try:
            _check_origin_host(scope, frozenset(), self._admin_hosts)
        except HttpError as e:
            self._log_rejection(e, request_id, None, _peer(scope))
            await self._error(send, e, request_id)
            return
        path, method = scope["path"], scope["method"]
        evidence = path.startswith("/evidence/")
        if method != "GET" or not (
            evidence or path in {"/healthz", "/readyz", "/metrics", "/dashboard"}
        ):
            await self._error(send, HttpError(404, "not found", "not_found"), request_id)
            return
        if evidence:
            found = await self._off_loop(
                self._control_pool, read_evidence, self.config.admin_evidence_dir, path
            )
            if found is None:
                await self._error(send, HttpError(404, "not found", "not_found"), request_id)
                return
            ctype, data = found
            headers = [(b"content-type", ctype), *DASHBOARD_HEADERS]
            await send({"type": "http.response.start", "status": 200, "headers": headers})
            await send({"type": "http.response.body", "body": data})
            return
        if path == "/healthz":
            await self._json(send, 200, {"status": "ok"}, request_id)
            return
        try:
            # Without traffic nothing else checks for a new bundle; this keeps readiness honest.
            await self._off_loop(self._control_pool, self._maybe_reload)
        except Exception:  # noqa: BLE001 - _maybe_reload logs its own failures
            _LOG.exception("bundle reload from the admin listener failed")
        # Redeliver a SIEM backlog even with no traffic.
        await self._off_loop(self._control_pool, self.metrics.flush)
        policies = self._policies
        if path == "/metrics":
            ages = {} if self._feeds is None else self._feeds.ages()
            body = self.metrics.render(policies, ages).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"content-type", b"text/plain; version=0.0.4; charset=utf-8"),
                        (b"cache-control", b"no-store"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        expired = policies.expires is not None and datetime.now(UTC) >= policies.expires
        audit_ok = True
        if self._audit_probe is not None:
            try:
                await self._off_loop(self._control_pool, self._audit_probe)
            except OSError:
                audit_ok = False
        payload = {
            "status": "policy_expired"
            if expired
            else "audit_unwritable"
            if not audit_ok
            else "ready",
            "policy_rev": policies.revision,
            # Shown so a group left in monitor mode is not forgotten.
            "monitor_groups": [g.group for g in policies.groups if g.mode == "monitor"],
        }
        if self._feeds is not None:
            # Still ready: a stale deny list keeps blocking what it listed (on_stale decides).
            payload["blocklist_stale"] = self._feeds.stale()
        if path == "/dashboard":
            report = await self._off_loop(
                self._control_pool, load_fuzz_summary, self.config.admin_fuzz_report
            )
            listing = await self._off_loop(
                self._control_pool, list_evidence, self.config.admin_evidence_dir
            )
            snap = self.metrics.snapshot()
            feeds = None if self._feeds is None else self._feeds.status()
            body = render_dashboard(payload, policies, snap, report, listing, feeds).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"text/html; charset=utf-8"), *DASHBOARD_HEADERS],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self._json(send, 503 if expired or not audit_ok else 200, payload, request_id)

    # ------------------------------------------------------------ policy
    def _group_policy(self, groups: tuple[str, ...]) -> tuple[PolicySet, GroupPolicy]:
        self._maybe_reload()
        policies = self._policies  # one read: the request keeps this revision throughout
        if policies.expires is not None and datetime.now(UTC) >= policies.expires:
            # Stale policy is a slow failure: refuse service rather than enforce it forever.
            raise HttpError(503, "policy bundle expired", "policy_expired")
        gp = policies.resolve(groups)
        if gp is None:
            raise HttpError(403, "forbidden", "forbidden")
        return policies, gp

    def _bundle_fingerprint(self) -> str | None:
        bundle = self.config.bundle
        if bundle is None:
            return None
        h = hashlib.sha256()
        for name in (MANIFEST, SIGNATURE):
            try:
                with (Path(bundle.dir) / name).open("rb") as fh:
                    # Bounded, like the verifier: anyone who can write the directory must not be
                    # able to make the gateway read a huge file into memory.
                    h.update(fh.read(MAX_FILE_BYTES + 1))
            except OSError:
                h.update(b"missing")
            h.update(b"\0")
        return h.hexdigest()

    def _maybe_reload(self) -> None:
        self._refresh_feeds()  # on its own interval; reads files, so also off the event loop
        bundle = self.config.bundle
        if bundle is None or bundle.reload_interval_s == 0:
            return
        now = self._reload_clock()
        if now < self._next_reload or not self._reload_lock.acquire(blocking=False):
            return  # not due, or another request is already reloading
        try:
            self._next_reload = now + bundle.reload_interval_s
            seen = self._bundle_fingerprint()
            if seen == self._bundle_seen:
                return
            current = self._policies
            try:
                new = load_bundle(
                    bundle.dir,
                    bundle.public_key,
                    upstreams=set(self.config.upstreams),
                    mcp_upstreams=set(self.config.mcp_upstreams),
                )
                if new.revision == current.revision:
                    self._bundle_seen = seen  # the bundle already in force
                    return
                floor = max(bundle.min_revision, (current.numeric_revision or 0) + 1)
                if new.numeric_revision is None or new.numeric_revision < floor:
                    raise BundleError(
                        f"revision {new.numeric_revision} is not above the current "
                        f"{current.numeric_revision} (rollback refused)"
                    )
                missing = unpinned(new, self.config.mcp_upstreams)
                if self.config.mcp_require_pins and missing:
                    raise BundleError(f"mcp.require_pins: no pins for {missing}")
                if bundle.state_file is not None:
                    # Persist before enforcing: if this fails, the old bundle stays in force.
                    write_state(bundle.state_file, new)
            except Exception as e:  # noqa: BLE001 - any failure keeps the last good bundle
                # Retried every interval (a bundle copied file by file settles), logged once.
                if str(e) != self._last_reject:
                    self._last_reject = str(e)
                    self._audit.log(
                        "gateway_bundle_rejected", reason=str(e), policy_rev=current.revision
                    )
                return
            self._policies, self._bundle_seen, self._last_reject = new, seen, None
            self._audit.log(
                "gateway_bundle_loaded",
                policy_rev=new.revision,
                groups=[g.group for g in new.groups],
                unpinned_mcp_upstreams=missing,
            )
            self._log_allow_expiry(new)
        finally:
            self._reload_lock.release()

    @staticmethod
    async def _off_loop(pool: ThreadPoolExecutor, fn: Callable[..., Any], *args: Any) -> Any:
        """``asyncio.to_thread`` on one of our own pools (the contextvars come along, as there)."""
        ctx = contextvars.copy_context()
        return await asyncio.get_running_loop().run_in_executor(pool, ctx.run, fn, *args)

    def _log_request(
        self, event: str, user: str, groups: tuple[str, ...], policies: PolicySet,
        gp: GroupPolicy, request_id: str, **data: Any,
    ) -> None:  # fmt: skip
        """The record of a request that is not a chat completion, shaped like gateway_request."""
        key = gp.dlp.fingerprint_key
        self._audit.bind(
            actor=user, session_id=request_id, email_key=key, detectors=gp.dlp.detectors
        ).log(
            event,
            groups=list(groups),
            policy_group=gp.group,
            policy_rev=policies.revision,
            mode=gp.mode,
            token_id=_TOKEN_ID.get(),
            **data,
        )

    def _log_auth_failed(self, request_id: str, reason: str, peer: str | None) -> None:
        if self._preauth_audit.allow(peer or ""):
            self._audit.log("gateway_auth_failed", request_id=request_id, reason=reason, peer=peer)

    def _log_rejection(
        self, e: HttpError, request_id: str, user: str | None, peer: str | None
    ) -> None:
        # A refused user is always recorded; an unidentified peer only within its budget.
        if user is None and not self._preauth_audit.allow(peer or ""):
            return
        try:
            self._audit.bind(actor=user).log(
                "gateway_rejected", request_id=request_id, status=e.status, code=e.code, peer=peer
            )
        except Exception:  # noqa: BLE001 - the client gets its error either way
            _LOG.warning("could not audit a rejected request", exc_info=True)

    def _log_failure(
        self, e: Exception, request_id: str, user: str | None, peer: str | None
    ) -> None:
        _LOG.error("request %s failed", request_id, exc_info=e)
        if user is None and not self._preauth_audit.allow(peer or ""):
            return
        try:
            # Only the type: an exception message can carry secret material.
            self._audit.bind(actor=user).log(
                "gateway_error", request_id=request_id, error=type(e).__name__, peer=peer
            )
        except Exception:  # noqa: BLE001 - best effort; the audit file may be what failed
            _LOG.warning("could not audit a failed request", exc_info=True)

    async def _identify(
        self, scope: Scope, request_id: str
    ) -> tuple[str, tuple[str, ...], str | None]:
        token_id = None
        bearer, peer = _bearer(scope), _peer(scope)
        if self._tokens is not None and bearer is not None and looks_like_token(bearer):
            # An access token stands in for the SSO sign-in it was issued after, from any peer.
            if self._auth_slots.locked():
                raise HttpError(503, "busy", "busy")
            async with self._auth_slots:
                user, groups, token_id = await self._off_loop(
                    self._control_pool, self._from_access_token, bearer, request_id, peer
                )
        elif self._oidc is None:
            user, groups = self._from_trusted_header(scope)
        else:
            # Unauthenticated work is bounded before any per-user limiter can apply: a flood of
            # bad tokens gets 503s instead of queueing up the worker threads.
            if self._auth_slots.locked():
                raise HttpError(503, "busy", "busy")
            async with self._auth_slots:
                # A JWKS refresh is blocking network I/O: keep it off the event loop.
                user, groups = await self._off_loop(
                    self._control_pool, self._from_token, self._oidc, scope, request_id
                )
        e = None
        # The disabled list lives in the token store: without a `tokens` section there is none,
        # and a disabled user's SSO identity is accepted. An access token was checked by verify().
        if (
            self._tokens is not None
            and token_id is None
            and await self._off_loop(self._control_pool, self._tokens.is_user_disabled, user)
        ):
            e = HttpError(403, "user disabled", "user_disabled", audited=True)
        allowed = self.config.allowed_groups
        if e is None and allowed and not set(groups) & set(allowed):
            e = HttpError(403, "forbidden", "forbidden", audited=True)
        if e is not None:
            # Audited here, where the user is known: the caller only sees the error.
            self._log_rejection(e, request_id, user, peer)
            raise e
        return user, groups, token_id

    def _from_token(
        self, verifier: OidcVerifier, scope: Scope, request_id: str
    ) -> tuple[str, tuple[str, ...]]:
        auth = [v for k, v in scope.get("headers", []) if k.lower() == b"authorization"]
        scheme, _, token = (auth[0].decode("latin-1") if len(auth) == 1 else "").partition(" ")
        try:
            if scheme.lower() != "bearer" or not token.strip():
                raise TokenRejected("no single bearer token")
            return verifier.verify(token.strip())
        except TokenRejected:
            # A fixed reason: the verifier's message can quote the token's own header (alg).
            self._log_auth_failed(request_id, "bearer token rejected", _peer(scope))
            raise HttpError(401, "unauthenticated", "unauthenticated", audited=True) from None

    def _from_trusted_header(self, scope: Scope) -> tuple[str, tuple[str, ...]]:
        """Trusted-header identity: the header counts only from a configured auth proxy."""
        client = scope.get("client")
        try:
            peer = ipaddress.ip_address(client[0]) if client else None
        except ValueError:
            peer = None
        if isinstance(peer, ipaddress.IPv6Address) and peer.ipv4_mapped:
            peer = peer.ipv4_mapped
        if peer is None or not any(peer in net for net in self.config.trusted_proxies):
            raise HttpError(401, "unauthenticated", "unauthenticated")
        users, groups_raw = [], []
        for name, value in scope.get("headers", []):
            key = name.decode("latin-1").lower()
            if key == self.config.user_header:
                users.append(value.decode("latin-1"))
            elif key == self.config.groups_header:
                groups_raw.append(value.decode("latin-1"))
        user = users[0].strip() if len(users) == 1 else ""
        # Repeated identity headers are refused: proxies and apps disagree on which one wins.
        if not user or len(user) > 256 or not user.isprintable() or len(groups_raw) > 1:
            raise HttpError(401, "unauthenticated", "unauthenticated")
        groups = (
            tuple(g.strip() for g in groups_raw[0].split(",") if g.strip()) if groups_raw else ()
        )
        return user, groups

    async def _read_body(self, receive: Receive) -> bytes:
        chunks, size, limit = [], 0, self.config.max_body_bytes
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                raise HttpError(400, "client disconnected", "bad_request")
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > limit:
                raise HttpError(413, "request body too large", "body_too_large")
            chunks.append(chunk)
            if not message.get("more_body"):
                return b"".join(chunks)

    # ------------------------------------------------------------- the request
    def _complete(
        self,
        body: bytes,
        user: str,
        groups: tuple[str, ...],
        request_id: str,
        policies: PolicySet,
        gp: GroupPolicy,
    ) -> tuple[int, dict[str, Any] | Generator[dict[str, Any], None, None], bool]:
        cfg = self.config
        # Email addresses in this request's records: the group's DLP fingerprint key.
        key = gp.dlp.fingerprint_key
        log = self._audit.bind(
            actor=user, session_id=request_id, email_key=key, detectors=gp.dlp.detectors
        )
        enforce = gp.mode == "enforce"
        req = self._parse(body, gp)
        stream = req.pop("stream")
        include_usage = req.pop("include_usage")
        log.log(
            "gateway_request",
            groups=list(groups),
            policy_group=gp.group,
            policy_rev=policies.revision,
            mode=gp.mode,
            model=req["model"],
            stream=stream,
            stream_mode=gp.stream_mode if stream else None,
            token_id=_TOKEN_ID.get(),
        )
        upstream = cfg.upstreams[req["model"]]
        blocklist = self._blocklist()  # one read: this request keeps the list it started with
        if blocklist is not None and cfg.egress is not None and cfg.egress.check_model_links:
            links = BlocklistLinkValidator(
                blocklist, lambda fields: log.log("egress_blocked", **fields)
            )
            guard_out = OutputGuard(
                [*gp.output_guard.validators, links],
                blocked_message=gp.output_guard.blocked_message,
            )
            gp = dataclasses.replace(gp, output_guard=guard_out)
        guard = ToolGuard(gp.policy, audit=log, blocklist=blocklist, dlp=gp.dlp)
        mw = AgentMiddleware(
            guard=guard,
            output_guard=gp.output_guard,
            scanner=self._scanner,
            audit=log,
            block_on_injection=gp.block_on_injection,
            spotlight_untrusted=gp.spotlight_tool_results,
        )
        session = Session(id=request_id)  # taint is per request: the history is resent each turn

        removed_tools = self._filter_tools(req, log, enforce, gp.policy)
        blocked = self._screen_messages(req, mw, session)
        if blocked:
            log.log("gateway_input_blocked", reasons=blocked, enforced=enforce)
            if enforce:
                raise HttpError(400, "request blocked by input policy", "input_blocked")
        self._screen_outbound(req, upstream, log, gp)

        if stream and gp.stream_mode == "holdback":
            req["model"], req["stream"] = upstream.model, True
            if include_usage:
                req["stream_options"] = {"include_usage": True}
            events = self._holdback_events(
                upstream, json.dumps(req).encode(), mw, session, enforce, log, gp,
                request_id, include_usage, removed_tools,
            )  # fmt: skip
            return 200, events, True
        req["model"], req["stream"] = upstream.model, False
        payload = json.dumps(req).encode()
        try:
            raw = self._transport(upstream, payload, cfg.upstream_timeout_s, cfg.max_response_bytes)
        except UpstreamError as e:
            log.log("gateway_upstream_error", upstream=upstream.name, error=str(e))
            raise HttpError(502, "upstream error", "upstream_error") from None
        except TimeoutError:
            log.log("gateway_upstream_error", upstream=upstream.name, error="timeout")
            raise HttpError(504, "upstream timeout", "upstream_timeout") from None

        result = self._check_response(raw, mw, session, enforce, log, gp)
        result.update(
            id=f"chatcmpl-{request_id}", object="chat.completion", created=int(time.time())
        )
        result["model"] = upstream.name
        if not include_usage and stream:
            result.pop("usage", None)
        log.log(
            "gateway_response",
            tools_removed=removed_tools,
            finish_reason=result["choices"][0]["finish_reason"],
        )
        return 200, result, stream

    def _holdback_events(
        self,
        upstream: Upstream,
        payload: bytes,
        mw: AgentMiddleware,
        session: Session,
        enforce: bool,
        log: AuditLogger,
        gp: GroupPolicy,
        request_id: str,
        include_usage: bool,
        removed_tools: list[str],
    ) -> Generator[dict[str, Any], None, None]:
        """Chunks to send. Text is released through Holdback; tool calls only at the end."""
        cfg = self.config
        base = {
            "id": f"chatcmpl-{request_id}",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": upstream.name,
        }

        def chunk(delta: dict[str, Any], finish: str | None = None) -> dict[str, Any]:
            return base | {"choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}

        held = Holdback(gp.output_guard, gp.holdback_chars)
        calls: dict[int, dict[str, Any]] = {}
        finish: Any = None
        usage: Any = None
        first = True
        upstream_events = self._stream_transport(
            upstream, payload, cfg.upstream_timeout_s, cfg.max_response_bytes
        )
        try:
            for event in upstream_events:
                if not isinstance(event, dict):
                    raise UpstreamError("upstream stream event is not an object")
                if event.get("error") is not None:
                    # Servers report a failure mid-stream as an error event, often followed by
                    # [DONE]: the text so far is a cut-off answer, not a finished one. The
                    # event's message is upstream text and is not kept.
                    raise UpstreamError("upstream stream reported an error")
                if isinstance(event.get("usage"), dict):
                    usage = event["usage"]
                choices = event.get("choices")
                if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
                    continue
                if choices[0].get("finish_reason") is not None:
                    finish = choices[0]["finish_reason"]
                delta = choices[0].get("delta")
                delta = delta if isinstance(delta, dict) else {}
                tool_deltas = delta.get("tool_calls") or []
                if not isinstance(tool_deltas, list):
                    raise UpstreamError("malformed streamed tool call")
                for tc in tool_deltas:
                    _merge_tool_call(calls, tc)
                text = delta.get("content")
                if text is not None and not isinstance(text, str):
                    raise UpstreamError("stream content is not a string")
                out = held.feed(text) if text else ""
                if out:
                    yield chunk(
                        {"role": "assistant", "content": out} if first else {"content": out}
                    )
                    first = False
        except UpstreamError as e:
            self._audit_cut_stream(held, mw, log, enforce)
            log.log(
                "gateway_upstream_error",
                upstream=upstream.name,
                error=str(e),
                released_chars=len(held.released),
            )
            raise HttpError(502, "upstream error", "upstream_error", audited=True) from None
        except TimeoutError:
            self._audit_cut_stream(held, mw, log, enforce)
            log.log(
                "gateway_upstream_error",
                upstream=upstream.name,
                error="timeout",
                released_chars=len(held.released),
            )
            raise HttpError(504, "upstream timeout", "upstream_timeout", audited=True) from None
        except GeneratorExit:
            self._audit_cut_stream(held, mw, log, enforce)
            log.log("gateway_client_disconnected", released_chars=len(held.released))
            raise
        except HttpError:
            raise
        except Exception as e:
            # Any other failure mid-stream still gets a record of what was already delivered;
            # once the stream has started the client only sees an error event.
            _LOG.error("holdback stream %s failed", request_id, exc_info=e)
            self._audit_cut_stream(held, mw, log, enforce)
            log.log("gateway_error", error=type(e).__name__, released_chars=len(held.released))
            raise HttpError(500, "internal error", "internal_error", audited=True) from None
        finally:
            upstream_events.close()  # client gone or upstream failed: stop the upstream too

        raw = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": held.text or None,
                        "tool_calls": [calls[i] for i in sorted(calls)],
                    },
                    "finish_reason": finish,
                }
            ],
            "usage": usage,
        }
        result = self._check_response(raw, mw, session, enforce, log, gp)
        msg, final_reason = result["choices"][0]["message"], result["choices"][0]["finish_reason"]
        final, sent = msg.get("content") or "", held.released
        if not final.startswith(sent):
            # Already delivered and cannot be recalled: end without [DONE], loudly.
            log.log(
                "gateway_output_violation_after_delivery",
                severity="high",
                released_chars=len(sent),
                enforced=enforce,
            )
            raise HttpError(
                502, "output policy violation after delivery", "output_violation", audited=True
            )
        delta_out: dict[str, Any] = {"role": "assistant"} if first else {}
        rest = final[len(sent) :]
        if rest or first:
            delta_out["content"] = rest or msg.get("content")
        if msg.get("tool_calls"):
            delta_out["tool_calls"] = [{"index": i, **tc} for i, tc in enumerate(msg["tool_calls"])]
        if delta_out:
            yield chunk(delta_out)
        yield chunk({}, final_reason)
        if include_usage and "usage" in result:
            yield base | {"choices": [], "usage": result["usage"]}
        log.log(
            "gateway_response",
            tools_removed=removed_tools,
            finish_reason=final_reason,
            released_early=len(sent),
            buffered=held.buffering,
        )

    @staticmethod
    def _audit_cut_stream(
        held: Holdback, mw: AgentMiddleware, log: AuditLogger, enforce: bool
    ) -> None:
        """Record what a holdback stream delivered before it was cut short.

        The final check of a finished answer never runs on a cut stream, so the text the
        client already has would otherwise be in no record, and a violation in it (a secret
        longer than the window, say) would go unnoticed. Recorded like a finished answer: the
        ``model_output`` record holds the checked text, never what a validator removed.
        """
        sent = held.released
        if not sent:
            return
        try:
            checked = mw.screen_output(sent)
            if not checked.allowed or checked.text != sent:
                log.log(
                    "gateway_output_violation_after_delivery",
                    severity="high",
                    released_chars=len(sent),
                    enforced=enforce,
                    interrupted=True,
                )
        except Exception:  # noqa: BLE001 - the stream's own failure is what gets reported
            _LOG.warning("could not audit a cut-off stream", exc_info=True)

    async def _stream_events(
        self, send: Send, events: Generator[dict[str, Any], None, None], request_id: str
    ) -> None:
        """Send holdback chunks. Before the first one an error is a normal HTTP error."""
        started = False
        try:
            while True:
                try:
                    # Each step may wait on the upstream and run validators: off the loop.
                    event = await self._off_loop(self._upstream_pool, next, events, None)
                except Exception as e:  # noqa: BLE001 - mapped below; never leak internals
                    if not started:
                        raise
                    if not isinstance(e, HttpError):
                        _LOG.exception("holdback stream failed")
                        e = HttpError(500, "internal error", "internal_error")
                    error = {
                        "error": {"message": e.message, "type": "gateway_error", "code": e.code}
                    }
                    # No [DONE]: a client must not mistake a cut-off stream for a whole answer.
                    body = f"data: {json.dumps(error)}\n\n".encode()
                    await send({"type": "http.response.body", "body": body})
                    return
                if event is None:
                    break
                if not started:
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 200,
                            "headers": [
                                (b"content-type", b"text/event-stream"),
                                (b"x-request-id", request_id.encode()),
                                (b"cache-control", b"no-store"),
                            ],
                        }
                    )
                    started = True
                data = f"data: {json.dumps(event)}\n\n".encode()
                await send({"type": "http.response.body", "body": data, "more_body": True})
            await send({"type": "http.response.body", "body": b"data: [DONE]\n\n"})
        except OSError:
            if not started:
                raise
            # The client went away mid-stream: no second response; finally stops the upstream.
        finally:
            try:
                events.close()  # also audits the disconnect when the stream was cut short
            except ValueError:
                # "generator already executing": this task was cancelled while a worker ran a
                # step. That step ends by the upstream deadline; do not mask the cancellation.
                _LOG.warning("holdback stream %s cancelled mid-step", request_id)

    def _parse(self, body: bytes, gp: GroupPolicy) -> dict[str, Any]:
        try:
            data = json.loads(body)
        except ValueError:
            raise HttpError(400, "body is not valid JSON", "bad_request") from None
        if not isinstance(data, dict):
            raise HttpError(400, "body must be a JSON object", "bad_request")
        model = data.get("model")
        if (
            not isinstance(model, str)
            or model not in self.config.upstreams
            or (gp.models is not None and model not in gp.models)
        ):
            raise HttpError(404, "unknown model", "model_not_found")
        if data.get("n", 1) != 1:
            raise HttpError(400, "only n=1 is supported", "bad_request")
        stream = data.get("stream", False)
        if not isinstance(stream, bool):
            raise HttpError(400, "stream must be a boolean", "bad_request")
        options = data.get("stream_options") or {}
        include_usage = isinstance(options, dict) and options.get("include_usage") is True
        messages = data.get("messages")
        if not isinstance(messages, list) or not messages:
            raise HttpError(400, "messages must be a non-empty list", "bad_request")
        clean = []
        for m in messages:
            if not isinstance(m, dict) or m.get("role") not in _ROLES:
                raise HttpError(400, "each message needs a valid role", "bad_request")
            if not (m.get("content") is None or isinstance(m.get("content"), str | list)):
                raise HttpError(400, "message content must be a string or a list", "bad_request")
            m = {k: v for k, v in m.items() if k in _MESSAGE_FIELDS}
            if isinstance(m.get("content"), list):
                m["content"] = [_content_part(p) for p in m["content"]]
            clean.append(m)
        req = {k: v for k, v in data.items() if k in _REQUEST_FIELDS}
        req["messages"] = clean
        max_tokens = data.get("max_tokens", self.config.max_tokens_cap)
        if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens <= 0:
            raise HttpError(400, "max_tokens must be a positive integer", "bad_request")
        req["max_tokens"] = min(max_tokens, self.config.max_tokens_cap)
        req["stream"], req["include_usage"] = stream, include_usage
        return req

    def _filter_tools(
        self, req: dict[str, Any], log: AuditLogger, enforce: bool, policy: Policy
    ) -> list[str]:
        """Offer the model only tools the policy allows and whose definitions scan clean."""
        if not enforce:
            return self._monitor_tools(req, log, policy)
        tools = req.pop("tools", None)
        choice = req.pop("tool_choice", None)
        parallel = req.pop("parallel_tool_calls", None)
        if tools is None:
            if isinstance(choice, dict) or choice == "required":
                raise HttpError(400, "tool_choice names a tool that is not offered", "bad_request")
            return []
        if not isinstance(tools, list):
            raise HttpError(400, "tools must be a list", "bad_request")
        rules = policy.tools
        kept, removed = [], []
        for t in tools:
            fn = t.get("function") if isinstance(t, dict) and t.get("type") == "function" else None
            name = fn.get("name") if isinstance(fn, dict) else None
            rule = rules.get(name) if isinstance(name, str) else None
            if rule is None or not rule.allow:
                removed.append(str(name))
                continue
            kept.append(t)
        flagged = {f.tool for f in scan_tool_definitions([_scannable(t) for t in kept])}
        if flagged:
            log.log("gateway_tool_definition_flagged", tools=sorted(flagged))
            removed += sorted(flagged)
            kept = [t for t in kept if t["function"]["name"] not in flagged]
        if removed:
            log.log("gateway_tools_removed", tools=removed, enforced=True)
        names = {t["function"]["name"] for t in kept}
        if isinstance(choice, dict):
            fn = choice.get("function")
            if not isinstance(fn, dict) or fn.get("name") not in names:
                raise HttpError(400, "tool_choice names a tool that is not offered", "bad_request")
        elif choice == "required" and not kept:
            raise HttpError(400, "tool_choice names a tool that is not offered", "bad_request")
        if kept:
            req["tools"] = kept
            for key, value in (("tool_choice", choice), ("parallel_tool_calls", parallel)):
                if value is not None:
                    req[key] = value
        return removed

    def _monitor_tools(self, req: dict[str, Any], log: AuditLogger, policy: Policy) -> list[str]:
        """Monitor mode: record what enforce mode would remove, and remove nothing."""
        tools = req.get("tools")
        if not isinstance(tools, list):
            return []
        rules = policy.tools
        named = [t for t in tools if isinstance(t, dict) and isinstance(t.get("function"), dict)]
        would = []
        for t in named:
            name = t["function"].get("name")
            rule = rules.get(name) if isinstance(name, str) else None
            if rule is None or not rule.allow:
                would.append(str(name))
        would += [f.tool for f in scan_tool_definitions([_scannable(t) for t in named])]
        if would:
            log.log("gateway_tools_removed", tools=sorted(set(would)), enforced=False)
        return []

    def _screen_messages(
        self, req: dict[str, Any], mw: AgentMiddleware, session: Session
    ) -> list[str]:
        # shortcut: the whole history is rescanned (and audited) on every turn; add a scan cache
        # keyed by message hash when long conversations make this measurable.
        reasons: list[str] = []
        for i, m in enumerate(req["messages"]):
            untrusted = m["role"] == "tool"
            if untrusted:
                # Taint whatever the content: an image or an empty list is still a tool result.
                session.mark_untrusted(f"tool[{i}]")
            for part in m["content"] if isinstance(m.get("content"), list) else []:
                ref = part.get("image_url") if isinstance(part, dict) else None
                url = ref.get("url") if isinstance(ref, dict) else ref
                if ref is not None and not (isinstance(url, str) and url.startswith("data:")):
                    # The model server would fetch it from its own network position (SSRF).
                    # shortcut: inline data: images only; add a host allowlist if remote ones are needed.
                    reasons.append(f"{m['role']}[{i}]: remote image URL")
            texts = _texts(m.get("content"))
            if not texts:
                continue
            out = []
            for text in texts:
                screen = mw.screen_input(
                    text, source=f"{m['role']}[{i}]", untrusted=untrusted, session=session
                )
                out.append(screen.text)
                if screen.blocked:
                    reasons += [f"{m['role']}[{i}]: {r}" for r in screen.reasons]
            m["content"] = _replace_texts(m["content"], out)
        return reasons

    def _screen_outbound(
        self, req: dict[str, Any], upstream: Upstream, log: AuditLogger, gp: GroupPolicy
    ) -> None:
        """DLP on the whole request (the ``upstream`` surface), with the upstream's
        ``outbound`` overrides. Independent of monitor/enforce: it is a data-handling setting."""
        policy = upstream_policy(gp.dlp, upstream.outbound_on_secret, upstream.outbound_on_pii)
        hits: list[DlpMatch] = []
        clean = screen(req, "request", policy, hits)
        for m in hits[:MAX_MATCH_RECORDS]:
            log.log("dlp_match", upstream=upstream.name, **m.audit())
        acted = [m for m in hits if m.action in ("redact", "block")]
        # Attachments cannot be scanned, so they are refused whenever anything would be acted on.
        stuck = attachments(req["messages"]) if policy.strictest("upstream") != "monitor" else []
        if not acted and not stuck:
            return
        kinds = sorted({m.kind for m in acted} | ({"attachment"} if stuck else set()))
        where = ([m.location for m in acted] + stuck)[:20]
        if stuck or any(m.action == "block" for m in acted):
            log.log(
                "gateway_outbound_blocked", upstream=upstream.name, kinds=kinds, locations=where
            )
            raise HttpError(400, "request blocked by outbound policy", "outbound_blocked")
        log.log("gateway_outbound_redacted", upstream=upstream.name, kinds=kinds, locations=where)
        req.update(clean)

    def _check_response(
        self,
        raw: Any,
        mw: AgentMiddleware,
        session: Session,
        enforce: bool,
        log: AuditLogger,
        gp: GroupPolicy,
    ) -> dict[str, Any]:
        choices = raw.get("choices") if isinstance(raw, dict) else None
        if not isinstance(choices, list):
            choices = None  # a dict or string here is a malformed answer (502), not a crash
        message = choices[0].get("message") if choices and isinstance(choices[0], dict) else None
        if not isinstance(message, dict):
            log.log("gateway_upstream_error", error="response has no message")
            raise HttpError(502, "upstream error", "upstream_error")
        content = message.get("content")
        if content is not None and not isinstance(content, str):
            log.log("gateway_upstream_error", error="message content is not a string")
            raise HttpError(502, "upstream error", "upstream_error")
        tool_calls = message.get("tool_calls") or []
        if not isinstance(tool_calls, list):
            tool_calls = [tool_calls]

        kept, withheld = [], 0
        for tc in tool_calls:
            call, refusal = parse_openai_tool_call(tc if isinstance(tc, dict) else {})
            if refusal is None:
                allowed = mw.authorize_tool(call, session).allowed
            else:
                log.log("gateway_tool_call_malformed", tool=call.name, reason=refusal)
                allowed = False
            if not allowed:
                withheld += 1
                if enforce:
                    continue
            if enforce:
                # Re-serialized from what was checked, so the client cannot parse something else.
                arguments = json.dumps(call.arguments)
                # A fresh id: the upstream's is model-chosen text that no check has seen.
                call_id = f"call_{uuid.uuid4().hex}"
            else:
                fn = tc.get("function") if isinstance(tc, dict) else None
                raw_args = fn.get("arguments") if isinstance(fn, dict) else None
                arguments = raw_args if isinstance(raw_args, str) else json.dumps(call.arguments)
                call_id = str(tc.get("id") or "") if isinstance(tc, dict) else ""
                call_id = call_id or f"call_{uuid.uuid4().hex}"
            # Arguments are model output too: a secret or protected string must not ride out in
            # one. Withheld rather than rewritten, since a rewritten argument changes the action.
            arg_check = gp.argument_guard.process(arguments)
            if arg_check.violations:
                log.log(
                    "gateway_tool_call_output_violation",
                    tool=call.name,
                    validators=sorted({v.validator for v in arg_check.violations}),
                    enforced=enforce,
                )
                if allowed:
                    withheld += 1
                if enforce:
                    continue
            kept.append(
                {
                    "id": call_id,
                    "type": "function",
                    "function": {"name": call.name, "arguments": arguments},
                }
            )

        text = content
        if content:
            checked = mw.screen_output(content)
            if not checked.allowed or checked.redacted:
                log.log("gateway_output_changed", blocked=not checked.allowed, enforced=enforce)
            if enforce:
                text = checked.text
        if withheld:
            log.log("gateway_tool_calls_withheld", count=withheld, enforced=enforce)

        finish = choices[0].get("finish_reason") if choices else None
        finish = finish if finish in _FINISH else "stop"
        if kept:
            finish = "tool_calls"
        elif finish == "tool_calls" or withheld:
            finish = "stop"
            text = text or WITHHELD_NOTICE
        out_msg: dict[str, Any] = {"role": "assistant", "content": text}
        if kept:
            out_msg["tool_calls"] = kept
        result: dict[str, Any] = {
            "choices": [{"index": 0, "message": out_msg, "finish_reason": finish}],
        }
        usage = raw.get("usage")
        if isinstance(usage, dict):
            result["usage"] = {
                k: v for k, v in usage.items()
                if k in {"prompt_tokens", "completion_tokens", "total_tokens"}
                and isinstance(v, int) and not isinstance(v, bool)
            }  # fmt: skip
        return result

    # ------------------------------------------------------------- responses
    @staticmethod
    async def _json(send: Send, status: int, payload: dict[str, Any], request_id: str) -> None:
        body = json.dumps(payload).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"x-request-id", request_id.encode()),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def _error(self, send: Send, e: HttpError, request_id: str) -> None:
        payload = {"error": {"message": e.message, "type": "gateway_error", "code": e.code}}
        await self._json(send, e.status, payload, request_id)

    @staticmethod
    async def _sse(send: Send, result: dict[str, Any], request_id: str) -> None:
        """Replay an already-checked completion as chat.completion.chunk events."""
        msg, choice = result["choices"][0]["message"], result["choices"][0]
        base = {k: result[k] for k in ("id", "created", "model")} | {
            "object": "chat.completion.chunk"
        }
        delta: dict[str, Any] = {"role": "assistant", "content": msg.get("content")}
        if msg.get("tool_calls"):
            delta["tool_calls"] = [{"index": i, **tc} for i, tc in enumerate(msg["tool_calls"])]
        events = [
            base | {"choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
            base
            | {"choices": [{"index": 0, "delta": {}, "finish_reason": choice["finish_reason"]}]},
        ]
        if "usage" in result:
            events.append(base | {"choices": [], "usage": result["usage"]})
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/event-stream"),
                    (b"x-request-id", request_id.encode()),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        for event in events:
            data = f"data: {json.dumps(event)}\n\n".encode()
            await send({"type": "http.response.body", "body": data, "more_body": True})
        await send({"type": "http.response.body", "body": b"data: [DONE]\n\n"})


def _merge_tool_call(calls: dict[int, dict[str, Any]], tc: Any) -> None:
    """Assemble streamed tool-call fragments by index; nothing is released until the end."""
    index = tc.get("index", 0) if isinstance(tc, dict) else None
    if not isinstance(index, int) or isinstance(index, bool):
        raise UpstreamError("malformed streamed tool call")
    if not 0 <= index < MAX_STREAM_TOOL_CALLS:
        raise UpstreamError("too many streamed tool calls")
    call = calls.setdefault(
        index, {"id": "", "type": "function", "function": {"name": "", "arguments": ""}}
    )
    fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
    if isinstance(tc.get("id"), str) and not call["id"]:
        call["id"] = tc["id"]
    if isinstance(fn.get("name"), str) and not call["function"]["name"]:
        call["function"]["name"] = fn["name"]  # sent once; a repeat must not grow the name
    if isinstance(fn.get("arguments"), str):
        call["function"]["arguments"] += fn["arguments"]


_HOST = re.compile(r"(\[[^\]]*\]|[^:]*)(:[0-9]*)?")  # a name or [IPv6], then an optional port


def _check_origin_host(scope: Scope, origins: frozenset[str], hosts: frozenset[str] | None) -> None:
    """Refuse cross-site browser requests and DNS rebinding (a page whose name points here).

    A browser sends ``Origin`` on cross-site requests and always sends ``Host``, which under
    rebinding is the attacker's name. Clients that are not browsers send no ``Origin``.
    """
    headers = scope.get("headers", [])
    origin = [v for k, v in headers if k.lower() == b"origin"]
    if origin and (len(origin) > 1 or origin[0].decode("latin-1").lower() not in origins):
        raise HttpError(403, "origin not allowed", "origin_not_allowed")
    host = [v for k, v in headers if k.lower() == b"host"]
    # No Host header is HTTP/1.0, which no browser speaks, so it cannot be a rebinding page.
    if hosts is None or not host:
        return
    # The port is not compared: under rebinding the name is the attacker's, and a forwarded
    # port (ssh -L, docker -p) differs from the one in the config.
    name = _HOST.fullmatch(host[0].decode("latin-1").lower())
    if len(host) > 1 or name is None or name.group(1) not in hosts:
        raise HttpError(403, "host not allowed", "host_not_allowed")


def _bearer(scope: Scope) -> str | None:
    """The token of a single ``Authorization: Bearer`` header, or None."""
    auth = [v for k, v in scope.get("headers", []) if k.lower() == b"authorization"]
    if len(auth) != 1:
        return None
    scheme, _, token = auth[0].decode("latin-1").partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token.strip() else None
