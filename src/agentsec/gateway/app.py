"""The gateway's ASGI app: an OpenAI-compatible chat-completions proxy that enforces policy.

It controls what reaches and leaves the model, not what the client runs (docs/design/GATEWAY.md).
Requests are rebuilt from an allowlist of fields, never forwarded as bytes. Streaming is served
in ``buffer`` mode: the upstream is always called without streaming, the whole answer is checked,
and only then sent to the client as SSE chunks.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from typing import Any

from agentsec.gateway.config import GatewayConfig, Upstream
from agentsec.gateway.oidc import OidcVerifier, TokenRejected, fetch_jwks
from agentsec.integrations.mcp import scan_tool_definitions
from agentsec.middleware.audit import AuditLogger, AuditSink, FileSink, TeeSink
from agentsec.middleware.cef import CefSink
from agentsec.middleware.injection import InjectionScanner
from agentsec.middleware.pipeline import AgentMiddleware
from agentsec.middleware.validators import (
    OutputGuard,
    OutputValidator,
    ProtectedStringValidator,
    SecretLeakValidator,
)
from agentsec.sandbox.adapters import parse_openai_tool_call
from agentsec.sandbox.guard import Session, ToolGuard

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
# (upstream, JSON body, timeout seconds, max response bytes) -> parsed JSON response
Transport = Callable[[Upstream, bytes, float, int], Any]

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
_LOG = logging.getLogger("agentsec.gateway")
# Decision metadata stays readable with log_content off; prompts and answers are still hashed.
# These hold policy reasons, names and error kinds, never message text.
AUDIT_KEEP_FIELDS = frozenset(
    {"reasons", "reason", "error", "tools", "validators", "signals", "policy_rev", "groups"}
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


_OPENER = urllib.request.build_opener(_NoRedirect)


def http_transport(upstream: Upstream, body: bytes, timeout: float, max_bytes: int) -> Any:
    # shortcut: blocking urllib in a worker thread; a client disconnect does not cancel the
    # upstream call. Move to an async client when streaming passthrough modes arrive.
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    key = upstream.api_key()
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(  # noqa: S310 - URL is from config and checked as http(s)
        upstream.url + "/chat/completions", data=body, headers=headers, method="POST"
    )
    # The socket timeout bounds each read, not the call: an upstream dripping a byte at a time
    # would otherwise hold the worker. Check a total deadline between reads (worst case about
    # twice ``timeout``).
    deadline = time.monotonic() + timeout
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise UpstreamError(f"upstream returned HTTP {resp.status}")
            buf = bytearray()
            while len(buf) <= max_bytes:
                if time.monotonic() > deadline:
                    raise TimeoutError
                chunk = resp.read1(65536)
                if not chunk:
                    break
                buf.extend(chunk)
            data = bytes(buf)
    except TimeoutError:
        raise
    except urllib.error.HTTPError as e:
        raise UpstreamError(f"upstream returned HTTP {e.code}") from None
    except (urllib.error.URLError, OSError) as e:
        raise UpstreamError(f"upstream unreachable: {type(e).__name__}") from None
    if len(data) > max_bytes:
        raise UpstreamError("upstream response too large")
    try:
        return json.loads(data)
    except ValueError:
        raise UpstreamError("upstream response is not JSON") from None


class _Limiter:
    """Per-user request rate and concurrency, in memory: limits are per gateway process."""

    def __init__(self, per_min: int, concurrent: int, clock: Callable[[], float]) -> None:
        self._per_min, self._concurrent, self._clock = per_min, concurrent, clock
        self._recent: defaultdict[str, deque[float]] = defaultdict(deque)
        self._active: defaultdict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    @contextmanager
    def slot(self, user: str) -> Iterator[None]:
        with self._lock:
            now, recent = self._clock(), self._recent[user]
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
        sink: AuditSink | None = None,
        clock: Callable[[], float] = time.monotonic,
        jwks_fetch: Callable[[str], dict[str, Any]] = fetch_jwks,
    ) -> None:
        self.config = config
        self._transport = transport
        if sink is None:
            sink = FileSink(config.audit_file)
            if config.cef_file:
                # The hash-chained file is the record; CEF is a copy for the SIEM, and TeeSink
                # carries on (and logs) if that copy fails.
                cef = open(config.cef_file, "a", encoding="utf-8")  # noqa: SIM115 - lives with the app
                sink = TeeSink(sink, CefSink(cef))
        # The chain head is read once here; bind() gives each request a logger on that chain.
        self._audit = AuditLogger(
            sink, actor="gateway", log_content=config.log_content, keep_fields=AUDIT_KEEP_FIELDS
        )
        self._output_guard = OutputGuard.default(
            allowed_hosts=config.allowed_hosts, protected=config.protected
        )
        # Tool arguments: secrets and protected strings only. PII and links are normal in
        # arguments (an email address for send_email); the policy's argument rules cover those.
        arg_validators: list[OutputValidator] = [SecretLeakValidator()]
        if config.protected:
            arg_validators.append(ProtectedStringValidator(config.protected))
        self._argument_guard = OutputGuard(arg_validators)
        self._scanner = InjectionScanner()
        self._oidc = None if config.oidc is None else OidcVerifier(config.oidc, fetch=jwks_fetch)
        self._auth_slots = asyncio.Semaphore(MAX_CONCURRENT_AUTH)
        self._limiter = _Limiter(config.requests_per_min, config.concurrent_requests, clock)
        self._audit.log("gateway_start", policy_rev=config.policy_rev, mode=config.mode)

    # ------------------------------------------------------------------ ASGI
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return  # lifespan is turned off in serve(); websockets are not served
        request_id = uuid.uuid4().hex
        try:
            path, method = scope["path"], scope["method"]
            if path == "/healthz" and method == "GET":
                await self._json(send, 200, {"status": "ok"}, request_id)
                return
            user, groups = await self._identify(scope, request_id)
            if path == "/v1/models" and method == "GET":
                data = [
                    {"id": n, "object": "model", "owned_by": "agentsec"}
                    for n in self.config.upstreams
                ]
                await self._json(send, 200, {"object": "list", "data": data}, request_id)
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
                status, payload, stream = await asyncio.to_thread(
                    self._complete, body, user, groups, request_id
                )
        except HttpError as e:
            if not e.audited:
                self._log_rejection(e, request_id)
            await self._error(send, e, request_id)
            return
        except OSError:
            # Most likely the audit file: an unaudited model call is a gap in the evidence.
            await self._error(send, HttpError(503, "unavailable", "unavailable"), request_id)
            return
        except Exception:  # noqa: BLE001 - fail closed, never leak internals to the client
            await self._error(send, HttpError(500, "internal error", "internal_error"), request_id)
            return
        if stream:
            await self._sse(send, payload, request_id)
        else:
            await self._json(send, status, payload, request_id)

    def _log_rejection(self, e: HttpError, request_id: str) -> None:
        try:
            self._audit.log("gateway_rejected", request_id=request_id, status=e.status, code=e.code)
        except Exception:  # noqa: BLE001 - the client gets its error either way
            _LOG.warning("could not audit a rejected request", exc_info=True)

    async def _identify(self, scope: Scope, request_id: str) -> tuple[str, tuple[str, ...]]:
        if self._oidc is None:
            user, groups = self._from_trusted_header(scope)
        else:
            # Unauthenticated work is bounded before any per-user limiter can apply: a flood of
            # bad tokens gets 503s instead of queueing up the worker threads.
            if self._auth_slots.locked():
                raise HttpError(503, "busy", "busy")
            async with self._auth_slots:
                # A JWKS refresh is blocking network I/O: keep it off the event loop.
                user, groups = await asyncio.to_thread(
                    self._from_token, self._oidc, scope, request_id
                )
        allowed = self.config.allowed_groups
        if allowed and not set(groups) & set(allowed):
            raise HttpError(403, "forbidden", "forbidden")
        return user, groups

    def _from_token(
        self, verifier: OidcVerifier, scope: Scope, request_id: str
    ) -> tuple[str, tuple[str, ...]]:
        auth = [v for k, v in scope.get("headers", []) if k.lower() == b"authorization"]
        scheme, _, token = (auth[0].decode("latin-1") if len(auth) == 1 else "").partition(" ")
        try:
            if scheme.lower() != "bearer" or not token.strip():
                raise TokenRejected("no single bearer token")
            return verifier.verify(token.strip())
        except TokenRejected as e:
            # The reason is for the log; the client learns nothing about why.
            self._audit.log("gateway_auth_failed", request_id=request_id, reason=str(e))
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
        self, body: bytes, user: str, groups: tuple[str, ...], request_id: str
    ) -> tuple[int, dict[str, Any], bool]:
        cfg = self.config
        log = self._audit.bind(actor=user, session_id=request_id)
        enforce = cfg.mode == "enforce"
        req = self._parse(body)
        stream = req.pop("stream")
        include_usage = req.pop("include_usage")
        log.log(
            "gateway_request",
            groups=list(groups),
            policy_rev=cfg.policy_rev,
            mode=cfg.mode,
            model=req["model"],
            stream=stream,
        )
        upstream = cfg.upstreams[req["model"]]
        guard = ToolGuard(cfg.policy, audit=log)
        mw = AgentMiddleware(
            guard=guard,
            output_guard=self._output_guard,
            scanner=self._scanner,
            audit=log,
            block_on_injection=cfg.block_on_injection,
            spotlight_untrusted=cfg.spotlight_tool_results,
        )
        session = Session(id=request_id)  # taint is per request: the history is resent each turn

        removed_tools = self._filter_tools(req, log, enforce)
        blocked = self._screen_messages(req, mw, session)
        if blocked:
            log.log("gateway_input_blocked", reasons=blocked, enforced=enforce)
            if enforce:
                raise HttpError(400, "request blocked by input policy", "input_blocked")

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

        result = self._check_response(raw, mw, session, enforce, log)
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

    def _parse(self, body: bytes) -> dict[str, Any]:
        try:
            data = json.loads(body)
        except ValueError:
            raise HttpError(400, "body is not valid JSON", "bad_request") from None
        if not isinstance(data, dict):
            raise HttpError(400, "body must be a JSON object", "bad_request")
        model = data.get("model")
        if not isinstance(model, str) or model not in self.config.upstreams:
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
            clean.append({k: v for k, v in m.items() if k in _MESSAGE_FIELDS})
        req = {k: v for k, v in data.items() if k in _REQUEST_FIELDS}
        req["messages"] = clean
        max_tokens = data.get("max_tokens", self.config.max_tokens_cap)
        if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens <= 0:
            raise HttpError(400, "max_tokens must be a positive integer", "bad_request")
        req["max_tokens"] = min(max_tokens, self.config.max_tokens_cap)
        req["stream"], req["include_usage"] = stream, include_usage
        return req

    def _filter_tools(self, req: dict[str, Any], log: AuditLogger, enforce: bool) -> list[str]:
        """Offer the model only tools the policy allows and whose definitions scan clean."""
        if not enforce:
            return self._monitor_tools(req, log)
        tools = req.pop("tools", None)
        choice = req.pop("tool_choice", None)
        parallel = req.pop("parallel_tool_calls", None)
        if tools is None:
            if isinstance(choice, dict) or choice == "required":
                raise HttpError(400, "tool_choice names a tool that is not offered", "bad_request")
            return []
        if not isinstance(tools, list):
            raise HttpError(400, "tools must be a list", "bad_request")
        policy = self.config.policy.tools
        kept, removed = [], []
        for t in tools:
            fn = t.get("function") if isinstance(t, dict) and t.get("type") == "function" else None
            name = fn.get("name") if isinstance(fn, dict) else None
            rule = policy.get(name) if isinstance(name, str) else None
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

    def _monitor_tools(self, req: dict[str, Any], log: AuditLogger) -> list[str]:
        """Monitor mode: record what enforce mode would remove, and remove nothing."""
        tools = req.get("tools")
        if not isinstance(tools, list):
            return []
        policy = self.config.policy.tools
        named = [t for t in tools if isinstance(t, dict) and isinstance(t.get("function"), dict)]
        would = []
        for t in named:
            name = t["function"].get("name")
            rule = policy.get(name) if isinstance(name, str) else None
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

    def _check_response(
        self, raw: Any, mw: AgentMiddleware, session: Session, enforce: bool, log: AuditLogger
    ) -> dict[str, Any]:
        choices = raw.get("choices") if isinstance(raw, dict) else None
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
            arg_check = self._argument_guard.process(arguments)
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
