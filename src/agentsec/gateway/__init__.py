"""agentsec gateway: an OpenAI-compatible proxy that enforces policy in front of local models.

Install with ``pip install "ai-agent-security-toolkit[gateway]"`` and run ``agentsec serve``.
Design and limits: docs/design/GATEWAY.md.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

from agentsec.gateway.app import Gateway, HttpError, UpstreamError, http_transport
from agentsec.gateway.config import ConfigError, GatewayConfig, Upstream, load_config


def header_timeout_protocol(timeout_s: float) -> type[asyncio.Protocol]:
    """uvicorn's h11 protocol, closing a connection that does not send a request head in time.

    uvicorn only times out a connection that is idle after a response. One that never sends
    a request, or sends a request head a byte at a time, stays open for ever and counts
    towards ``limits.max_connections``: enough of them get everyone else a 503. The body is
    not covered here; ``limits.body_timeout_s`` bounds that once the head has arrived.
    """
    from uvicorn.protocols.http.h11_impl import H11Protocol

    class HeaderTimeoutProtocol(H11Protocol):
        _head_timer: asyncio.TimerHandle | None = None

        def _in_flight(self) -> bool:
            return self.cycle is not None and not self.cycle.response_complete

        def _arm(self) -> None:
            # One deadline for the whole head: more bytes do not push it back.
            if self._head_timer is None:
                self._head_timer = self.loop.call_later(timeout_s, self._head_timed_out)

        def _disarm(self) -> None:
            if self._head_timer is not None:
                self._head_timer.cancel()
                self._head_timer = None

        def _head_timed_out(self) -> None:
            self._head_timer = None
            if not self._in_flight() and not self.transport.is_closing():
                self.transport.close()

        def connection_made(self, transport: Any) -> None:
            super().connection_made(transport)
            self._arm()

        def data_received(self, data: bytes) -> None:
            super().data_received(data)
            if self._in_flight():
                self._disarm()
            else:
                self._arm()  # between requests on a kept-alive connection, a new head began

        def on_response_complete(self) -> None:
            # Idle now: uvicorn's own keep-alive timer takes over until the next byte.
            self._disarm()
            super().on_response_complete()
            if not self._in_flight() and self.conn.trailing_data[0]:
                self._arm()  # part of the next head arrived with the last request

        def connection_lost(self, exc: Exception | None) -> None:
            self._disarm()
            super().connection_lost(exc)

    return HeaderTimeoutProtocol


def serve(config: GatewayConfig) -> None:
    """Run the gateway with uvicorn (the ``gateway`` extra)."""
    try:
        import uvicorn
    except ImportError as e:  # pragma: no cover - depends on the install
        raise SystemExit(
            'agentsec serve needs the gateway extra: pip install "ai-agent-security-toolkit[gateway]"'
        ) from e
    gateway = Gateway(config)
    if config.admin_port is not None:
        admin = uvicorn.Server(
            uvicorn.Config(
                gateway.admin,
                host=config.admin_host,
                port=config.admin_port,
                interface="asgi3",  # a bound method: uvicorn would guess ASGI2 and fail
                proxy_headers=False,
                server_header=False,
                http="h11",
                ws="none",
                lifespan="off",
                log_level="warning",
            )
        )
        # A daemon thread: it stops with the main server. Outside the main thread uvicorn
        # installs no signal handlers, so Ctrl+C still reaches the main server.
        thread = threading.Thread(target=admin.run, name="agentsec-admin", daemon=True)
        thread.start()
        deadline = time.monotonic() + 10
        while not admin.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        if not admin.started:
            # A port in use, say: refuse to run without the readiness and metrics configured.
            raise SystemExit(
                f"admin listener failed to start on {config.admin_host}:{config.admin_port}"
            )
    uvicorn.run(
        gateway,
        host=config.host,
        port=config.port,
        ssl_certfile=config.tls_cert_file,
        ssl_keyfile=config.tls_key_file,
        # The trusted-header check reads the TCP peer. With proxy_headers on, uvicorn would
        # replace it with a client-supplied X-Forwarded-For and defeat that check.
        proxy_headers=False,
        server_header=False,
        # The strict pure-Python h11 parser (ambiguous framing is rejected), with a deadline
        # for the request head.
        http=header_timeout_protocol(config.header_timeout_s),
        # The gateway serves no websockets. Left on, uvicorn hands an upgrade request to
        # another protocol object, outside the head deadline and the rest of this setup.
        ws="none",
        lifespan="off",
        workers=1,  # one audit chain per process; see docs/design/GATEWAY.md
        # Unauthenticated connections are otherwise unbounded: above the cap uvicorn answers
        # 503 before the gateway (and its per-user limits) ever sees the request.
        limit_concurrency=config.max_connections,
        # Without it a SIGTERM waits for every open stream, until the orchestrator kills us.
        # uvicorn takes whole seconds.
        timeout_graceful_shutdown=max(1, round(config.shutdown_timeout_s)),
        log_level="info",
    )


__all__ = [
    "ConfigError",
    "Gateway",
    "GatewayConfig",
    "HttpError",
    "Upstream",
    "UpstreamError",
    "header_timeout_protocol",
    "http_transport",
    "load_config",
    "serve",
]
