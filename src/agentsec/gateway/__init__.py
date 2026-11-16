"""agentsec gateway: an OpenAI-compatible proxy that enforces policy in front of local models.

Install with ``pip install "ai-agent-security-toolkit[gateway]"`` and run ``agentsec serve``.
Design and limits: docs/design/GATEWAY.md.
"""

from __future__ import annotations

import threading
import time

from agentsec.gateway.app import Gateway, HttpError, UpstreamError, http_transport
from agentsec.gateway.config import ConfigError, GatewayConfig, Upstream, load_config


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
        http="h11",  # the strict pure-Python parser: ambiguous framing is rejected
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
    "http_transport",
    "load_config",
    "serve",
]
