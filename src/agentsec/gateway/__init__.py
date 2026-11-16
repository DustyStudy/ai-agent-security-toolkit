"""agentsec gateway: an OpenAI-compatible proxy that enforces policy in front of local models.

Install with ``pip install "ai-agent-security-toolkit[gateway]"`` and run ``agentsec serve``.
Design and limits: docs/design/GATEWAY.md.
"""

from __future__ import annotations

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
    uvicorn.run(
        Gateway(config),
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
