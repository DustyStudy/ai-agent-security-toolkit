"""Gateway metrics and the admin listener (/healthz, /readyz, /metrics)."""

from __future__ import annotations

import asyncio
import dataclasses
import json
from datetime import UTC, datetime, timedelta

import pytest

from agentsec.gateway import ConfigError, Gateway
from agentsec.gateway.metrics import _label
from agentsec.middleware.audit import verify_file
from tests.test_gateway import USER, FakeUpstream, call, chat, gateway, write_config


def admin(app, path, method="GET"):
    scope = {"type": "http", "method": method, "path": path, "headers": [], "client": ("x", 1)}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app.admin(scope, receive, send))
    body = b"".join(m.get("body", b"") for m in sent[1:]).decode()
    return sent[0]["status"], body


def metric(text, line_start):
    hits = [ln for ln in text.splitlines() if ln.startswith(line_start)]
    return float(hits[0].rsplit(" ", 1)[1]) if hits else 0.0


def test_metrics_count_responses_and_audit_events(tmp_path):
    app, _ = gateway(tmp_path)
    assert call(app, body=chat())[0] == 200
    assert call(app, body=chat(), headers=[])[0] == 401
    assert call(app, path="/healthz", method="GET", headers=[])[0] == 200
    status, text = admin(app, "/metrics")
    assert status == 200
    assert metric(text, 'agentsec_gateway_responses_total{status="200"}') == 2
    assert metric(text, 'agentsec_gateway_responses_total{status="401"}') == 1
    assert metric(text, 'agentsec_gateway_events_total{event="gateway_request"}') == 1
    assert metric(text, 'agentsec_gateway_events_total{event="gateway_start"}') == 1
    assert metric(text, 'agentsec_gateway_events_total{event="gateway_rejected"}') == 1
    assert 'agentsec_gateway_policy_info{policy_rev="sha256:' in text
    assert metric(text, "agentsec_gateway_monitor_groups") == 0


def test_blocked_tool_calls_show_up_as_events(tmp_path):
    message = {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "c1",
                "type": "function",
                "function": {"name": "delete_everything", "arguments": "{}"},
            }
        ],
    }
    app, _ = gateway(tmp_path, upstream=FakeUpstream(message=message))
    assert call(app, body=chat())[0] == 200
    _, text = admin(app, "/metrics")
    assert metric(text, 'agentsec_gateway_events_total{event="gateway_tool_calls_withheld"}') == 1


def test_an_event_is_counted_only_once_written(tmp_path):
    class FailingSink:
        def __init__(self):
            self.fail = False

        def write(self, record):
            if self.fail:
                raise OSError("disk full")

        def last_record(self):
            return None

    sink = FailingSink()
    app = Gateway(write_config(tmp_path), transport=FakeUpstream(), sink=sink)
    sink.fail = True
    assert call(app, body=chat())[0] == 503
    _, text = admin(app, "/metrics")
    assert metric(text, 'agentsec_gateway_events_total{event="gateway_request"}') == 0
    assert metric(text, 'agentsec_gateway_responses_total{status="503"}') == 1


def test_counting_sink_keeps_the_audit_chain_across_restarts(tmp_path):
    cfg = write_config(tmp_path)
    for _ in range(2):  # the second start resumes the chain through the wrapper
        assert call(Gateway(cfg, transport=FakeUpstream()), body=chat())[0] == 200
    assert verify_file(tmp_path / "audit.jsonl").ok


def test_readyz_reports_policy_and_monitor_groups(tmp_path):
    app, _ = gateway(tmp_path, mode="monitor")
    status, body = admin(app, "/readyz")
    payload = json.loads(body)
    assert status == 200
    assert payload["status"] == "ready"
    assert payload["monitor_groups"] == ["*"]
    assert payload["policy_rev"].startswith("sha256:")
    assert metric(admin(app, "/metrics")[1], "agentsec_gateway_monitor_groups") == 1


def test_readyz_fails_once_the_policy_expired(tmp_path):
    app, _ = gateway(tmp_path)
    past = datetime.now(UTC) - timedelta(seconds=1)
    app._policies = dataclasses.replace(app._policies, expires=past)
    status, body = admin(app, "/readyz")
    assert status == 503
    assert json.loads(body)["status"] == "policy_expired"
    assert "agentsec_gateway_policy_expiry_timestamp_seconds" in admin(app, "/metrics")[1]


@pytest.mark.parametrize(("path", "method"), [("/v1/models", "GET"), ("/metrics", "POST")])
def test_admin_serves_only_its_endpoints(tmp_path, path, method):
    app, _ = gateway(tmp_path)
    assert admin(app, path, method)[0] == 404
    assert admin(app, "/healthz")[0] == 200


def test_main_listener_does_not_serve_metrics(tmp_path):
    app, _ = gateway(tmp_path)
    assert call(app, path="/metrics", method="GET", headers=USER)[0] == 404


def test_admin_config(tmp_path):
    cfg = write_config(tmp_path, "admin:\n  port: 9090\n")
    assert (cfg.admin_host, cfg.admin_port) == ("127.0.0.1", 9090)
    assert write_config(tmp_path).admin_port is None
    with pytest.raises(ConfigError, match="loopback"):
        write_config(tmp_path, "admin:\n  host: 0.0.0.0\n  port: 9090\n")
    for host in ("localhost", "::ffff:8.8.8.8"):
        with pytest.raises(ConfigError, match="loopback"):
            write_config(tmp_path, f"admin:\n  host: '{host}'\n  port: 9090\n")
    assert write_config(tmp_path, "admin:\n  host: '::1'\n  port: 9090\n").admin_host == "::1"
    with pytest.raises(ConfigError, match="differ"):
        write_config(tmp_path, "admin:\n  port: 8443\n")
    with pytest.raises(ConfigError, match="differ"):  # overlapping binds, different host strings
        write_config(
            tmp_path,
            "listen:\n  host: 0.0.0.0\n  port: 8443\n  tls_terminated_by_proxy: true\n"
            "admin:\n  port: 8443\n",
        )
    with pytest.raises(ConfigError, match="admin.port"):
        write_config(tmp_path, "admin:\n  host: 127.0.0.1\n")


def test_counting_sink_can_be_copied():
    import copy

    from agentsec.gateway.metrics import CountingSink, Metrics
    from agentsec.middleware.audit import MemorySink

    inner = MemorySink()
    assert copy.copy(CountingSink(inner, Metrics())).records is inner.records


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_serve_refuses_to_run_when_the_admin_port_is_taken(tmp_path):  # uvicorn exits its thread
    import socket

    pytest.importorskip("uvicorn")
    from agentsec.gateway import serve

    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        port = taken.getsockname()[1]
        cfg = write_config(tmp_path, f"admin:\n  port: {port}\n")
        with pytest.raises(SystemExit, match="admin listener failed"):
            serve(cfg)


def test_label_values_are_escaped():
    assert _label('a"b\\c\nd') == 'a\\"b\\\\c\\nd'
