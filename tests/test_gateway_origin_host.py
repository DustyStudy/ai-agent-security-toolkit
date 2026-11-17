"""Origin and Host checks on both listeners: cross-site browser requests and DNS rebinding."""

from __future__ import annotations

import asyncio
import json
import logging

import pytest

from agentsec.gateway import ConfigError
from tests.test_gateway import USER, FakeUpstream, call, chat, gateway, write_config
from tests.test_gateway_metrics import metric

ADMIN = "admin:\n  port: 9090\n"


def admin(app, path="/metrics", headers=()):
    scope = {"type": "http", "method": "GET", "path": path, "headers": list(headers)}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app.admin(scope, receive, send))
    return sent[0]["status"], b"".join(m.get("body", b"") for m in sent[1:]).decode()


def rejections(sink):
    return [r["data"]["code"] for r in sink.records if r["event"] == "gateway_rejected"]


def test_clients_without_origin_and_with_a_loopback_host_are_served(tmp_path):
    app, _ = gateway(tmp_path, extra=ADMIN)
    assert call(app, body=chat())[0] == 200  # no Host at all: HTTP/1.0, not a browser
    # Any port: ssh -L or docker -p puts another one in Host than the config has.
    for host in (b"127.0.0.1:8443", b"localhost:9999", b"LOCALHOST", b"[::1]:8443"):
        assert call(app, body=chat(), headers=[*USER, (b"host", host)])[0] == 200
    assert admin(app, headers=[(b"host", b"127.0.0.1:9090")])[0] == 200
    assert admin(app)[0] == 200


def test_a_foreign_origin_is_refused_on_both_listeners(tmp_path):
    upstream = FakeUpstream()
    app, sink = gateway(tmp_path, upstream, extra=ADMIN)
    for origin in (b"https://evil.example", b"null"):
        status, body = call(app, body=chat(), headers=[*USER, (b"origin", origin)])
        assert (status, body["error"]["code"]) == (403, "origin_not_allowed")
    twice = [*USER, (b"origin", b"https://evil.example"), (b"origin", b"https://evil.example")]
    assert call(app, body=chat(), headers=twice)[0] == 403
    assert not upstream.requests
    status, body = admin(app, headers=[(b"origin", b"http://localhost:3000")])
    assert (status, json.loads(body)["error"]["code"]) == (403, "origin_not_allowed")
    assert rejections(sink) == ["origin_not_allowed"] * 4
    text = admin(app)[1]
    assert metric(text, 'agentsec_gateway_events_total{event="gateway_rejected"}') == 4
    assert metric(text, 'agentsec_gateway_responses_total{status="403"}') == 3  # main listener


def test_a_rebinding_host_is_refused_on_both_listeners(tmp_path):
    upstream = FakeUpstream()
    app, sink = gateway(tmp_path, upstream, extra=ADMIN)
    evil = (b"host", b"evil.example:8443")
    status, body = call(app, body=chat(), headers=[*USER, evil])
    assert (status, body["error"]["code"]) == (403, "host_not_allowed")
    assert call(app, body=chat(), headers=[*USER, (b"host", b"localhost"), evil])[0] == 403
    for host in (b"localhost.evil.example", b"localhost:x", b"evil.example:@localhost", b""):
        assert call(app, body=chat(), headers=[*USER, (b"host", host)])[0] == 403
    assert not upstream.requests
    for path in ("/metrics", "/readyz", "/healthz"):
        status, body = admin(app, path, headers=[evil])
        assert (status, json.loads(body)["error"]["code"]) == (403, "host_not_allowed")
        assert "agentsec_gateway" not in body
    assert rejections(sink) == ["host_not_allowed"] * 9


def test_an_allowed_origin_and_host_are_served(tmp_path):
    extra = (
        "listen:\n  allowed_origins: ['https://Chat.corp.example']\n"
        "  allowed_hosts: [gateway.corp.example]\n"
    )
    app, _ = gateway(tmp_path, extra=extra)
    ok = [*USER, (b"origin", b"https://chat.corp.example"), (b"host", b"gateway.corp.example:443")]
    assert call(app, body=chat(), headers=ok)[0] == 200
    # An explicit list replaces the loopback names, and the main list is not the admin's.
    assert call(app, body=chat(), headers=[*USER, (b"host", b"localhost:8443")])[0] == 403
    assert (
        call(app, body=chat(), headers=[*USER, (b"origin", b"https://chat.corp.example:8443")])[0]
        == 403
    )


def test_healthz_on_the_main_listener_is_exempt(tmp_path):
    app, _ = gateway(tmp_path)
    headers = [(b"host", b"10.1.2.3:8443")]  # a container probe uses the pod address
    assert call(app, "/healthz", method="GET", headers=headers)[0] == 200


def test_a_non_loopback_bind_without_allowed_hosts_warns_and_skips_the_host_check(tmp_path, caplog):
    listen = "listen:\n  host: 0.0.0.0\n  tls_terminated_by_proxy: true\n"
    with caplog.at_level(logging.WARNING, logger="agentsec.gateway"):
        app, _ = gateway(tmp_path, extra=listen)
    assert "listen.allowed_hosts is not set" in caplog.text
    assert call(app, body=chat(), headers=[*USER, (b"host", b"gateway.corp.example")])[0] == 200
    assert call(app, body=chat(), headers=[*USER, (b"origin", b"https://evil.example")])[0] == 403
    caplog.clear()
    app, _ = gateway(tmp_path, extra=listen + "  allowed_hosts: [gateway.corp.example]\n")
    assert "allowed_hosts" not in caplog.text
    assert call(app, body=chat(), headers=[*USER, (b"host", b"evil.example:8443")])[0] == 403


@pytest.mark.parametrize(
    "listen",
    [
        "allowed_origins: ['*']",
        "allowed_origins: ['null']",
        "allowed_origins: ['https://chat.corp.example/']",
        "allowed_origins: ['chat.corp.example']",
        "allowed_origins: 'https://chat.corp.example'",
        "allowed_hosts: ['*']",
        "allowed_hosts: ['*.corp.example']",
        "allowed_hosts: ['https://gateway.corp.example']",
        "allowed_hosts: ['gateway.corp.example:8443']",
        "allowed_hosts: ['']",
    ],
)
def test_malformed_allowlists_are_refused(tmp_path, listen):
    with pytest.raises(ConfigError, match="allowed_"):
        write_config(tmp_path, f"listen:\n  {listen}\n")
