"""listen.allowed_clients: the main listener serves only peers in these networks."""

from __future__ import annotations

import pytest

from agentsec.gateway import ConfigError, Gateway
from agentsec.middleware.audit import MemorySink
from tests.test_gateway import FakeUpstream, call, chat, write_config

IDENTITY = "identity:\n  trusted_proxies: [10.0.0.0/24]\n"


def _app(tmp_path, clients):
    cfg = write_config(tmp_path, IDENTITY + f"listen:\n  allowed_clients: {clients}\n")
    sink = MemorySink()
    return Gateway(cfg, transport=FakeUpstream(), sink=sink), sink


def test_a_peer_inside_the_list_is_served(tmp_path):
    app, _ = _app(tmp_path, "[10.0.0.0/24, 2001:db8::/32]")
    assert call(app, body=chat(), peer="10.0.0.7")[0] == 200
    assert call(app, body=chat(), peer="::ffff:10.0.0.7")[0] == 200  # dual-stack socket


@pytest.mark.parametrize("peer", ["10.0.1.7", "192.168.1.1", "2001:db9::1", "not-an-ip"])
def test_a_peer_outside_the_list_gets_403_before_identity(tmp_path, peer):
    app, sink = _app(tmp_path, "[10.0.0.0/24, 2001:db8::/32]")
    status, body = call(app, body=chat(), peer=peer)
    assert status == 403 and body["error"]["code"] == "client_not_allowed"
    rejected = [r for r in sink.records if r["event"] == "gateway_rejected"]
    assert rejected and rejected[0]["data"]["code"] == "client_not_allowed"


def test_every_path_but_healthz_is_covered(tmp_path):
    app, _ = _app(tmp_path, "[10.0.0.0/24]")
    assert call(app, "/v1/models", method="GET", peer="192.168.1.1")[0] == 403
    assert call(app, "/healthz", method="GET", peer="192.168.1.1")[0] == 200


def test_off_by_default(tmp_path):
    assert write_config(tmp_path).allowed_clients == ()


@pytest.mark.parametrize(
    ("clients", "error"),
    [
        ("[0.0.0.0/0]", "every address"),
        ("[10.0.0.1/24]", "host bits"),
        ("[nonsense]", "allowed_clients"),
        ("[10.0.5.0/24]", "trusted_proxies"),  # would lock out the auth proxy
    ],
)
def test_bad_lists_are_refused(tmp_path, clients, error):
    with pytest.raises(ConfigError, match=error):
        write_config(tmp_path, IDENTITY + f"listen:\n  allowed_clients: {clients}\n")
