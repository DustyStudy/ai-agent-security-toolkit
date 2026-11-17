"""``agentsec probe-isolation``: a TCP connect to each upstream, and nothing more."""

from __future__ import annotations

import json
import socket

import pytest

from agentsec.cli import main as cli
from agentsec.gateway import config as gateway_config
from tests.test_gateway import write_config


@pytest.fixture
def no_secrets(monkeypatch):
    """Fail the test if anything resolves a secret reference."""

    def refuse(ref):
        raise AssertionError(f"secret reference {ref!r} was resolved")

    monkeypatch.setattr(gateway_config, "resolve_secret", refuse)


def listening():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    return sock


def closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def config(tmp_path, model_port: int, mcp_port: int):
    # The secret references point at nothing: resolving either one would also raise.
    write_config(
        tmp_path,
        f"""
        mcp_upstreams:
          jira:
            url: http://localhost:{mcp_port}/mcp
            auth: env:AGENTSEC_TEST_UNSET_MCP_TOKEN
        """,
    )
    path = tmp_path / "gateway.yaml"
    path.write_text(
        path.read_text().replace(
            "url: http://127.0.0.1:11434/v1",
            f"url: http://127.0.0.1:{model_port}/v1\n    api_key: file:{tmp_path}/no-such-key",
        )
    )
    return str(path)


def probe(path, *extra):
    return cli(["probe-isolation", "--config", path, "--timeout", "2", *extra])


def test_a_reachable_upstream_is_a_finding(tmp_path, capsys, no_secrets):
    with listening() as sock:
        path = config(tmp_path, sock.getsockname()[1], closed_port())
        assert probe(path, "--gateway-host", "127.0.0.1", "--json") == 1
        rows = {r["name"]: r for r in json.loads(capsys.readouterr().out)["upstreams"]}
        assert rows["local"]["status"] == "reachable" and rows["local"]["kind"] == "model"
        assert rows["jira"]["status"] == "isolated" and rows["jira"]["kind"] == "mcp"
        sock.settimeout(2)
        conn, _ = sock.accept()
        with conn:
            conn.settimeout(2)
            assert conn.recv(1) == b""  # connected and closed: not one byte was sent


def test_closed_ports_are_isolated(tmp_path, capsys, no_secrets):
    path = config(tmp_path, closed_port(), closed_port())
    assert probe(path, "--gateway-host", "127.0.0.1") == 0
    out = capsys.readouterr().out
    assert out.count("ISOLATED") == 2 and "0 reachable, 2 isolated, 0 unchecked" in out


def test_a_loopback_url_is_not_a_pass_without_the_gateway_host(tmp_path, capsys, no_secrets):
    with listening() as sock:  # reachable here, but "here" is not the gateway host
        path = config(tmp_path, sock.getsockname()[1], closed_port())
        assert probe(path) == 2
    assert capsys.readouterr().out.count("UNCHECKED") == 2


def test_an_invalid_config_exits_2(tmp_path, capsys):
    (tmp_path / "gateway.yaml").write_text("upstreams: {}\n")
    assert probe(str(tmp_path / "gateway.yaml")) == 2
    assert "invalid gateway config" in capsys.readouterr().err
