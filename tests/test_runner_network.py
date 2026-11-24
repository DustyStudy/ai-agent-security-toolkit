"""SafeCommandRunner(network="none"): no network, DNS included, for every command.

DNS tunnelling got data out of agent sandboxes that blocked TCP but left the resolver open
(CSA research notes, 2026-03-20 on Bedrock AgentCore and 2026-09-30 on an OpenAI agent).
"""

from __future__ import annotations

import os
import sys

import pytest

import agentsec.sandbox.subprocess_runner as runner_mod
from agentsec.sandbox import ExecRule, SafeCommandRunner

_PROBE = """
import socket, sys
try:
    socket.getaddrinfo("example.com", 443)
    print("dns ok")
except OSError as e:
    print("dns refused", type(e).__name__)
try:
    socket.create_connection(("192.0.2.1", 53), timeout=2).close()
    print("tcp ok")
except OSError as e:
    print("tcp refused", type(e).__name__)
"""

isolation = runner_mod._no_network_prefix()
needs_isolation = pytest.mark.skipif(
    isolation is None, reason="no unprivileged network namespaces on this host"
)


def _runner(tmp_path, **kwargs):
    return SafeCommandRunner(
        {"py": ExecRule(executable=sys.executable)},
        cwd_roots=[str(tmp_path)],
        timeout=10,
        **kwargs,
    )


@needs_isolation
def test_no_network_blocks_dns_and_tcp(tmp_path):
    script = tmp_path / "probe.py"
    script.write_text(_PROBE)
    out = _runner(tmp_path, network="none").run("py", [str(script)])
    assert out.returncode == 0, out.stderr
    assert "dns refused" in out.stdout and "tcp refused" in out.stdout


@needs_isolation
def test_no_network_still_runs_the_command_in_its_workdir(tmp_path):
    script = tmp_path / "w.py"
    script.write_text("import os; open('made.txt', 'w').write('x'); print(os.getcwd())")
    out = _runner(tmp_path, network="none").run("py", [str(script)])
    assert out.returncode == 0, out.stderr
    assert (tmp_path / "made.txt").read_text() == "x"
    assert out.argv[0] == os.path.realpath(sys.executable)  # the allowlisted command, no prefix


def test_no_network_fails_closed_when_isolation_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(runner_mod, "_no_network_prefix", lambda: None)
    with pytest.raises(ValueError, match="network='none' needs"):
        _runner(tmp_path, network="none")


def test_unknown_network_mode_is_refused(tmp_path):
    with pytest.raises(ValueError, match="network must be"):
        _runner(tmp_path, network="off")


def test_default_inherits_the_host_network(tmp_path):
    r = _runner(tmp_path)
    assert r.network == "inherit" and r._prefix == []
