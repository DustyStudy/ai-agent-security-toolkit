from __future__ import annotations

import os
import sys

import pytest

from agentsec.middleware import AuditLogger, MemorySink
from agentsec.sandbox import (
    ArgRule,
    CommandDenied,
    ExecRule,
    Policy,
    PolicyError,
    SafeCommandRunner,
    Session,
    ToolDenied,
    ToolGuard,
    Verdict,
    run_anthropic_tool_uses,
    run_openai_tool_calls,
)
from agentsec.sandbox.validators import check_arg, check_url, path_within_roots
from agentsec.types import ToolCall

# ------------------------------------------------------------------ policy loading


def test_unknown_keys_are_errors():
    with pytest.raises(PolicyError, match="unknown key"):
        Policy.from_dict({"tools": {"t": {"alow": True}}})
    with pytest.raises(PolicyError, match="unknown key"):
        Policy.from_dict({"toolz": {}})


def test_bad_regex_and_type_rejected():
    with pytest.raises(PolicyError, match="bad regex"):
        Policy.from_dict({"tools": {"t": {"args": {"a": {"pattern": "("}}}}})
    with pytest.raises(PolicyError, match="unknown type"):
        Policy.from_dict({"tools": {"t": {"args": {"a": {"type": "blob"}}}}})
    with pytest.raises(PolicyError):
        Policy.from_dict({"taint": {"action": "shrug"}})


def test_from_yaml_and_lint(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text(
        "tools:\n  fetch:\n    side_effects: true\n    args:\n      url: {type: url}\n      note: {type: string}\n"
    )
    notes = Policy.from_yaml(f).lint()
    assert any("without a host allowlist" in n for n in notes)
    assert any("unbounded string" in n for n in notes)


# ---------------------------------------------------------------- argument checks


def test_path_traversal_and_absolute_escape_blocked(tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    (root / "ok.txt").write_text("x")
    assert path_within_roots("ok.txt", [str(root)])[0]
    assert not path_within_roots("../secret.txt", [str(root)])[0]
    assert not path_within_roots(str(tmp_path / "elsewhere"), [str(root)])[0]
    assert not path_within_roots("a\x00b", [str(root)])[0]
    assert not path_within_roots("ok.txt", [])[0]


def test_symlink_escape_blocked(tmp_path):
    root = tmp_path / "ws"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    link = root / "link"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform")
    assert not path_within_roots("link/file", [str(root)])[0]


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.com/x",  # scheme
        "https://evil.example/x",  # host not allowlisted
        "https://user:pw@api.example.com/x",  # credentials
        "https://api.example.com.evil.example/",  # suffix trick
    ],
)
def test_url_rejections(url):
    rule = ArgRule(type="url", hosts=["api.example.com"])
    assert check_url(url, rule)


def test_url_allows_exact_and_wildcard_host():
    rule = ArgRule(type="url", hosts=["api.example.com", "*.corp.example"])
    assert check_url("https://api.example.com/v1", rule) == []
    assert check_url("https://a.corp.example/v1", rule) == []
    assert check_url("https://corp.example/v1", rule)  # wildcard must not match the apex


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "169.254.169.254",  # cloud metadata
        "10.0.0.5",
        "[::1]",
        "2130706433",  # decimal loopback
        "0x7f000001",  # hex loopback
        "0177.0.0.1",  # octal loopback
        "[::ffff:169.254.169.254]",  # v4-mapped v6
    ],
)
def test_ssrf_literal_addresses_blocked_without_allowlist(host):
    rule = ArgRule(type="url", schemes=["http", "https"], block_private=True)
    assert check_url(f"http://{host}/latest/meta-data/", rule)


def test_dns_resolution_check_uses_injected_resolver():
    rule = ArgRule(type="url", resolve_dns=True)
    assert check_url("https://rebind.example/", rule, resolver=lambda h: ["10.1.2.3"])
    assert check_url("https://ok.example/", rule, resolver=lambda h: ["93.184.216.34"]) == []


def test_scalar_checks():
    assert check_arg(True, ArgRule(type="integer"))  # bool is not an int
    assert check_arg(11, ArgRule(type="integer", maximum=10))
    assert check_arg("abc", ArgRule(pattern=r"\d+"))
    assert check_arg("x" * 5, ArgRule(max_length=3))
    assert check_arg("a", ArgRule(enum=["b"]))
    assert check_arg("rm -rf", ArgRule(deny_patterns=[r"rm\s"]))
    assert check_arg(5, ArgRule(type="string"))
    assert check_arg("fine", ArgRule(max_length=10)) == []


# --------------------------------------------------------------------- the guard


def _call(name, **args):
    return ToolCall(name=name, arguments=args)


def test_default_deny_and_disabled(sample_policy):
    g = ToolGuard(sample_policy)
    assert g.evaluate(_call("unknown")).verdict == Verdict.DENY
    assert "default deny" in g.evaluate(_call("unknown")).message()
    assert g.evaluate(_call("disabled")).verdict == Verdict.DENY


def test_argument_rules_enforced(sample_policy):
    g = ToolGuard(sample_policy)
    assert g.evaluate(_call("search_docs", query="quarterly")).allowed
    assert not g.evaluate(_call("search_docs")).allowed  # missing required
    assert not g.evaluate(_call("search_docs", query="q", extra=1)).allowed  # unexpected arg
    assert not g.evaluate(_call("search_docs", query="x" * 500)).allowed


def test_path_tool_confined_to_root(sample_policy, tmp_path):
    g = ToolGuard(sample_policy)
    (tmp_path / "workspace" / "a.txt").write_text("hi")
    assert g.evaluate(_call("read_file", path="a.txt")).allowed
    assert not g.evaluate(_call("read_file", path="../../etc/passwd")).allowed


def test_taint_blocks_side_effect_tools_after_untrusted_read(sample_policy):
    g = ToolGuard(sample_policy)
    s = Session()
    assert g.evaluate(_call("http_get", url="https://api.example.com/x"), s).allowed
    g.execute(_call("search_docs", query="q"), lambda query: "doc text", s)  # returns_untrusted
    assert s.tainted and s.taint_sources == ["search_docs"]
    d = g.evaluate(_call("http_get", url="https://api.example.com/x"), s)
    assert d.verdict == Verdict.DENY and "untrusted content" in d.message()
    # read-only tools stay available
    assert g.evaluate(_call("search_docs", query="again"), s).allowed


def test_taint_action_approve_routes_to_approver():
    policy = Policy.from_dict(
        {
            "taint": {"action": "approve"},
            "tools": {"post": {"side_effects": True, "allow_extra_args": True}},
        }
    )
    asked = []
    g = ToolGuard(policy, approver=lambda call, d: asked.append(call.name) or True)
    s = Session()
    s.mark_untrusted("web")
    assert g.authorize(_call("post"), s).allowed and asked == ["post"]


def test_require_approval_without_approver_denies(sample_policy):
    g = ToolGuard(sample_policy)
    d = g.authorize(_call("send_email", to="a@corp.example"))
    assert d.verdict == Verdict.DENY and "no approver" in d.message()


def test_approver_can_allow_or_refuse(sample_policy):
    yes = ToolGuard(sample_policy, approver=lambda c, d: True)
    no = ToolGuard(sample_policy, approver=lambda c, d: False)
    assert yes.authorize(_call("send_email", to="a@corp.example")).allowed
    refused = no.authorize(_call("send_email", to="a@corp.example"))
    assert not refused.allowed and "approval refused" in refused.message()


def test_attacker_recipient_rejected_even_with_approver(sample_policy):
    g = ToolGuard(sample_policy, approver=lambda c, d: True)
    assert not g.authorize(_call("send_email", to="x@attacker.example")).allowed


def test_per_tool_and_total_rate_limits(sample_policy):
    g = ToolGuard(sample_policy)
    s = Session()
    assert g.authorize(_call("limited", n=1), s).allowed
    assert g.authorize(_call("limited", n=2), s).allowed
    third = g.authorize(_call("limited", n=3), s)
    assert not third.allowed and "limit" in third.message()

    tiny = ToolGuard(Policy.from_dict({"max_total_calls": 1, "tools": {"t": {}}}))
    assert tiny.authorize(_call("t")).allowed
    assert not tiny.authorize(_call("t")).allowed


def test_denied_calls_do_not_consume_budget(sample_policy):
    g = ToolGuard(sample_policy)
    s = Session()
    for _ in range(5):
        assert not g.authorize(_call("limited", n=999), s).allowed
    assert s.calls["limited"] == 0


def test_execute_and_wrap_raise_tooldenied_and_run_when_allowed(sample_policy):
    g = ToolGuard(sample_policy)
    search = g.wrap("search_docs", lambda query: f"results for {query}")
    assert search(query="abc") == "results for abc"
    with pytest.raises(ToolDenied) as exc:
        g.wrap("run_shell", lambda command: "pwned")(command="id")
    assert exc.value.decision.verdict == Verdict.DENY


def test_guard_writes_audit_trail(sample_policy):
    sink = MemorySink()
    g = ToolGuard(sample_policy, audit=AuditLogger(sink))
    g.authorize(_call("run_shell", command="id"))
    events = [r["event"] for r in sink.records]
    assert events == ["tool_request", "tool_decision"]
    assert sink.records[1]["data"]["verdict"] == "deny"


# -------------------------------------------------------------------- adapters


def test_anthropic_adapter_runs_allowed_and_reports_denials(sample_policy):
    g = ToolGuard(sample_policy)
    s = Session()
    blocks = [
        {"type": "text", "text": "thinking"},
        {"type": "tool_use", "id": "t1", "name": "search_docs", "input": {"query": "q"}},
        {"type": "tool_use", "id": "t2", "name": "run_shell", "input": {"command": "id"}},
        {"type": "tool_use", "id": "t3", "name": "search_docs", "input": {"bad": 1}},
    ]
    out = run_anthropic_tool_uses(
        g, s, blocks, {"search_docs": lambda query: "found", "run_shell": lambda command: "x"}
    )
    assert [r["tool_use_id"] for r in out] == ["t1", "t2", "t3"]
    assert out[0]["content"] == "found" and "is_error" not in out[0]
    assert out[1]["is_error"] and "refused" in out[1]["content"]
    assert out[2]["is_error"]


def test_anthropic_adapter_reports_tool_exceptions(sample_policy):
    g = ToolGuard(sample_policy)

    def boom(query):
        raise RuntimeError("db down")

    out = run_anthropic_tool_uses(
        g,
        Session(),
        [{"type": "tool_use", "id": "t", "name": "search_docs", "input": {"query": "q"}}],
        {"search_docs": boom},
    )
    assert out[0]["is_error"] and "RuntimeError" in out[0]["content"]


def test_openai_adapter_handles_bad_json_and_denials(sample_policy):
    g = ToolGuard(sample_policy)
    calls = [
        {"id": "a", "function": {"name": "search_docs", "arguments": '{"query": "q"}'}},
        {"id": "b", "function": {"name": "search_docs", "arguments": "{oops"}},
        {"id": "c", "function": {"name": "run_shell", "arguments": '{"command": "id"}'}},
        {"id": "d", "function": {"name": "search_docs", "arguments": "[1]"}},
    ]
    msgs = run_openai_tool_calls(g, Session(), calls, {"search_docs": lambda query: "found"})
    assert msgs[0] == {"role": "tool", "tool_call_id": "a", "content": "found"}
    assert "not valid JSON" in msgs[1]["content"]
    assert "refused" in msgs[2]["content"]
    assert "JSON object" in msgs[3]["content"]


# ------------------------------------------------------------ subprocess runner


def _py_runner(tmp_path, **rule_kwargs):
    return SafeCommandRunner(
        {"py": ExecRule(executable=sys.executable, **rule_kwargs)},
        cwd_roots=[str(tmp_path)],
        timeout=5,
    )


def test_runner_runs_allowlisted_command_without_shell(tmp_path):
    r = _py_runner(tmp_path, allowed_subcommands=["--version"]).run("py", ["--version"])
    assert r.returncode == 0 and "Python" in (r.stdout + r.stderr)


def test_runner_rejects_unlisted_alias_subcommand_and_denied_args(tmp_path):
    runner = _py_runner(tmp_path, allowed_subcommands=["--version"], deny_args=["-c"])
    with pytest.raises(CommandDenied, match="not allowlisted"):
        runner.run("sh", ["-c", "id"])
    with pytest.raises(CommandDenied, match="subcommand"):
        runner.run("py", ["-c", "print(1)"])
    with pytest.raises(CommandDenied, match="subcommand"):
        runner.run("py", [])


def test_runner_arg_pattern_and_max_args(tmp_path):
    runner = _py_runner(tmp_path, arg_pattern=r"--[a-z]+", max_args=2)
    with pytest.raises(CommandDenied, match="pattern"):
        runner.run("py", ["--version; id"])
    with pytest.raises(CommandDenied, match="too many"):
        runner.run("py", ["--a", "--b", "--c"])


def test_runner_confines_cwd_and_scrubs_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_SECRET", "hunter2")
    runner = SafeCommandRunner(
        {"py": ExecRule(executable=sys.executable)}, cwd_roots=[str(tmp_path)], timeout=5
    )
    with pytest.raises(CommandDenied, match="working directory"):
        runner.run("py", ["--version"], cwd=str(tmp_path.parent))
    script = tmp_path / "env.py"
    script.write_text("import os; print(os.environ.get('AGENT_SECRET', 'absent'))")
    out = runner.run("py", [str(script)])
    assert out.stdout.strip() == "absent"


def test_runner_timeout_and_output_cap(tmp_path):
    runner = SafeCommandRunner(
        {"py": ExecRule(executable=sys.executable)},
        cwd_roots=[str(tmp_path)],
        timeout=1,
        max_output_bytes=100,
    )
    slow = tmp_path / "slow.py"
    slow.write_text("import time; time.sleep(30)")
    assert runner.run("py", [str(slow)]).timed_out
    loud = tmp_path / "loud.py"
    loud.write_text("print('x' * 10000)")
    res = runner.run("py", [str(loud)])
    assert res.truncated and len(res.stdout) <= 100


def test_runner_requires_resolvable_executable(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        SafeCommandRunner(
            {"x": ExecRule(executable="definitely-not-a-binary-xyz")}, cwd_roots=[str(tmp_path)]
        )
    with pytest.raises(ValueError):
        SafeCommandRunner({}, cwd_roots=[])
