"""Hardening of the Claude Code hook: `--block-approvals`, and the scan-config checks on how
`agentsec hook` is registered (a matcher narrower than every tool, a fail-open handler)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.cli import main
from agentsec.configscan import scan_config
from agentsec.integrations.claude_code import BLOCK, handle, load_session
from tests.test_claude_code_hook import cli_args, guard_for, pre, run_cli, state, workspace

__all__ = ["cli_args", "state", "workspace"]  # fixtures, reused

COMMAND = "agentsec hook --policy /etc/agentsec/p.yaml --state-dir /var/lib/agentsec/hook"
ITEM = ".claude/settings.json#hooks.PreToolUse"


# ------------------------------------------------------------------------- --block-approvals


def test_approval_is_ask_by_default_and_exit_2_with_block_approvals(workspace, state):
    guard = guard_for(workspace)
    handle(pre("WebSearch", query="x"), guard, state)  # taints: the next shell call needs approval
    asked = handle(pre("Bash", command="ls"), guard, state)
    assert asked.exit_code == 0 and '"ask"' in asked.stdout

    blocked = handle(pre("Bash", command="ls"), guard, state, block_approvals=True)
    assert (blocked.exit_code, blocked.stdout) == (BLOCK, "")
    assert "approval is blocked" in blocked.stderr
    # Like a denial, the blocked call is not counted: the tool never ran.
    session = load_session(next(state.glob("*.jsonl")), "s1")
    assert session.calls["Bash"] == 1


def test_block_approvals_leaves_allowed_and_denied_calls_alone(workspace, state):
    guard = guard_for(workspace)
    allowed = handle(pre("Bash", command="ls"), guard, state, block_approvals=True)
    assert (allowed.exit_code, allowed.stdout, allowed.stderr) == (0, "", "")
    denied = handle(pre("Unknown"), guard, state, block_approvals=True)
    assert denied.exit_code == BLOCK and "approval is blocked" not in denied.stderr


def test_cli_block_approvals_flag(monkeypatch, capsys, cli_args):
    run_cli(monkeypatch, capsys, pre("WebSearch", query="x"), *cli_args)
    event = pre("Bash", command="ls")
    code, out, err = run_cli(monkeypatch, capsys, event, *cli_args, "--block-approvals")
    assert (code, out) == (2, "") and "approval is blocked" in err
    code, out, _ = run_cli(monkeypatch, capsys, event, *cli_args)
    assert code == 0 and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "ask"


# ------------------------------------------------------------------- scan-config registration


def settings(tmp_path: Path, *groups: object) -> Path:
    path = tmp_path / ".claude" / "settings.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps({"hooks": {"PreToolUse": list(groups)}}), encoding="utf-8")
    return tmp_path


def group(matcher: str | None = "*", **handler) -> dict:
    handler = {"type": "command", "command": COMMAND, "onFailure": "block", **handler}
    out: dict = {"hooks": [{k: v for k, v in handler.items() if v is not None}]}
    if matcher is not None:
        out["matcher"] = matcher
    return out


def found(root: Path) -> set[tuple[str, str]]:
    return {(f.item, f.kind) for f in scan_config(root).findings}


@pytest.mark.parametrize("matcher", ["*", "", ".*", None])
def test_hardened_registration_has_no_finding(tmp_path, matcher):
    assert found(settings(tmp_path, group(matcher))) == set()


@pytest.mark.parametrize("matcher", ["Bash", "Bash|Edit|Write", "mcp__.*", "^(?!Read$).*", 7])
def test_matcher_narrower_than_every_tool_is_unguarded(tmp_path, matcher):
    scan = scan_config(settings(tmp_path, group(matcher)))
    assert {(f.item, f.kind) for f in scan.findings} == {(ITEM, "unguarded")}
    assert 'use matcher "*"' in scan.findings[0].detail


def test_if_filter_narrows_a_match_all_group(tmp_path):
    assert found(settings(tmp_path, group("*", **{"if": "Bash(git *)"}))) == {(ITEM, "unguarded")}


def test_narrow_group_beside_a_match_all_group_is_covered(tmp_path):
    assert found(settings(tmp_path, group("Bash"), group("*"))) == set()


@pytest.mark.parametrize("on_failure", [None, "continue", True])
def test_handler_without_on_failure_block_is_failopen(tmp_path, on_failure):
    assert found(settings(tmp_path, group("*", onFailure=on_failure))) == {(ITEM, "failopen")}


def test_both_gaps_are_reported_and_the_matcher_is_escaped(tmp_path):
    scan = scan_config(settings(tmp_path, group("Bash\x1b[31m", onFailure=None)))
    assert {(f.item, f.kind) for f in scan.findings} == {(ITEM, "unguarded"), (ITEM, "failopen")}
    assert "\x1b" not in "".join(f.detail for f in scan.findings)


@pytest.mark.parametrize(
    "handler",
    [
        {"command": "agentsec", "args": ["hook", "--policy", "p.yaml", "--state-dir", "s"]},
        {"command": "python -m agentsec.cli hook --policy p.yaml --state-dir s"},
        {"command": "/opt/venv/bin/agentsec.exe  hook --policy p.yaml --state-dir s"},
    ],
)
def test_other_spellings_of_the_command_are_recognised(tmp_path, handler):
    assert found(settings(tmp_path, group("Bash", **handler))) == {(ITEM, "unguarded")}


def test_other_hooks_and_malformed_registrations_are_not_flagged(tmp_path):
    other = group("Bash", command="./lint.sh", onFailure=None)
    assert found(settings(tmp_path, other, "junk", {"hooks": "junk"}, {"hooks": [1]})) == set()
    (tmp_path / ".claude" / "settings.json").write_text('{"hooks": {"PreToolUse": 1}}')
    assert found(tmp_path) == set()


def test_plugin_hooks_file_is_checked_too(tmp_path):
    plugin = tmp_path / ".claude-plugin" / "hooks.json"
    plugin.parent.mkdir()
    plugin.write_text(json.dumps({"hooks": {"PreToolUse": [group("Bash")]}}), encoding="utf-8")
    assert found(tmp_path) == {(".claude-plugin/hooks.json#hooks.PreToolUse", "unguarded")}


def test_cli_reports_the_findings_and_refuses_to_pin(tmp_path, capsys):
    root = settings(tmp_path, group("Bash", onFailure=None))
    pins = tmp_path / "pins.json"
    assert main(["scan-config", str(root), "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert {f["kind"] for f in report["findings"]} == {"unguarded", "failopen"}
    assert main(["scan-config", str(root)]) == 1
    out = capsys.readouterr().out
    assert f"UNGUARDED {ITEM}" in out and f"FAILOPEN  {ITEM}" in out
    assert main(["scan-config", str(root), "--pins", str(pins), "--update-pins"]) == 1
    assert not pins.exists()
