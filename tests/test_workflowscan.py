from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.cli import main
from agentsec.workflowscan import scan_workflows

ROOT = Path(__file__).resolve().parents[1]

AGENT_ON_ISSUES = """
name: triage
on:
  issues:
    types: [opened]
permissions:
  contents: write
  issues: write
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          prompt: "Triage: ${{ github.event.issue.title }}"
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
"""


def workflow(tmp_path: Path, text: str, name: str = "agent.yml") -> Path:
    folder = tmp_path / ".github" / "workflows"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(text, encoding="utf-8")
    return tmp_path


def kinds(findings) -> list[tuple[str, str]]:
    return [(f.item, f.kind) for f in findings]


def test_agent_on_an_issue_event_with_write_access_and_secrets_is_reported(tmp_path):
    (finding,) = scan_workflows(workflow(tmp_path, AGENT_ON_ISSUES))
    assert (finding.item, finding.kind) == (
        ".github/workflows/agent.yml#triage",
        "agent_untrusted_input",
    )
    assert "claude-code-action" in finding.detail and "on issues" in finding.detail
    assert "write access: contents, issues" in finding.detail
    # The token every job has is not listed; the publish token is.
    assert "secrets in this workflow: ANTHROPIC_API_KEY, NPM_TOKEN" in finding.detail


@pytest.mark.parametrize(
    "trigger",
    [
        "on: issue_comment",
        "on: [push, pull_request_target]",
        "on:\n  pull_request_review_comment:\n    types: [created]",
        "'on':\n  discussion: {}",
        "on:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]",
    ],
)
def test_every_spelling_of_an_untrusted_trigger_counts(tmp_path, trigger):
    text = f"{trigger}\njobs:\n  a:\n    steps:\n      - run: npx @openai/codex exec 'review'\n"
    assert kinds(scan_workflows(workflow(tmp_path, text))) == [
        (".github/workflows/agent.yml#a", "agent_untrusted_input")
    ]


@pytest.mark.parametrize(
    "step",
    [
        "uses: google-github-actions/run-gemini-cli@v0",
        "run: |\n          npm i -g @anthropic-ai/claude-code\n          claude -p 'triage'",
        "run: aider --yes --message 'fix'",
        "uses: Some-Org/OpenHands-resolver@main",
    ],
)
def test_agents_are_recognised_in_uses_and_run(tmp_path, step):
    text = f"on: issues\njobs:\n  a:\n    steps:\n      - {step}\n"
    assert len(scan_workflows(workflow(tmp_path, text))) == 1


def test_trusted_triggers_and_jobs_without_an_agent_are_not_reported(tmp_path):
    workflow(tmp_path, AGENT_ON_ISSUES.replace("issues:\n    types: [opened]", "push: {}"))
    no_agent = "on: issues\njobs:\n  label:\n    steps:\n      - uses: actions/labeler@v6\n"
    workflow(tmp_path, no_agent, "label.yaml")
    # pull_request from a fork runs without secrets and with a read-only token.
    fork = "on: pull_request\njobs:\n  a:\n    steps:\n      - run: claude -p review\n"
    workflow(tmp_path, fork, "fork.yml")
    assert scan_workflows(tmp_path) == []


def test_missing_permissions_are_called_out_and_job_permissions_win(tmp_path):
    text = "on: issues\njobs:\n  a:\n    steps:\n      - run: claude -p x\n"
    (finding,) = scan_workflows(workflow(tmp_path, text))
    assert "write access: not set" in finding.detail and "secrets in this workflow: none" in (
        finding.detail
    )
    text = (
        "on: issues\npermissions: write-all\njobs:\n  a:\n    permissions: {}\n"
        "    steps:\n      - run: claude -p x\n  b:\n    steps:\n      - run: claude -p x\n"
    )
    a, b = scan_workflows(workflow(tmp_path, text))
    assert "write access: none" in a.detail and "write access: all" in b.detail


def test_a_job_that_checks_the_author_is_not_reported(tmp_path):
    gate = 'if: contains(fromJSON(\'["MEMBER","OWNER"]\'), github.event.comment.author_association)'
    job_gate = f"on: issue_comment\njobs:\n  a:\n    {gate}\n    steps:\n      - run: claude -p x\n"
    assert scan_workflows(workflow(tmp_path, job_gate)) == []
    step_gate = (
        "on: issue_comment\njobs:\n  a:\n    steps:\n"
        "      - run: claude -p x\n        if: github.actor == 'maintainer'\n"
    )
    assert scan_workflows(workflow(tmp_path, step_gate)) == []


def test_known_limit_a_weak_author_check_still_counts_as_a_gate(tmp_path):
    """The scanner sees that the author is looked at, not whether the check keeps anyone out."""
    text = (
        "on: issue_comment\njobs:\n  a:\n"
        "    if: github.event.comment.author_association != 'NONE'\n"
        "    steps:\n      - run: claude -p x\n"
    )
    assert scan_workflows(workflow(tmp_path, text)) == []


def test_known_limit_an_agent_it_does_not_know_by_name_is_missed(tmp_path):
    text = "on: issues\njobs:\n  a:\n    steps:\n      - run: ./scripts/run-our-llm-bot.sh\n"
    assert scan_workflows(workflow(tmp_path, text)) == []


@pytest.mark.parametrize("text", ["on: issues\njobs: [", "- just\n- a list\n", "on: issues\n"])
def test_a_file_that_is_not_a_readable_workflow_is_a_finding(tmp_path, text):
    assert kinds(scan_workflows(workflow(tmp_path, text))) == [
        (".github/workflows/agent.yml", "unparsed")
    ]


def test_yaml_alias_bomb_is_handled_quickly(tmp_path):
    lines = ["a0: &a0 [x, x, x, x, x, x, x, x, x]"]
    lines += [f"a{i}: &a{i} [{', '.join([f'*a{i - 1}'] * 9)}]" for i in range(1, 12)]
    text = "\n".join(lines) + "\non: issues\njobs:\n  a:\n    env: *a11\n    steps:\n"
    text += "      - run: claude -p x\n"
    (finding,) = scan_workflows(workflow(tmp_path, text))
    assert finding.kind == "agent_untrusted_input"


def test_alias_bomb_in_a_condition_or_trigger_is_never_turned_into_text(tmp_path):
    lines = ["a0: &a0 [xxxxxxxxxxxxxxxx, xxxxxxxxxxxxxxxx]"]
    lines += [f"a{i}: &a{i} [{', '.join([f'*a{i - 1}'] * 8)}]" for i in range(1, 14)]
    bomb = "\n".join(lines)
    in_if = bomb + "\non: issues\njobs:\n  a:\n    if: *a13\n    steps: [{run: claude, if: *a13}]\n"
    (finding,) = scan_workflows(workflow(tmp_path, in_if))  # not a gate, and no hang
    assert finding.kind == "agent_untrusted_input"
    in_on = bomb + "\non: [issues, *a13]\njobs:\n  a:\n    steps: [{run: claude}]\n"
    assert len(scan_workflows(workflow(tmp_path, in_on))) == 1


@pytest.mark.parametrize(
    "steps", ["steps: 1", "steps: text", "steps: {a: b}", "steps: [1, [2], null]", "steps: null"]
)
def test_steps_of_the_wrong_type_do_not_crash(tmp_path, steps):
    text = f"on: issues\njobs:\n  a:\n    uses: owner/claude/.github/workflows/a.yml@main\n    {steps}\n"
    (finding,) = scan_workflows(workflow(tmp_path, text))  # the job-level uses: names an agent
    assert finding.kind == "agent_untrusted_input"
    assert scan_workflows(workflow(tmp_path, "on: issues\njobs:\n  a: 7\n  b: [x]\n")) == []


def test_permission_names_from_the_file_are_escaped(tmp_path, capsys):
    text = (
        'on: issues\njobs:\n  a:\n    permissions: {"evil\\e[2J": write, 3: write}\n'
        "    steps: [{run: claude}]\n"
    )
    (finding,) = scan_workflows(workflow(tmp_path, text))
    assert "\x1b" not in finding.detail and "evil" in finding.detail
    assert main(["scan-workflows", str(tmp_path)]) == 1
    assert "\x1b" not in capsys.readouterr().out


def test_known_limit_plain_pull_request_is_not_reported(tmp_path):
    """A fork's run has no secrets and a read-only token; a same-repository author is trusted."""
    text = "on: pull_request\njobs:\n  a:\n    steps:\n      - run: claude -p review\n"
    assert scan_workflows(workflow(tmp_path, text)) == []


def test_cli_exit_codes_json_and_safe_output(tmp_path, capsys):
    assert main(["scan-workflows", str(tmp_path)]) == 0  # no workflows directory
    assert main(["scan-workflows", str(tmp_path / "missing")]) == 2
    text = 'on: issues\njobs:\n  "evil\\e[2J":\n    steps:\n      - run: claude -p x\n'
    workflow(tmp_path, text)
    capsys.readouterr()
    assert main(["scan-workflows", str(tmp_path)]) == 1
    assert "\x1b" not in capsys.readouterr().out  # a job name cannot drive the terminal
    assert main(["scan-workflows", str(tmp_path), "--json"]) == 1
    (row,) = json.loads(capsys.readouterr().out)["findings"]
    assert row["kind"] == "agent_untrusted_input"
    single = tmp_path / ".github" / "workflows" / "agent.yml"
    assert main(["scan-workflows", str(single)]) == 1


def test_this_repository_has_no_such_workflow():
    assert scan_workflows(ROOT) == []
