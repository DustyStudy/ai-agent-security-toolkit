from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.cli import main
from agentsec.workflowscan import scan_workflows

JOB = "on: issues\njobs:\n  a:\n{job_if}    steps:\n      - run: claude -p x\n{step_if}{later}"
LATER = "      - run: echo done\n        if: github.actor != 'dependabot[bot]'\n"


def workflow(tmp_path: Path, text: str, name: str = "agent.yml") -> Path:
    folder = tmp_path / ".github" / "workflows"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(text, encoding="utf-8")
    return tmp_path


def test_a_gate_on_another_step_does_not_cover_the_agent_step(tmp_path):
    text = JOB.format(job_if="", step_if="", later=LATER)
    (finding,) = scan_workflows(workflow(tmp_path, text))
    assert finding.kind == "agent_untrusted_input"
    on_step = JOB.format(job_if="", step_if="        if: github.actor == 'me'\n", later="")
    assert scan_workflows(workflow(tmp_path, on_step)) == []
    on_job = JOB.format(job_if="    if: github.actor == 'me'\n", step_if="", later="")
    assert scan_workflows(workflow(tmp_path, on_job)) == []


def test_a_directory_with_no_workflows_is_an_error_not_a_clean_scan(tmp_path, capsys):
    with pytest.raises(ValueError, match="no workflow files found under"):
        scan_workflows(tmp_path)
    assert main(["scan-workflows", str(tmp_path)]) == 2
    assert "no workflow files found under" in capsys.readouterr().err


def test_a_workflows_folder_can_be_passed_directly(tmp_path, capsys):
    workflow(tmp_path, JOB.format(job_if="", step_if="", later=""))
    folder = tmp_path / ".github" / "workflows"
    (finding,) = scan_workflows(folder)
    assert finding.item == "agent.yml#a"
    assert main(["scan-workflows", str(folder)]) == 1
    assert "1 file(s) scanned, 1 finding(s)" in capsys.readouterr().out


def test_a_tag_that_does_not_fit_its_value_does_not_hide_other_files(tmp_path):
    workflow(tmp_path, "x: !!bool maybe\n", "bad.yml")
    workflow(tmp_path, JOB.format(job_if="", step_if="", later=""))
    kinds = [f.kind for f in scan_workflows(tmp_path)]
    assert kinds == ["agent_untrusted_input", "unparsed"]
