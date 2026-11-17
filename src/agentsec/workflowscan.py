"""Find GitHub Actions workflows that hand an outsider's text to an AI agent.

An agent that triages issues or reviews pull requests reads text anyone can write: an issue
title, a comment, a pull request body. If the job that runs it also holds secrets or a token
with write access, an injected instruction can spend them. That is how a single issue title
ended in a compromised package release. :func:`scan_workflows` reports each job where the three
meet: a trigger an outsider controls, a step that runs an agent, and no check on who the author
is.

This is a tripwire for one pattern, by name. It does not know every agent, cannot judge
whether an ``if:`` condition is a real gate, and does not follow reusable workflows. It does
not look for script injection through ``${{ }}`` in ``run:`` steps; use a workflow linter such
as zizmor or actionlint for that.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from agentsec.configscan import ConfigFinding, show

MAX_FILE_BYTES = 1_000_000

# Events whose payload holds text from someone without write access to the repository, in a
# run that can hold secrets and a read-write token. ``workflow_run`` is here because it runs
# with both after a fork's pull request workflow. ``pull_request`` is left out: a fork's run has
# no secrets and a read-only token, and flagging it would report every agent that reviews pull
# requests.
UNTRUSTED_EVENTS = frozenset(
    {
        "discussion",
        "discussion_comment",
        "issue_comment",
        "issues",
        "pull_request_review",
        "pull_request_review_comment",
        "pull_request_target",
        "workflow_run",
    }
)
# Agent actions and command-line agents, by the name that appears in ``uses:`` or ``run:``.
_AGENT = re.compile(
    r"\b(aider|claude|cline|codex|copilot|cursor-agent|gemini|opencode|openhands)\b", re.IGNORECASE
)
# An ``if:`` that looks at who wrote the event. Presence only: whether it is strict enough
# (``!= 'NONE'`` is not) is for a human to read.
_AUTHOR_GATE = re.compile(
    r"author_association|github\.(?:triggering_)?actor\b|\.sender\.login|\.user\.login"
)
_SECRET = re.compile(r"\bsecrets\.([A-Za-z0-9_]+)")


# Only strings are ever read out of the parsed file. A value built from nested YAML aliases is
# a few hundred bytes to parse and gigabytes to turn into text.


def _events(workflow: Mapping[Any, Any]) -> set[str]:
    # YAML 1.1 reads the bare key ``on`` as the boolean true.
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list | Mapping):
        return {e for e in on if isinstance(e, str)}
    return set()


def _steps(job: Mapping[Any, Any]) -> list[Mapping[Any, Any]]:
    steps = job.get("steps")
    return [s for s in steps if isinstance(s, Mapping)] if isinstance(steps, list) else []


def _write_access(permissions: Any) -> str:
    if permissions is None:
        return "not set (the repository default may be read-write)"
    if isinstance(permissions, Mapping):
        # Scope names come from the file, so they are escaped like any other scanned text.
        scopes = sorted(
            show(k, 40) for k, v in permissions.items() if isinstance(k, str) and v == "write"
        )
        return ", ".join(scopes) or "none"
    return "all" if permissions == "write-all" else "none"


def _agent_step(job: Mapping[Any, Any]) -> str | None:
    """The first ``uses:`` or ``run:`` in the job that names an agent."""
    for step in (job, *_steps(job)):
        for key in ("uses", "run"):
            value = step.get(key)
            if isinstance(value, str) and _AGENT.search(value):
                return value
    return None


def _gated(job: Mapping[Any, Any]) -> bool:
    conditions = [job.get("if"), *(s.get("if") for s in _steps(job))]
    return any(_AUTHOR_GATE.search(c) for c in conditions if isinstance(c, str))


def _scan_file(path: Path, rel: str) -> list[ConfigFinding]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return [ConfigFinding(rel, "unparsed", f"over {MAX_FILE_BYTES} bytes")]
        text = path.read_text(encoding="utf-8-sig")
        workflow = yaml.safe_load(text)
    except (OSError, ValueError, yaml.YAMLError, RecursionError) as exc:
        return [ConfigFinding(rel, "unparsed", f"cannot read: {type(exc).__name__}")]
    jobs = workflow.get("jobs") if isinstance(workflow, Mapping) else None
    if not isinstance(jobs, Mapping):
        return [ConfigFinding(rel, "unparsed", "not a workflow: no jobs mapping")]
    events = sorted(_events(workflow) & UNTRUSTED_EVENTS)
    if not events:
        return []
    # Read from the text, not the parsed data: a file built from nested YAML aliases is small
    # to parse and enormous to walk.
    secrets = sorted(set(_SECRET.findall(text)) - {"GITHUB_TOKEN"})
    findings = []
    for name, job in jobs.items():
        if not isinstance(job, Mapping):
            continue
        step = _agent_step(job)
        if step is None or _gated(job):
            continue
        permissions = job["permissions"] if "permissions" in job else workflow.get("permissions")
        detail = (
            f"runs an agent ({show(step.strip(), 80)}) on {', '.join(events)} with no check on "
            f"the author; write access: {_write_access(permissions)}; "
            f"secrets in this workflow: {', '.join(secrets) or 'none'}"
        )
        findings.append(ConfigFinding(f"{rel}#{name}", "agent_untrusted_input", detail))
    return findings


def scan_workflows(root: str | Path) -> list[ConfigFinding]:
    """Scan ``root/.github/workflows`` (or one workflow file)."""
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"no such file or directory: {root}")
    if root.is_file():
        return _scan_file(root, root.name)
    folder = root / ".github" / "workflows"
    files = sorted(p for p in folder.glob("*") if p.suffix.lower() in (".yml", ".yaml"))
    findings: list[ConfigFinding] = []
    for path in files:
        findings += _scan_file(path, path.relative_to(root).as_posix())
    return findings
