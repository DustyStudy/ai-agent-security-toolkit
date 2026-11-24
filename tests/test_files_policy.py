"""Policy-wide folder rules (files: read_roots, write_roots, deny_patterns)."""

from __future__ import annotations

import os

import pytest

from agentsec.sandbox import Policy, PolicyError, ToolGuard, Verdict
from agentsec.types import ToolCall


@pytest.fixture
def tree(tmp_path):
    for d in ("repo/src", "repo/out", "home/.ssh", "other"):
        (tmp_path / d).mkdir(parents=True)
    for f in ("repo/src/a.py", "repo/.env", "home/.ssh/id_ed25519", "other/x.txt"):
        (tmp_path / f).write_text("x")
    return tmp_path


def _policy(tree, **tools):
    return Policy.from_dict(
        {
            "files": {
                "read_roots": [str(tree / "repo")],
                "write_roots": [str(tree / "repo" / "out")],
                "deny_patterns": [r"(^|[\\/])\.env$"],
            },
            "tools": tools
            or {
                "Read": {"args": {"file_path": {"type": "path", "required": True}}},
                "Grep": {"args": {"path": {"type": "path"}, "pattern": {}}},
                "Write": {
                    "side_effects": True,
                    "args": {"file_path": {"type": "path", "required": True}, "content": {}},
                },
            },
        }
    )


def _verdict(policy, tool, **args):
    return ToolGuard(policy).evaluate(ToolCall(name=tool, arguments=args)).verdict


def test_reads_stay_inside_read_roots(tree):
    p = _policy(tree)
    assert _verdict(p, "Read", file_path=str(tree / "repo/src/a.py")) == Verdict.ALLOW
    assert _verdict(p, "Grep", path=str(tree / "repo"), pattern="x") == Verdict.ALLOW
    for outside in ("home/.ssh/id_ed25519", "other/x.txt", "repo/../other/x.txt"):
        assert _verdict(p, "Read", file_path=str(tree / outside)) == Verdict.DENY
    assert _verdict(p, "Grep", path=str(tree / "home"), pattern="x") == Verdict.DENY


def test_a_symlink_out_of_the_read_roots_is_refused(tree):
    if os.name == "nt":
        pytest.skip("symlinks need privileges on Windows")
    os.symlink(tree / "home" / ".ssh", tree / "repo" / "keys")
    p = _policy(tree)
    assert _verdict(p, "Read", file_path=str(tree / "repo/keys/id_ed25519")) == Verdict.DENY


def test_writes_stay_inside_write_roots(tree):
    p = _policy(tree)
    assert (
        _verdict(p, "Write", file_path=str(tree / "repo/out/r.txt"), content="x") == Verdict.ALLOW
    )
    assert _verdict(p, "Write", file_path=str(tree / "repo/src/a.py"), content="x") == Verdict.DENY


def test_deny_patterns_apply_to_every_path_argument(tree):
    p = _policy(tree)
    assert _verdict(p, "Read", file_path=str(tree / "repo/.env")) == Verdict.DENY
    assert _verdict(p, "Read", file_path=str(tree / "repo/.ENV")) == Verdict.DENY


def test_a_tool_root_outside_the_folder_rules_is_refused_at_load(tree):
    with pytest.raises(PolicyError, match="outside files.read_roots"):
        _policy(
            tree, Read={"args": {"file_path": {"type": "path", "roots": [str(tree / "other")]}}}
        )
    narrower = _policy(
        tree, Read={"args": {"file_path": {"type": "path", "roots": [str(tree / "repo/src")]}}}
    )
    assert narrower.tools["Read"].args["file_path"].roots == [str(tree / "repo/src")]


@pytest.mark.parametrize(
    "files",
    [{"read_roots": ["relative/dir"]}, {"deny_patterns": ["("]}, {"read_roots": "/x"}, {"x": 1}],
)
def test_bad_folder_rules_are_refused(files):
    with pytest.raises(PolicyError):
        Policy.from_dict({"files": files, "tools": {}})


def test_without_files_nothing_changes(tree):
    p = Policy.from_dict({"tools": {"Read": {"args": {"file_path": {"type": "path"}}}}})
    assert p.tools["Read"].args["file_path"].roots == []
    assert _verdict(p, "Read", file_path=str(tree / "repo/src/a.py")) == Verdict.DENY  # no roots
