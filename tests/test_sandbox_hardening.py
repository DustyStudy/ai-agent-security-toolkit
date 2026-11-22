from __future__ import annotations

import gc
import os
import shutil
import sys
import warnings

import pytest

from agentsec.sandbox import (
    ArgRule,
    CommandDenied,
    ExecRule,
    Policy,
    PolicyError,
    SafeCommandRunner,
    locked_install_rules,
)
from agentsec.sandbox.subprocess_runner import _find_executable
from agentsec.sandbox.validators import check_arg, check_url, has_win32_trailing_dot_or_space

EXE = ".exe" if os.name == "nt" else ""


def plant(directory, name: str) -> str:
    """Copy the interpreter to ``directory/name`` as a runnable stand-in binary."""
    directory.mkdir(parents=True, exist_ok=True)
    return shutil.copy(sys.executable, directory / (name + EXE))


# --------------------------------------------------------------------------- A1
def test_run_closes_both_output_pipes(tmp_path):
    runner = SafeCommandRunner(
        {"py": ExecRule(executable=sys.executable)}, cwd_roots=[str(tmp_path)], timeout=20
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert runner.run("py", ["-c", "print('ok')"]).stdout.strip() == "ok"
        gc.collect()  # an unclosed pipe warns when it is collected
    assert not [w for w in caught if issubclass(w.category, ResourceWarning)]


# --------------------------------------------------------------------------- A2
def test_path_lookup_ignores_the_current_directory(tmp_path, monkeypatch):
    plant(tmp_path / "repo", "planted-tool")
    monkeypatch.chdir(tmp_path / "repo")
    # "" and "." both mean the current directory in a PATH.
    monkeypatch.setenv("PATH", os.pathsep.join(["", ".", str(tmp_path / "empty")]))
    assert _find_executable("planted-tool") is None

    real = plant(tmp_path / "bin", "planted-tool")
    monkeypatch.setenv("PATH", os.pathsep.join(["", ".", str(tmp_path / "bin")]))
    assert os.path.samefile(_find_executable("planted-tool"), real)


def test_executable_inside_a_cwd_root_is_refused(tmp_path, monkeypatch):
    plant(tmp_path / "repo" / "bin", "tool")
    monkeypatch.setenv("PATH", str(tmp_path / "repo" / "bin"))
    with pytest.raises(ValueError, match="inside cwd_roots"):
        SafeCommandRunner({"tool": ExecRule(executable="tool")}, cwd_roots=[str(tmp_path / "repo")])
    # Outside the roots the same binary is accepted.
    SafeCommandRunner({"tool": ExecRule(executable="tool")}, cwd_roots=[str(tmp_path / "other")])


# --------------------------------------------------------------------------- A3
def test_locked_install_pins_requirements_and_cwd(tmp_path):
    rule = locked_install_rules(cwd=str(tmp_path))["pip-install"]
    assert rule.cwd == str(tmp_path)
    assert rule.exact_args == [
        ["install", "--require-hashes", "-r", str(tmp_path / "requirements.txt")]
    ]


def test_exact_and_fixed_cwd_rules_refuse_a_caller_cwd(tmp_path):
    sub = tmp_path / "attacker"
    sub.mkdir()
    show_cwd = ["-c", "import os; print(os.getcwd())"]
    runner = SafeCommandRunner(
        {
            "exact": ExecRule(executable=sys.executable, exact_args=[show_cwd]),
            "fixed": ExecRule(executable=sys.executable, cwd=str(sub)),
            "outside": ExecRule(executable=sys.executable, cwd=str(tmp_path.parent)),
        },
        cwd_roots=[str(tmp_path)],
        timeout=20,
    )
    for alias in ("exact", "fixed"):
        with pytest.raises(CommandDenied, match="fixes the working directory"):
            runner.run(alias, show_cwd, cwd=str(sub))
    assert os.path.samefile(runner.run("exact").stdout.strip(), tmp_path)
    assert os.path.samefile(runner.run("fixed", show_cwd).stdout.strip(), sub)
    with pytest.raises(CommandDenied, match="escapes allowed roots"):
        runner.run("outside", show_cwd)


# --------------------------------------------------------------------------- A4
@pytest.mark.parametrize(
    "url",
    [
        "https://x.atla\u00dfian.net/",  # IDNA 2003 folds the sharp s to "ss", IDNA 2008 does not
        "https://b\u00fccher.example/",
        "https://\u0430pi.example.com/",  # Cyrillic a
    ],
)
def test_non_ascii_host_is_refused(url):
    rule = ArgRule(type="url", hosts=["*.atlassian.net", "*.example", "api.example.com"])
    assert any("not a valid hostname" in e for e in check_url(url, rule))


def test_punycode_host_is_checked_as_written():
    rule = ArgRule(type="url", hosts=["xn--bcher-kva.example"])
    assert check_url("https://xn--bcher-kva.example/", rule) == []
    assert check_url("https://xn--x-atlaian-x9a.net/", rule)  # not in the allowlist


# --------------------------------------------------------------------------- A5
@pytest.mark.parametrize(
    "path",
    [
        r"C:\repo\.mcp.json .",
        r"C:\repo\.mcp.json.",
        r"C:\repo\.mcp.json ",
        r"C:\repo\.claude.\settings.json",
        "C:/repo/.claude /settings.json",
        r"C:\repo\...\x",
    ],
)
def test_trailing_dot_or_space_component_is_detected(path):
    assert has_win32_trailing_dot_or_space(path)


@pytest.mark.parametrize(
    "path", [r"C:\repo\.mcp.json", r"C:\repo\.\a\..\b.txt", "/srv/repo/a b/.env", "C:\\repo\\"]
)
def test_ordinary_components_are_not_flagged(path):
    assert not has_win32_trailing_dot_or_space(path)


def test_path_rule_refuses_trailing_dot_on_windows(tmp_path, monkeypatch):
    import agentsec.sandbox.validators as validators

    rule = ArgRule(type="path", roots=[str(tmp_path)], deny_patterns=[r"\.mcp\.json$"])
    target = str(tmp_path / ".mcp.json .")
    # shortcut: os.name is patched only for the validator's own checks, so this runs on Linux.
    monkeypatch.setattr(validators.os, "name", "nt")
    assert check_arg(target, rule) == ["path escapes allowed roots"]


# --------------------------------------------------------------------------- A6
def test_duplicate_tool_block_is_an_error(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "tools:\n"
        "  Bash:\n    side_effects: true\n    require_approval: true\n"
        "  Bash:\n    allow: true\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="duplicate key"):
        Policy.from_yaml(policy)


def test_duplicate_key_inside_a_rule_is_an_error(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "tools:\n  Bash:\n    require_approval: true\n    require_approval: false\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="duplicate key"):
        Policy.from_yaml(policy)


def test_merge_key_override_still_loads(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "tools:\n"
        "  Read: &base\n    require_approval: true\n    max_calls: 3\n"
        "  Write:\n    <<: *base\n    max_calls: 1\n",
        encoding="utf-8",
    )
    loaded = Policy.from_yaml(policy)
    assert loaded.tools["Write"].require_approval is True
    assert loaded.tools["Write"].max_calls == 1
