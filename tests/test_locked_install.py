from __future__ import annotations

import dataclasses
import sys

import pytest

from agentsec.sandbox import CommandDenied, ExecRule, SafeCommandRunner, locked_install_rules


def runner_for(rule: ExecRule, tmp_path) -> SafeCommandRunner:
    # The rule's own executable (pip, npm) may not be installed where the tests run, so the
    # argument checks are exercised with the Python interpreter standing in for it.
    stand_in = dataclasses.replace(rule, executable=sys.executable)
    return SafeCommandRunner({"cmd": stand_in}, cwd_roots=[str(tmp_path)], timeout=20)


def test_exact_args_allows_only_the_listed_argument_lists(tmp_path):
    rule = ExecRule(executable="x", exact_args=[["-c", "print('one')"], ["-c", "print('two')"]])
    runner = runner_for(rule, tmp_path)
    assert runner.run("cmd", ["-c", "print('two')"]).stdout.strip() == "two"
    for args in (
        [],  # two commands are listed, so there is no default
        ["-c", "print('three')"],
        ["-c", "print('one')", "extra"],
        ["-c"],
        ["print('one')", "-c"],  # the same tokens in another order
    ):
        with pytest.raises(CommandDenied):
            runner.run("cmd", args)


def test_a_rule_with_one_command_runs_it_when_called_without_arguments(tmp_path):
    runner = runner_for(ExecRule(executable="x", exact_args=[["-c", "print('only')"]]), tmp_path)
    assert runner.run("cmd").stdout.strip() == "only"
    assert runner.run("cmd").argv[1:] == ["-c", "print('only')"]


def test_exact_args_does_not_switch_off_the_other_checks(tmp_path):
    rule = ExecRule(executable="x", exact_args=[["-c", "print(1)"]], deny_args=["-c"])
    with pytest.raises(CommandDenied, match="denied"):
        runner_for(rule, tmp_path).run("cmd")


@pytest.mark.parametrize("bad", [[], [["ok"], "not-a-list"], [[1]], "install"])
def test_malformed_exact_args_is_refused_at_construction(tmp_path, bad):
    with pytest.raises(ValueError, match="exact_args"):
        runner_for(ExecRule(executable="x", exact_args=bad), tmp_path)


def test_preset_commands(tmp_path):
    rules = locked_install_rules(
        ["pip", "uv", "npm", "pnpm"], requirements="reqs/lock.txt", cwd=str(tmp_path)
    )
    # The requirements path is absolute, so it does not depend on the directory of the run.
    lock = str(tmp_path / "reqs" / "lock.txt")
    assert {alias: (r.executable, r.exact_args) for alias, r in rules.items()} == {
        "pip-install": ("pip", [["install", "--require-hashes", "-r", lock]]),
        "uv-install": ("uv", [["sync", "--locked"]]),
        "npm-install": ("npm", [["ci", "--ignore-scripts"]]),
        "pnpm-install": ("pnpm", [["install", "--frozen-lockfile", "--ignore-scripts"]]),
    }
    assert list(locked_install_rules()) == ["pip-install"]
    with pytest.raises(ValueError, match="no locked install"):
        locked_install_rules(["conda"])


@pytest.mark.parametrize(
    "args",
    [
        ["install", "left-pad"],  # the ad-hoc package a README or tool result named
        ["install", "--require-hashes", "-r", "requirements.txt", "left-pad"],
        ["install", "-r", "requirements.txt"],  # the lock file without hash checking
        ["install", "--require-hashes", "-r", "other.txt"],  # another file
        ["install", "--require-hashes", "-r", "requirements.txt", "--index-url", "https://x"],
        ["install", "--require-hashes", "--index-url=https://x", "-r", "requirements.txt"],
        ["install", "--require-hashes", "-rrequirements.txt"],
        ["download", "left-pad"],
        ["config", "set", "global.index-url", "https://attacker.example/simple"],
    ],
)
def test_pip_preset_refuses_everything_but_the_locked_install(tmp_path, args):
    runner = runner_for(locked_install_rules(cwd=str(tmp_path))["pip-install"], tmp_path)
    with pytest.raises(CommandDenied):
        runner.run("cmd", args)


def test_pip_preset_passes_the_locked_install_through(tmp_path):
    runner = runner_for(locked_install_rules(cwd=str(tmp_path))["pip-install"], tmp_path)
    expected = ["install", "--require-hashes", "-r", str(tmp_path / "requirements.txt")]
    # The stand-in interpreter cannot run "install"; what matters is that it was not denied
    # and that the exact command line was handed to the program.
    assert runner.run("cmd").argv[1:] == expected
    assert runner.run("cmd", expected).argv[1:] == expected
