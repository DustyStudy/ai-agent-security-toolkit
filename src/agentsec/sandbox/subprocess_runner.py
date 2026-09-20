"""Run external commands for an agent without a shell and with a narrow blast radius.

**Not an OS sandbox.** This removes the shell (no injection through
metacharacters), restricts *which* binaries and arguments are allowed, scrubs
the environment, bounds runtime and output, and pins the working directory. It
does not stop an allowed binary from doing something harmful within its own
capabilities. For untrusted code execution use a container / gVisor /
Firecracker / seccomp boundary and treat this as an additional layer inside it.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # noqa: S404 - the point of this module is to constrain subprocess use
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from agentsec.sandbox.validators import path_within_roots


class CommandDenied(PermissionError):
    pass


@dataclass
class ExecRule:
    """Constraints for one allowed executable."""

    executable: str  # resolved with PATH lookup at construction time
    allowed_subcommands: list[str] | None = None  # first argument must be one of these
    arg_pattern: str | None = None  # every argument must fully match this regex
    deny_args: list[str] = field(default_factory=list)  # exact-match forbidden arguments
    max_args: int = 16


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    truncated: bool
    timed_out: bool


class SafeCommandRunner:
    def __init__(
        self,
        rules: Mapping[str, ExecRule],
        *,
        cwd_roots: Sequence[str],
        timeout: float = 10.0,
        max_output_bytes: int = 64_000,
        env: Mapping[str, str] | None = None,
    ) -> None:
        if not cwd_roots:
            raise ValueError("cwd_roots must not be empty")
        self._resolved: dict[str, tuple[str, ExecRule]] = {}
        for alias, rule in rules.items():
            path = shutil.which(rule.executable)
            if path is None:
                raise ValueError(f"executable {rule.executable!r} for {alias!r} not found")
            self._resolved[alias] = (os.path.realpath(path), rule)
        self.cwd_roots = list(cwd_roots)
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes
        self._env = dict(env or {})

    def run(self, alias: str, args: Sequence[str] = (), *, cwd: str | None = None) -> CommandResult:
        if alias not in self._resolved:
            raise CommandDenied(f"command {alias!r} is not allowlisted")
        exe, rule = self._resolved[alias]
        args = list(args)
        if len(args) > rule.max_args:
            raise CommandDenied(f"too many arguments (max {rule.max_args})")
        if not all(isinstance(a, str) and "\x00" not in a for a in args):
            raise CommandDenied("arguments must be NUL-free strings")
        if rule.allowed_subcommands is not None and (
            not args or args[0] not in rule.allowed_subcommands
        ):
            raise CommandDenied(f"subcommand must be one of {rule.allowed_subcommands}")
        for a in args:
            if a in rule.deny_args:
                raise CommandDenied(f"argument {a!r} is denied")
            if rule.arg_pattern is not None and not re.fullmatch(rule.arg_pattern, a):
                raise CommandDenied(f"argument {a!r} does not match allowed pattern")

        ok, workdir = path_within_roots(cwd or self.cwd_roots[0], self.cwd_roots)
        if not ok:
            raise CommandDenied("working directory escapes allowed roots")

        argv = [exe, *args]
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, shell=False, allowlisted binary
                argv,
                cwd=workdir,
                env=self._env,
                capture_output=True,
                timeout=self.timeout,
                shell=False,
                check=False,
            )
            out, err, code, timed_out = proc.stdout, proc.stderr, proc.returncode, False
        except subprocess.TimeoutExpired as exc:
            out, err, code, timed_out = exc.stdout or b"", exc.stderr or b"", -1, True

        limit = self.max_output_bytes
        truncated = len(out) > limit or len(err) > limit
        return CommandResult(
            argv=argv,
            returncode=code,
            stdout=out[:limit].decode("utf-8", "replace"),
            stderr=err[:limit].decode("utf-8", "replace"),
            truncated=truncated,
            timed_out=timed_out,
        )
