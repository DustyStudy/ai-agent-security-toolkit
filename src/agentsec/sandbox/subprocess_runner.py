"""Run external commands for an agent without a shell and with a narrow blast radius.

**Not an OS sandbox.** This removes the shell (no injection through
metacharacters), restricts *which* binaries and arguments are allowed, scrubs
the environment, bounds runtime and output, and pins the working directory. It
does not stop an allowed binary from doing something harmful within its own
capabilities. For untrusted code execution use a container / gVisor /
Firecracker / seccomp boundary and treat this as an additional layer inside it.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess  # noqa: S404 - the point of this module is to constrain subprocess use
import threading
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
    # Option allowlist. None leaves options unchecked (the pre-0.3 behaviour). A list
    # means every argument that starts with "-" must be one of these flags, either
    # exactly or as "--flag=value". Include "--" to let a caller end option parsing;
    # arguments after it are positional and are not checked as options.
    allowed_options: list[str] | None = None


def _is_option_like(arg: str) -> bool:
    # A lone "-" conventionally means stdin/stdout, not an option.
    return arg.startswith("-") and arg != "-"


def _option_allowed(arg: str, allowed: list[str]) -> bool:
    if arg in allowed:
        return True
    # "--flag=value" is accepted when "--flag" is listed. Short options with an
    # attached value ("-ofile") are not split: list them exactly or not at all.
    if arg.startswith("--") and "=" in arg:
        return arg.split("=", 1)[0] in allowed
    return False


def check_options(args: list[str], rule: ExecRule) -> None:
    """Refuse option-like arguments the rule does not allow.

    Without this, a value the agent meant as data (a git ref, a file name, a search
    term) that starts with "-" is parsed by the target program as an option. That is
    argument injection: ``git diff --output=/tmp/x`` writes a file instead of naming a
    revision (CVE-2026-97662 in AWS security-agent-mcp-server was this bug).
    """
    if rule.allowed_options is None:
        return
    # allowed_subcommands already pins the first argument to an exact value.
    start = 1 if rule.allowed_subcommands is not None else 0
    for a in args[start:]:
        if a == "--" and "--" in rule.allowed_options:
            return
        if _is_option_like(a) and not _option_allowed(a, rule.allowed_options):
            raise CommandDenied(f"option {a!r} is not in allowed_options")


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
            if rule.allowed_options is not None and not all(
                isinstance(o, str) and _is_option_like(o) and "=" not in o
                for o in rule.allowed_options
            ):
                raise ValueError(
                    f"allowed_options for {alias!r} must be flags starting with '-' and "
                    "without '=' (values are allowed with --flag=value automatically)"
                )
            self._resolved[alias] = (os.path.realpath(path), rule)
        self.cwd_roots = list(cwd_roots)
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes
        self._env = dict(env or {})

    def _run_bounded(self, argv: list[str], workdir: str) -> tuple[bytes, bytes, int, bool, bool]:
        """Run ``argv`` and read its output incrementally, stopping the process at the cap.

        ``subprocess.run(capture_output=True)`` buffers everything the child writes and only
        then lets us truncate it, so a command that prints gigabytes exhausts the host's memory
        before ``max_output_bytes`` is ever consulted.
        """
        limit = self.max_output_bytes
        proc = subprocess.Popen(  # noqa: S603 - argv list, shell=False, allowlisted binary
            argv,
            cwd=workdir,
            env=self._env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        buffers = {"out": bytearray(), "err": bytearray()}
        overflow = threading.Event()

        def pump(stream: object, key: str) -> None:
            buf = buffers[key]
            read = stream.read1  # type: ignore[attr-defined]
            while True:
                chunk = read(65536)
                if not chunk:
                    return
                room = limit + 1 - len(buf)
                if room > 0:
                    buf.extend(chunk[:room])
                if len(buf) > limit:
                    overflow.set()
                    proc.kill()  # stop the producer; keep draining until the pipe closes

        threads = [
            threading.Thread(target=pump, args=(proc.stdout, "out"), daemon=True),
            threading.Thread(target=pump, args=(proc.stderr, "err"), daemon=True),
        ]
        for t in threads:
            t.start()
        timed_out = False
        try:
            proc.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            proc.wait()
        for t in threads:
            t.join(timeout=5)
        code = -1 if timed_out else proc.returncode
        return bytes(buffers["out"]), bytes(buffers["err"]), code, timed_out, overflow.is_set()

    async def arun(
        self, alias: str, args: Sequence[str] = (), *, cwd: str | None = None
    ) -> CommandResult:
        """Async :meth:`run`: same validation and limits, executed in a worker thread."""
        return await asyncio.to_thread(self.run, alias, args, cwd=cwd)

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
        check_options(args, rule)

        ok, workdir = path_within_roots(cwd or self.cwd_roots[0], self.cwd_roots)
        if not ok:
            raise CommandDenied("working directory escapes allowed roots")

        argv = [exe, *args]
        out, err, code, timed_out, overflow = self._run_bounded(argv, workdir)

        limit = self.max_output_bytes
        truncated = overflow or len(out) > limit or len(err) > limit
        return CommandResult(
            argv=argv,
            returncode=code,
            stdout=out[:limit].decode("utf-8", "replace"),
            stderr=err[:limit].decode("utf-8", "replace"),
            truncated=truncated,
            timed_out=timed_out,
        )
