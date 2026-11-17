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
import signal
import subprocess  # noqa: S404 - the point of this module is to constrain subprocess use
import sys
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
    # Forbidden arguments. An option also matches its other spellings: "--output" denies
    # "--output=x" and GNU abbreviations like "--outp"; "-c" denies an attached "-cvalue"
    # and a cluster such as "-Ic". This is a backstop; allowed_options is the real control.
    deny_args: list[str] = field(default_factory=list)
    max_args: int = 16
    # Option allowlist. None leaves options unchecked (the pre-0.3 behaviour). A list
    # means every argument that starts with "-" must be one of these flags, either
    # exactly or as "--flag=value". Include "--" to let a caller end option parsing;
    # arguments after it are positional and are not checked as options, unless the "--"
    # comes right after an option (it may then be that option's value).
    allowed_options: list[str] | None = None


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    """Kill ``proc`` and the processes it started, not just the direct child."""
    if sys.platform == "win32":
        # shortcut: taskkill /T walks the tree from the parent's PID, so grandchildren orphaned
        # after the parent exited survive; use a Job Object if that matters on Windows.
        if proc.poll() is None:
            # Full path: a bare "taskkill" would be looked up on PATH and the cwd.
            taskkill = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
            subprocess.run(  # noqa: S603 - fixed argv, system binary
                [os.path.join(taskkill, "taskkill.exe"), "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)  # the child leads its own session/group
        except (ProcessLookupError, PermissionError):
            pass  # group already gone
    if proc.poll() is None:
        proc.kill()


def _denied_spelling(arg: str, denied: str) -> bool:
    """True if ``arg`` is ``denied`` or a spelling a program would parse as that option."""
    if arg == denied:
        return True
    if denied.startswith("--") and arg.startswith("--"):
        name = arg.split("=", 1)[0]
        # getopt_long accepts any unambiguous prefix, so "--outp" means "--output".
        return len(name) > 2 and denied.startswith(name)
    if len(denied) == 2 and denied[0] == "-" and denied[1] != "-":
        if not arg.startswith("-") or arg.startswith("--"):
            return False
        if arg.startswith(denied):  # "-cprint(1)"
            return True
        # getopt clusters short flags ("-Ic" is "-I -c") and any character can be an option
        # letter ("-?c"). Searching the whole argument over-matches when an earlier flag takes
        # an attached value ("-ofile.c" for a denied "-c"); that fails closed.
        return denied[1] in arg[1:]
    return False


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
    after_option = False
    for a in args[start:]:
        if a == "--" and "--" in rule.allowed_options:
            if not after_option:
                return
            # Right after an option, "--" may be that option's value, not the end of options:
            # Python reads "-W -- -c code" as -W with the value "--", then -c. The rule does
            # not say which options take a value, so this "--" ends nothing and the arguments
            # after it are still checked.
            after_option = False
            continue
        after_option = _is_option_like(a)
        if after_option and not _option_allowed(a, rule.allowed_options):
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
        inherit_env: Sequence[str] = (),
    ) -> None:
        """``env`` is the child's whole environment (empty by default). ``inherit_env`` names
        variables to copy from this process, e.g. ``("PATH", "SystemRoot")`` for tools such as
        git on Windows that fail without them. Names are explicit: nothing is inherited by
        default, so secrets in this process's environment never reach the command."""
        if not cwd_roots:
            raise ValueError("cwd_roots must not be empty")
        self._resolved: dict[str, tuple[str, ExecRule]] = {}
        for alias, rule in rules.items():
            path = shutil.which(rule.executable)
            if path is None:
                raise ValueError(f"executable {rule.executable!r} for {alias!r} not found")
            # Check the canonical path that is actually run: realpath turns "npm.cmd." or
            # "npm.cmd " into "npm.cmd" on Windows.
            path = os.path.realpath(path)
            if os.name == "nt" and os.path.splitext(path)[1].lower() in {".bat", ".cmd"}:
                # Windows runs batch files through cmd.exe even with shell=False, which
                # re-parses the arguments ("BatBadBut"): `x&ver` would run `ver`.
                raise ValueError(
                    f"executable {rule.executable!r} for {alias!r} resolves to a batch file "
                    f"({path}); batch files run through cmd.exe and cannot be argument-safe"
                )
            if rule.allowed_options is not None and not all(
                isinstance(o, str) and _is_option_like(o) and "=" not in o
                for o in rule.allowed_options
            ):
                raise ValueError(
                    f"allowed_options for {alias!r} must be flags starting with '-' and "
                    "without '=' (values are allowed with --flag=value automatically)"
                )
            self._resolved[alias] = (path, rule)
        self.cwd_roots = list(cwd_roots)
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes
        if isinstance(inherit_env, str):
            raise TypeError("inherit_env must be a sequence of names, not a string")
        self._env = {k: os.environ[k] for k in inherit_env if k in os.environ}
        self._env.update(env or {})

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
            # Never hand the child our stdin: under an MCP stdio server it is the JSON-RPC
            # channel, and a command that reads stdin would steal protocol frames.
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            # Own process group, so a timeout or overflow can kill what the command spawned.
            start_new_session=sys.platform != "win32",
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
                    _kill_tree(proc)  # stop the producers; keep draining until the pipe closes

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
        # Also after a normal exit: background children it left behind must not outlive the
        # call or hold the output pipes open past the timeout.
        _kill_tree(proc)
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
            if any(_denied_spelling(a, d) for d in rule.deny_args):
                raise CommandDenied(f"argument {a!r} is denied")
            if rule.arg_pattern is not None and not re.fullmatch(rule.arg_pattern, a):
                raise CommandDenied(f"argument {a!r} does not match allowed pattern")
        check_options(args, rule)

        # A relative cwd is anchored to the first root here; safe because Popen gets the
        # resolved workdir, not the raw string.
        base = os.path.realpath(self.cwd_roots[0])
        ok, workdir = path_within_roots(os.path.join(base, cwd or ""), self.cwd_roots)
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
