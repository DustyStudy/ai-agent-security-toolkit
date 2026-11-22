# Sandbox: async use, framework adapters and the command runner

Detail for [`agentsec.sandbox`](../src/agentsec/sandbox) and [`agentsec.integrations`](../src/agentsec/integrations). The [README](../README.md#2-constrain-tool-calls) has the short version.

## Async applications

Every entry point has an async form, so the guard fits FastAPI, the MCP Python SDK, LangGraph and other `asyncio` code without blocking the event loop:

```python
guard = ToolGuard(Policy.from_yaml("policy.yaml"), approver=ask_a_human)   # approver may be sync or async
session = Session()

search = guard.awrap("search_docs", search_docs, session)   # search_docs may be async def or a plain function
await search(query="Q3 revenue")

results = await arun_anthropic_tool_uses(guard, session, blocks, registry)   # or arun_openai_tool_calls
out = await runner.arun("git", ["status"])                    # SafeCommandRunner
```

- `aauthorize`, `aexecute` and `awrap` mirror `authorize`, `execute` and `wrap`, with the same policy, taint, limit and audit behavior.
- Plain (non-`async`) tools and approvers run in a worker thread so a blocking tool or a human-approval prompt cannot stall the loop. DNS-resolving URL rules are evaluated off the loop too.
- Limits stay exact under concurrent tasks (`asyncio.gather` over many calls cannot exceed `max_calls`), and the session is tainted even if an untrusted-content tool raises or its task is cancelled.
- An approver must return a `bool`: only `True` approves. Any other answer (`"n"` from `input()`, `1`, an object) refuses the call, and so does an approver that raises or times out. Each refusal is audited.
- The sync API **fails closed** on async pieces instead of misreading them: an `async def` approver used with `authorize()` is refused, and `execute()` on an `async def` tool raises `TypeError` instead of returning a coroutine.
- `arun_*_tool_uses` run one model turn's calls in the order given, so taint from a read applies to a later side-effecting call in the same turn. For concurrency, call `aexecute` yourself.
- A worker thread cannot be interrupted: if a task is cancelled while a plain tool runs, the tool may still finish. Prefer `async def` tools where cancellation matters.
- `AuditLogger` / `FileSink` do a small synchronous append. For latency-sensitive loops, use a `CallbackSink` that hands records to a queue.

Complete loop: [`examples/async_agent_loop.py`](../examples/async_agent_loop.py).

## LangChain and LangGraph

`guard_tool` / `guard_tools` return tools with the same name, description and argument schema whose every call goes through the guard first, for both `invoke` and `ainvoke`:

```python
from agentsec.integrations.langchain import guard_tools
from langgraph.prebuilt import create_react_agent

agent = create_react_agent(model, guard_tools([search_docs, send_email], guard, session))
```

A refused call comes back to the model as readable text ("Tool call refused by security policy: ...") instead of crashing the run, and the original tool never runs. The caller's run configuration (callbacks, tags) is passed through to the original tool. `pip install "ai-agent-security-toolkit[langchain]"`.

The guard sees the arguments after LangChain's own validation, including defaults LangChain fills in, so the policy must allow every argument in the tool's schema. Tools with injected arguments (`InjectedState`, `InjectedToolCallId`) and tool artifacts (`content_and_artifact`) are not supported. Tested against real `langchain-core` and a LangGraph `ToolNode` in CI; not run against a live model.

## MCP servers

MCP servers describe their own tools and return content your model then reads, so both are attacker-influenceable: **tool poisoning** hides instructions in a description or parameter schema, and a **rug pull** swaps a reviewed description later. `GuardedMCPClient` wraps an MCP client (the SDK's `Client` or `ClientSession`) so the guard sits in front of it:

```python
from agentsec.integrations.mcp import GuardedMCPClient, ToolPins, result_text

pins = ToolPins.load("mcp-pins.json")           # reviewed fingerprints; ToolPins() to start fresh
client = GuardedMCPClient(mcp_client, guard, session, pins=pins)

tools = await client.list_tools()               # hides tools outside the policy, changed or suspicious ones
result = await client.call_tool("lookup", {"customer": "acme"})   # allowlist, argument checks, audit
text = result_text(result)                      # untrusted: pass through middleware.screen_input
pins.save("mcp-pins.json")
```

- `list_tools` shows the model only tools the policy allows, drops tools whose definition changed since it was pinned, and drops tools whose name, description or parameter schema looks like an injection (`scan_tool_definitions`). A dropped tool cannot be called through the wrapper. Findings are collected in `client.findings` and written to the audit log; `on_finding="raise"` raises `ToolManifestError` instead.
- `call_tool` goes through `ToolGuard.aexecute`, and the session is tainted afterward because MCP results are third-party content (`taint_results=False` to opt out). A call the guard refuses never reaches the server and does not taint.
- Pins are trust-on-first-use by default (`pin_new=False` treats unpinned tools as findings). Save them where the agent cannot write, and review a tool before pinning it. A tool that fails the scan is never pinned.
- Attributes other than `list_tools` and `call_tool` are deliberately **not** forwarded, so the wrapper cannot be used to reach an unguarded call.
- A tool can only be called after it passed the checks in a `list_tools()` listing, with or without pins: otherwise its definition was never scanned.
- To guard tools you *serve*, wrap them: `server.tool()(guard.awrap("lookup", lookup, session))` (the signature is preserved for the schema). Without a session the wrapper uses the guard's process-wide `default_session` and warns: every client then shares one taint flag and one set of call counts.

The adapter imports nothing from `mcp`. It uses only `list_tools()` and `call_tool()` and reads both the 1.x (`inputSchema`, `isError`) and 2.x (`input_schema`, `is_error`) spellings. It is tested against fakes of both shapes and, in CI, against the real SDK 2.x over its in-memory transport (`pip install "ai-agent-security-toolkit[mcp]"`). It has not been run against a remote MCP server. The scan is a heuristic tripwire, so pinning and human review of tool descriptions still matter.

## Claude Code hook

The gateway enforces policy on the calls it makes. A coding agent's shell, file and fetch tools run on the developer's machine and never pass through it, so text planted in a tool result (a forged error event, a fetched web page) can lead straight to a shell command. `agentsec hook` puts the same policy and taint in front of those tools, as a Claude Code `PreToolUse` hook:

```json
{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{
  "type": "command", "onFailure": "block",
  "command": "agentsec hook --policy /etc/agentsec/claude-code.policy.yaml --state-dir /var/lib/agentsec/hook --audit /var/log/agentsec/hook.jsonl"
}]}]}}
```

Start from [`examples/claude-code.policy.yaml`](../examples/claude-code.policy.yaml). Tool names are Claude Code's (`Bash`, `Read`, `Edit`, `Write`, `WebFetch`, `mcp__<server>__<tool>`), and arguments are the tool's input fields.

| Policy result | What the hook does |
|---|---|
| Allowed | Prints nothing. Claude Code's own permission rules and prompts still apply; the hook never approves a call for the user. |
| Denied (not in the policy, a bad argument, a limit, taint with `action: deny`) | Exit code 2: the call is blocked and the model is shown the reason. |
| Needs approval (`require_approval`, or taint with `action: approve`) | Answers `ask`, so the human decides in Claude Code's permission prompt, with the reason. With `--block-approvals`: exit code 2, as for a denial. |

- **Register it on every tool, failing closed.** The registration above is the hardened one. A matcher narrower than `"*"` (`"Bash"`), or an `if` filter on the handler, means the hook never sees the other tools: `Read`, `WebFetch` and every MCP tool then run with no policy and no taint. Without `"onFailure": "block"` (Claude Code 2.1.295 or later) a hook that times out or crashes lets the call run. `agentsec scan-config` reports the first as `unguarded` and the second as `failopen`, on the settings file that registers the hook. It recognises a handler whose own command line is `agentsec hook`, not a wrapper script that runs it, and a `"disableAllHooks": true` in the same settings file is reported as `unguarded`. A hook switched off in another file is not seen.
- **`--block-approvals`: when `ask` is not enough.** Add it to the hook command when nobody can answer a prompt (CI, `claude -p`), or when a `permissions.deny` rule must hold on a Claude Code version you have not checked. It was reported (anthropics/claude-code issue 39344) that a hook answering `ask` made Claude Code skip a matching `permissions.deny` rule. The hooks documentation now says deny and ask rules "are still evaluated regardless of what the hook returns"; we have not tested either claim against a build. With the flag a call that needs approval is blocked and not counted, so the only way through is to change the policy.

- **What taints is the policy's choice.** The example marks web fetches, web searches, MCP tools and the shell `returns_untrusted`, and not `Read`: an agent reads files first thing, so every session would be tainted. A planted file in a repository you did not write is therefore not covered until you set `returns_untrusted: true` on `Read`. The shell is marked because its output can carry third-party text (`curl`, `gh`, `git log`); the cost is that after the first shell command every later shell command, file write and fetch asks. `Edit` and `Write` are `side_effects`, and files that steer the agent or run code (`CLAUDE.md`, `AGENTS.md`, `.mcp.json`, `.claude/`, `.vscode/`, `.husky/`, `.github/workflows/`, `.git/`) are denied outright, since a planted one acts in a later, untainted session.
- **Taint.** A call to a tool marked `returns_untrusted` taints the session when the hook lets it through, not when it returns. One hook event is then enough, and a missing `PostToolUse` registration cannot turn taint off. A call the human then declines has still tainted the session. To clear it, start a new session.
- **State.** Every hook run is a new process, so taint and call counts are kept in one append-only file per session under `--state-dir`. Runs are serialised with a file lock, so parallel tool calls cannot pass a call limit together or fork the audit chain.
- **Fails closed, if you register it that way.** A missing or invalid policy, unreadable input and corrupt state all exit 2. So does an input that names a tool under any event name but `PreToolUse` (missing, misspelt, unknown); only `PostToolUse` and `PostToolUseFailure` are ignored. A URL host that does not resolve within five seconds is denied, and the lookup runs before the lock is taken. Claude Code lets a call through when a hook times out or exits with any other code, which is why the registration above sets `"onFailure": "block"`.

Limits:

- The agent runs as the same user as the hook. A shell command can delete the state file or edit the policy, and a test asserts that deleting the state clears the taint. Keep the policy, the state directory and the settings file that registers the hook outside every path the policy lets the agent write, mark shell access `side_effects`, and pin the registration with `agentsec scan-config`. A managed settings file the user cannot edit is stronger.
- Path rules are checked when the hook runs; the tool opens the path afterwards, so the race described under [Path arguments](#path-arguments) applies and the resolved path is not handed to the tool.
- A shell command is one string. The policy can bound and pattern-match it, but cannot tell what it does; taint, not `deny_patterns`, is the control for the shell.
- Run once, by hand, inside Claude Code 2.1.317 in headless mode (`claude -p`), with a test policy that marks `Read` untrusted. An allowed shell command ran; an unlisted tool was blocked and the model was shown the reason; after a file read the next shell command got `ask`, which headless mode refuses because nobody is there to answer; and a subagent's file read tainted the parent, because a subagent's calls carry the parent's `session_id`. The audit chain verified across the four sessions. The interactive permission prompt that `ask` raises was not exercised, and CI does not run Claude Code. Other agents' hook formats (Cursor, Codex) are not supported.

## Command runner

`SafeCommandRunner` runs external commands with no shell, an executable/argument allowlist, a scrubbed environment, a pinned working directory, a timeout, and an output cap. It is **not** an OS sandbox. Put it inside a container or microVM for untrusted code.

No shell does not mean no injection. A value the agent passes as data (a git ref, a file name, a search term) that starts with `-` is read by the program as an option, so `git diff --output=/tmp/x` writes a file instead of naming a revision. That is how [CVE-2026-97662](https://aws.amazon.com/security/security-bulletins/2026-121-aws/) in AWS `security-agent-mcp-server` worked. Set `allowed_options` on every `ExecRule` that takes agent-supplied arguments:

```python
runner = SafeCommandRunner(
    {"git": ExecRule(executable="git", allowed_subcommands=["diff"], allowed_options=["--stat", "--"])},
    cwd_roots=["/srv/repo"],
)
runner.run("git", ["diff", "--stat", "--", agent_supplied_ref])   # ref is positional after "--"
runner.run("git", ["diff", "--output=/tmp/x"])                     # CommandDenied
```

Every argument that starts with `-` must then be a listed flag, exactly or as `--flag=value`. Short options with an attached value (`-ofile`) and look-alikes (`--stats`) are refused. List `--` to let a caller end option parsing; arguments after it are not checked as options, so put `--` in your own argv before untrusted values. A `--` that comes right after an option does not end the check: the program may read it as that option's value (Python reads `-W -- -c code` as `-W` with the value `--`, then `-c`), so the arguments after it are still checked as options. Put a positional argument or nothing before `--` when a value after it starts with `-`. Leaving `allowed_options` unset keeps the old behavior (options unchecked). The check knows the POSIX `-` convention only; Windows programs that take `/flag` options need an `arg_pattern` or `deny_args` instead. `deny_args` is only a backstop: it also catches a denied short flag inside a cluster (`-Ic` for `-c`), but a list of what is forbidden cannot anticipate every spelling a program accepts.

**Installs from the lock file only.** An agent that runs `pip install <name>` installs whatever a README or a tool result named. `locked_install_rules` returns rules that allow one exact command per package manager and nothing else:

```python
from agentsec.sandbox import SafeCommandRunner, locked_install_rules

runner = SafeCommandRunner(
    locked_install_rules(
        ["pip", "uv"], requirements="requirements/requirements-runtime.txt", cwd="/srv/repo"
    ),
    cwd_roots=["/srv/repo"],
    inherit_env=["PATH"],
)
runner.run("pip-install")                 # pip install --require-hashes -r requirements/requirements-runtime.txt
runner.run("uv-install")                  # uv sync --locked
runner.run("pip-install", ["install", "left-pad"])   # CommandDenied
```

| Tool | The one command allowed |
|---|---|
| `pip` | `pip install --require-hashes -r <requirements>` |
| `uv` | `uv sync --locked` |
| `npm` | `npm ci --ignore-scripts` |
| `pnpm` | `pnpm install --frozen-lockfile --ignore-scripts` |

It is built on `ExecRule(exact_args=[[...]])`, which requires the whole argument list to equal one of the listed ones; use it directly for any command with a single safe spelling. This pins what is installed to the lock file; it does not vouch for the lock file, so review changes to it. `pip` and `uv` still run build scripts of source distributions the lock file names. The preset leaves out `pip install --only-binary :all:` and `uv sync --no-build` because both fail on a lock file that names a package published only as a source distribution, and `uv sync --no-build` still builds the project itself; add them in your own `exact_args` rule if every dependency has a wheel. On Windows `npm` is a batch file (`npm.cmd`), which the runner refuses, and so is the `pnpm.cmd` shim npm creates; pnpm 12 also ships a native `pnpm.exe`, which the runner starts when that is what `pnpm` resolves to on `PATH`.

What was checked: every flag was read in the tool's own documentation (pip.pypa.io, docs.astral.sh, docs.npmjs.com, pnpm.io) and, for the three tools installed on the development machine, in its `--help`: pip 26.2.1, uv 0.12.19 and npm 11.19.1. `uv sync --locked` was also dry-run (`--dry-run`) against a current, a stale and a missing `uv.lock`, and refused the last two; `--frozen` accepts a stale one, which is why the preset does not use it.

What was run: each command once against the real tool on Windows 11 (build 26300), in a throwaway project whose lock file names two small packages (`six` and `idna` for pip and uv; `is-number`, `ms` and a local tarball with `preinstall` and `postinstall` scripts for npm and pnpm). pip 26.3, uv 0.12.19 and pnpm 12.21.0 (its native `pnpm.exe`) were started by `SafeCommandRunner` with only `PATH` inherited and `timeout=180`; npm 11.19.1 on Node.js 24.22.1 is a batch file there, so the same argument list was run directly. All four installed from the lock file. All four refused with a non-zero exit once the manifest named a package the lock file did not (for pip, a requirement with no hash). With `--ignore-scripts`, neither the project's nor the dependency's install scripts ran under npm or pnpm; without it npm ran both and pnpm ran the project's. `["install", "left-pad"]` was denied for the three the runner started. Not run: Linux or macOS, npm through the runner, other versions of the tools, a lock file that names a source distribution or a native build, and a private index. The runner's default `timeout` is 10 seconds, so set a longer one for a real lock file. The tests check the rules and the denial logic, not the package managers.

The child gets an empty environment unless you pass `env`. Tools that need a few host variables (git on Windows needs `PATH` and `SystemRoot`) can name them: `SafeCommandRunner(..., inherit_env=["PATH", "SystemRoot"])`. Nothing is inherited by default, so secrets in the agent's environment never reach the command.

## Path arguments

A `path` argument is resolved (symlinks and `..` included) and must sit under one of its `roots`. `execute`, `aexecute` and everything built on them pass the tool that resolved path, re-checked just before the call, not the raw string. A symlink retargeted after authorization therefore cannot redirect the tool.

A race remains: someone who can write inside a root can still replace a directory on the resolved path with a symlink between that last check and the tool's `open()`. Closing it needs `openat`-style, no-follow opens in the tool itself. If the agent shares a writable directory with an attacker, keep that directory out of the roots or isolate the tool at the OS level.

`deny_patterns` on a path match case-insensitively, because Windows and macOS file systems ignore case.
