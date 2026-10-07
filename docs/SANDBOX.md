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
- Plain (non-`async`) tools run in a worker thread so a blocking tool cannot stall the loop. DNS-resolving URL rules are evaluated off the loop too.
- Limits stay exact under concurrent tasks (`asyncio.gather` over many calls cannot exceed `max_calls`), and the session is tainted even if an untrusted-content tool raises or its task is cancelled.
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
- To guard tools you *serve*, wrap them: `server.tool()(guard.awrap("lookup", lookup))` (the signature is preserved for the schema).

The adapter imports nothing from `mcp`. It uses only `list_tools()` and `call_tool()` and reads both the 1.x (`inputSchema`, `isError`) and 2.x (`input_schema`, `is_error`) spellings. It is tested against fakes of both shapes and, in CI, against the real SDK 2.x over its in-memory transport (`pip install "ai-agent-security-toolkit[mcp]"`). It has not been run against a remote MCP server. The scan is a heuristic tripwire, so pinning and human review of tool descriptions still matter.

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

Every argument that starts with `-` must then be a listed flag, exactly or as `--flag=value`. Short options with an attached value (`-ofile`) and look-alikes (`--stats`) are refused. List `--` to let a caller end option parsing; arguments after it are not checked as options, so put `--` in your own argv before untrusted values. Leaving `allowed_options` unset keeps the old behavior (options unchecked). The check knows the POSIX `-` convention only; Windows programs that take `/flag` options need an `arg_pattern` or `deny_args` instead.
