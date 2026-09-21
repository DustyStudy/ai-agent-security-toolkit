# ai-agent-security-toolkit

[![CI](https://github.com/DustyStudy/ai-agent-security-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/DustyStudy/ai-agent-security-toolkit/actions/workflows/ci.yml)
[![CodeQL](https://github.com/DustyStudy/ai-agent-security-toolkit/actions/workflows/codeql.yml/badge.svg)](https://github.com/DustyStudy/ai-agent-security-toolkit/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Fuzz, contain, validate, and audit LLM agents.** Four pieces that fit together:

| | Module | What it does |
|---|---|---|
| 1 | [`agentsec.fuzzer`](src/agentsec/fuzzer) | Prompt-injection test harness. 25 payloads x 10 obfuscations x 2 delivery modes = 500 cases, mechanically scored with canaries (no judge model). Emits JSON/Markdown and gates CI on attack-success rate. |
| 2 | [`agentsec.sandbox`](src/agentsec/sandbox) | Deny-by-default tool allowlist for agent frameworks: per-argument validation, path confinement, SSRF-safe URL checks, rate limits, human approval, and **taint tracking** that blocks side-effecting tools after untrusted content is read. Plus a no-shell subprocess runner. |
| 3 | [`agentsec.middleware`](src/agentsec/middleware) | Output validation (secrets/PII, markdown-image exfiltration, XSS markup, JSON-schema, protected strings) and a **hash-chained, tamper-evident audit log** with secret redaction. |
| 4 | [`agentsec.threatmodel`](src/agentsec/threatmodel) | **STRIDE-for-agents** threat catalog (25 threats mapped to the OWASP LLM Top 10 2025, the OWASP Top 10 for Agentic Applications 2026 and MITRE ATLAS) and a generator that turns a YAML system description into a threat model with data-flow diagram, threat register, and verification plan. |

```mermaid
flowchart LR
  U[User / untrusted content] --> S[screen_input<br/>scan + taint + spotlight]
  S --> M[(LLM)]
  M -->|tool_use| G[ToolGuard<br/>allowlist + args + taint + approval]
  G --> T[Tools]
  T -->|results = untrusted| S
  M -->|text| O[screen_output<br/>secrets, exfil links, markup]
  O --> R[Response]
  S -.-> A[(Audit log<br/>hash chain)]
  G -.-> A
  O -.-> A
  F[Fuzzer] -. measures .-> S & G & O
```

## Why this exists

A prompt-injection filter will be bypassed; that is a property of the problem, not of any one filter. What you can control is **blast radius**: what the agent is *allowed* to do once its instructions have been hijacked, what leaves the system, and whether you can reconstruct what happened. This toolkit is built around that idea, and around **measuring** it rather than asserting it.

The reference results below make the point. They come from the built-in simulator (see [Honest limitations](#honest-limitations)), not from a real model:

| Target | Attack-success rate | tool_misuse | exfiltration | prompt_leak | canary echo |
|---|---:|---:|---:|---:|---:|
| `builtin:naive` (obeys any injection) | **100%** | 100% | 100% | 100% | 100% |
| `builtin:guarded-noscanner` (policy + output guard only) | **60%** | 0% | 0% | 0% | 100% |
| `builtin:guarded` (+ heuristic scanner) | **34%** | 0% | 0% | 0% | 57% |

Read it this way: tool policy and output validation reduce the *dangerous* outcomes (side effects, exfiltration, secret leaks) to zero **even when the model is fully compromised**. Merely getting the model to say something (canary echo) cannot be stopped by those layers, and the pattern-matching scanner only catches part of it. Base64, ROT13, homoglyphs, leetspeak and non-English variants slip past it, while zero-width and Unicode-tag smuggling are caught. [Full sample report](docs/sample-fuzz-report.md).

## Install

```bash
pip install -e ".[dev]"          # from a clone
pip install -e ".[anthropic]"    # optional: fuzz Claude models directly
```

Python 3.11+. Runtime dependencies: `PyYAML`, `jsonschema`.

## 1. Fuzz an agent

```bash
# self-check against the built-in simulators
agentsec fuzz --target builtin:guarded --md report.md --json report.json

# your own agent, as a Python callable: def my_agent(prompt: str) -> str
agentsec fuzz --target mypkg.agent:respond --max-asr 0.10

# an HTTP endpoint fronting your agent
agentsec fuzz --target https://staging.example.com/agent/chat

# a Claude model directly (needs ANTHROPIC_API_KEY)
agentsec fuzz --target anthropic:claude-sonnet-5 --max-cases 100
```

Each case plants a random **canary** (split in two so a model that merely *quotes* the injection does not count), a **system-prompt secret**, and a set of **forbidden tools**. An attack succeeds if the response contains the canary or the secret, calls a forbidden tool, references the attacker domain in tool arguments, or renders a markdown/HTML image or link to the attacker domain. Results break down by goal, category, obfuscation, and delivery (payload typed by the user vs. hidden in a retrieved document).

`--max-asr 0.05` makes the command exit `1` above 5%, so it can gate a release. Add `--categories tool_misuse,exfiltration,prompt_leak --max-asr 0` to gate specifically on containment.

**CI reports.** `--sarif report.sarif` writes SARIF 2.1.0 for GitHub code scanning and `--junit report.xml` writes JUnit XML for any CI test UI. Successful attacks become findings (`error` for tool misuse, exfiltration and prompt leak; `warning` for instruction-following), each tagged with its OWASP LLM Top 10 (2025) id. Fuzz findings have no source location, so pass `--sarif-artifact path/to/agent.py` (repo-relative) to say which file the alerts attach to.

```yaml
# .github/workflows/agent-fuzz.yml (excerpt)
permissions: {contents: read, security-events: write}
steps:
  - run: agentsec fuzz --target mypkg.agent:respond --max-asr 0.10 --quiet
         --sarif agentsec.sarif --sarif-artifact src/mypkg/agent.py
  - uses: github/codeql-action/upload-sarif@v4
    if: always()
    with: {sarif_file: agentsec.sarif}
```

Text taken from the target's output is bounded and stripped of control characters before it enters either format. The SARIF output is validated against the official 2.1.0 schema in the tests; it has not been uploaded to GitHub code scanning by this repo's CI.

Targets may be `async def`: `agentsec fuzz --target mypkg.agent:respond` detects a coroutine function and runs it on one reused event loop, and `text_target` / `sync_target` do the same when you call the harness from Python.

For richer targets, pass a callable that accepts an `AttackInput` and returns a `TargetResponse` (with `tool_calls`); see [`targets.py`](src/agentsec/fuzzer/targets.py).

## 2. Constrain tool calls

Policies are data, so they can be reviewed and diffed. Unknown keys are load-time errors and anything unlisted is denied. See [`examples/policy.yaml`](examples/policy.yaml).

```python
from agentsec.sandbox import Policy, ToolGuard, Session

guard = ToolGuard(Policy.from_yaml("policy.yaml"), approver=ask_a_human)
session = Session()

# Wrap a function; the model's arguments are validated before it ever runs.
search = guard.wrap("search_docs", search_docs, session)
search(query="Q3 revenue")                       # allowed; result marks the session tainted
guard.wrap("http_get", http_get, session)(       # ToolDenied: session read untrusted content
    url="https://api.corp.example/x")            # and http_get has side effects
```

What the guard enforces:

- **Default deny.** Tools and arguments not in the policy are refused; extra arguments are refused.
- **Argument constraints.** Type, enum, regex (`pattern`, `deny_patterns`), length, numeric bounds.
- **Paths** are resolved (symlinks and `..` included) and must sit under an allowed root.
- **URLs** must match scheme and host allowlists, reject embedded credentials, and reject private, loopback and link-local targets including `169.254.169.254` and decimal/hex/octal/IPv4-mapped IP forms. `resolve_dns: true` also rejects hostnames that resolve to private ranges. (This narrows DNS-rebinding exposure but does not eliminate it; pin the resolved address at connect time for a full fix.)
- **Taint tracking.** Tools marked `returns_untrusted` taint the session; tools marked `side_effects` are then denied (or routed to approval) for the rest of that session. This breaks the "private data + untrusted content + outbound channel" combination without needing to detect the injection.
- **Human approval** hook, per-tool and per-session call limits, and an audit trail of every request and decision.

Drop-in helpers for the tool-calling wire formats: `run_anthropic_tool_uses` and `run_openai_tool_calls` turn model tool requests into results, with denials returned as error text the model can read. See the complete loop in [`examples/agent_loop.py`](examples/agent_loop.py).

### Async applications

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

Complete loop: [`examples/async_agent_loop.py`](examples/async_agent_loop.py).

### LangChain and LangGraph

`guard_tool` / `guard_tools` return tools with the same name, description and argument schema whose every call goes through the guard first, for both `invoke` and `ainvoke`:

```python
from agentsec.integrations.langchain import guard_tools
from langgraph.prebuilt import create_react_agent

agent = create_react_agent(model, guard_tools([search_docs, send_email], guard, session))
```

A refused call comes back to the model as readable text ("Tool call refused by security policy: ...") instead of crashing the run, and the original tool never runs. The caller's run configuration (callbacks, tags) is passed through to the original tool. `pip install "ai-agent-security-toolkit[langchain]"`.

The guard sees the arguments after LangChain's own validation, including defaults LangChain fills in, so the policy must allow every argument in the tool's schema. Tools with injected arguments (`InjectedState`, `InjectedToolCallId`) and tool artifacts (`content_and_artifact`) are not supported. Tested against real `langchain-core` and a LangGraph `ToolNode` in CI; not run against a live model.

### MCP servers

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

`SafeCommandRunner` runs external commands with no shell, an executable/argument allowlist, a scrubbed environment, a pinned working directory, a timeout, and an output cap. It is **not** an OS sandbox. Put it inside a container or microVM for untrusted code.

## 3. Validate output and keep an audit trail

```python
from agentsec.middleware import AgentMiddleware, AuditLogger, FileSink, InjectionScanner, OutputGuard

audit = AuditLogger(FileSink("audit.jsonl"), actor="support-copilot")
mw = AgentMiddleware(
    guard=guard,
    scanner=InjectionScanner(),
    output_guard=OutputGuard.default(allowed_hosts=["corp.example"], protected=[SYSTEM_PROMPT_CANARY]),
    audit=audit,
)

screen = mw.screen_input(ticket_text, source="ticket", untrusted=True, session=session)
...
result = mw.screen_output(model_text)      # redacts secrets/PII, strips external images, blocks XSS markup
```

```bash
agentsec audit verify audit.jsonl           # exit 1 if any record was edited or removed
```

The audit log chains records with SHA-256. Editing or deleting a record in the middle breaks verification from that point. It does **not** stop someone with write access from truncating the tail or replacing the whole file; ship records to append-only storage (S3 Object Lock, CloudWatch Logs with a restrictive resource policy) and anchor `AuditLogger.checkpoint()` somewhere the agent host cannot write. Secrets and PII are redacted before hashing, and `log_content=False` stores only hashes and lengths of long fields.

**SIEM feed (CEF).** Keep the hash-chained file as the evidence of record and stream a copy to your SIEM in ArcSight Common Event Format, which Splunk, Microsoft Sentinel, QRadar, Elastic and most syslog pipelines ingest:

```python
from agentsec.middleware import AuditLogger, CefSink, FileSink, TeeSink

audit = AuditLogger(TeeSink(FileSink("audit.jsonl"), CefSink(send_to_syslog)))   # or format_cef(record) yourself
```

Denials, approval refusals and MCP tool findings get higher CEF severities than routine activity. Audit records carry attacker-influenceable text (tool names and arguments, model output), so every value is escaped per the CEF rules and bounded: a value cannot end its field, forge a `key=value` pair or start a new event. Each line includes the record's hash and its predecessor's, so a receiver can check the chain. `TeeSink` treats the first sink as the source of truth; a failing secondary sink (the SIEM is down) is logged to the `agentsec.audit` logger and does not interrupt the agent or break the chain. The CEF output is tested with a reference parser built from the CEF escaping rules; it has not been ingested by a specific SIEM product.

## 4. Threat model an agent (STRIDE-for-agents)

```bash
agentsec threatmodel init -o system.yaml     # describe components, trust zones, data flows
agentsec threatmodel render system.yaml -o THREATMODEL.md
```

The generator selects candidate threats by component type, draws the data-flow diagram with trust-boundary crossings, gives each row a triage hint (raised for components that ingest untrusted input, have side effects, or hold sensitive data), and links each threat to its mitigations, the toolkit control that implements it, and the fuzzer categories that test it. See the worked example: [`docs/threat-model/EXAMPLE-support-copilot.md`](docs/threat-model/EXAMPLE-support-copilot.md), the [method and blank template](docs/threat-model/README.md), and `agentsec threatmodel catalog`. Each threat is also mapped to the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) and to [MITRE ATLAS](https://github.com/mitre-atlas/atlas-data) techniques (content release 2026.09). `agentsec threatmodel crosswalk` prints the [framework crosswalk](docs/threat-model/frameworks.md), which lists the toolkit controls and fuzzer categories behind each entry.

## Coverage against OWASP Top 10 for LLM Applications (2025)

| Risk | Where this toolkit helps |
|---|---|
| LLM01 Prompt injection | Fuzzer (measure), scanner + spotlighting (reduce), taint policy (contain) |
| LLM02 Sensitive information disclosure | Secret/PII redaction, protected-string tripwire, audit redaction |
| LLM03 Supply chain | Threat catalog entries and mitigations (no runtime control here) |
| LLM04 Data and model poisoning | Catalog + retrieval-time scanning |
| LLM05 Improper output handling | `OutputGuard` validators: markup, exfil links, JSON schema |
| LLM06 Excessive agency | Deny-by-default `Policy`, approval, taint, `SafeCommandRunner` |
| LLM07 System prompt leakage | Fuzzer `prompt_leak` category, `ProtectedStringValidator` |
| LLM08 Vector and embedding weaknesses | Catalog entries only |
| LLM09 Misinformation | Out of scope |
| LLM10 Unbounded consumption | Per-session call limits, subprocess timeouts and output caps |

The catalog also covers all ten OWASP agentic risks; the [crosswalk](docs/threat-model/frameworks.md) shows which toolkit controls back each one. A mapping means a threat is an instance of, or contributes to, that entry, not that the entry is mitigated. NIST AI RMF and ISO/IEC 42001 are not mapped.

## Honest limitations

- **The built-in agents are simulators.** `NaiveAgent` deterministically obeys injections and understands common obfuscations; it exists so the harness, detectors and CI gate can be tested offline. The numbers above show how *these controls behave when the model is compromised*, not how any real model behaves. Run the fuzzer against your real agent for that. `AnthropicTarget` and `HttpTarget` are tested against fakes and a local server, and have not been run against a live endpoint by this repo's CI.
- **Canary-echo success is a proxy.** It measures whether the model followed an injected instruction, which is the necessary first step of every real attack, but not the impact of a real one.
- **The corpus is a starting set** of well-known technique families, not an exhaustive or adaptive attacker. Extend it with your own payloads (`FuzzConfig(corpus=...)`).
- **The scanner is a tripwire.** Its documented bypasses are asserted in the tests on purpose.
- **Output validators are pattern-based** and will not catch data a model re-encodes.
- **No OS-level isolation.** Use containers/microVMs for code execution, and IMDSv2 with hop limit 1 for cloud-hosted agents.

## Development

```bash
pip install -e ".[dev]"
ruff check src tests && ruff format --check src tests
mypy src
pytest --cov=agentsec
```

CI runs lint, type-check and tests on Linux (Python 3.11 to 3.13) and Windows and macOS (3.11, 3.12), builds and checks the package, validates the example policy, re-generates the example threat model to confirm it is current, and runs the fuzzer as a regression check that the containment layers still hold at 0% for tool misuse, exfiltration and prompt leak. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

MIT
