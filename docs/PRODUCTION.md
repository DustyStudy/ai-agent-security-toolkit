# Using agentsec in production

This is a checklist for teams putting the toolkit in front of a real agent. It states what the toolkit does, what it does not do, and what you still own. Read the README's [Honest limitations](../README.md#honest-limitations) first.

## What it is, and what it is not

agentsec is a set of **defense-in-depth controls and measurement tools**. It bounds what a hijacked agent can do, checks what leaves the system, records what happened, and measures how well that works. It is not an OS sandbox, not a complete prompt-injection defense, and not a substitute for IAM, network controls or isolation around the agent host. There is no auto-remediation.

## Suggested rollout order

Each step is useful on its own, and later steps build on earlier ones.

1. **Threat model the agent.** Describe components, trust zones and data flows and render a threat register (`agentsec threatmodel render`). Confirm or dismiss each candidate threat with the team; the value is in that conversation. See [threat-model/README.md](threat-model/README.md).
2. **Write a deny-by-default tool policy.** Start from [`examples/policy.yaml`](../examples/policy.yaml). List only the tools the agent needs, constrain every argument, and mark tools that read attacker-influenceable content (`returns_untrusted: true`) and tools that act on the world (`side_effects: true`). Run `agentsec policy validate --strict` in CI and add `agentsec policy check` cases as regression tests.
3. **Put the guard in the loop.** Use `ToolGuard` (sync) or its async forms, or the adapters for [LangChain/LangGraph and MCP](../README.md#async-applications). Every tool call is then allowlisted, argument-checked, rate-limited, optionally approved by a human, and audited.
4. **Turn on the audit trail** (see below) before you turn on anything else in production, so you can reconstruct what the agent did.
5. **Fuzz in CI and before release.** `agentsec fuzz --target <your agent> --categories tool_misuse,exfiltration,prompt_leak --max-asr 0` gates on containment. Upload `--sarif` to code scanning if you use it. Extend the corpus with your own payloads.
6. **Add screening and output validation** (`AgentMiddleware`): scan and spotlight untrusted input, and validate model output for secrets, exfiltration links and dangerous markup before it reaches a user or another system.

## Policy authoring

- **Default deny is the point.** A tool that is not in the policy cannot run; extra arguments are refused. Keep it that way.
- **Taint tracks the dangerous combination.** Once a session has read untrusted content, side-effecting tools are denied or sent to a human (`taint.action`). This works without detecting the injection. Mark *every* tool that can return third-party text as `returns_untrusted`; MCP results are tainted by default.
- **Approvals need context.** Show the approver the exact recipient, URL or command and the reason the guard asked. In your approver, cap how many approvals can be outstanding per session so a flood of harmless requests cannot bury the real one; the toolkit does not do this for you.
- **One `Session` per conversation.** Never share a `Session` across users. Counters and taint are per session, and sharing would let one user's untrusted content affect another's calls or exhaust their limits.
- **Set limits** (`max_calls`, `max_total_calls`) to cap runaway loops and cost. They stay exact under threads and async tasks.
- **Resolve DNS for URL rules** (`resolve_dns: true`) to catch hostnames that point at private ranges. This narrows DNS-rebinding exposure but does not eliminate it; pin the resolved address at connect time for a full fix.

## Audit trail

- **Write it somewhere the agent cannot rewrite.** The hash chain detects edits and deletions in the middle of the log. It does not stop someone with write access from truncating the tail or replacing the whole file. Ship records to append-only storage (S3 Object Lock, CloudWatch Logs with a restrictive resource policy) and anchor `AuditLogger.checkpoint()` outside the agent host.
- **Verify on a schedule:** `agentsec audit verify audit.jsonl` exits `1` if any record was edited or removed.
- **Feed your SIEM** with `TeeSink(FileSink(...), CefSink(...))`. The file stays the evidence of record; the CEF copy is the live feed. A SIEM outage is logged and does not break the chain.
- **Decide what to store.** Secrets and PII are redacted before hashing. Use `log_content=False` to store only hashes and lengths of long fields when prompts and outputs are sensitive. Treat fuzz reports and audit logs as sensitive either way.

## Performance

The overhead is small next to a model call, which takes hundreds of milliseconds to seconds. Measured with [`scripts/bench_overhead.py`](../scripts/bench_overhead.py) on one machine (the code that became agentsec 0.2.0, Python 3.14.7, Windows 11, AMD64). Re-run it on your hardware; these numbers are indicative, not a guarantee.

| Operation | median (us) |
|---|---:|
| `ToolGuard.evaluate` (allowed call) | 1.0 |
| `ToolGuard.evaluate` (URL argument checks) | 5.1 |
| `ToolGuard.execute`, no audit | 4.8 |
| `ToolGuard.execute` + audit (memory sink) | 55.7 |
| `ToolGuard.aexecute` (async tool) | 5.2 |
| `InjectionScanner.scan` (1 KB) | 130.8 |
| `InjectionScanner.scan` (10 KB) | 1,311.5 |
| `OutputGuard.default().process` (4 KB) | 1,008.5 |
| `redact_text` (4 KB) | 506.8 |
| `AgentMiddleware.screen_input` (1 KB, audited) | 285.9 |
| `AuditLogger.log` (memory sink) | 11.0 |
| `AuditLogger.log` (file sink, no fsync) | 203.8 |

Scanning and output validation scale with text length; the tool guard does not. `FileSink` does a small synchronous append, so in async code that is latency-sensitive use a queue-backed `CallbackSink`. Turning on `fsync` trades throughput for durability.

## Supply chain and releases

- Releases are built by a tag-triggered workflow that attaches a CycloneDX SBOM and a SLSA build provenance attestation. Verify an artifact with `gh attestation verify <file> --repo DustyStudy/ai-agent-security-toolkit`.
- Runtime dependencies are `PyYAML` and `jsonschema`. Integrations (`mcp`, `langchain`, `anthropic`) are optional extras.
- CI runs CodeQL, dependency review (high-severity and GPL/AGPL licence gates) and an OpenSSF Scorecard workflow, Dependabot keeps dependencies current, and tests run on Linux, Windows and macOS.
- The version is below 1.0, so minor releases may change public APIs. Pin a version and read the [changelog](../CHANGELOG.md) before upgrading.

## Operating checklist

- [ ] Threat model reviewed, with an owner for each open threat
- [ ] Policy is default-deny, validated in CI, with `policy check` regression cases
- [ ] Every tool that returns third-party text is `returns_untrusted`; every acting tool is `side_effects`
- [ ] One `Session` per conversation; approvers show full context
- [ ] Audit log is on append-only storage, verified on a schedule, and mirrored to the SIEM
- [ ] Containment fuzz gate (`--max-asr 0` on tool misuse, exfiltration and prompt leak) runs on every change to the agent
- [ ] Agent runs with least-privilege credentials inside a container or microVM; IMDSv2 with hop limit 1 on cloud hosts
- [ ] Known limitations from the README have been read and accepted

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on the repository (see [SECURITY.md](../SECURITY.md)). Bypasses of the tool guard, audit log verification, redaction or the threat-model renderer are in scope.
