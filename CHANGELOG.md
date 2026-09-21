# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/). While the version is below 1.0, minor releases may change public APIs.

## [Unreleased]

### Added
- Fuzz targets for the toolkit's own security-critical code (`fuzz/`): CEF formatting, URL allowlisting, private-address blocking across IP encodings, path confinement, redaction, the injection scanner, policy loading, the tool guard and audit-chain verification. They run as ordinary tests on a seed corpus and random inputs, and in CI with coverage-guided fuzzing (Atheris). Each target's ability to fail is itself tested.
- Releases attach the attestation bundle (`*.sigstore.json` and `*.intoto.jsonl`) next to the artifacts, so they can be verified offline with `gh attestation verify --bundle`. The release workflow verifies every artifact against the bundle before publishing.

### Fixed
- URL host checks were more lenient than the fetchers they protect. Extra trailing dots (`api.example.com..`) were stripped, and leading or trailing whitespace, control, zero-width, bidirectional and line-separator characters were trimmed instead of rejected, so the guard could judge a different host than the one a client connects to. Such hosts are now refused. IP literals were already blocked in these forms.
- Loading a policy with a wrongly typed value crashed with `TypeError` instead of raising `PolicyError`, and a quoted `allow: "false"` (a truthy string) silently enabled the tool. Policy fields are now type-checked, a `hosts: api.example.com` given as a string instead of a list is an error, and `max_total_calls`, `max_calls` and `version` must be integers. Policies that only worked by accident may now be rejected with a clear message.
- CEF header fields (vendor, product, version, event name) kept U+2028 and U+2029, which several parsers treat as line breaks. They are now replaced with spaces.

## [0.2.0] - 2026-09-21

### Added
- `docs/TOUR.md` (a five-minute tour with real CLI output), `docs/PRODUCTION.md` (rollout order, policy and audit guidance, an operating checklist), and `scripts/bench_overhead.py`, which measures the per-call overhead the toolkit adds (a table of results is in the production guide).
- `format_cef` and `CefSink`: audit records as ArcSight Common Event Format for SIEM ingestion, with CEF-compliant escaping and bounding of attacker-influenceable values and severities that rank denials and findings above routine activity. `TeeSink` writes to several sinks with the first as the source of truth, so a SIEM outage cannot break the hash chain.
- `agentsec.integrations.langchain`: `guard_tool` / `guard_tools` wrap LangChain and LangGraph tools so every call passes through the guard (sync and async), with refusals returned to the model as readable text and the run configuration passed through. `langchain` optional extra; tested against real `langchain-core` and LangGraph in CI.
- `agentsec.integrations.mcp`: `GuardedMCPClient` puts the tool guard in front of an MCP client, with `ToolPins` (rug-pull detection by definition fingerprint), `scan_tool_definitions` (tool-poisoning tripwire over descriptions and parameter schemas), guarded and audited calls, and taint of results. Duck-typed on both MCP SDK 1.x and 2.x spellings; `mcp` optional extra and a CI job that runs it against the real SDK 2.x.
- A repository hygiene test that rejects literal zero-width and bidirectional-control characters in source files.
- Threat catalog mapped to the OWASP Top 10 for Agentic Applications (2026) and MITRE ATLAS (content 2026.09). Rendered threat models name the entries, and `agentsec threatmodel crosswalk` (also committed as `docs/threat-model/frameworks.md`) lists the toolkit controls and fuzzer categories behind each one, flagging entries with no catalog threat as gaps. Unknown ids are rejected when a catalog loads.
- Two catalog threats for OWASP agentic risks that had none: AG-D-04 (cascading failure across chained agents) and AG-E-06 (rogue or unsanctioned agent). The catalog now has 25 threats.
- `agentsec fuzz --sarif` (SARIF 2.1.0 for GitHub code scanning, with `--sarif-artifact` to choose the file alerts attach to) and `--junit` (JUnit XML). `FuzzReport.to_sarif()` / `to_junit()`.
- Async API for `asyncio` applications: `ToolGuard.aauthorize`, `aexecute` and `awrap` (async or sync approvers; async or sync tools, with sync tools run in a worker thread), `arun_anthropic_tool_uses`, `arun_openai_tool_calls` and `SafeCommandRunner.arun`. See `examples/async_agent_loop.py`.
- `async def` fuzz targets: `agentsec fuzz --target module:callable`, `text_target` and the new `sync_target` accept coroutine functions and run them on a single reused event loop.

### Fixed
- Fuzzing an `async def` target used to score the text of the un-awaited coroutine object and report no attack success. It is now supported, and passing an un-awaited coroutine to the harness is an error.
- `ToolGuard.authorize` treated an async approver's un-awaited coroutine as truthy, which approved every request. It now refuses.
- `ToolGuard.execute` on an `async def` tool returned a coroutine object as the tool's output without running the tool. It now raises `TypeError`.

## [0.1.0] - 2026-09-21

### Added
- `agentsec.fuzzer`: prompt-injection harness (25 payloads x 10 obfuscations x 2 delivery modes) scored with canaries, JSON and Markdown reports, and a CI gate on attack-success rate.
- `agentsec.sandbox`: deny-by-default tool policy with per-argument validation, path confinement, SSRF-safe URL checks, rate limits, human approval, taint tracking, and a no-shell subprocess runner.
- `agentsec.middleware`: output validators, injection scanner, and a hash-chained audit log with secret redaction.
- `agentsec.threatmodel`: STRIDE-for-agents threat catalog mapped to the OWASP LLM Top 10 (2025) and a threat-model generator.

### Build and release
- CI runs the test suite on Windows and macOS as well as Linux, on Python 3.13 in addition to 3.11 and 3.12, and enforces a 90% coverage floor.
- CI builds the sdist and wheel, runs `twine check --strict`, and confirms the wheel bundles `py.typed` and the threat catalog.
- Release workflow: pushing a `vX.Y.Z` tag builds the package, generates a CycloneDX SBOM, attests build provenance, and publishes a GitHub Release. It does not upload to PyPI.
- OpenSSF Scorecard workflow.
- Dependency review rejects GPL and AGPL licensed dependencies.
- Issue and pull request templates, `CODE_OF_CONDUCT.md`, `SUPPORT.md`.
- Project URLs in the package metadata.

### Security
- Closed bypasses found in a security review of the toolkit (see the commit history for details).

[Unreleased]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/DustyStudy/ai-agent-security-toolkit/releases/tag/v0.1.0
