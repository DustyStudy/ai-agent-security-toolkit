# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/). While the version is below 1.0, minor releases may change public APIs.

## [Unreleased]

### Added
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

[Unreleased]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DustyStudy/ai-agent-security-toolkit/releases/tag/v0.1.0
