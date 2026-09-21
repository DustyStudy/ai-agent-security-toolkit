# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/). While the version is below 1.0, minor releases may change public APIs.

## [Unreleased]

### Added
- CI runs the test suite on Windows and macOS as well as Linux, on Python 3.13 in addition to 3.11 and 3.12, and enforces a 90% coverage floor.
- CI builds the sdist and wheel, runs `twine check --strict`, and confirms the wheel bundles `py.typed` and the threat catalog.
- Release workflow: pushing a `vX.Y.Z` tag builds the package, generates a CycloneDX SBOM, attests build provenance, and publishes a GitHub Release. It does not upload to PyPI.
- OpenSSF Scorecard workflow.
- Dependency review rejects GPL and AGPL licensed dependencies.
- Issue and pull request templates, `CODE_OF_CONDUCT.md`, `SUPPORT.md`.
- Project URLs in the package metadata.

## [0.1.0]

### Added
- `agentsec.fuzzer`: prompt-injection harness (25 payloads x 10 obfuscations x 2 delivery modes) scored with canaries, JSON and Markdown reports, and a CI gate on attack-success rate.
- `agentsec.sandbox`: deny-by-default tool policy with per-argument validation, path confinement, SSRF-safe URL checks, rate limits, human approval, taint tracking, and a no-shell subprocess runner.
- `agentsec.middleware`: output validators, injection scanner, and a hash-chained audit log with secret redaction.
- `agentsec.threatmodel`: STRIDE-for-agents threat catalog mapped to the OWASP LLM Top 10 (2025) and a threat-model generator.

### Security
- Closed bypasses found in a security review of the toolkit (see the commit history for details).

[Unreleased]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/main...HEAD
