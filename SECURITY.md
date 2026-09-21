# Security Policy

## Reporting a vulnerability

Please [report a vulnerability privately](https://github.com/DustyStudy/ai-agent-security-toolkit/security/advisories/new) (GitHub: **Security -> Report a vulnerability**) rather than opening a public issue. This is a solo-maintained project with no SLA, so reports are handled as time allows. If that is unavailable, open an issue with minimal detail asking for a private channel.

Things worth reporting: a way to bypass `ToolGuard` (path, URL/SSRF, argument validation, taint or approval logic), a way to make `AuditLogger` verify a modified log, a redaction miss for a documented secret format, or an injection into the threat-model renderer.

## What this toolkit is and is not

- It is a set of **defense-in-depth controls and measurement tools** for LLM agents.
- It is **not** an OS sandbox, a complete prompt-injection defense, or a substitute for IAM/network controls around the agent host. The README's "Honest limitations" section lists known gaps. Please flag any place where code or docs imply more than that.
- The injection scanner and output validators are pattern-based and have known, tested bypasses.

## Handling of adversarial content

The fuzzer's payloads are inert strings that ask for observable, harmless outcomes (echoing a canary, calling a tool that the harness never executes). Run them only against systems you own or are authorised to test. Fuzz reports and audit logs can contain prompts and model output, so treat them as sensitive and keep them out of source control (`.gitignore` excludes the default names).

## CI/CD hardening

- Workflows run with `contents: read` and pin third-party actions to full commit SHAs. First-party GitHub actions that track major tags are noted inline.
- `step-security/harden-runner` runs in audit mode to log runner egress.
- CodeQL runs on every push/PR and weekly; dependency review runs on PRs and fails on high-severity findings.
- Dependabot updates Python dependencies and GitHub Actions weekly.
- Releases are built by a tag-triggered workflow that attaches a CycloneDX SBOM and a build provenance attestation to the GitHub Release. Verify an artifact with `gh attestation verify <file> --repo DustyStudy/ai-agent-security-toolkit`, or offline with the attestation bundle attached to the release: `gh attestation verify <file> --bundle <name>.sigstore.json --repo DustyStudy/ai-agent-security-toolkit`.
- The security-critical parsers and validators (tool-guard argument and URL checks, path confinement, policy loading, redaction, the CEF formatter, audit-chain verification) are fuzzed with Atheris in CI, and the same targets run as regression tests on every change.
- OpenSSF Scorecard runs weekly and on pushes to `main`; results are published to the public Scorecard API (api.scorecard.dev).
- Dependency review rejects GPL and AGPL licensed dependencies.
