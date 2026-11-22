# Release checklist: 0.12.0

The release tracker for the next version (the `[Unreleased]` section of CHANGELOG.md). Each
criterion has a pass/fail check that someone else can rerun. Keep it current: a later session
picks up from the **Status** and **Evidence / blocker** columns.

- **Release branch:** `claude/project-thread-zxl7cq` (PR into `main`; nothing is merged, tagged or published without the maintainer's approval)
- **Candidate:** the branch head named in the latest "Verification log" entry below
- **Target users:** teams running LLM agents (Python libraries: fuzzer, ToolGuard sandbox, middleware, threat model) and platform teams running the `agentsec serve` gateway in front of local models and MCP servers
- **Distribution:** PyPI package `ai-agent-security-toolkit` (sdist + wheel, provenance attested) and the gateway container image, both published by `.github/workflows/release.yml` and `image.yml` from a `v*.*.*` tag on `main`
- **Owner key:** `claude` = the release session on this branch; `maintainer` = Dusty (decisions, approvals, access); `CI` = GitHub Actions on the PR

Status values: `PASS` (evidence attached), `FAIL`, `OPEN` (not yet run), `BLOCKED` (needs something outside the branch).

## Launch criteria

| # | Criterion | Pass/fail check | Owner | Depends on | Status | Evidence / blocker |
|---|---|---|---|---|---|---|
| R1 | Lint, format and types are clean | `ruff check src tests fuzz scripts && ruff format --check src tests fuzz scripts && mypy src` exit 0 | claude | | PASS | Local, Python 3.13, 2026-11-22 baseline and after each batch |
| R2 | Full test suite passes with coverage >= 90% | `pytest --cov=agentsec --cov-fail-under=90` exit 0 | claude, CI | R3 | OPEN | Baseline: 1689 passed, **2 failed**, 3 skipped, 96.2% coverage. Both failures fixed (R3); rerun on the integrated branch pending |
| R3 | Tests are hermetic: no test needs public DNS or internet | Full suite passes on a machine without public DNS | claude | | PASS | `tests/test_claude_code_hook.py` resolved `example.com` for real and failed offline; now uses a fixed resolver table (commit `80a1cba`) |
| R4 | CI matrix green on the PR (3.11-3.14 Linux, Windows, macOS, package, fuzz, locks, integrations, self-checks, container, CodeQL, Gitleaks, Trivy, zizmor, Checkov, Scorecard) | Every required check on the PR head is `success` | CI | R2 | OPEN | `main` @ `89ceb9f` is all green (30 checks). PR head not yet run |
| R5 | Clean build produces valid release artifacts | `python -m build --no-isolation` from `requirements-release-tools.txt`; `twine check --strict dist/*`; wheel has `py.typed` and `threatmodel/data/threats.yaml` | claude, CI | | PASS | Local fresh venv: sdist + wheel built, twine PASSED, 55 files in wheel incl. both data files |
| R6 | Clean install from the wheel works through the CLI entry point | Fresh venv, `pip install --require-hashes -r requirements/requirements-runtime.txt` + `pip install --no-deps dist/*.whl`; `agentsec --help`, `agentsec policy validate --strict examples/policy.yaml` | claude | R5 | PASS | Local fresh venv, outside the checkout |
| R7 | Containment holds on the reference simulator | `agentsec fuzz --target builtin:guarded --categories tool_misuse,exfiltration,prompt_leak --max-asr 0` exit 0, also with `--scenarios tool_result`; `builtin:naive` ASR = 1.0 | claude, CI | R6 | PASS | Installed wheel: guarded 0/200 and 0/100 (tool_result), naive 500/500. **Simulator, not a model** |
| R8 | Example threat model is current | `agentsec threatmodel render examples/support-copilot.system.yaml` equals `docs/threat-model/EXAMPLE-support-copilot.md` | claude, CI | R6 | PASS | `diff` empty |
| R9 | Gateway container builds and runs hardened | `docker build`; `serve --check` on `examples/gateway.container.yaml`; read-only, cap-drop ALL, uid 10001; `/healthz` 200, unlisted Host 403, no identity 401; no pip in image; audit file written | claude, CI | | PASS | Local Docker 2026-11-22. The sandbox needed its proxy CA added to the **build stage only** (`/tmp` copy of the Dockerfile, not committed); runtime stage unchanged. CI `container` job is the authoritative run (R4) |
| R10 | Gateway end to end: real `agentsec serve` process, real HTTP upstream, fuzz through it | Tool misuse and exfiltration from a model that obeys every injection reach 0 in `buffer` (stream off and on) and `holdback` stream modes; `agentsec audit verify` intact | claude | R6 | PASS | 60 cases per mode: 0 tool misuse, 0 exfiltration; 5 plain-text system-secret leaks, which is documented behaviour (the gateway is not told the per-case secret; use `output.protected`). Chain intact, 457 records. **Upstream is a local stub running `NaiveAgent`, not a model** |
| R11 | Gateway upstream failure paths fail closed and are bounded | Upstream 429, 500, non-JSON body, hang past `upstream_timeout_s`, SSE cut before `[DONE]`: client gets 502/504 within the timeout, no partial unchecked output, `gateway_upstream_error` audited, chain intact | claude | R10 | OPEN | Real-process run: 429/500/garbage -> 502, hang -> 504 at 5.0 s, holdback stream cut -> 502, all audited, chain intact. Code review of streaming, rate-limit pass-through and bounded reads in progress |
| R12 | Fuzzer provider failure paths cannot produce a false pass | Timeouts, 429/quota, 5xx, cut SSE streams and malformed output are counted as errors, `--max-asr` exits 2 on any errored case, retries bounded, tokens never in reports or errors | claude | | OPEN | Real-process run against a failing gateway: errored cases -> exit 2. Code review in progress |
| R13 | Tool-call authorization and secret handling hold | Adversarial review of ToolGuard, adapters, MCP and LangChain integration, validators, redaction and audit; every confirmed bug has a regression test | claude | | OPEN | In progress |
| R14 | Optional-SDK integrations work | `pytest tests/test_integration_mcp.py tests/test_integration_langchain.py` with `requirements-integrations.txt` | claude, CI | | PASS | Local: 11 passed |
| R15 | Coverage-guided fuzzing finds no crash | `fuzz/run_fuzzer.py <target>` for all 11 targets, no artifact | claude, CI | | PASS | Local: 10 s per target, 0 crashes (CI runs 30 s per target, R4) |
| R16 | Hash-pinned locks match `pyproject.toml` | `python scripts/lock.py && git diff --exit-code -- requirements` | claude, CI | | PASS | Local: no diff |
| R17 | Live model evaluation recorded for this candidate | Fuzz matrix against a real model, direct and behind the full stack, with model, hardware and date recorded in `docs/PROOF.md` | maintainer | R2 | BLOCKED | Last live evidence is Llama 3.1 8B on a local GPU (`docs/PROOF.md`), for an earlier version. Needs a machine with Ollama and a GPU, or approval for paid API calls (`anthropic:` target). No paid calls made |
| R18 | Docs and CHANGELOG describe every behaviour change in this candidate | Each fix in this branch has a CHANGELOG line; README/docs flags and exit codes match `--help` | claude | R11-R13 | OPEN | |
| R19 | Version set for the release | `pyproject.toml` version = tag; CHANGELOG `[Unreleased]` renamed with the release date | maintainer | R1-R18 | OPEN | Proposed `0.12.0` (breaking changes in `[Unreleased]`, pre-1.0 minor bump). Set when the maintainer approves the release |
| R20 | Release published from `main` | PR merged, tag `v0.12.0` on `main`, `release.yml` and `image.yml` succeed, PyPI shows the version | maintainer | R19 | BLOCKED | Needs the maintainer's approval to merge and tag; not done by the release session |
| R21 | Staging acceptance for gateway deployments | The table in `docs/PRODUCTION.md` "Gateway acceptance before employee rollout" (identity/offboarding, network isolation, tool authorization, audit retention, rollback) | maintainer | R20 | BLOCKED | Needs a staging environment with the real IdP and network; none available to this session. Applies to each deployment, not to the package release |

## Verification log

Newest first. Say what ran, where, and whether it used mocks.

- **2026-11-22, `80a1cba`, local Linux, Python 3.13.18 (Docker 29.10.0 for R9).** R1, R3, R5-R10, R14-R16 as above. Mocks: R7 uses the built-in simulators; R10 and R11 use a local stub upstream; no live provider was called.

## Backlog (not release blockers)

- Upstream 429 is returned to gateway clients as 502 `upstream_error`, without `Retry-After`. Clients cannot tell rate limiting from an outage. Candidate change once R11 review settles it.
