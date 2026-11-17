# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/). While the version is below 1.0, minor releases may change public APIs.

## [Unreleased]

A second review of `scan-config` (Codex, on the `--accept`, YAML and empty-entry code that had none) found five ways a change could pass a pinned check. All five are fixed. They change what is pinned: if you keep a pin file, expect `new`, `removed`, `changed` or `unparsed` findings on the first check after upgrading where one of the cases below applies, then review and run `--update-pins`.

### Added
- `agentsec audit summary <file>`: counts of audit records by event and by decision (`verdict`, or the `allowed` flag of `gateway_mcp_call` and `validation` records), and the ten most-denied tools and actors. `--since`, `--until`, `--actor` and `--event` filter the records and `--json` prints JSON. The hash chain is verified in the same pass: a log that fails gets no summary and exit code 1 unless `--no-verify` is passed, and then the output is marked `UNVERIFIED`. The file is streamed, and values read from the log are stripped of control characters and bounded before printing. `verify_file` takes an optional `records` wrapper for reading the records it verifies, and `agentsec.middleware.audit.read_records` is the file reader it uses.

### Fixed
- `agentsec audit verify` crashed with a `ValueError` on a line holding an integer too long for Python to convert (more than 4300 digits). Such a line is now reported as `not valid JSON`, like any other malformed line, and the `TAMPERED` message is bounded and stripped of control characters.

### Security
- `agentsec scan-config`: a symlinked agent directory (`.claude` pointing at `payload`) was pinned only by its target, so the settings behind it could be swapped with no finding: under their own path they are not agent configuration. A symlinked directory that is, or is under, an agent directory is now followed and its files are listed under the link's name. Each target is followed once, so a link to its own parent ends. A Windows junction is handled the same way on Python 3.12 and later, and is no longer walked into without bound.
- `agentsec scan-config`: a file under an agent directory named like an entry id (`settings.json#hooks.PreToolUse`) and holding the JSON that entry was fingerprinted from took over the pin of a deleted hook. A `#` in a path is now `%23` in the item id, and `%` is `%25`.
- `agentsec scan-config`: a YAML scalar that YAML 1.1 (PyYAML) and YAML 1.2 (most agents) read differently is now `unparsed`. `command: yes` and `command: on` had one fingerprint, as did `017` and `15`, and `1e3` and `"1e3"`. Refused: `yes`/`no`/`on`/`off`, capitalised booleans, octal, hex, binary, `_` in numbers, sexagesimal, `.5`, `+5`, exponents, bare dates, `!!binary`, and the merge key `<<`. Kept: strings, `null`, `true`, `false` and numbers spelled as JSON spells them.
- `agentsec scan-config`: a TOML date and a string spelling its Python `repr` (`x = 1979-05-27` and `x = "datetime.date(1979, 5, 27)"`) had one fingerprint. An entry that holds a TOML date or time is now hashed so no string can match it; the fingerprint of such an entry changes.
- `agentsec scan-config`: a project-root `opencode.jsonc`, which OpenCode loads, was not inventoried at all. It is now pinned whole, like any other file under an agent directory.

### Added
- A Grafana dashboard (`examples/grafana/agentsec-gateway.json`) and Prometheus alert rules (`examples/grafana/alerts.yaml`) for the gateway's `/metrics`, with a section in `docs/GATEWAY.md` on scraping the loopback admin listener. They use only the existing metrics; a test checks that every metric and event name they reference is one the gateway emits. Neither file has been loaded into Grafana or Prometheus.

### Changed
- `test_known_limit_dns_rebinding_between_the_check_and_the_tools_own_lookup` records the DNS-rebinding limit of URL argument rules: the guard resolves the host once and the tool resolves it again. README, `docs/PRODUCTION.md` and `docs/GATEWAY.md` now say where the limit is (the sandbox URL check, not the gateway, which does not check upstream addresses) and what closes it.
- `tests/test_gateway_bypass_regressions.py` pins the gateway against the bypass classes published for AI gateways in 2026: auth fail-open on a bad or repeated credential or a failing verifier, public-route confusion (`/mcp?.well-known`, `/healthz/../mcp`), self-service privilege escalation through `POST /tokens`, and spoofed or repeated identity headers. No gap was found; the gateway code is unchanged.

## [0.11.0] - 2026-11-17

`scan-config` now parses YAML config files per entry, and a new fuzz target for its parsers found two cases it skipped. Both change what is pinned: if you keep a pin file, expect `new` and `removed` findings on the first check after upgrading, then review and run `--update-pins`.

### Added
- A `config` fuzz target for the `scan-config` parsers (`fuzz/targets.py`, seeds in `fuzz/corpus/config/`). It writes the input bytes as a JSON, a TOML and a YAML config file under an agent directory and checks that `scan_config` never raises, lists every file or reports it as `unparsed` or `oversized`, finishes within a time bound, and gives the same fingerprints and findings on a second scan. It runs with the other targets in the test suite and in the CI fuzz job. It found the crash and the skipped entries described below.

### Fixed
- `agentsec scan-config` crashed on a YAML config file that puts a standard tag on a value it does not fit, such as `a: !!int ""` (`IndexError`), `a: !!bool maybe` (`KeyError`) or `a: !!timestamp x` (`AttributeError`): PyYAML raises these instead of a YAML error. Such a file is now an `unparsed` finding.

### Changed
- **Behaviour change, re-pin needed if you have one:** a JSON, TOML or YAML config file with no entries (`{}`, or a TOML file that is empty or only comments) used to produce no item and no finding, so it was missing from the inventory and from the pins. It is now listed as one item under its path, and an empty `hooks`, `mcpServers`, `mcp_servers` or `servers` mapping, which was skipped the same way, as one item under `<path>#<key>`. A check against an older pin file reports such a file or key as `new` until you run `--update-pins`; deleting it later is reported as `removed`.
- `agentsec scan-config` parses YAML config files (`.yaml`, `.yml`) under an agent directory into entries, as it does JSON and TOML: one per top-level key, with `mcpServers`, `mcp_servers`, `servers` and `hooks` listed per member, so a changed server or hook is reported by name. Each entry is run through the injection and secret scanners. It fails closed: a YAML file with a duplicate key, an alias, a tag that is not a standard data tag, a key that is not a string, more than one document, or a top level that is not a mapping (an empty file included) is an `unparsed` finding.
- **Behaviour change, re-pin needed:** a YAML file used to be pinned whole under its path. Its ids are now `<path>#<key>`, so a check against an older pin file reports the path as `removed` ("pinned as a whole file, now listed per entry: review and re-pin") and each entry as `new`, and exits 1 until you review the entries and run `--update-pins`. A change to a YAML comment alone no longer changes a pin. A YAML file that is now `unparsed` cannot be pinned until it is rewritten.
- `docs/SANDBOX.md`: the four `locked_install_rules` commands were each run against the real package manager on Windows 11 (pip 26.3, uv 0.12.19, npm 11.19.1, pnpm 12.21.0). All four installed from the lock file, refused a manifest the lock file did not cover, and, for npm and pnpm, ran no install scripts. pip, uv and pnpm's native `pnpm.exe` ran through `SafeCommandRunner`; `npm.cmd` is a batch file and was run directly. No command changed.
- Threat catalog and framework crosswalk: the coding-agent controls from 0.9.0 and 0.10.0 are now listed against the threats they address, each with its known limits. `agentsec hook` is under AG-S-01 (untrusted content impersonates an instruction source), `agentsec scan-workflows` under AG-E-02 (untrusted input chained to a privileged action) and `locked_install_rules` under AG-T-05 (dependency supply chain), next to `scan-config`, which was already there. No threat was added and no framework mapping changed; `docs/threat-model/frameworks.md` and the example threat model are regenerated.

## [0.10.0] - 2026-11-17

Two additions: lock-file-only installs for the command runner, and a way to accept a reviewed scanner false positive in `scan-config`. One behaviour change: a `scan-config` pin file with a duplicate key is now refused.

### Added
- `locked_install_rules` and `ExecRule(exact_args=...)` for `SafeCommandRunner`: rules that let an agent install dependencies only from the project's lock file (`pip install --require-hashes -r ...`, `uv sync --locked`, `npm ci --ignore-scripts`, `pnpm install --frozen-lockfile --ignore-scripts`). A package name, an index URL or another requirements file is refused. `exact_args` requires the whole argument list to equal one of the listed ones.
- `agentsec scan-config --pins FILE --update-pins --accept ITEM_ID`: records a reviewed false positive from the injection scanner in the pin file (`"accepted": {item id: fingerprint}`), so a repository whose instruction file quotes an injection phrase can be pinned. The acceptance lapses when the entry changes. Only `injection` findings can be accepted; `secret`, `unparsed`, `oversized` and `ambiguous` always block. Accepted findings are printed as `ACCEPTED` and listed under `accepted` in `--json`. Pin files without the new key still load; a pin file with a duplicate key is now refused.

### Changed
- `docs/PROOF.md`: the tool-result fuzz mode was run against a second local model, Gemma 4 12B, with the same control. 2.8% attack success on the model alone (7 of 250, no forbidden tool call), 0% behind the guards. Unlike Llama 3.1 8B, it did not follow a tool result less often than a pasted document. Reports are in `docs/proof/`.

## [0.9.0] - 2026-11-17

Four additions for coding agents, aimed at the ways they are attacked in practice: planted configuration, instructions in tool results, and agents run in CI on text an outsider wrote. Nothing that worked in 0.8.2 changes. One thing to know if you import it: `agentsec.fuzzer.harness.SCENARIOS` now has three entries; the default run still uses two, through the new `DEFAULT_SCENARIOS`.

### Added
- `agentsec scan-config` (`agentsec.configscan`): lists the agent configuration in a directory (MCP servers, hooks, settings, and instruction files such as `AGENTS.md`, for Claude Code, Cursor, Codex, Gemini and others), runs the injection and secret scanners over it, and with `--pins FILE` exits 1 when an entry was added, changed or removed since the pins were written. This is the path used by packages and repositories that plant an MCP server or a hook for a coding agent.
- `agentsec hook` (`agentsec.integrations.claude_code`): a Claude Code `PreToolUse` hook that applies a tool policy and taint tracking to the agent's own shell, file, fetch and MCP tools. A denied call is blocked, a call that needs approval goes to Claude Code's permission prompt, and taint and call counts are kept per session between hook runs. This is the path where an instruction planted in a tool result (a forged error event read through an MCP server) reaches a shell command. `examples/claude-code.policy.yaml` is a starting policy.
- Fuzzer: `--scenarios tool_result`, an opt-in third delivery mode. The user asks what is causing an issue and the payload comes back as the result of the agent's own tool, laid out like the tool's record. `AnthropicTarget`, `OllamaTarget` and `OpenAICompatTarget` send it in the tool-result role; `HttpTarget` adds `context_tool` to its request body in this mode only; `AttackInput` has a new `untrusted_tool` field. The default matrix is still 500 cases. CI gates the guarded reference agent at 0% tool misuse, exfiltration and prompt leak for this mode as well. `docs/PROOF.md` has a run of it against Llama 3.1 8B.
- `agentsec scan-workflows` (`agentsec.workflowscan`): reports GitHub Actions jobs that run an AI agent on an event whose text an outsider controls (`issues`, `issue_comment`, `pull_request_target`, `workflow_run`, review and discussion events) with no check on the author, and lists the write permissions and secrets within reach. This is the path where an issue title steers an agent that holds a publish token.

## [0.8.2] - 2026-11-17

Two gateway fixes. Connections that do not send a request head within 10 seconds are now closed, and new access token ids start with `tok_`. Websocket upgrade requests, which the gateway never served, are answered as plain HTTP. Nothing else changes for 0.8.1 users.

### Security
- Gateway `limits.header_timeout_s` (default 10): a connection that has not sent a whole request head by then is closed. The HTTP server only timed out connections that were idle after a response, so sockets that sent nothing, or a request head a byte at a time, stayed open for ever and counted towards `limits.max_connections`: 1000 of them got every other client a 503.
- Gateway: websocket upgrades are turned off on both listeners. The gateway serves none, but with the `websockets` package installed the HTTP server handed an upgrade request to another protocol, outside the gateway's connection limits.

### Fixed
- Gateway: access token ids start with `tok_`. An id is 16 hex characters, and about one in 18,000 is 16 digits that pass the Luhn check: the audit log then redacted it as a payment card number, so that token's records could not be tied to it. Ids issued before this release keep their form.

## [0.8.1] - 2026-11-17

One fix that fails closed, and the first published container image. `SafeCommandRunner` now refuses an option-like argument after a `--` that itself comes right after an option (`--stat -- -name`); everything else behaves as in 0.8.0.

### Added
- The gateway image is published to `ghcr.io/dustystudy/ai-agent-security-toolkit:<version>` on each release tag (`.github/workflows/image.yml`), with a build provenance attestation that `gh attestation verify` checks against the workflow and the tag. `linux/amd64` only, no `latest` tag, and the workflow does not replace a published version tag. This release is the first with a published image.

### Security
- `SafeCommandRunner`: a `--` right after an option no longer ends the `allowed_options` check. With both `--` and an option that takes a separate value allowed, `-W -- -c code` passed the check, and Python then ran `-c`: it read `--` as the value of `-W`. Arguments after such a `--` are still checked, so `git diff --stat -- -name` is now refused while `git diff --stat -- name` and `git diff -- -name` work as before.

## [0.8.0] - 2026-11-16

A security review of the toolkit: redaction, scan limits and gateway input checks. Fails closed in four places that worked before: the gateway refuses a remote `image_url` in enforce mode and a `/0` network in `identity.trusted_proxies`, `JsonSchemaValidator` refuses `NaN` and `Infinity`, and `agentsec fuzz` exits 2 when every case errored. A JWT directly after a `-` is no longer redacted by the JWT rule. Also new: a container image for the gateway (build it yourself; none is published), a connection cap and a shutdown timeout.

### Added
- A `Dockerfile` for the gateway: built from a new hash-pinned `requirements/requirements-gateway.txt` on a digest-pinned `python:3.13-slim`, running as uid 10001 with no pip, and working with a read-only root filesystem and no capabilities. CI builds it and smoke-tests it that way. `examples/gateway.container.yaml` and the "Container image" section of [docs/GATEWAY.md](docs/GATEWAY.md) show how to run it. No image is published yet.
- Gateway `limits.max_connections` (default 1000): above that many open connections and requests in flight, the HTTP server answers 503 before authentication. There was no cap.
- Gateway `limits.shutdown_timeout_s` (default 30): on SIGTERM, requests in flight get that long to finish. The gateway used to wait for every open stream, until the orchestrator killed it.

### Security
- Gateway: a message part with a remote `image_url` is refused in enforce mode (`input_blocked`, reason `remote image URL`) and logged in monitor mode. A model server that fetches image URLs would otherwise fetch any address a user names from its own network position. Inline `data:` images pass.
- Gateway: `identity.trusted_proxies` refuses a `/0` network, which let every peer name any user in a header.
- Gateway: a warning at config load when an upstream or MCP upstream with a credential uses a plain `http://` URL to a non-loopback host.
- The audit log redacts the whole value under a credential key: `{"password": "..."}` and `{"api_key": "..."}` were written in full, because keys and values were scanned separately.
- `SecretLeakValidator`, `PIIValidator` and `OutputGuard.default()` scan the whole output. They stopped at 200,000 characters and passed the rest unread. `redact_text` and `find_sensitive` keep their `max_scan_chars` default.
- Redaction covers quoted credential values up to 4,096 characters, and values whose closing quote is missing. A quoted value over 200 characters matched nothing and was left in full.
- `InjectionScanner` and redaction: the `exfil_markdown` and JWT patterns run in linear time. Text made of repeated `![` or `eyJ-` took quadratic time, several seconds for 200 KB, which one gateway user could use to stall the process. A JWT directly after a `-` is no longer matched.
- `JsonSchemaValidator` refuses `NaN` and `Infinity`. Python's JSON parser accepts them, and `NaN` passes every `minimum` and `maximum`.
- Windows: a path argument with stream syntax (`.env::$DATA`, `file:stream`) is refused. It opened the file while no `deny_patterns` entry for the file name matched.
- `GuardedMCPClient`: a tool missing from a complete listing can no longer be called. It stayed callable from the earlier listing.

### Fixed
- `agentsec fuzz` exits 2 when every case errored. It printed `0/0 attacks succeeded` and passed any `--max-asr` gate.
- `agentsec audit verify` and `verify_file` read the log one record at a time instead of loading it whole.
- Gateway: the per-user rate limiter kept an entry for every user it had ever seen. Users idle for a full window are now forgotten.
- Gateway: expired and revoked access tokens are deleted from the store 7 days afterwards. Issuing and revoking in a loop grew the table and every `GET /tokens` answer without bound.

### Changed
- CI tests Python 3.14 on Linux, and 3.14 is listed in the classifiers.
- The hash-pinned lock files are refreshed (`scripts/lock.py --upgrade`). No runtime dependency changed; the release SBOM tool moves to cyclonedx-bom 8.

## [0.7.0] - 2026-11-16

Phase 3 of the gateway, in preview: an MCP endpoint and access tokens for IDE clients. Tested end to end with Claude Code (list, call, taint denial, revocation). Nothing in the library API is removed or made stricter. The MCP endpoint needs the `mcp` extra as well as `gateway`, with MCP SDK 2.3 or newer (checked at startup).

### Added
- Gateway access tokens (`tokens:`), for IDE MCP configs and scripts that only take a fixed header: a signed-in user mints one with `POST /tokens` (JSON only), lists and revokes their own with `GET /tokens` and `DELETE /tokens/<id>`; admins use `agentsec token list|revoke`. Tokens are `agt_` plus 256 random bits, stored as SHA-256 hashes in SQLite, short-lived (default 7 days, at most `max_ttl_days`), capped per user, and cannot manage tokens themselves. Audit records carry the `token_id`.
- Gateway MCP endpoint (`mcp_upstreams`, needs the `gateway` and `mcp` extras): one streamable-HTTP `/mcp` in front of approved upstream MCP servers, the third phase of [docs/design/GATEWAY.md](docs/design/GATEWAY.md). The MCP SDK speaks the protocol (2025 sessions and the 2026 stateless revision); every `tools/list` and `tools/call` runs under the caller's identity and group. Tools are namespaced `<upstream>__<tool>`; `GuardedMCPClient` scans and pins definitions, applies the tool policy and refuses unlisted tools; taint is shared across upstreams and sessions per user, so a new session cannot drop it; a session id works only for its opener; upstream answers are size-capped. Bundles gain per-group `mcp: [upstreams]` and signed `mcp_pins`.

## [0.6.0] - 2026-11-16

The gateway (`agentsec serve`, the `gateway` extra) is new and in preview: its config format may still change. Nothing in the library API is removed or made stricter.

### Added
- `agentsec serve` (preview, `pip install "ai-agent-security-toolkit[gateway]"`): an OpenAI-compatible `/v1/chat/completions` gateway in front of local model servers such as Ollama and vLLM, the first phase of [docs/design/GATEWAY.md](docs/design/GATEWAY.md). It identifies users from a trusted auth-proxy header, rebuilds each request from an allowlist, offers the model only tools the policy allows, strips denied `tool_calls` from responses (per-request taint from `role: tool` messages), runs input screening and `OutputGuard`, serves streaming from the checked response, rate-limits per user, writes a hash-chained audit log, and fails closed. See [docs/GATEWAY.md](docs/GATEWAY.md) and [`examples/gateway.yaml`](examples/gateway.yaml).
- Gateway `identity.mode: oidc`: verifies `Authorization: Bearer` JWTs against the IdP's JWKS with PyJWT (now in the `gateway` extra). Asymmetric algorithms only, required `iss`/`aud`/`exp`/`iat`/`sub`, a key's declared `alg` enforced, JWKS over https with a bounded cache and at most one unknown-`kid` refresh a minute. Header identity settings are refused in this mode.
- Gateway signed policy bundles and per-group policy (`bundle:` in the config, `agentsec bundle sign|verify`): Ed25519 over the hashes of the manifest and every referenced policy, checked before any YAML is parsed. The first matching group's entry sets the tool policy, mode, allowed models and output/input rules; no match is a 403. The gateway will not start without a valid bundle, reloads newer ones without a restart, refuses rollbacks (across restarts too with `bundle.state_file`), keeps the last good bundle on any failure, and stops serving (503) once a bundle expires. Example in `examples/bundle/`.
- `OpenAICompatTarget` and `--target openai-compat:<base_url>#model=NAME[&token=env:VAR][&stream=1][&header=Name:value]`: fuzz any OpenAI-compatible `/chat/completions` server, including the agentsec gateway (and `guarded:openai-compat:...`). A gateway `input_blocked` refusal scores as blocked; a stream cut short scores what was delivered. Tokens are `env:`/`file:` references only.
- Gateway holdback streaming (`output.stream_mode: holdback`, per group): text streams from the model once it is `holdback_chars` (default 256) behind the newest text and the window around it checks clean; unclosed links, tags and code fences are held whole; tool calls are held to the end. A violation the final check finds in already-sent text ends the stream with an error event, no `[DONE]` and a high-severity audit record. `buffer` stays the default.
- Gateway admin listener (`admin: {port: ...}`, loopback only): `/healthz`, `/readyz` (policy revision, monitor-mode groups, 503 once expired) and Prometheus `/metrics` with audit events by name, responses by status and the policy in force. No new dependency.
- `AuditLogger.bind(actor=..., session_id=...)`: a logger on the same chain with another actor or session, without re-reading the sink.
- `AuditLogger(keep_fields=[...])`: top-level data fields that `log_content=False` leaves readable (still redacted and truncated). The gateway uses it so block and denial reasons are readable while prompts and answers stay hashed; before, any reason over 64 characters was stored only as a hash.
- `agentsec.sandbox.adapters.parse_openai_tool_call` (was private `_openai_call`).

## [0.5.0] - 2026-11-15

Breaking (fails closed): `resolve_dns` is on by default for URL rules without a `hosts` allowlist, `GuardedMCPClient.call_tool` needs a prior `list_tools()`, path arguments reach the tool resolved, and `deny_args` refuses more spellings.

### Security
- URL checks refuse hosts containing `\`, `%` or any character outside `[a-z0-9._-]` (IP literals excepted). `urlsplit` kept them in the host while WHATWG fetchers read `\` as `/` and percent-decode the host, so `http://169.254.169.254\y.allowed.com/` passed a `*.allowed.com` allowlist and `http://%31%32%37.0.0.1/` passed `block_private`.
- `SafeCommandRunner` gives the command `stdin=DEVNULL` instead of the host's stdin (under an MCP stdio server, the JSON-RPC channel), and runs it in its own process group. Timeout, output overflow and normal exit now kill the processes it started, not just the direct child, so a background grandchild can no longer hold the pipes open past the timeout. On Windows the tree is killed with `taskkill /T`, which misses grandchildren orphaned after their parent exited; on POSIX a descendant that calls `setsid()` leaves the group and escapes. It is still not an OS sandbox.
- Redaction (audit log, `SecretLeakValidator`, `OutputGuard.default()`) covers generic `api_key` / `secret` / `client_secret` / `*_token` / `AccountKey` / `pass` assignments, Stripe `sk_live_` / `rk_live_` keys and `Authorization: Basic` headers. A key name that merely contains one of these words (`max_tokens`, `secretary`) is left alone; prose like `the secret: x` is redacted.
- The audit log redacts dict keys as well as values.
- `deny_args` matches other spellings of a denied option: `--output` also denies `--output=x` and GNU abbreviations such as `--outp`, and a short option `-c` denies an attached `-cvalue` and a flag cluster such as `-Ic`. Previously `deny_args=["-c"]` let `python -Ic "code"` run. Any single-dash argument containing the denied letter is refused, including `-?c` and `-ofile.c`; that over-matches on purpose.
- Path `deny_patterns` match case-insensitively. Windows and macOS file systems ignore case, so `\.env$` let `.Env` open `.ENV`.
- `resolve_dns` now defaults to automatic: on when `block_private` is set and the rule has no `hosts` allowlist. Before, such a rule allowed any hostname that resolves to a private address (`127.0.0.1.nip.io`). Set `resolve_dns: false` to opt out; `lint()` then warns.
- `execute` / `aexecute` (and `wrap`, `awrap` and the adapters) hand the tool the resolved, symlink-free path that was checked, re-checked in full (roots and `deny_patterns`, with an audited denial) just before the call, instead of the raw string the tool would resolve again later. A symlink retargeted after authorization can no longer redirect the tool outside the roots; a race on the resolved path's own components remains (see docs/SANDBOX.md).
- `GuardedMCPClient.call_tool` refuses a tool that has not passed the checks in a `list_tools()` listing even without pins. Before, without pins, a tool whose definition was never scanned could be called. The names of extra `call_tool` options such as `meta` are now audited (not their values, which redaction cannot reliably clean).
- Redaction also covers `PGPASSWORD`, `SSHPASS`, `MYSQL_PWD`, `pw`, `passphrase`, Azure SAS `sig=`, any `Authorization: <scheme> <credential>` header, and GitLab (`glpat-`), npm (`npm_`) and Hugging Face (`hf_`) tokens.

### Fixed
- `resolve_dns: true` with a hostname label over 63 characters raised `UnicodeError` out of `evaluate()`, crashing the LangChain and MCP wrappers. It is now a denial.
- A `tool_use` block with no name, or an OpenAI tool call with a non-string name, non-string arguments or a non-object `function`, raised and crashed the agent loop. Each is now refused and audited.

### Changed
- `Policy.lint()` also flags `allow_extra_args: true`, `type: any`, a URL argument with `block_private: false`, and `resolve_dns: false` on a URL argument without a host allowlist.
- `ToolGuard.wrap` / `awrap` warn when no `Session` is given: the wrapped tool then shares the guard's process-wide `default_session`, so in a multi-user service one user's taint and call counts apply to everyone.
- `SafeCommandRunner(inherit_env=["PATH", "SystemRoot"])` copies named variables from the host into the otherwise empty child environment, for tools such as git on Windows that fail without them.
- The release and CI builds run `python -m build --no-isolation` with `setuptools` and `wheel` installed from the hash-pinned release-tools lock, so the build backend is no longer fetched unpinned at release time.
- `project.license` is the SPDX string `"MIT"` (the table form stops building on 2027-02-18), and Python 3.13 is listed in the classifiers.
- `scan_tool_definitions` reports an `oversized` finding (so the tool is blocked and never pinned) when a definition's text exceeds the scanned limit, instead of scanning only the prefix that padding could push an injection past.
- `InjectionScanner` strips every Unicode format (`Cf`) character plus invisible combining marks, Hangul fillers and variation selectors before matching. Characters such as U+2062 or U+180E inside a word previously hid it from every signal.

## [0.4.1] - 2026-11-14

Same code as 0.4.0. This is the first release published to PyPI.

### Fixed
- The `v0.4.0` release run was refused at startup because the repository's allowed-actions list did not include `pypa/gh-action-pypi-publish`, so 0.4.0 has no GitHub Release or PyPI upload. The tag is protected and stays in place.

## [0.4.0] - 2026-11-14

Tagged but never released; use 0.4.1.

### Added
- The release workflow publishes the wheel and sdist to PyPI as `ai-agent-security-toolkit` with trusted publishing (OIDC; no stored API token) and PEP 740 attestations. It runs after the GitHub Release, in a `pypi` environment that can require a reviewer, and uploads only the distributions, not the SBOM.

### Security
- **Breaking:** `path` arguments must now be absolute. A relative path was checked as if it sat under the first root, but the tool received the raw string and opened it against the process working directory, so `"secret.txt"` passed the check and read a file outside every root. Relative paths are now refused (on Windows, a path must also name a drive or UNC share). `SafeCommandRunner` still accepts a relative `cwd`, anchored to its first root, because it runs the command in the resolved directory.
- `SafeCommandRunner` refuses an executable that resolves to a `.bat` or `.cmd` file on Windows. Windows runs batch files through `cmd.exe` even with `shell=False`, so it re-parses their arguments, and an argument like `x&ver` ran `ver` ("BatBadBut"). The check uses the canonical path, so `npm.cmd.` (which Windows runs as `npm.cmd`) is refused too.
- `ExfilLinkValidator` treats `\` as `/` before reading a URL's host, as browsers do. `https://attacker.example\@allowed.example/` was read as `allowed.example` but fetched from `attacker.example`, so a markdown image could exfiltrate data past the host allowlist. It also accepts any number of slashes after `http(s):` (`https:/attacker.example/`, `https:///attacker.example/`), as browsers do, and treats an http(s) URL whose host it cannot read as external instead of letting it through or crashing on a malformed `[...]` host.
- URL checks reject every non-global address. `is_private` missed carrier-grade NAT space (100.64.0.0/10), which holds Alibaba Cloud's metadata service at `100.100.100.200`. `localhost` and `*.localhost` are now rejected even with `resolve_dns` off; the README previously implied all loopback targets were.
- Secret redaction now covers current OpenAI keys (`sk-proj-`, `sk-svcacct-`, `sk-admin-`, with `-` and `_`), AWS secret keys under STS/boto field names (`SecretAccessKey`, `secret_access_key`) or ending in `/` or `+`, passwords in URLs (`postgres://user:PASSWORD@host`, `redis://:PASSWORD@host`), and `password=` / `"password": "..."` assignments, including quoted values with spaces or escaped quotes. Redaction skips its own `[REDACTED:...]` placeholders, so `OutputGuard` delivers the redacted text instead of withholding it as "could not be fully redacted".
- `DangerousContentValidator` flags any `on*=` attribute inside a tag instead of a short list of handler names (`onbegin`, `onpageshow` and others got through). Tags are read quote-aware, as browsers read them, so `<img title=">" onerror=...>` is caught, while handler-like text inside a quoted value (`title="online=true"`) is not flagged. URL schemes are also checked after decoding HTML character references, so `href="&#106;avascript:..."` is caught; `sanitize` neutralises such references instead of returning decoded text, and escaped markup such as `&lt;script&gt;` is no longer blocked. The patterns run in linear time on adversarial input.
- Audit loggers in one process that write to the same `FileSink` file now share one chain head. Two loggers on one file (say, one per conversation) used to fork the chain, and `verify` then reported tampering. Separate processes must still use separate files.
- `FileSink` refuses to resume unless the last line is a complete record (newline-terminated, integer `seq`, string `hash` that matches its contents), with an error that says why, instead of crashing on a torn write or chaining onto a bad head. It resolves its path when created, so a later `chdir` does not move the file. `verify_records`/`verify_file` report a non-object JSON line or invalid UTF-8 as tampering instead of raising.
- Refreshed every hash-pinned lock in `requirements/`. This moves certifi to 2026.10.23 (removes the emSign roots with compromised intermediate keys), GitPython to 3.2.1 (submodule path RCE) and opentelemetry-api to 1.45.1 (unbounded tracestate parsing).
- `ExfilLinkValidator` treats every URL a renderer fetches without a click as an image: reference-style markdown images (`![a][1]` with `[1]: url`; labels match as in CommonMark, and every definition of a label is checked), `src`, `srcset`, `poster`, `background` and `data` attributes on any tag, `href` on `<link>` and SVG `<image>`/`<use>`, CSS `url()` and `@import`. These were classed as links, so with `links_action=WARN` they were delivered. Tags are tokenised quote-aware, so `src=` text inside another attribute's value is not a fetch; character references and surrounding whitespace in URLs are decoded before the host check (`https&#58;//...`); and extraction runs in linear time, including on unclosed `![` alt text.
- **Breaking:** `GuardedMCPClient` with `pins` refuses to call a tool that has not passed a pin check in a `list_tools()` listing. A tool that was never listed, or sat on a page that was not fetched, used to go straight to the server.
- `ToolGuard` rechecks session taint when it commits an approved call. A session tainted while the approver was deciding (or while DNS was resolved off the loop) let a side-effecting call through even with `taint.action: deny`; in `approve` mode the call now needs an approval that saw the taint.
- `GuardedMCPClient(on_finding="raise")` records which tools are blocked before raising, so catching `ToolManifestError` and then calling the changed tool is refused.
- `run_openai_tool_calls` / `arun_openai_tool_calls` pass tool calls with malformed or non-object JSON arguments through the guard, so they are audited (as the Anthropic adapter already did) before being refused.

### Fixed
- `ToolGuard.aauthorize` runs a plain (non-`async`) approver in a worker thread. It ran on the event loop, so a blocking approver (a prompt, an HTTP round trip) stalled every task, contrary to `docs/SANDBOX.md`.

### Documentation
- The README no longer calls the URL checks "SSRF-safe", and `docs/PRODUCTION.md` says tool fetchers must not follow redirects unchecked: the guard checks the requested URL, not where a redirect leads.

## [0.3.0] - 2026-10-24

### Added
- `OllamaTarget` and the `ollama:<model>` target spec drive a local model through Ollama's `/api/chat` with pinned decoding (temperature 0, fixed seed), so the fuzzer can measure a real model without an API key or billing.
- The `guarded:anthropic:<model>` and `guarded:ollama:<model>` target specs put a model behind the toolkit's scanner, tool policy and output guard (the same layers as `builtin:guarded`), so the same model can be measured with and without them. They only wrap model targets, which propose tool calls without running them. `GuardedAgent` now accepts any target as its model and passes it the screened (spotlighted) input.
- [`docs/PROOF.md`](docs/PROOF.md): the 500-case fuzz matrix run against a real model (Llama 3.1 8B, local). Attack success fell from 34.9% for the model alone to 2.0% behind the tool policy and output guard, with no tool misuse, exfiltration or prompt leaks, and to 0.2% with the scanner added.
- `ExecRule.allowed_options`: an allowlist of option flags for `SafeCommandRunner`. When set, any argument that starts with `-` must be a listed flag (exactly, or as `--flag=value`), so an agent-supplied value cannot be parsed as an option by the target program (argument injection, the bug behind [CVE-2026-97662](https://aws.amazon.com/security/security-bulletins/2026-121-aws/) in AWS `security-agent-mcp-server`). Listing `--` lets a caller end option parsing. Unset keeps the previous behavior. A new `exec_options` fuzz target checks that no unlisted option is ever accepted.

## [0.2.2] - 2026-09-23

### Added
- Dependabot no longer manages the hash-pinned files in `requirements/` (it bumped transitive packages in isolation and broke the lock's consistency); refresh them with `python scripts/lock.py --upgrade`.
- The Scorecard workflow can be run on demand (`workflow_dispatch`), and the README explains how to read the score for a solo-maintained project.

### Fixed
- `InjectionScanner.scan` and `redact_text`/`find_sensitive` had no cap on input size, unlike every other place in the toolkit that processes attacker-influenceable text (MCP tool-definition scanning, CEF values, audit-log fields, `SafeCommandRunner` output). A large enough untrusted tool result (a fetched page, a large document) cost the scanner and redactor work proportional to its full size on every screen. Both now scan at most `max_scan_chars` (default 200,000, overridable) and `ScanResult` reports `truncated` so an oversized input is itself visible in the audit log rather than silently costing more.
- On Windows, every file the CLI and `ToolPins.save` write (`threatmodel render`/`init`, `fuzz --json`/`--md`/`--sarif`/`--junit`, MCP tool pins) came out CRLF instead of LF, because `Path.write_text` translates `\n` to the platform line separator by default. A rendered threat model no longer matched its committed LF original line-for-line, and committing a regenerated report or pin file from Windows produced an all-lines-changed diff. These writes now pass `newline="\n"` so output is byte-identical across platforms; the toolkit already claims Windows support and CI runs the suite there, but the one job that diffs generated output against a committed file (`toolkit-self-checks`) only ran on Linux, so this went uncaught.

## [0.2.1] - 2026-09-21

### Added
- Fuzz targets for the toolkit's own security-critical code (`fuzz/`): CEF formatting, URL allowlisting, private-address blocking across IP encodings, path confinement, redaction, the injection scanner, policy loading, the tool guard and audit-chain verification. They run as ordinary tests on a seed corpus and random inputs, and in CI with coverage-guided fuzzing (Atheris). Each target's ability to fail is itself tested.
- Releases attach the attestation bundle (`*.sigstore.json` and `*.intoto.jsonl`) next to the artifacts, so they can be verified offline with `gh attestation verify --bundle`. The release workflow verifies every artifact against the bundle before publishing.

### Changed
- CI and the release workflow install Python tooling from hash-pinned, cross-platform requirement files (`requirements/`, generated by `scripts/lock.py` with a pinned `uv`) using `pip install --require-hashes`. A CI job fails if they no longer match `pyproject.toml`. The SBOM is generated from the pinned runtime dependencies, so it is reproducible.

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

[Unreleased]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.8.2...v0.9.0
[0.8.2]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/DustyStudy/ai-agent-security-toolkit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/DustyStudy/ai-agent-security-toolkit/releases/tag/v0.1.0
