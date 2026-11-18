# Design: agentsec gateway

Status: phases 1 and 2 implemented in 0.6.0, phase 3 (MCP gateway and access tokens for IDE clients) in 0.7.0, the container image in 0.8.0 (published from 0.8.1); all in preview. Owner: TBD.

## Problem

agentsec is a library, so it only protects an app if that app's team wires it in correctly. In a company running local models (Ollama, vLLM, LM Studio), the security team cannot enforce a library. They need one chokepoint that every model call and every sanctioned MCP tool call goes through, with identity, policy and audit they control.

The gateway is that chokepoint. It is mostly a composition of components that already exist: `ToolGuard`, `AgentMiddleware`, `OutputGuard`, `AuditLogger`, `CefSink` and `GuardedMCPClient`, run as a service.

## The hard limit

**The gateway controls what reaches and leaves the model. It cannot control what the client executes.** A tool call the gateway strips never reaches the client. But a client can run any tool it likes, parse tool calls out of plain text, read the model's answer and act on it, or skip the gateway entirely if the network allows it. The model gateway therefore:

- bounds what an *injected model* can ask a well-behaved client to do, and what secrets or exfiltration links it can return;
- gives security a central audit trail and policy for every model call;
- does **not** sandbox the client, and does not replace `ToolGuard` inside agents that run tools.

The MCP gateway is stronger. There the gateway is the one executing the tool call (against the upstream MCP server), so its policy really is enforced, as long as the upstream servers can only be reached through it.

Both guarantees depend on the network. The gateway is a control only if model servers and upstream MCP servers accept connections from the gateway and nothing else. Ollama has no authentication and binds to all interfaces when `OLLAMA_HOST=0.0.0.0` is set. That isolation is a deployment requirement, not an optional extra.

## Goals

1. `agentsec serve`: an OpenAI-compatible `/v1/chat/completions` proxy (streaming and `tool_calls` included) in front of local model servers.
2. A single sanctioned MCP endpoint in front of approved upstream MCP servers, for Claude Code, Cursor and Continue.
3. Per-user identity from SSO, recorded in every audit record, with policy per group.
4. Signed policy bundles, hot reload, the policy revision in every audit record, and a monitor (dry-run) mode.
5. Operable: SIEM feed, metrics, health checks, a container image, TLS, and failure behaviour defined for every failure mode.

## Non-goals

- Controlling client-side execution (see above).
- Legacy `/v1/completions`, `/v1/embeddings` and the Responses API in the MVP. Unrouted paths return 404.
- A full API gateway (billing, quotas by cost, caching responses, load balancing across a model fleet).
- Synchronous human approval inside the model path. A tool that needs approval is **denied** at the gateway (see open questions).
- Model routing to external SaaS providers. Upstreams are configured internal endpoints only.
- MCP resources, prompts and sampling in the MVP. Only `tools/list` and `tools/call` are proxied, matching `GuardedMCPClient`, which deliberately forwards nothing else.

## Threat model of the gateway itself

The gateway sees every prompt, holds upstream credentials and decides policy, so it becomes a high-value target.

| Threat | Mitigation |
|---|---|
| **Auth bypass** (missing/forged token, `alg: none`, HS256 signed with the RSA public key, wrong `iss`/`aud`, expired token) | Every route except `/healthz` requires authentication. Accept only an allowlist of algorithms (RS256, ES256 by default). Require `iss`, `aud`, `exp`; ±60 s clock skew. JWKS comes only from the configured issuer. An unknown `kid` triggers at most one JWKS refresh per minute, then denies. |
| **Identity header spoofing** (client sends `X-Forwarded-User` itself) | Trusted-header mode is off by default. When enabled, the header is accepted only if the TCP peer is in `trusted_proxies` (CIDRs), preferably with mTLS from the proxy. From any other peer the header is stripped and the request is denied. A request with the header repeated is rejected. JWT and header modes cannot both be on for one listener. |
| **Request smuggling / desync** (CL+TE, duplicate `Content-Length`, obs-fold) | One strict HTTP/1.1 parser (h11 via the ASGI server), with ambiguous framing rejected. The gateway never forwards raw bytes: it parses the JSON body and **builds a new upstream request** from an allowlist of fields, and drops hop-by-hop headers and the client's `Authorization`. |
| **SSRF through the gateway** (client-chosen upstream) | The `model` field selects an entry from `upstreams` by exact name. No URL or host from the client is ever used. An unknown model returns 404. |
| **Sensitive data at rest in logs** | `log_content: false` by default (unlike the library default), so long prompt and response fields are stored as SHA-256 and length. `redact: true` always on. Audit storage gets its own access controls; it holds sensitive data either way. |
| **Log injection into SIEM** | Existing `CefSink` escaping and bounds. |
| **Audit stream sniffed or forged in transit** | SIEM shipping over TLS syslog (RFC 5425) only; plaintext UDP/TCP is rejected at config load. The local hash-chained file stays the evidence of record. |
| **DoS** (huge bodies, long contexts, slowloris, many streams) | Body limit (default 1 MiB), header and time limits, `max_tokens` cap, per-user concurrency and request-rate limits, `InjectionScanner(max_scan_chars=...)`, an upstream timeout, and cancelling the upstream request when the client disconnects. |
| **Policy tampering or rollback** | Bundles are Ed25519-signed and carry a monotonic `revision`; an older revision is refused. The public key is the only trust anchor in config. |
| **Confused deputy on MCP** (the gateway's upstream credentials used on behalf of any user) | Per-group tool policy is evaluated before every upstream call; audit records name the user. Upstream credentials come from secret references, never from config literals. |
| **DNS rebinding and cross-site requests** (a web page reaches a loopback listener through a hostname it re-points, or posts cross-site) | Both listeners check `Origin` and `Host` before routing and authentication. Any `Origin` outside `listen.allowed_origins` (default empty) is refused. `Host` must be a loopback name on a loopback bind and on the admin listener, or one of `listen.allowed_hosts`. A non-loopback bind without that list skips the `Host` check and warns. `/healthz` on the main listener is exempt. |
| **MCP rug pull** (an approved upstream changes a tool's description or schema after review) | Signed or configured `ToolPins` per upstream; `mcp.require_pins: true` refuses to start, or to reload a bundle, with an unpinned upstream. Without pins the gateway pins each tool in memory on first listing (trust on first use, until restart), names the unpinned upstreams in `gateway_start`, and blocks a later change like a pin mismatch. |
| **Admin surface exposure** | Metrics and readiness are on a separate admin listener bound to `127.0.0.1`. There is no remote admin API; reload uses a signal or a file watch. |
| **Gateway compromise** | Non-root, read-only filesystem container; no shell needed at runtime; egress only to upstreams, IdP JWKS and the SIEM. The audit file is append-only storage outside the container (PRODUCTION.md applies). |

## Architecture

```
 client (app / IDE)            agentsec gateway                              upstreams
 ─────────────────  HTTPS   ┌─────────────────────────────────────────┐
  POST /v1/chat/... ───────►│ 1 authn (JWT | trusted header)          │
                            │ 2 resolve group -> PolicySet (rev N)    │
                            │ 3 rate/concurrency limits               │
                            │ 4 parse + rebuild request (allowlist)   │
                            │ 5 filter request `tools` to policy      │
                            │ 6 screen_input on user/tool messages    │──► Ollama / vLLM
                            │ 7 upstream call (stream or not)         │◄── (gateway-only network)
                            │ 8 tool_calls -> ToolGuard.authorize     │
                            │   strip denied calls                    │
                            │ 9 content -> OutputGuard.process        │
                            │10 audit every step (user, group, rev)   │
  ◄──────────────────────── │                                         │
  POST /mcp ───────────────►│ MCP server facade -> GuardedMCPClient   │──► MCP server A
                            │   per (user, Mcp-Session-Id, upstream)  │──► MCP server B
                            └──────────────┬──────────────────────────┘
                                           ▼
                              TeeSink(FileSink, CefSink -> SIEM)
```

### Model request flow, in detail

1. **Authenticate**, then map groups to a `PolicySet` (tool policy, output-guard config, scanner config, limits). Order is explicit: the first matching `group_policies` entry wins, and no match means 403.
2. **Rebuild the request.** Forward only allowlisted fields (`model`, `messages`, `tools`, `tool_choice`, `stream`, `stream_options`, `temperature`, `top_p`, `max_tokens`, `stop`, `seed`, `response_format`). Unknown fields are dropped and counted. `n > 1` is rejected in the MVP, so there is one choice to validate.
3. **Filter declared tools.** Tools in the request's `tools` array that the policy does not allow are removed, so the model never sees them. A `tool_choice` naming a removed tool returns 400. Tool definitions are also run through `scan_tool_definitions`, which flags poisoned descriptions supplied by the client.
4. **Screen input.** The API is stateless, so the client resends the whole history on every turn. `role: tool` messages are tool results and count as untrusted: they are scanned, optionally spotlighted, and they taint the request. User messages are scanned. Scan results are cached by message hash (an LRU per replica), so the same history is not rescanned on every turn.
5. **Taint is per request, not sticky per user.** A request that contains tool results is evaluated as tainted, so side-effecting tool calls in the response are denied. A sticky per-user taint would lock a user out for the life of the process after a single RAG call. Limitation: a client that puts tool output into a `user` message evades this. The taint protects against an injected model, not against a dishonest client.
6. **Tool calls in the response.** Each `tool_calls` entry is parsed with the adapters' existing parser (`_openai_call`, to be made public), then passed to `ToolGuard.authorize` with the request's session. That covers the allowlist, argument rules (path roots, URL/SSRF/DNS), rate limits and taint. Denied calls are removed. If every call is removed, `finish_reason` becomes `stop` and the assistant content gets a fixed notice ("A tool call was withheld by policy"). Policy reason strings are not passed back to the client, so they cannot leak policy detail. `require_approval` is treated as deny.
7. **Content** goes through `OutputGuard.process`: block, redact or warn as configured.

Limitation: models that emit tool calls as JSON in `content` instead of native `tool_calls` (common with small local models) are not recognised as tool calls. The client may still parse and run them. Optional `BlockedPatternValidator` rules can catch known formats; this is heuristic.

### Streaming (SSE)

`tool_calls` arguments arrive as fragments. **Tool-call deltas are always buffered** until the call's arguments are complete and valid JSON (that is, until `finish_reason`), then evaluated and released or dropped. Arguments are small, so the cost is low.

Content has three modes, set per policy:

| Mode | Behaviour | Guarantee | Cost |
|---|---|---|---|
| `buffer` (**default**) | Collect the whole response, validate, then send it as SSE chunks | Same as non-streaming | Time to first token equals the full generation time |
| `holdback` | Release text only once it is more than `holdback_chars` (default 256) behind the generation head. Also hold everything after an unclosed `[`, `![`, `<` or a code fence. Run validators over the held window plus the released tail on each chunk | Secrets and links shorter than the window are redacted before release | Adds ~window of latency; validators run repeatedly (bounded by window size) |
| `passthrough` | Forward as it arrives; validate at the end | Detection only | None |

What happens to a secret mid-stream:

- In `holdback`, a 40-character token split across chunks is still inside the window when its last character arrives, so it is redacted before release. A secret longer than the window, or a violation that needs the whole text (`JsonSchemaValidator`, `MaxLengthValidator`), cannot be caught that way.
- In every streaming mode the full text is validated once more at the end. If that finds something already released, the gateway cannot take it back. It ends the stream with an error event, sends no `[DONE]`, and writes a high-severity `output_violation_after_delivery` audit record. Clients should not treat an unterminated stream as complete, but some will display partial text anyway.
- `holdback` and `passthrough` are therefore opt-in per group, and the startup log says which groups use them.

## Component reuse map

| Need | Existing component | Change needed |
|---|---|---|
| Tool-call decision on responses | `ToolGuard.authorize` / `aauthorize` | None |
| Parse OpenAI `tool_calls` | `sandbox.adapters._openai_call` | Make public |
| Input screening, spotlighting, taint | `AgentMiddleware.screen_input`, `InjectionScanner`, `spotlight` | Scan cache wrapper (gateway side) |
| Output validation/redaction | `OutputGuard.default(...)`, validators, `redact_text` | Add an incremental `holdback` driver around `process` (gateway side) |
| Client-declared tool scan | `integrations.mcp.scan_tool_definitions` | None |
| MCP upstream enforcement | `GuardedMCPClient`, `ToolPins` | None to the class; new server facade |
| Audit + SIEM | `AuditLogger`, `FileSink`, `TeeSink`, `CefSink` | Add `user`, `groups`, `policy_rev`, `request_id` fields (extra `**data` already supports this; `actor` = user) |
| Per-user limits | `Session` counters | **New**: time-windowed limits; `Session` limits are per session lifetime, which is wrong for a long-lived per-user session. Split counters from taint so a per-request taint can share per-user counters |
| Policy loading | `Policy.from_dict` (strict) | Wrapped by bundle verification |
| Policy CI | `agentsec policy validate/check` | Accept bundles |
| Testing | fuzzer, `HttpTarget`, `OllamaTarget` | **New** `OpenAICompatTarget` |

New code: the HTTP/ASGI app, authentication, bundle verification and reload, the SSE driver, the MCP server facade, metrics, and the CLI commands. This needs an optional `[gateway]` extra (an ASGI server, an HTTP client, a JWT library, `cryptography`, and `mcp`), so the base install keeps its two dependencies.

## Config schema sketch

```yaml
# gateway.yaml - strict: unknown keys are an error, like Policy.from_dict
listen:
  host: 127.0.0.1              # non-loopback requires tls, or trusted_proxy_tls_terminated: true
  port: 8443
  tls:
    cert_file: /etc/agentsec/tls/server.crt
    key_file: /etc/agentsec/tls/server.key   # 0600, mounted secret
admin:
  host: 127.0.0.1
  port: 9090                   # /metrics, /readyz
limits:
  max_body_bytes: 1048576
  max_tokens_cap: 4096
  upstream_timeout_s: 120
identity:
  mode: oidc                   # oidc | trusted_header
  oidc:
    issuer: https://idp.corp.example/realms/main
    audience: agentsec-gateway
    algorithms: [RS256, ES256]
    groups_claim: groups
    jwks_cache_s: 600
  # trusted_header:
  #   user_header: X-Auth-Request-User
  #   groups_header: X-Auth-Request-Groups
  #   trusted_proxies: [10.20.0.0/24]
  #   require_mtls: true
policy:
  bundle: /var/lib/agentsec/bundle.tar
  public_key_file: /etc/agentsec/bundle-signing.pub
  reload: watch                # watch | signal
  on_expired: deny             # deny | serve_last_good
upstreams:
  llama3.1-8b:
    kind: openai               # vLLM, LM Studio, Ollama /v1
    url: http://ollama.internal:11434/v1
    model: llama3.1:8b
    api_key: env:VLLM_API_KEY  # env:/file: references only; literals rejected
mcp_upstreams:
  jira:
    transport: streamable_http
    url: https://mcp-jira.internal/mcp
    auth: file:/run/secrets/jira-mcp-token
    pins: jira                 # pin set inside the bundle
audit:
  file: /var/log/agentsec/audit.jsonl
  log_content: false
  cef: {syslog: tls://siem.internal:6514}   # new: CefSink takes a stream/callback today; TLS only, never plaintext UDP
```

The bundle (`manifest.yaml` plus files, with a detached signature over the manifest, which lists the SHA-256 of every file):

```yaml
revision: 42                   # monotonic; rollback refused
created: 2026-11-15T00:00:00Z
expires: 2027-02-15T00:00:00Z
group_policies:                # first match wins; no match = 403
  - group: ml-platform
    tools: policies/ml-platform.yaml      # existing Policy format
    output: {allowed_hosts: [wiki.corp.example], protected: [], stream_mode: holdback}
    scanner: {threshold: 0.5, block: true}
    models: [llama3.1-8b]
    mcp: {jira: [jira__search_issues, jira__get_issue]}
    mode: enforce              # enforce | monitor
    rate: {requests_per_min: 60, tool_calls_per_min: 30, concurrent_streams: 4}
  - group: all-employees
    tools: policies/default-deny.yaml
    models: [llama3.1-8b]
    mode: monitor
pins: {jira: pins/jira.json}
```

## API surface

| Endpoint | Listener | Notes |
|---|---|---|
| `POST /v1/chat/completions` | main | `stream` true/false; errors use the OpenAI error JSON shape |
| `GET /v1/models` | main | Only models the caller's group may use |
| `POST`/`GET`/`DELETE /mcp` | main | MCP streamable HTTP. Tools are namespaced `upstream__tool`; policy keys use the namespaced name |
| `GET /healthz` | main + admin | Liveness, unauthenticated, no detail |
| `GET /readyz` | admin | Bundle loaded and unexpired, audit primary writable, upstreams reachable |
| `GET /metrics` | admin | Prometheus text |

CLI: `agentsec serve --config gateway.yaml`, `agentsec gateway check-config`, `agentsec bundle build`, `agentsec bundle sign --key <ref>`, `agentsec bundle verify`. Signing keys should live in a KMS or HSM; how `--key` refers to one is an open question. Never a plaintext key file in the repo.

## Identity and session state

- **User key** = `iss` + `sub` (not email, which can be reassigned). It goes in every audit record as `actor`, along with `groups`, `policy_rev`, `request_id` and `mode`.
- **Model path**: a per-user, in-memory limits record, plus a per-request `Session` for taint.
- **MCP path**: one `GuardedMCPClient` and `Session` per (user, `Mcp-Session-Id`, upstream). Taint is sticky within that MCP session, which is the right scope: MCP results really do land in that conversation's context. Idle sessions expire (default 1 h).
- **Multiple replicas**: the state is in memory, so rate limits are per replica (N replicas allow N× the limit), and an MCP session must be pinned to one replica (sticky routing on `Mcp-Session-Id`). Each replica writes its **own** audit chain file, because `AuditLogger` forbids several processes appending to one file. Each replica runs a single worker process. A shared store (Redis) for limits is phase 4. Until then, the documented deployment is one replica, or sticky routing with limits divided by N.

## Policy distribution

- Bundles are verified before they are parsed: signature, then file hashes, then `revision > current`, then `expires`, then strict `Policy.from_dict` for every group. Any failure keeps the last good bundle and raises an alert. With no valid bundle at startup, the gateway **refuses to start**.
- Hot reload swaps an immutable `PolicySet` atomically. In-flight requests finish under the revision they started with, and that revision is what their audit records show.
- **Monitor mode** applies per group. In monitor mode the gateway computes every decision and logs it with `enforced: false`, but delivers the original request and response. Authentication, request limits, body limits and upstream allowlisting are **never** in monitor mode. A group in monitor mode is shown on `/readyz` and in a metric, so it cannot be forgotten.

## Failure modes

| Failure | Behaviour | Why |
|---|---|---|
| No valid bundle at startup | Refuse to start | Never run without policy |
| New bundle invalid / bad signature / rollback | Keep last good; alert | Availability without trusting bad input |
| Bundle past `expires` | `deny` by default (503); `serve_last_good` opt-in | Stale policy is a slow failure |
| JWKS endpoint unreachable | Use cached keys until `jwks_cache_s`, then deny | Bounded degradation |
| Unknown `kid` | One rate-limited refresh, then 401 | Stops key-confusion floods |
| Primary audit sink write fails | 503, request not forwarded | An unaudited model call is a gap in evidence |
| SIEM (secondary) down | Continue; logged; metric | Existing `TeeSink` semantics |
| Scanner/validator raises | Request denied / response withheld | Fail closed |
| Upstream model down or timeout | 502/504; no automatic fallback to another model | Fallback could change policy context |
| Client disconnects mid-stream | Cancel upstream; audit `client_disconnected` | Avoid wasted compute and orphaned streams |
| Violation found after release (streaming) | Terminate stream, no `[DONE]`, high-severity audit | Cannot recall bytes; make it visible |
| Tool needs approval | Denied | No human loop in the model path |
| MCP upstream tool definition changed | Dropped from listing (`ToolPins`, or the first listing this process saw when the upstream has no pins), finding audited | Existing rug-pull defence |
| MCP upstream down | Its tools are omitted from `tools/list`; calls return an MCP error | Isolate one bad upstream |
| Body too large / malformed JSON | 413 / 400 | Validate at the boundary |

## Performance budget

From PRODUCTION.md: about 1.3 ms to scan 10 KB, about 1 ms for `OutputGuard` on 4 KB, about 0.2 ms per audit write to a file. Targets on reference hardware, excluding upstream time:

- Non-streaming with 32 KB in and 4 KB out: p50 added latency under 15 ms, p99 under 50 ms. The scan cache keeps long multi-turn histories from costing O(n²).
- `holdback` streaming: under 50 ms added to time to first token beyond the window, and under 2 ms per chunk.
- Audit writes are synchronous for the primary sink, because evidence comes first. SIEM shipping goes through a bounded queue.
- Each target is measured by an extended `scripts/bench_overhead.py`. If a release misses it, that is a release blocker, and the target is not relaxed.

## Security decisions and rationale

1. **Rebuild requests, never forward bytes.** This removes whole classes of smuggling and header-injection bugs, and makes the upstream contract explicit.
2. **Buffered streaming by default.** Correctness over latency. The weaker modes are opt-in and visible.
3. **Per-request taint on the model path, sticky taint on the MCP path.** Each matches where untrusted content actually enters the context.
4. **Strip denied tool calls rather than fail the whole response.** The user still gets the text. The denial is audited, and the client sees a fixed notice without the policy detail.
5. **Fail closed on audit failure.** A central chokepoint that cannot record what it did is not providing the control it claims.
6. **Loopback bind, separate admin listener, no remote admin API.** The smallest possible exposed surface.
7. **Secrets only by reference** (`env:`, `file:`); literals are rejected at config load.
8. **Trusted-header identity only with a peer allowlist.** Header trust is a network property, so it is configured as one.

## Phased rollout

- **MVP (phase 1), the smallest useful slice**: non-streaming and `buffer`-mode streaming chat completions; one or more upstreams; trusted-header identity; one bundle-less policy set from a local file whose SHA-256 is recorded as `policy_rev`; tool-call stripping, request tool filtering, input screening and output guard; per-replica limits; audit to file and CEF; `/healthz`, `/readyz`; loopback bind and TLS; monitor mode. This already makes the gateway the only path to Ollama, with central audit.
- **Phase 2**: OIDC JWT, per-group policy, signed bundles with hot reload, `/metrics`, `holdback` mode, `OpenAICompatTarget`.
- **Phase 3**: the MCP gateway (streamable HTTP facade over `GuardedMCPClient`, namespacing, pins in bundles).
- **Phase 4**: a shared limit store for multi-replica, approval workflow, personal access tokens for IDE clients, embeddings.

## Open questions

1. **IDE client credentials.** Resolved: gateway-minted access tokens (stored hashed, short-lived, revocable, issued after SSO), see docs/GATEWAY.md. A local helper that refreshes OIDC tokens remains an option for clients that can run one.
2. **Users in several groups.** First match wins is predictable. The intersection of policies is safer but harder to reason about. Which do security teams expect?
3. **Approvals.** Deny is safe but blunt. Could MCP elicitation, or an out-of-band approval with a resumable call, work on the MCP path?
4. **Signing key custody.** Should `bundle sign` call into a KMS or HSM, or use Sigstore/cosign offline, or something else? This decides the `--key` format.
5. **Rewriting `role: tool` content** (spotlighting) changes what the model sees. Should it be the default, or opt-in per group?
6. **Prompt retention.** With `log_content: false`, strings of 64 characters or fewer (`preview_chars`) are still stored in full after redaction, so a short prompt is kept verbatim. Is that acceptable under the company's data classification, or should `preview_chars` be 0?
7. **Text-encoded tool calls** from small models. Is it worth parsing common formats on the gateway side?

## Testing plan

- **Unit**: tool-call stripping and `finish_reason` fix-up; field allowlisting; `tool_choice` naming a filtered tool; config and bundle strictness (unknown keys, literals where references are required).
- **Streaming property tests**: a secret, an exfil link and a markdown image, each split at **every byte offset** across chunks. `holdback` must redact all of them within the window and flag them after delivery beyond it, and `buffer` must never release them. Tool-call fragments are reordered and interleaved across indexes.
- **Authentication**: `alg: none`; HS256 signed with the public key; wrong `iss`/`aud`; expired and not-yet-valid tokens; an unknown `kid` flood; a spoofed identity header from an untrusted peer; duplicate identity headers; header mode with JWT mode.
- **HTTP hardening**: CL+TE, duplicate `Content-Length`, oversized headers, slow body, and a model name that looks like a URL.
- **Bundles**: bad signature, file hash mismatch, rollback, expiry, truncated archive, hot reload during in-flight requests (the audit must show the starting revision).
- **Failure-mode table**: one test per row, injecting the fault (sink raising, JWKS 500, upstream timeout).
- **Fuzzer against the gateway**: add `OpenAICompatTarget` (`--target openai-compat:https://127.0.0.1:8443/v1#model=llama3.1-8b`, token from an env reference). In CI, offline: gateway → fake OpenAI-compatible upstream backed by `NaiveAgent` → `--categories tool_misuse,exfiltration,prompt_leak --max-asr 0`, in every stream mode. By hand: gateway → Ollama, comparing the attack-success rate with and without the gateway, recorded as in PROOF.md.
- **Audit**: `agentsec audit verify` on every test run's log; every record carries `actor`, `groups` and `policy_rev`.
- **Load**: hold the performance budget at a target concurrency, and check that limits stay exact under concurrency.
