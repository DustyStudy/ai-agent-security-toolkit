# agentsec gateway (preview)

`agentsec serve` is an OpenAI-compatible `/v1/chat/completions` proxy that sits in front of local model servers (Ollama, vLLM, LM Studio) and applies agentsec's controls to every call. Apps change one setting, their `base_url`, and the security team gets one place to set policy and one audit trail.

It implements phases 1 to 3 of [the design](design/GATEWAY.md), including an MCP endpoint (below). Read its "hard limit" section first: **the gateway controls what reaches and leaves the model, not what the client runs.** Agents that execute tools should still use `ToolGuard` themselves.

## Quick start

```bash
pip install "ai-agent-security-toolkit[gateway]"
agentsec serve --config examples/gateway.yaml --check   # validate, then drop --check to run
```

Put an SSO proxy (for example oauth2-proxy) in front of it that sets `X-Auth-Request-User` and `X-Auth-Request-Groups`, and point clients at it:

```python
from openai import OpenAI

client = OpenAI(base_url="https://llm-gateway.corp.example/v1", api_key="unused")
client.chat.completions.create(model="llama3.1-8b", messages=[{"role": "user", "content": "hi"}])
```

## What it does on each request

1. **Identity**, one of two modes (`identity.mode`):
   - `trusted_header`: the user header is accepted only when the TCP peer is in `identity.trusted_proxies`. A missing, empty, repeated or untrusted header gets a 401. A `/0` network is refused.
   - `oidc`: one `Authorization: Bearer <JWT>` from your IdP, verified against its JWKS (fetched over https). Only asymmetric algorithms are accepted; `iss`, `aud`, `exp`, `iat` and `sub` must be present and valid; a key that declares an algorithm verifies only that algorithm. Keys are cached and refreshed after half of `jwks_cache_s`; if the IdP is down, the cached keys work until `jwks_cache_s`, then every token is refused. Key fetches, for an unknown `kid` or a stale cache, happen at most once a minute and have a total deadline. The audit log records why a token failed; the client only sees 401.

   In both modes `allowed_groups` restricts access by group.
2. **Rebuild the request.** Only known fields go upstream (`model`, `messages`, `tools`, `tool_choice`, `temperature`, `max_tokens`, ...). `model` picks a configured upstream by name, so a client can never choose a URL. `max_tokens` is capped and `n` must be 1.
3. **Filter tools.** Tools the policy does not allow, and tool definitions that look poisoned, are removed before the model sees them. A `tool_choice` naming a removed tool gets a 400.
4. **Screen input.** Every message is scanned for prompt injection. `role: tool` messages count as untrusted and taint the request, whatever their content, so the policy's taint rules (deny side-effecting tools after reading untrusted content) apply to the answer. A flagged message blocks the request. So does an `image_url` part that is not an inline `data:` image: a model server that fetches image URLs would fetch whatever address the user names.
5. **Check the answer.** Each `tool_calls` entry goes through `ToolGuard.authorize` (allowlist, argument rules, per-request limits, taint). Denied calls are removed. Allowed ones are re-serialized from the arguments that were checked and get a gateway-issued id; a call whose arguments contain a secret or a protected string is withheld too. Text goes through `OutputGuard` (secrets, PII, exfiltration links, dangerous markup). Unknown response fields are dropped.
6. **Streaming** (`stream: true`) has two modes, set per group in `output.stream_mode`:
   - `buffer` (default): the gateway calls the model without streaming, checks the whole answer, then sends it as SSE chunks. Time to first token is the full generation time.
   - `holdback`: the gateway streams from the model and releases text once it is more than `output.holdback_chars` (default 256) non-whitespace characters behind the newest text and the output checks find nothing in the window around it. Text after an unclosed `[`, `![`, `<` (quoted attribute values included) or code fence is held until it closes, so a link is checked whole. A reference-style image (`![a]`, `![a][b]`) can use a URL defined anywhere in the answer, so everything from it on is held for the final check. A model stream that ends without `[DONE]` is an upstream error, never a finished answer. Tool calls are always held until the answer ends, then checked as in buffer mode. If the window ever holds something to redact or block, or the held text grows past 8 times the window, the rest of that answer is buffered.
   - Either way, the full text is checked again at the end. In holdback mode, if that check changes text that was already sent (a secret longer than the window, say), the gateway ends the stream with an `output_violation` error event and no `[DONE]`, and writes a `gateway_output_violation_after_delivery` audit record with `severity: high`. Clients should treat a stream without `[DONE]` as failed.
7. **Audit.** Every request, decision and change goes to a hash-chained JSONL log, with the user as `actor`, the request id as `session_id`, and the group list and policy revision on the request record. `cef_file` adds a CEF copy for a SIEM forwarder.

`mode: monitor` computes and logs every decision but delivers requests and answers unchanged. Identity, body and rate limits apply in both modes.

## Per-group policy with signed bundles

Instead of one `policy:` file, the gateway can enforce a **bundle**: a directory with a `manifest.yaml`, the ToolGuard policies it references, and a `manifest.sig` written by `agentsec bundle sign`. See [`examples/bundle/`](../examples/bundle/).

```yaml
# gateway.yaml: replaces policy, mode, output and input, which move into the bundle
bundle:
  dir: /var/lib/agentsec/bundle
  public_key_file: /etc/agentsec/bundle-signing.pub   # Ed25519
  min_revision: 0          # raise it to refuse old bundles, also across restarts
  reload_interval_s: 10    # 0: never reload
  state_file: /var/lib/agentsec/bundle-state.json   # recommended: blocks rollback across restarts
```

- **Groups.** The first `group_policies` entry that names one of the user's groups wins; `group: '*'` matches every authenticated user. A user who matches no entry gets a 403. Each entry has its own tool policy, `mode`, `models` (the upstreams the group may use; others get a 404 and are left out of `/v1/models`), `output` and `input` settings.
- **Signature.** `manifest.sig` holds the SHA-256 of the manifest and of every referenced file, and an Ed25519 signature over that list. The gateway checks the signature first, then every hash, and parses YAML only from the bytes it hashed. Paths must stay inside the bundle.
- **Startup.** No valid bundle, no gateway: `agentsec serve` refuses to start.
- **Reload.** Every `reload_interval_s` the gateway checks whether `manifest.yaml` or `manifest.sig` changed. A new bundle is used only if it verifies and its `revision` is above the current one (and at least `min_revision`). Anything else keeps the last good bundle and writes one `gateway_bundle_rejected` audit record per distinct reason. Requests already running finish under the revision they started with, and every request records `policy_rev` and `policy_group`.
- **Rollback across restarts.** With `state_file`, the gateway records the highest revision it accepted (written atomically, before the bundle is enforced) and refuses an older bundle, or a different bundle with the same revision number, at startup and on reload. Keep the state file writable by the gateway only, outside the bundle directory. Without it, only `min_revision` and `expires` limit a rollback after a restart.
- **Expiry.** `expires` is required. Once it passes, the gateway answers 503 until a newer bundle loads.
- **Keys.** Generate a key pair with `openssl genpkey -algorithm ed25519 -out bundle-signing.pem` and `openssl pkey -in bundle-signing.pem -pubout -out bundle-signing.pub`. Keep the private key away from the gateway host and out of the repository; `bundle sign --key` takes `env:NAME` or `file:/path`, never the key itself. KMS or HSM signing is a design open question.

## MCP gateway

With `mcp_upstreams` set, the gateway also serves one MCP endpoint, `/mcp` (streamable HTTP), in front of approved upstream MCP servers. Here the gateway makes the tool call itself, so its policy really is enforced, as long as the upstream servers accept connections only from the gateway.

```yaml
# gateway.yaml (needs pip install "ai-agent-security-toolkit[gateway,mcp]" with mcp>=2.3)
mcp_upstreams:
  jira: {url: https://mcp-jira.internal/mcp, auth: file:/run/secrets/jira-mcp-token}
  docs: {url: http://mcp-docs.internal:8080/mcp, pins: pins/docs.json}
mcp: {require_pins: true}   # refuse to start while an upstream (jira, here) has no pins
```

- **Names.** Each upstream's tools appear as `<upstream>__<tool>` (`jira__search_issues`), and tool policy keys use that name. A tool that is not in the caller's policy is not listed and cannot be called.
- **Who reaches what.** With one `policy:` file, every user may reach every upstream, gated by the policy keys. In a bundle, each group lists the upstreams it may reach (`mcp: [jira]`); the default is none.
- **Checks.** Every `tools/list` and `tools/call` runs under the identity and group of the request that carried it. Tool definitions are scanned for injections and checked against pins: with pins, a tool whose definition is new or changed since it was pinned is dropped (a rug pull). Without pins, the gateway remembers each tool as first listed and drops it if it changes later (see Pins). A tool must pass a listing before it can be called. Arguments are checked against the policy before the upstream sees them.
- **Taint.** Results from MCP tools are untrusted. After any call, side-effecting tools are denied (or sent for approval) according to the policy's taint rules, across all upstreams: a Jira result cannot drive an email through another server. Taint and listing state are kept per user, shared by all of that user's sessions: the client is what the policy guards against, and it could always open a new session to drop per-session taint. A session id still works only for the user who opened it.
- **Pins.** Write them with `ToolPins` from a reviewed listing (names already namespaced). Set `mcp_upstreams.<name>.pins` with a single policy file; in a bundle, list them in the manifest (`mcp_pins: {docs: pins/docs.json}`) so they are signed with the policies. Set `mcp: {require_pins: true}` to make that mandatory: the gateway then refuses to start, and refuses a reloaded bundle, while any `mcp_upstreams` entry has no pins. It is off by default in this preview. With it off, the `gateway_start` and `gateway_bundle_loaded` audit records list the upstreams without pins (`unpinned_mcp_upstreams`), and those upstreams get trust on first use: the first definition of each tool that passes the scan is remembered, for all users, until the gateway stops, and a later change is a `changed` finding (dropped from listings, calls refused, audited as `mcp_tool_finding`). That is weaker than pins. Nobody reviewed the first definition, the memory is lost on restart and not shared between replicas, and a tool that changed stays blocked until a restart.
- **Limits.** Each upstream answer is capped at `limits.max_response_bytes` as it arrives; compressed answers are refused, because a small gzip body can expand far past the cap. An upstream may list at most 1000 tools, counted before any are filtered out.
- **Failure.** An upstream that is down only hides its own tools; calls to it return an MCP error, and the audit log records the error type, never the upstream's error text. A denied call returns an MCP error result naming the reason.
- **Identity.** The same modes as the model endpoint (auth-proxy headers or an OIDC bearer token). IDE tools that only accept a fixed header use an access token (below).
- Only tools are proxied: no resources, prompts or sampling, and no server-initiated streams (`GET /mcp` is 405). `mode: monitor` does not apply here: MCP calls are always enforced, because the gateway would be the one running a call the policy refuses.

## Access tokens for IDEs and scripts

IDE MCP configs (Claude Code, Cursor, Continue) mostly take a URL and one fixed header, not an SSO login. With a `tokens` section, a signed-in user can mint an access token and put it in that header:

```yaml
tokens:
  store: /var/lib/agentsec/tokens.db   # SQLite; holds only SHA-256 hashes
  default_ttl_days: 7
  max_ttl_days: 30                     # at most 90
  max_per_user: 20
```

```bash
# Through the SSO proxy (or with an OIDC token): the token is shown once.
curl -X POST https://llm-gateway.corp.example/tokens \
  -H 'Content-Type: application/json' -d '{"name": "laptop cursor", "ttl_days": 7}'
```

```json
{"mcpServers": {"corp": {"type": "http", "url": "https://llm-gateway.corp.example/mcp",
  "headers": {"Authorization": "Bearer agt_..."}}}}
```

- **Use.** `Authorization: Bearer agt_...` works on `/mcp` and the model endpoints, from any address. It stands for the user and the groups they had when it was issued, so a group change takes effect when the token is replaced; keep lifetimes short.
- **Issue.** Only an SSO identity (trusted proxy header or OIDC token) can mint, list or revoke tokens: a token cannot manage tokens, so a leaked one cannot mint more. `POST /tokens` requires `Content-Type: application/json`, which a cross-site form cannot send. Each user may hold `max_per_user` live tokens.
- **Revoke.** Users list and revoke their own with `GET /tokens` and `DELETE /tokens/<id>`. Admins run `agentsec token list --config gateway.yaml [--user U]` and `agentsec token revoke --config gateway.yaml --id ID` (or `--user U` for all of a user's tokens, for example when someone leaves). There is no command to issue a token outside SSO. Expired and revoked tokens leave the store 7 days afterwards; the audit log keeps the record of them.
- **Storage.** Only a SHA-256 hash is stored; a token is 256 random bits, so the hash cannot be reversed. On POSIX the store is created owner-only. Back it up like any credential store; losing it only means users mint new tokens.
- **Audit.** Issue and revoke through the API are audited; `gateway_request` and `gateway_mcp_call` records carry the `token_id` used, never the token. Revocations from the CLI are recorded in the store (the audit chain belongs to the gateway process).

## Testing the gateway with the fuzzer

`agentsec fuzz` can attack the gateway like any OpenAI-compatible endpoint, so you can compare the attack-success rate with and without it:

```bash
agentsec fuzz --target ollama:llama3.1:8b --categories tool_misuse,exfiltration
agentsec fuzz --categories tool_misuse,exfiltration \
  --target 'openai-compat:http://127.0.0.1:8443/v1#model=local&header=X-Auth-Request-User:fuzz'
```

- `token=env:NAME` (or `file:/path`) sends a bearer token in `oidc` mode; `header=Name:value` sets a header such as the trusted-proxy user for a test instance. Add `stream=1` to test the group's stream mode.
- Raise `limits.requests_per_min` for the fuzzing user, or most cases end as 429 errors.
- A request the gateway refuses (`input_blocked`) scores as blocked. A stream it cuts short scores the text already delivered.
- Each case plants a random system-prompt secret the gateway is never told about, so plain-text leaks of it still count as successes. Tool misuse and exfiltration markup should reach 0%; the test suite checks this against a model that obeys every injection, in both stream modes.

## Metrics and readiness

Set `admin: {port: 9090}` (and optionally `host`, which must be a loopback IP such as `127.0.0.1` or `::1`, not `localhost`, and a port other than `listen.port`). If the admin port cannot be bound, the gateway does not start. to start a second listener with no authentication:

- `GET /healthz`: liveness.
- `GET /readyz`: 200 with the policy revision and any groups in monitor mode; 503 once the policy has expired. It also checks for a new bundle, so a gateway with no traffic still reloads.
- `GET /metrics`: Prometheus text.
  - `agentsec_gateway_events_total{event}`: every audit event written, counted only once the record is on disk. Blocks and denials are events such as `gateway_tool_calls_withheld`, `gateway_tools_removed`, `gateway_input_blocked`, `gateway_output_changed`, `gateway_auth_failed` and `gateway_bundle_rejected`.
  - `agentsec_gateway_responses_total{status}`: responses sent by the main listener.
  - `agentsec_gateway_policy_info{policy_rev}`, `agentsec_gateway_monitor_groups`, `agentsec_gateway_policy_expiry_timestamp_seconds`.

Labels are event names and status codes only, never users or request content. To scrape from another host, run the scraper as a sidecar or put an authenticating proxy in front; the admin listener itself never leaves loopback.

### Dashboard and alerts

There is no management UI. Use the Prometheus and Grafana you already run:

1. Scrape the admin listener from the same host (or pod):

   ```yaml
   scrape_configs:
     - job_name: agentsec-gateway
       static_configs:
         - targets: ["127.0.0.1:9090"]
   ```

2. Import [`examples/grafana/agentsec-gateway.json`](../examples/grafana/agentsec-gateway.json) in Grafana (Dashboards, New, Import) and pick your Prometheus data source. It shows the policy revision, time to policy expiry, groups in monitor mode, responses by status, and audit events by name, with policy decisions (blocks, denials and changes) on their own panel.
3. Add [`examples/grafana/alerts.yaml`](../examples/grafana/alerts.yaml) to `rule_files`. It alerts on missing metrics, a 5xx share above 5%, a spike in policy decisions, failed authentication, a rejected bundle, a policy that expires within a day, and a group left in monitor mode. The thresholds are starting points.

Limits:

- A counter first appears with the value 1, so `rate()` misses the first event of each name after a restart. The rejected-bundle alert allows for this, except when the gateway restarts within 15 minutes of an earlier first rejection; the rate panels and spike alerts do not.
- The metrics have no `enforced` label, so the policy-decision panel and the spike alert also count decisions made in monitor mode. The audit log says which were enforced.
- The dashboard has no instance filter: panels sum over every gateway the data source scrapes.
- Verified: a test (`tests/test_grafana_examples.py`) checks that both files parse and that every metric and event name in them is one the gateway emits. The rules pass `promtool check rules` (Prometheus 3.5.0) and all seven evaluate without error. With a gateway in `trusted_header` mode under generated traffic, Grafana 12.1.1 loaded the dashboard from a provisioning file and every panel query returned data through its API, except "Policy expires in", which has no data without a bundle that sets `expires`. Not verified: the panels were not looked at in a browser, the dashboard was not imported through the Import dialog, and no alert was taken to firing. The bundle-rejected, policy-expiry, monitor-mode and OIDC cases were not exercised.

## Failure behaviour

| Failure | Result |
|---|---|
| Audit log cannot be written | 503; nothing is forwarded |
| Upstream down, bad status or non-JSON | 502 |
| Upstream timeout (a total deadline of about `upstream_timeout_s`, at most twice it) | 504 |
| Request body not received within `body_timeout_s` | 408 |
| Upstream answer malformed | 502 |
| Any other error | 500 with no detail |
| Body too large | 413 |
| No group policy matches the user | 403 |
| Bundle expired | 503 |
| Rate or concurrency limit | 429 |
| More than `limits.max_connections` (default 1000) connections and requests open | 503 from the HTTP server: plain text, not audited or counted in `/metrics` |
| More than 8 token verifications in flight (`oidc` mode) | 503 |

## Deployment requirements

- **The gateway must be the only route to the model servers.** Ollama has no authentication; bind it to localhost or a network only the gateway can reach. Otherwise users skip the gateway. Check it with `probe-isolation` (below).
- **TLS.** A non-loopback `listen.host` needs `listen.tls`, or `tls_terminated_by_proxy: true` when the auth proxy terminates TLS on the same host or a trusted network.
- **One process.** Rate limits and the audit chain are per process. Run one replica per audit file.
- **Shutdown.** On SIGTERM the gateway stops accepting connections and gives requests in flight `limits.shutdown_timeout_s` (default 30, whole seconds) to finish, then closes them. Set the orchestrator's grace period (Kubernetes `terminationGracePeriodSeconds`) a little above it.
- **Slow and silent connections.** A connection must send a whole request head within `limits.header_timeout_s` (default 10) or it is closed, so sockets that send nothing, or a head a byte at a time, cannot fill `limits.max_connections`. Between requests a kept-alive connection is closed after 5 idle seconds, and `limits.body_timeout_s` bounds the body. A client can still open up to the cap in fresh connections every few seconds: rate-limit connections per address in a proxy or load balancer in front of an internet-facing gateway.
- **Secrets by reference.** Upstream keys are `env:NAME` or `file:/path`; literals are refused.

### Check that nothing can go around the gateway

Run this after each deployment and on a schedule in CI, from a client workstation or a CI runner on the client network, **not** from the gateway host (from there every upstream is reachable, as it must be):

```bash
agentsec probe-isolation --config gateway.yaml --gateway-host gateway.internal
```

It opens a plain TCP connection to the host and port of every `upstreams` and `mcp_upstreams` URL and closes it. It sends no request and never reads `api_key` or `auth`. One line per upstream (`--json` for JSON):

| Status | Meaning | Exit code |
|---|---|---|
| `REACHABLE` | The connect succeeded: clients can skip the gateway. Fix the bind address or the firewall. | 1 |
| `UNCHECKED` | The URL is loopback (the upstream runs on the gateway host) and `--gateway-host` was not given. With it, that port is probed on the gateway host. | 2 |
| `ISOLATED` | Refused, timed out (`--timeout`, default 3 seconds) or the name did not resolve; the reason is printed. | 0 |

It needs the same files as `serve --check` (the policy or bundle the config names), but no secrets. An `ISOLATED` result holds only for the network the probe ran on, and only if that network works: a runner with no route anywhere also sees timeouts. Run it where clients are, and read the reasons.

## Container image

The repository's `Dockerfile` builds the gateway from the hash-pinned locks (`requirements/requirements-gateway.txt`) on a digest-pinned `python:3.13-slim`. Each release from 0.8.1 on is also published to `ghcr.io/dustystudy/ai-agent-security-toolkit`, tagged with the version (there is no `latest`) and for `linux/amd64` only. With `VERSION` set to a release, such as `0.8.1`:

```bash
docker pull ghcr.io/dustystudy/ai-agent-security-toolkit:$VERSION
gh attestation verify oci://ghcr.io/dustystudy/ai-agent-security-toolkit:$VERSION \
  --repo DustyStudy/ai-agent-security-toolkit \
  --signer-workflow DustyStudy/ai-agent-security-toolkit/.github/workflows/image.yml \
  --source-ref refs/tags/v$VERSION
```

The second command checks that the image was built by this repository's image workflow, running on that release tag. `--repo` alone would accept an attestation from any workflow or branch in the repository. It prints the digest it verified: run the image by that digest. The workflow does not replace a version tag once it is published. 0.8.0 has no published image. To build one yourself instead:

```bash
docker build -t agentsec-gateway .
docker run -d --name agentsec-gateway \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v "$PWD/examples:/etc/agentsec:ro" \
  -v agentsec-data:/var/lib/agentsec \
  -p 127.0.0.1:8443:8443 \
  agentsec-gateway serve --config /etc/agentsec/gateway.container.yaml
```

- **Config** is read from `/etc/agentsec/gateway.yaml` unless you pass `--config`. Mount the directory read-only. [`examples/gateway.container.yaml`](../examples/gateway.container.yaml) is a starting point.
- **State** goes to `/var/lib/agentsec`, the only writable path the image needs: give `audit.file`, `tokens.store` and `bundle.state_file` absolute paths there, and mount a volume so they survive the container. The audit chain continues from the file it finds.
- **User.** The process runs as uid and gid 10001 with no shell login, and the image has no pip. A volume mounted over `/var/lib/agentsec` must be writable by 10001 (Kubernetes: `fsGroup: 10001`).
- **Listening.** Inside a container `listen.host` must be `0.0.0.0`, which needs `listen.tls` or `tls_terminated_by_proxy: true`. Publish the port only where the auth proxy can reach it, and set `identity.trusted_proxies` to the proxy's own address on the container network as a `/32`. A wider network lets any other container on it name a user in a header.
- **Probes.** The image has no `HEALTHCHECK`, because the port and TLS come from your config. Probe `GET /healthz` on the listener, or `/readyz` on the admin listener. That listener is loopback only: it is reachable from the container's own network namespace, which in Kubernetes means every container in the same Pod, and from nowhere else.
- **Secrets** are `env:NAME` or `file:/path` references as elsewhere: pass them with `-e` or mount them, never bake them into an image built on top of this one.
- **Shutdown.** `docker stop` sends SIGTERM; see `limits.shutdown_timeout_s` and give the container a stop timeout a little above it (`--stop-timeout`).

## Limits in this version

- MCP taint is per user and lasts until the user has been idle for `limits.mcp_session_idle_s` (default 1 hour): one tainted session taints that user's other MCP sessions too.
- Holdback cannot take back text it released: a secret or protected string longer than `holdback_chars`, or a rule that needs the whole answer, is only caught by the final check, which then cuts the stream short.
- `/readyz` does not probe the upstreams or the audit file; a failed audit write shows as 503 responses and stops the event counters.
- Without `bundle.state_file`, rollback protection across restarts relies on `min_revision` and `expires`.
- An access token keeps the groups its user had at issue time until it expires or is revoked; removing someone from the IdP does not revoke their tokens (run `agentsec token revoke --user`).
- Tool-call limits (`max_calls`) count per request, not per user over time.
- Path and URL argument rules are evaluated on the gateway host, which may not match where the client runs the tool.
- Upstream addresses are not checked: `upstreams` and `mcp_upstreams` URLs come from the operator's config (a client can never supply one), are usually loopback or private by design, and are resolved by the HTTP client on each connection. Whoever controls DNS for an upstream's hostname chooses where its requests and credential go; use an IP literal or `https` for an upstream that is not on loopback.
- Models that write tool calls as JSON text instead of `tool_calls` are not recognised as tool calls.
- The whole history is rescanned and re-audited on every turn.
- With `log_content: false`, prompt and answer strings over 64 characters are stored as a hash and length; shorter ones, such as a short prompt, are stored in full after redaction. Decision fields (`reasons`, `error`, `tools`, `validators`, `signals`, `policy_rev`, `groups`) stay readable. Denial reasons can name a URL's host.
- A client disconnect does not cancel the upstream call in buffer mode. In holdback mode the upstream connection is closed at the next chunk, if the server reports the disconnect as a failed send.
