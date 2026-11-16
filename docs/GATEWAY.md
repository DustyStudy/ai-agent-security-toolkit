# agentsec gateway (preview)

`agentsec serve` is an OpenAI-compatible `/v1/chat/completions` proxy that sits in front of local model servers (Ollama, vLLM, LM Studio) and applies agentsec's controls to every call. Apps change one setting, their `base_url`, and the security team gets one place to set policy and one audit trail.

This is phase 1 of [the design](design/GATEWAY.md). Read its "hard limit" section first: **the gateway controls what reaches and leaves the model, not what the client runs.** Agents that execute tools should still use `ToolGuard` themselves.

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
   - `trusted_header`: the user header is accepted only when the TCP peer is in `identity.trusted_proxies`. A missing, empty, repeated or untrusted header gets a 401.
   - `oidc`: one `Authorization: Bearer <JWT>` from your IdP, verified against its JWKS (fetched over https). Only asymmetric algorithms are accepted; `iss`, `aud`, `exp`, `iat` and `sub` must be present and valid; a key that declares an algorithm verifies only that algorithm. Keys are cached and refreshed after half of `jwks_cache_s`; if the IdP is down, the cached keys work until `jwks_cache_s`, then every token is refused. Key fetches, for an unknown `kid` or a stale cache, happen at most once a minute and have a total deadline. The audit log records why a token failed; the client only sees 401.

   In both modes `allowed_groups` restricts access by group.
2. **Rebuild the request.** Only known fields go upstream (`model`, `messages`, `tools`, `tool_choice`, `temperature`, `max_tokens`, ...). `model` picks a configured upstream by name, so a client can never choose a URL. `max_tokens` is capped and `n` must be 1.
3. **Filter tools.** Tools the policy does not allow, and tool definitions that look poisoned, are removed before the model sees them. A `tool_choice` naming a removed tool gets a 400.
4. **Screen input.** Every message is scanned for prompt injection. `role: tool` messages count as untrusted and taint the request, whatever their content, so the policy's taint rules (deny side-effecting tools after reading untrusted content) apply to the answer. A flagged message blocks the request.
5. **Check the answer.** Each `tool_calls` entry goes through `ToolGuard.authorize` (allowlist, argument rules, per-request limits, taint). Denied calls are removed. Allowed ones are re-serialized from the arguments that were checked and get a gateway-issued id; a call whose arguments contain a secret or a protected string is withheld too. Text goes through `OutputGuard` (secrets, PII, exfiltration links, dangerous markup). Unknown response fields are dropped.
6. **Streaming** (`stream: true`) is served from the checked answer: the gateway calls the model without streaming, checks the whole answer, then sends it as SSE chunks. Time to first token is the full generation time.
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
| More than 8 token verifications in flight (`oidc` mode) | 503 |

## Deployment requirements

- **The gateway must be the only route to the model servers.** Ollama has no authentication; bind it to localhost or a network only the gateway can reach. Otherwise users skip the gateway.
- **TLS.** A non-loopback `listen.host` needs `listen.tls`, or `tls_terminated_by_proxy: true` when the auth proxy terminates TLS on the same host or a trusted network.
- **One process.** Rate limits and the audit chain are per process. Run one replica per audit file.
- **Secrets by reference.** Upstream keys are `env:NAME` or `file:/path`; literals are refused.

## Limits in this version

- Metrics, holdback streaming and the MCP gateway are later phases of the design.
- Without `bundle.state_file`, rollback protection across restarts relies on `min_revision` and `expires`.
- IDE tools that only take a static API key cannot get an OIDC token; see the design's open questions.
- Tool-call limits (`max_calls`) count per request, not per user over time.
- Path and URL argument rules are evaluated on the gateway host, which may not match where the client runs the tool.
- Models that write tool calls as JSON text instead of `tool_calls` are not recognised as tool calls.
- The whole history is rescanned and re-audited on every turn.
- With `log_content: false`, prompt and answer strings over 64 characters are stored as a hash and length; shorter ones, such as a short prompt, are stored in full after redaction. Decision fields (`reasons`, `error`, `tools`, `validators`, `signals`, `policy_rev`, `groups`) stay readable. Denial reasons can name a URL's host.
- A client disconnect does not cancel the upstream call.
