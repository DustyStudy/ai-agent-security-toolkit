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

1. **Identity.** The user header is accepted only when the TCP peer is in `identity.trusted_proxies`. A missing, empty, repeated or untrusted header gets a 401. `allowed_groups` restricts access by group.
2. **Rebuild the request.** Only known fields go upstream (`model`, `messages`, `tools`, `tool_choice`, `temperature`, `max_tokens`, ...). `model` picks a configured upstream by name, so a client can never choose a URL. `max_tokens` is capped and `n` must be 1.
3. **Filter tools.** Tools the policy does not allow, and tool definitions that look poisoned, are removed before the model sees them. A `tool_choice` naming a removed tool gets a 400.
4. **Screen input.** Every message is scanned for prompt injection. `role: tool` messages count as untrusted and taint the request, whatever their content, so the policy's taint rules (deny side-effecting tools after reading untrusted content) apply to the answer. A flagged message blocks the request.
5. **Check the answer.** Each `tool_calls` entry goes through `ToolGuard.authorize` (allowlist, argument rules, per-request limits, taint). Denied calls are removed. Allowed ones are re-serialized from the arguments that were checked and get a gateway-issued id; a call whose arguments contain a secret or a protected string is withheld too. Text goes through `OutputGuard` (secrets, PII, exfiltration links, dangerous markup). Unknown response fields are dropped.
6. **Streaming** (`stream: true`) is served from the checked answer: the gateway calls the model without streaming, checks the whole answer, then sends it as SSE chunks. Time to first token is the full generation time.
7. **Audit.** Every request, decision and change goes to a hash-chained JSONL log, with the user as `actor`, the request id as `session_id`, and the group list and policy revision on the request record. `cef_file` adds a CEF copy for a SIEM forwarder.

`mode: monitor` computes and logs every decision but delivers requests and answers unchanged. Identity, body and rate limits apply in both modes.

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
| Rate or concurrency limit | 429 |

## Deployment requirements

- **The gateway must be the only route to the model servers.** Ollama has no authentication; bind it to localhost or a network only the gateway can reach. Otherwise users skip the gateway.
- **TLS.** A non-loopback `listen.host` needs `listen.tls`, or `tls_terminated_by_proxy: true` when the auth proxy terminates TLS on the same host or a trusted network.
- **One process.** Rate limits and the audit chain are per process. Run one replica per audit file.
- **Secrets by reference.** Upstream keys are `env:NAME` or `file:/path`; literals are refused.

## Limits in this version

- Identity is trusted-header only; OIDC tokens, signed policy bundles, per-group policies and the MCP gateway are later phases of the design.
- Tool-call limits (`max_calls`) count per request, not per user over time.
- Path and URL argument rules are evaluated on the gateway host, which may not match where the client runs the tool.
- Models that write tool calls as JSON text instead of `tool_calls` are not recognised as tool calls.
- The whole history is rescanned and re-audited on every turn.
- With `log_content: false`, prompt and answer strings over 64 characters are stored as a hash and length; shorter ones, such as a short prompt, are stored in full after redaction. Decision fields (`reasons`, `error`, `tools`, `validators`, `signals`, `policy_rev`, `groups`) stay readable. Denial reasons can name a URL's host.
- A client disconnect does not cancel the upstream call.
