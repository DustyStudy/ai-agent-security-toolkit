# agentsec gateway (preview)

`agentsec serve` is an OpenAI-compatible `/v1/chat/completions` proxy that sits in front of local model servers (Ollama, vLLM, LM Studio) and applies agentsec's controls to every call. Apps change one setting, their `base_url`, and the security team gets one place to set policy and one audit trail.

It implements phases 1 to 3 of [the design](design/GATEWAY.md), including an MCP endpoint (below). Read its "hard limit" section first: **the gateway controls what reaches and leaves the model, not what the client runs.** Agents that execute tools should still use `ToolGuard` themselves.

## Quick start

```bash
pip install "ai-agent-security-toolkit[gateway]"
export AGENTSEC_DLP_FINGERPRINT_KEY="$(openssl rand -hex 32)"   # the example's dlp.fingerprint_key
agentsec serve --config examples/gateway.yaml --check   # validate, then drop --check to run
```

On Windows PowerShell, which has no `openssl`, set the key with:

```powershell
$bytes = New-Object byte[] 32; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes); $env:AGENTSEC_DLP_FINGERPRINT_KEY = -join ($bytes | ForEach-Object { $_.ToString("x2") })
```

Put an SSO proxy (for example oauth2-proxy) in front of it that sets `X-Auth-Request-User` and `X-Auth-Request-Groups`, and point clients at it:

```python
from openai import OpenAI

client = OpenAI(base_url="https://llm-gateway.corp.example/v1", api_key="unused")
client.chat.completions.create(model="llama3.1-8b", messages=[{"role": "user", "content": "hi"}])
```

## What it does on each request

1. **Identity**, one of two modes (`identity.mode`):
   - `trusted_header`: the user header is accepted only when the TCP peer is in `identity.trusted_proxies`. A missing, empty, repeated or untrusted header gets a 401. A `/0` network is refused, and so is a network with host bits set or broader than /16 (IPv4) or /48 (IPv6).
   - `oidc`: one `Authorization: Bearer <JWT>` from your IdP, verified against its JWKS (fetched over https). Only asymmetric algorithms are accepted; `iss`, `aud`, `exp`, `iat` and `sub` must be present and valid; a key that declares an algorithm verifies only that algorithm. Keys are cached and refreshed after half of `jwks_cache_s`; if the IdP is down, the cached keys work until `jwks_cache_s`, then every token is refused. Key fetches, for an unknown `kid` or a stale cache, happen at most once a minute and have a total deadline. The audit log records why a token failed; the client only sees 401.

   In both modes `allowed_groups` restricts access by group.
2. **Rebuild the request.** Only known fields go upstream (`model`, `messages`, `tools`, `tool_choice`, `temperature`, `max_tokens`, ...). `model` picks a configured upstream by name, so a client can never choose a URL. `max_tokens` is capped and `n` must be 1.
3. **Filter tools.** Tools the policy does not allow, and tool definitions that look poisoned, are removed before the model sees them. A `tool_choice` naming a removed tool gets a 400.
4. **Screen input.** Every message is scanned for prompt injection. `role: tool` messages count as untrusted and taint the request, whatever their content, so the policy's taint rules (deny side-effecting tools after reading untrusted content) apply to the answer. A flagged message blocks the request. Content parts are an allowlist: `text`, and `image_url` only as an inline `data:` image. A remote image URL is blocked here. Every other part type (`video_url`, `audio_url`, `input_audio`, `file`, ...) is refused with a 400 in every mode, because a model server that fetches a URL would fetch whatever address the user names.
   **Screen outbound.** The whole request that would go to the upstream is scanned under the group's `dlp` policy on the `upstream` surface: every role (system, developer, user, assistant), the full history, `tool_calls` arguments, tool results, tool definitions and `stop`. By default every category is `monitor`, so findings are only recorded. Per upstream, `upstreams.<name>.outbound.on_secret` (credentials and cloud or service tokens) and `outbound.on_pii` are `off` (use the group's modes), `block` or `redact`, so you can block PII to a third-party provider and allow it to a self-hosted model. **Recommended:** set `outbound.on_secret: block` on every upstream run by a third party (a hosted model API), so a credential pasted into a prompt or returned by a tool is never sent outside your network; `redact` is the alternative when a refused request is worse than a changed one. `block` refuses the request with a 400 (`outbound_blocked`) and nothing is sent; `redact` replaces each value with `[REDACTED:<kind>]` and sends the rest. Strings over the scan limit are treated as a finding. When anything on this surface is redact or block, attachments are refused, since they cannot be scanned. The audit log gets a `dlp_match` per finding (with `upstream` and the request path, such as `request.messages[2].content`) and `gateway_outbound_blocked` or `gateway_outbound_redacted` with the kinds and locations, never the value. This applies in `monitor` mode too, because it is an explicit data-handling setting.
5. **Check the answer.** Each `tool_calls` entry goes through `ToolGuard.authorize` (allowlist, argument rules, per-request limits, taint). Denied calls are removed. Allowed ones are re-serialized from the arguments that were checked and get a gateway-issued id; a call whose arguments contain a secret or a protected string is withheld too. Text goes through `OutputGuard` (secrets, PII, exfiltration links, dangerous markup). Unknown response fields are dropped.
6. **Streaming** (`stream: true`) has two modes, set per group in `output.stream_mode`:
   - `buffer` (default): the gateway calls the model without streaming, checks the whole answer, then sends it as SSE chunks. Time to first token is the full generation time.
   - `holdback`: the gateway streams from the model and releases text once it is more than `output.holdback_chars` (default 256) non-whitespace characters behind the newest text and the output checks find nothing in the window around it. Text after an unclosed `[`, `![`, `<` (quoted attribute values included) or code fence is held until it closes, so a link is checked whole. A reference-style image (`![a]`, `![a][b]`) can use a URL defined anywhere in the answer, so everything from it on is held for the final check. A model stream that ends without `[DONE]` is an upstream error, never a finished answer. Tool calls are always held until the answer ends, then checked as in buffer mode. If the window ever holds something to redact or block, or the held text grows past 8 times the window, the rest of that answer is buffered.
   - Either way, the full text is checked again at the end. In holdback mode, if that check changes text that was already sent (a secret longer than the window, say), the gateway ends the stream with an `output_violation` error event and no `[DONE]`, and writes a `gateway_output_violation_after_delivery` audit record with `severity: high`. Clients should treat a stream without `[DONE]` as failed.
7. **Audit.** Every request, decision and change goes to a hash-chained JSONL log, with the user as `actor`, the request id as `session_id`, and the group list and policy revision on the request record. `cef_file` adds a CEF copy for a SIEM forwarder.

`mode: monitor` computes and logs every decision but delivers requests and answers unchanged. Identity, body and rate limits apply in both modes.

## Data-loss prevention

Credentials, non-human identities (cloud and service tokens) and PII are checked under one `dlp` policy: top level in single-policy mode, or per group in a bundle entry. Each category gets a mode per surface: `monitor` (deliver and audit), `redact` (replace the value with `[REDACTED:<kind>]`) or `block` (withhold the answer, or deny the tool call). The design is in [design/DATA_LOSS_PREVENTION.md](design/DATA_LOSS_PREVENTION.md).

```yaml
dlp:
  fingerprint_key: env:AGENTSEC_DLP_FINGERPRINT_KEY   # optional, at least 32 bytes
  categories:
    credentials: {output: redact, tool_args: block}   # password=, Authorization, cookies, JWTs, private keys
    nhi: {output: redact, tool_args: block}           # AWS, GitHub, GitLab, Slack, Stripe, OpenAI, ... keys
    pii:
      output: redact                                  # SSNs and payment cards
      tool_args: monitor
      kinds:
        email: {output: monitor}                      # addresses are normal in answers and send_email
  allow:
    - id: support-mailbox
      reason: replies go to the shared support address
      owner: platform-security
      expires: 2027-02-28                             # required, at most 180 days ahead
      kinds: [email]
      tools: [send_email]                             # optional; surfaces: [...] too
      match: {email_domain: support.example.com}      # or hmac_sha256: <hex>, or pattern: (PII only)
```

**Allowlist expiry.** An entry stops matching the day after its `expires` date. At start and on every bundle load, the gateway writes `dlp_allow_expired` (entries that no longer match) and `dlp_allow_expiring` (entries that expire within 14 days) for each group, with the entry ids and dates. `agentsec bundle verify` prints the same as warnings. A gateway that runs for days without a reload logs these only at its last start or reload.

To allowlist one specific credential, token or number, put its keyed hash in `match.hmac_sha256`: `agentsec dlp hash --key env:AGENTSEC_DLP_FINGERPRINT_KEY` (the same reference as the policy's `fingerprint_key`, which such entries require) reads the value from stdin (without echo when typed at a terminal, so it stays out of shell history and the config), prints only its HMAC-SHA256, and says on stderr which built-in kind matches the whole value, or warns when none does (the hash must be of the exact matched span; for cards and SSNs, separators included). One trailing newline is dropped, so `agentsec dlp hash --key ... < value.txt` works. A plain `sha256` is refused: the bundle is readable by everyone who deploys it, and an unkeyed hash of a password, SSN or card number is reversed by trying every value. Rotating `fingerprint_key` invalidates these entries; re-hash them.

The values above are the defaults. `redact` in `tool_args` means block, because a rewritten argument changes the action. Text over the scan limit is blocked unless every kind on that surface is only monitored. References such as `$API_TOKEN` or `${{ secrets.X }}` are not findings.

**Custom detectors.** Add patterns for your own token formats or IDs under `dlp.detectors`. Each one takes the modes of its category (and can be overridden under `categories.<category>.kinds.<kind>`, or allowlisted, like a built-in kind):

```yaml
dlp:
  detectors:
    - kind: acme_service_token                  # lowercase, not a built-in kind
      category: nhi                             # credentials, nhi or pii
      pattern: 'acme_(?:live|test)_[A-Za-z0-9]{32}'
      examples: ["acme_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]   # required; each must match
      counter_examples: ["acme_live_short"]     # optional; none may match
```

At load each pattern must compile, be at most 512 characters, not match the empty string, match every example and no counter-example, and finish each of a set of 64 KB adversarial inputs (long runs of the pattern's own characters, with and without a tail that cannot match) in under 50 ms. That last check runs in a separate Python process that is stopped at the first slow input, so a catastrophic pattern such as `(a+)+$` is a config error in well under a second instead of a hung gateway. Matches of custom detectors are also replaced in the audit log's values and keys (`[REDACTED:<kind>]`), but never in the actor, session id or event name. With holdback streaming, `holdback_chars` must be at least 256 when a custom detector is redacted or blocked in answers; a match longer than the window can still be released in part, so keep custom patterns bounded. The allowlist takes `hmac_sha256` (not `pattern`) for custom `credentials` and `nhi` kinds, as for built-in ones.

The gateway enforces all four surfaces: `output` (answer text, buffered or holdback), `tool_args` (model path and MCP endpoint), `tool_results` (MCP tool results: redacted, or the result withheld) and `upstream` (the request sent to a model provider, see step 4). Each finding is one `dlp_match` audit record with `kind`, `category`, `surface`, `action` (`monitor`, `redact`, `block` or `allowed`), the position and length, the tool and argument path, `allowed_by` for allowlisted values, and, with `fingerprint_key` set, an HMAC fingerprint that lets you count repeats of one value. The value itself, or any part of it, is never recorded. Email addresses elsewhere in the audit log (tool arguments, answers) are written as `[REDACTED:email]`, or as their fingerprint under the request's group key when one is set; the user (`actor`) stays readable. `/metrics` counts findings as `agentsec_gateway_dlp_matches_total{category,surface,action}`. Published example values (the AWS documentation key, card networks' test numbers, `example.com` addresses) are recorded as `allowed_by: builtin`. With holdback streaming, `holdback_chars` must be at least 256 when email is redacted or blocked in answers.

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
  docs: {url: https://mcp-docs.internal/mcp, pins: pins/docs.json}
mcp: {require_pins: true}   # refuse to start while an upstream (jira, here) has no pins
```

- **Names.** Each upstream's tools appear as `<upstream>__<tool>` (`jira__search_issues`), and tool policy keys use that name. A tool that is not in the caller's policy is not listed and cannot be called.
- **Who reaches what.** With one `policy:` file, every user may reach every upstream, gated by the policy keys. In a bundle, each group lists the upstreams it may reach (`mcp: [jira]`); the default is none.
- **Checks.** Every `tools/list` and `tools/call` runs under the identity and group of the request that carried it. Tool definitions are scanned for injections and checked against pins: with pins, a tool whose definition is new or changed since it was pinned is dropped (a rug pull). Without pins, the gateway remembers each tool as first listed and drops it if it changes later (see Pins). A tool must pass a listing before it can be called. Arguments are checked against the policy before the upstream sees them.
- **Taint.** Results from MCP tools are untrusted. After any call, side-effecting tools are denied (or sent for approval) according to the policy's taint rules, across all upstreams: a Jira result cannot drive an email through another server. Taint and listing state are kept per user, shared by all of that user's sessions: the client is what the policy guards against, and it could always open a new session to drop per-session taint. A session id still works only for the user who opened it.
- **Results.** Before a tool result reaches the client, all of its text (text blocks, embedded resource text, every string in `structuredContent` and `_meta`) is scanned for injection, including hidden Unicode TAG characters, and a `gateway_mcp_result` audit record holds the signals. The group's `input` settings decide what happens, as they do for `role: tool` messages on the model path: with `block_on_injection` (the default) a flagged result is replaced by an MCP error result, and with `spotlight_tool_results` text blocks are wrapped as data. Secrets are redacted and a result holding a protected string is withheld; PII, links and markup are left alone, since that is what a search or a file read returns. A result that is over the scan limit (200,000 characters), embeds a binary resource, or cannot be read is withheld. Images and audio pass unscanned. In `mode: monitor` the record says what would have happened and the result is delivered unchanged, except a result that cannot be read at all, which is always withheld.
- **Pins.** Write them with `ToolPins` from a reviewed listing (names already namespaced). Set `mcp_upstreams.<name>.pins` with a single policy file; in a bundle, list them in the manifest (`mcp_pins: {docs: pins/docs.json}`) so they are signed with the policies. Set `mcp: {require_pins: true}` to make that mandatory: the gateway then refuses to start, and refuses a reloaded bundle, while any `mcp_upstreams` entry has no pins. It is off by default in this preview. With it off, the `gateway_start` and `gateway_bundle_loaded` audit records list the upstreams without pins (`unpinned_mcp_upstreams`), and those upstreams get trust on first use: the first definition of each tool that passes the scan is remembered, for all users, until the gateway stops, and a later change is a `changed` finding (dropped from listings, calls refused, audited as `mcp_tool_finding`). That is weaker than pins. Nobody reviewed the first definition, the memory is lost on restart and not shared between replicas, and a tool that changed stays blocked until a restart.
- **Limits.** Each upstream answer is capped at `limits.max_response_bytes` as it arrives; compressed answers are refused, because a small gzip body can expand far past the cap. An upstream may list at most 1000 tools, counted before any are filtered out.
- **Failure.** An upstream that is down only hides its own tools; calls to it return an MCP error, and the audit log records the error type, never the upstream's error text. A denied call returns an MCP error result naming the reason.
- **Identity.** The same modes as the model endpoint (auth-proxy headers or an OIDC bearer token). IDE tools that only accept a fixed header use an access token (below).
- Only tools are proxied: no resources, prompts or sampling, and no server-initiated streams (`GET /mcp` is 405). `mode: monitor` does not apply to calls: they are always enforced, because the gateway would be the one running a call the policy refuses.

## Access tokens for IDEs and scripts

IDE MCP configs (Claude Code, Cursor, Continue) mostly take a URL and one fixed header, not an SSO login. With a `tokens` section, a signed-in user can mint an access token and put it in that header:

```yaml
tokens:
  store: /var/lib/agentsec/tokens.db   # SQLite; holds only SHA-256 hashes
  default_ttl_days: 7
  max_ttl_days: 30                     # at most 90
  max_per_user: 20
  offboarding_deadline_s: 3600   # `agentsec token offboard` alerts past this
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
- **Revoke.** Users list and revoke their own with `GET /tokens` and `DELETE /tokens/<id>`. Admins run `agentsec token list --config gateway.yaml [--user U]` and `agentsec token revoke --config gateway.yaml --id ID` (or `--user U` for all of a user's tokens, for example when someone leaves). `token revoke` exits 1 when nothing matched. Admins re-enable a disabled user with `agentsec token enable --config gateway.yaml --user U`. There is no command to issue a token outside SSO. Expired and revoked tokens leave the store 7 days afterwards; the audit log keeps the record of them.
- **Storage.** Only a SHA-256 hash is stored; a token is 256 random bits, so the hash cannot be reversed. On POSIX the store is created owner-only. Back it up like any credential store; losing it only means users mint new tokens.
- **Audit.** Issue and revoke through the API are audited; `gateway_request` and `gateway_mcp_call` records carry the `token_id` used, never the token. Revocations from the CLI are recorded in the store (the audit chain belongs to the gateway process).
- **Offboarding.** `agentsec token offboard --config gw1.yaml [--config gw2.yaml ...] --ledger offboard.db [--events FILE|-]` revokes tokens when the identity provider disables a user or removes one from a group. The events are one JSON document, chosen because every IdP automation (an Okta Workflow or event hook, an Entra Logic App or lifecycle workflow, a Keycloak event listener) can post a flat payload from a script: `{"disabled_users": ["a@example.com"], "removed_groups": [{"user": "b@example.com", "group": "admins"}]}`. A disabled user loses every live token; for a removed group, only that user's tokens issued with that group are revoked (a token without it keeps working, as it never carried the access). Repeat `--config` for every gateway: each config's `tokens.store` is revoked, and the command touches only token stores, so run it where those files are reachable. A user disabled this way cannot be issued a new access token until `agentsec token enable` runs. The gateway also refuses that user's SSO identity (an OIDC bearer token or the trusted header) with 403 `user_disabled`. **Known gap:** the disabled list is the token store, so a gateway with no `tokens` section, or one whose store was not passed with `--config`, still accepts a disabled user's IdP-issued JWT until its own `exp`; keep IdP token lifetimes short. The toolkit has no IdP client; the automation supplies the document.
  - **Ledger.** Each (event, store) pair is a row in the SQLite `--ledger` that stays pending until that store accepts the revocation, so a store that is down is retried on the next run (run it from cron or a timer, with no `--events`, as well as from the IdP automation). Replays are safe; if a finished event arrives again, for a user who was re-enabled and then disabled, it is applied again. A pending row is not dropped when its config is no longer passed.
  - **Alert.** A row pending longer than `tokens.offboarding_deadline_s` (default 3600; `--deadline-s` overrides) makes the command exit 3 and print one `offboarding_overdue` JSON line per row on stderr. `--metrics-file` writes `agentsec_offboarding_pending` and `agentsec_offboarding_overdue` for node_exporter's textfile collector; alert on `agentsec_offboarding_overdue > 0` or on the exit code. Exit 1 means bad input, an unreadable config, or a token store that does not exist (its row stays pending, and the file is never created). The gateway's audit chain is not written (it belongs to the gateway process). Tokens stay valid until the command runs, so the real exposure is the time to your automation plus the deadline.

## Egress blocklist

The gateway can deny tool calls whose URL arguments point at hosts that threat feeds list as malicious: Spamhaus DROP (hijacked IP ranges) and abuse.ch host lists (malware and botnet domains), or any list in the same simple formats. Design and rationale: [design/EGRESS_BLOCKLIST.md](design/EGRESS_BLOCKLIST.md).

```yaml
# gateway.yaml
egress:
  public_key_file: feeds.pub        # Ed25519 key of the FEED signer (not the bundle key)
  blocklists:
    - {name: drop, kind: ip, file: /var/lib/agentsec/feeds/drop.txt, max_age_h: 48}
    - {name: urlhaus, kind: domain, file: /var/lib/agentsec/feeds/urlhaus-hosts.txt}
  except_hosts: []                  # never blocked by a feed, for false positives ("*.x" allowed)
  on_stale: warn                    # warn (default): keep the last good list | deny: refuse URL calls
  check_model_links: true           # also redact listed links in model answers
  state_file: egress-state.json     # optional: refuse a feed rollback across restarts
  reload_interval_s: 10
```

- **What is checked.** Every `type: url` argument, on the model path (the call is stripped in `enforce`, audited in `monitor`) and the MCP path (the upstream is never called). The host and every parent domain are matched against domain lists. An IP literal, and every address a name resolves to, are matched against IP lists; the lookup is shared with the private-address check. With `check_model_links`, links and images in model text are redacted if their host is listed; those hosts are never resolved.
- **Feed key.** Make a key pair for feeds only: `openssl genpkey -algorithm ed25519 -out feeds.key` and `openssl pkey -in feeds.key -pubout -out feeds.pub`. Copy only `feeds.pub` to the gateway. [examples/gateway.yaml](../examples/gateway.yaml) has this section commented out; uncomment it once signed feeds are in place, since a missing feed refuses startup.
- **The gateway never downloads feeds.** A job you run fetches each feed, signs it with `agentsec egress sign-feed FILE --kind ip --name drop --key file:/path/feeds.key`, and moves `FILE` and `FILE.sig` into place. [examples/egress/fetch-feeds.sh](../examples/egress/fetch-feeds.sh) is a starting point. Keep the feed key off the gateway host and away from the policy bundle key. `agentsec egress check-feed FILE --kind ip --name drop --public-key feeds.pub` checks a file without the gateway.
- **Feed format.** One entry per line. `#` and `;` start comments, also after an entry (`1.2.3.0/24 ; SBL123`). IP lists take addresses or CIDRs (host bits set is an error); domain lists take names or hosts-file lines (`0.0.0.0 evil.example`), in punycode. One malformed line rejects the file.
- **Failures.** A missing, unsigned, badly signed or invalid feed refuses startup (`serve --check` reports it). On refresh, the same failures and a feed older than the loaded one (rollback) keep the last good list and are audited once as `gateway_blocklist_reload_failed`. Age comes from the signed `issued_at`. A feed older than `max_age_h` is stale: `on_stale: warn` keeps blocking with the last good list, audits `gateway_blocklist_stale` hourly and lists it under `blocklist_stale` in `/readyz` (still 200); `on_stale: deny` refuses every URL argument until a fresh feed arrives.
- **Audit and metrics.** Each match is an `egress_blocked` record: `source` (`tool_call` or `model_text`), `tool`, `argument`, `host`, `url_sha256` (no audit record holds a URL argument: `tool_request` stores it as `sha256:<hex>` too), `matched`, `match_value`, `entry`, `list`, `list_sha256`, `list_age_s`, `resolved`. The request's `gateway_request` record carries the mode. `/dashboard` shows each list's entries, age and status. `/metrics` adds `agentsec_gateway_blocklist_age_seconds{list=...}`; matches count under `agentsec_gateway_events_total{event="egress_blocked"}`.
- **Limits.** This checks the argument, not the connection: the client or MCP server resolves the name again later, redirects are not followed, URLs inside free-form strings are not seen, and feeds lag new attacker infrastructure. Apply the same feeds at your egress firewall, and use a filtering resolver (see docs/PRODUCTION.md).

## External policy or DLP service

`policy_hook` sends every tool call the local policy allows to your own service before the call reaches the client (model path) or the MCP upstream. This applies to calls that need approval too. The call goes ahead only on an explicit `{"allow": true}`.

```yaml
policy_hook:
  url: https://dlp.corp.example/v1/tool-call   # https, or http to a loopback address only
  timeout_s: 5                                 # default 5
  auth: env:AGENTSEC_POLICY_HOOK_TOKEN         # optional; sent as "Authorization: Bearer ..."
```

The gateway POSTs `{"tool": ..., "arguments": {...}, "verdict": "allow", "reasons": [], "actor": "alice@corp.example"}`. The arguments are sent as the model wrote them, unredacted, because a DLP service has to see them. The hook fails closed: any of the following denies the call.

- an error, a timeout, or a status other than 200
- a redirect (it would replay the arguments and the token to another host)
- an answer over 64 KB, one that is not JSON, or one where `allow` is anything but `true`

Each answer is audited as `policy_hook` with `allowed` and, on failure, only the error type. The service sits in the path of every tool call, so make it highly available. Library users pass `ToolGuard(policy_hook=HttpPolicyHook(url), policy_hook_timeout_s=...)` or any callable `(call, decision) -> bool`.

## Testing the gateway with the fuzzer

`agentsec fuzz` can attack the gateway like any OpenAI-compatible endpoint, so you can compare the attack-success rate with and without it:

```bash
agentsec fuzz --target ollama:llama3.1:8b --categories tool_misuse,exfiltration
agentsec fuzz --categories tool_misuse,exfiltration \
  --target 'openai-compat:http://127.0.0.1:8443/v1#model=local&header=X-Auth-Request-User:fuzz'
```

- `token=env:NAME` (or `file:/path`) sends a bearer token in `oidc` mode; `header=Name:value` sets a header such as the trusted-proxy user for a test instance; a value of `env:NAME` or `file:/path` is read from there, so an API key stays out of shell history. Add `stream=1` to test the group's stream mode.
- Raise `limits.requests_per_min` for the fuzzing user, or most cases end as 429 errors.
- A request the gateway refuses (`input_blocked`) scores as blocked. A stream it cuts short scores the text already delivered.
- Each case plants a random system-prompt secret the gateway is never told about, so plain-text leaks of it still count as successes. Tool misuse and exfiltration markup should reach 0%; the test suite checks this against a model that obeys every injection, in both stream modes.

## Metrics and readiness

Set `admin: {port: 9090}` (and optionally `host`, which must be a loopback IP such as `127.0.0.1` or `::1`, not `localhost`, and a port other than `listen.port`). If the admin port cannot be bound, the gateway does not start. to start a second listener with no authentication:

- `GET /healthz`: liveness.
- `GET /readyz`: 200 with the policy revision and any groups in monitor mode; 503 once the policy has expired, and 503 with `status: audit_unwritable` when the audit file cannot be opened for append. (A full disk is not detected by the probe: it shows in the write-failure counter.) It also checks for a new bundle, so a gateway with no traffic still reloads.
- `GET /dashboard`: a read-only HTML page for a person at the host: readiness, policy revision, expiry and group modes, the event and response counters below, DLP findings per category (credentials, nhi, pii) by action (block, redact, monitor, allowed; counts only, from `agentsec_gateway_dlp_matches_total`), and, with `admin.fuzz_report: fuzz.json` (relative to the config file), the summary of an `agentsec fuzz --json` report: cases, blocked, bypasses and attack success rate, overall and by category. The per-case results (payloads and agent replies) are never shown. A report generated more than a day ago, or with an unreadable time, is flagged **stale**. With `admin.evidence_dir: docs/evidence` (relative to the config file), it also links each release folder's evidence pages (see [docs/evidence](evidence/README.md)); `GET /evidence/<release>/<file>` serves only `.html` and `.png` files directly inside a release folder, with plain names, no symlinks out of the folder, and the same CSP. It reloads itself every 5 seconds, has no JavaScript and is served with `Content-Security-Policy: default-src 'none'`. Beyond what /readyz and /metrics expose, it adds only the policy's group names and modes and the files you point it at. From another machine, tunnel it (`ssh -L 9090:127.0.0.1:9090 host`, then open `http://localhost:9090/dashboard`).
- `GET /metrics`: Prometheus text.
  - `agentsec_gateway_events_total{event}`: every audit event written, counted only once the record is on disk. Blocks and denials are events such as `gateway_tool_calls_withheld`, `gateway_tools_removed`, `gateway_input_blocked`, `gateway_output_changed`, `gateway_auth_failed` and `gateway_bundle_rejected`.
  - `agentsec_gateway_audit_write_failures_total`: records the local audit file refused. Any increase is lost evidence or failed requests.
  - `agentsec_gateway_siem_backlog_records`: records written to the audit file but not yet delivered to the `cef_file` feed. The gateway keeps undelivered records in memory and redelivers them oldest first on the next record or scrape, so the SIEM sees every record once, in order, after an outage. A restart drops the backlog (the audit file keeps it). Always 0 without `cef_file`.
  - `agentsec_gateway_siem_last_delivery_age_seconds`: seconds since the last successful delivery while a backlog exists; 0 otherwise.
  - `agentsec_gateway_responses_total{status}`: responses sent by the main listener.
  - `agentsec_gateway_policy_info{policy_rev}`, `agentsec_gateway_monitor_groups`, `agentsec_gateway_policy_expiry_timestamp_seconds`.

Labels are event names and status codes only, never users or request content. To scrape from another host, run the scraper as a sidecar or put an authenticating proxy in front; the admin listener itself never leaves loopback.

### Dashboard and alerts

For a quick look on the host, open `/dashboard` (above). For history and alerting, use the Prometheus and Grafana you already run:

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
| Upstream down, bad status, non-JSON, a broken HTTP response or an invalid upstream API key | 502; the audit names only the cause type |
| Upstream timeout: name lookup, connect, headers or body, a total deadline of `upstream_timeout_s` | 504 |
| Upstream answers 429 (rate limit or exhausted quota) | 429 `upstream_rate_limited` with `Retry-After`: the upstream's value in seconds, clamped to 1-300, or 1 if it sent none or a date. Nothing else of the upstream's answer is passed on |
| Request body not received within `body_timeout_s` | 408 |
| Upstream answer malformed, or an error event inside a stream | 502 before any text is released; after that, the stream ends with an error event and no `[DONE]`, and the delivered text is audited and checked (`gateway_output_violation_after_delivery` with `interrupted: true` if it broke a rule) |
| Any other error | 500 with no detail |
| Body too large | 413 |
| No group policy matches the user | 403 |
| Bundle expired | 503 |
| Rate or concurrency limit | 429 |
| User over `limits.tokens_per_user_per_day` | 429 `budget_exceeded` with `Retry-After` (seconds until enough of the oldest spending leaves the 24-hour window); audited as `gateway_budget_exceeded`; nothing is forwarded |
| More than `limits.max_connections` (default 1000) connections and requests open | 503 from the HTTP server: plain text, not audited or counted in `/metrics` |
| More than 8 token verifications in flight (`oidc` mode) | 503 |
| More than 32 upstream model calls in flight | 503 `busy`, at once (not queued) |

## Deployment requirements

- **The gateway must be the only route to the model servers.** Ollama has no authentication; bind it to localhost or a network only the gateway can reach. Otherwise users skip the gateway. Check it with `probe-isolation` (below).
- **Origin and Host checks.** Both listeners refuse, with a 403 before authentication, what a web page can send but a real client does not. This stops DNS rebinding (a page whose hostname is re-pointed at `127.0.0.1`) and cross-site requests. Each refusal is a `gateway_rejected` audit event with code `origin_not_allowed` or `host_not_allowed`.
  - `Origin`: a request that carries one is refused unless it is listed in `listen.allowed_origins` (exact origins such as `https://chat.corp.example`, no wildcards, default empty). Clients that are not browsers send no `Origin` and are unaffected. A browser app that calls the gateway, same-origin or not, must be listed. The admin listener refuses every `Origin`.
  - `Host`: its name must be one of `listen.allowed_hosts` (names such as `gateway.corp.example`, without a port, no wildcards). The port in `Host` is not compared: the name is what a rebinding page cannot fake, and a forwarded port differs from the configured one. Unset with a loopback `listen.host`, the list is `localhost`, `127.0.0.1`, `[::1]` and `listen.host`. A non-loopback listener requires an explicit list containing the name your proxy forwards. The admin listener always requires a loopback name. A request with no `Host` header at all (HTTP/1.0, which no browser sends) is served.
  - `GET /healthz` on the main listener is exempt from both checks, because a container probe sends the pod address as `Host`. It returns a constant.
- **Upstream TLS.** Configure an HTTPS endpoint with a trusted certificate for every remote model and MCP service. Loopback endpoints also accept HTTP for local services.
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

### Pilot rollout

- **Sensitive workloads: keep `output.stream_mode: buffer`** (the default). The whole answer is validated before anyone sees text. `holdback` shows text early and can only end the stream if the final check finds something in what was already sent.
- **Rollout gate: every model and tool server must be unreachable from an employee workstation.** Each gateway policy applies only to traffic that passes through the gateway. From a typical workstation, for each upstream host and port in `gateway.yaml` (replace the example), the expected result is a failure or timeout, never an HTTP response:

  ```bash
  curl -sS -m 5 -o /dev/null -w '%{http_code}
' http://ollama.internal:11434/api/tags   # expected: curl error (refused/timeout), no status code
  ```

  ```powershell
  Test-NetConnection ollama.internal -Port 11434 -InformationLevel Quiet   # expected: False
  ```

  `agentsec probe-isolation` (above) does this for every upstream at once. Also confirm the gateway itself is reachable. Do not widen the pilot until every upstream returns the failing result.
- **Audit delivery:** alert on the three audit signals in `examples/grafana/alerts.yaml` before the pilot starts.

## Container image

The repository's `Dockerfile` builds the gateway from the hash-pinned locks (`requirements/requirements-gateway.txt`) on a digest-pinned `python:3.13-alpine`. The release workflow scans the built image for high and critical vulnerabilities before pushing it to the registry. Each release from 0.8.1 on is also published to `ghcr.io/dustystudy/ai-agent-security-toolkit`, tagged with the version (there is no `latest`) and for `linux/amd64` only. With `VERSION` set to a release, such as `0.8.1`:

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
- `/readyz` does not probe the upstreams. It checks that the audit file can be opened for append, not that the disk has room; a failed write shows as 503 responses, `agentsec_gateway_audit_write_failures_total` and stopped event counters.
- Without `bundle.state_file`, rollback protection across restarts relies on `min_revision` and `expires`.
- An access token keeps the groups its user had at issue time until it expires or is revoked. The gateway never learns of an IdP change by itself: tokens are revoked only when `agentsec token offboard` runs (see **Offboarding** in the token section), so access lasts until your automation calls it and every store accepts the revocation.
- Tool-call limits (`max_calls`) count per request, not per user over time.
- `limits.tokens_per_user_per_day` counts the `total_tokens` each upstream reports, over a rolling 24 hours, in the gateway process's memory: a restart forgets it and each replica counts on its own. A response with no usage report is charged its `max_tokens`. The check runs before the upstream call and the charge after it, so requests already in flight can take a user past the budget. With a budget set, holdback streams always ask the upstream for usage (clients still see it only if they ask). It counts tokens, not money.
- Path and URL argument rules are evaluated on the gateway host, which may not match where the client runs the tool.
- Upstream addresses are not checked: `upstreams` and `mcp_upstreams` URLs come from the operator's config (a client can never supply one), are usually loopback or private by design, and are resolved by the HTTP client on each connection. Whoever controls DNS for an upstream's hostname chooses where its requests and credential go; use an IP literal or `https` for an upstream that is not on loopback.
- Outbound screening finds only what the secret rules recognise (known key formats, private keys, token shapes); a password in prose or an encoded secret passes. It is per upstream, not per group. Audio and file parts, and remote image URLs, are refused in every mode.
- Models that write tool calls as JSON text instead of `tool_calls` are not recognised as tool calls.
- The whole history is rescanned and re-audited on every turn.
- With `log_content: false`, prompt and answer strings over 64 characters are stored as a hash and length; shorter ones, such as a short prompt, are stored in full after redaction. Decision fields (`reasons`, `error`, `tools`, `validators`, `signals`, `policy_rev`, `groups`) stay readable. Denial reasons can name a URL's host.
- A client disconnect does not cancel the upstream call in buffer mode. In holdback mode the upstream connection is closed at the next chunk, if the server reports the disconnect as a failed send.
