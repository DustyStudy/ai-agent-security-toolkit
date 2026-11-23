# Design: data-loss prevention for credentials, non-human identities and PII

Status: design approved 2026-11-23, not implemented. Owner: TBD.

## Problem

An injected or careless model can move sensitive data out of the system in three ways: in the arguments of a tool call (`send_email`, `http_post`, an MCP tool on another server), in the text it answers with, and in what a tool returns to it that it then repeats. The toolkit already detects and redacts some of this, but the checks grew one at a time and each surface has its own fixed behaviour:

| Surface | Today (0.12.0) | Code |
|---|---|---|
| Model answer text | Secrets and PII (SSN, payment card) redacted, always | `OutputGuard.default` (`SecretLeakValidator`, `PIIValidator`) via `AgentMiddleware.screen_output`; gateway `_check_response` and `Holdback` |
| Tool-call arguments, gateway model path | Secrets: call withheld. PII: not checked | `GroupPolicy.argument_guard` in `app.py` `_check_response` |
| Tool-call arguments, gateway MCP path | **Not checked** for secrets or PII; only the tool policy runs | `mcp.py` `_call_tool` -> `GuardedMCPClient.call_tool` -> `ToolGuard` |
| Tool-call arguments, library users | **Not checked**; `ToolGuard.evaluate` knows nothing about secrets | `sandbox/guard.py` |
| MCP tool results | Secrets redacted (withheld if redaction fails). PII: not checked | `mcp.py` `_screen` |
| Request sent to a model upstream | Per upstream `outbound.on_secret: off/block/redact`, secrets only | `outbound.py`, `app.py` `_screen_outbound` |
| Audit log fields | Secrets and PII redacted, always | `AuditLogger._clean*` |

So an operator cannot say "block cloud keys in tool calls, redact card numbers in answers, and only watch email addresses", cannot see PII leaving through tool arguments at all, and the MCP and library paths miss secrets in arguments entirely.

This design replaces those fixed behaviours with one policy: each data category gets a mode (`monitor`, `redact`, `block`) per surface, with a shared detector set, an audited allowlist for false positives, and audit records that never hold the sensitive value.

## Non-goals

- **Names, addresses, free-text PII.** Detection stays pattern based. Named-entity models are slow, nondeterministic and need a model dependency; they can plug in later as a custom detector source.
- **Encoded or paraphrased data.** Base64, hex, spaced-out digits, "five five five...", or a value split across two tool calls will get past a pattern check. See "Limits".
- **Files and attachments.** Binary parts cannot be scanned. They stay governed by the existing rules (refused by `outbound.on_secret`, withheld from MCP results).
- **Data at rest or in the model provider's hands.** This guards what crosses the gateway or the middleware. It is not a classifier for stored data.

## Categories and detector sources

There is one detector set, the `_RULES` table in `middleware/redact.py`. It stays the single source of truth so the audit log, the output guard and DLP cannot drift apart. Each rule already carries a `kind`; DLP adds a mapping from kind to category in a new `middleware/dlp.py`. `Finding.category` (`secret`/`pii`) keeps its meaning, so nothing that imports it breaks.

| DLP category | Meaning | Detector kinds |
|---|---|---|
| `credentials` | A secret recognised by its context: a field name, a header, a flag, a URL position | `password_assignment`, `secret_assignment`, `cli_credential`, `url_credentials`, `authorization_header`, `basic_auth`, `bearer_token`, `cookie_header`, `jwt`, `private_key_block` |
| `nhi` (non-human identities) | A machine credential recognised by its own issuer format, with no context needed | `aws_access_key_id`, `aws_secret_access_key`, `github_token`, `github_fine_grained_pat`, `gitlab_token`, `npm_token`, `huggingface_token`, `slack_token`, `slack_webhook`, `stripe_api_key`, `anthropic_api_key`, `openai_style_api_key`, `google_api_key`, `google_oauth_token`, `gateway_access_token` |
| `pii` | Personal data with a checkable shape | `us_ssn`, `payment_card`, `email` (new) |

A kind missing from the map is a startup error (enforced by a test), so a new rule cannot land without a category.

### Detector changes

The existing rules are kept as they are: they have a long tail of regression tests and ReDoS fixes. Changes:

- **`email` (new, `pii`).** Local part 1-64 characters from the RFC 5322 atom set, `@`, a domain of dot-separated labels (each 1-63, total up to 253) ending in a 2-63 letter TLD. Bounded quantifiers and possessive groups, so it stays linear on `a@a@a@...`. Not added to the audit log's always-on redaction (see "Audit records").
- **`payment_card`: cut false positives.** Today any 13-19 digit run that passes Luhn matches, so one random order number or timestamp in ten is a "card". Add: a known issuer prefix (4; 51-55 and 2221-2720; 34, 37; 6011, 644-649, 65; 35; 30, 36, 38, 39; 62), a length valid for that issuer, and consistent separators (all spaces, all dashes, or none, in 4-digit groups or the Amex 4-6-5 shape).
- **`us_ssn`: spaced form.** Add `123 45 6789`. A bare 9-digit run matches only within 20 characters after `ssn`, `social security` or `tin` (case-insensitive), because bare 9-digit numbers are everywhere.
- **New `nhi` kinds**, each from the issuer's published token format and each with positive and negative tests: GitLab runner/deploy/feed tokens (`glrt-`, `gldt-`, `glft-`), SendGrid (`SG.<22>.<43>`), DigitalOcean (`dop_v1_`, `doo_v1_`), Shopify (`shpat_`, `shpss_`), Databricks (`dapi` + 32 hex), Azure storage connection strings (`AccountKey=` is already caught by `secret_assignment`; the new rule names it `azure_storage_key` so it maps to `nhi`). gitleaks' MIT-licensed rule set is a useful cross-check for formats; it is not vendored.

### Custom detectors

Operators can add patterns for their own token formats (an internal `acme_live_...` key, an employee ID):

```yaml
dlp:
  detectors:
    - kind: acme_service_token
      category: nhi
      pattern: 'acme_(?:live|test)_[A-Za-z0-9]{32}'
      examples: ["acme_live_<32 chars>"]       # must match at load
      counter_examples: ["acme_live_short"]     # must not match at load
```

At load, each pattern must compile, be at most 512 characters, match every `examples` entry and no `counter_examples` entry, and scan a 64 KB adversarial string (built from the pattern's own literal characters repeated) in under 50 ms. A failure is a config error. Custom kinds must not reuse a built-in kind name.

## Where the check runs

DLP is one function, `DlpPolicy.scan(text, surface) -> DlpResult`, called from the places that already scan. It runs `find_sensitive` **once** per string and applies each finding's category mode for that surface. Today the output path calls `redact_text` up to six times per answer (check, sanitise and recheck for each of two validators), so a single pass is also the main performance win.

| Surface name | What is scanned | Hook |
|---|---|---|
| `output` | Model answer text, buffered or holdback-streamed | `OutputGuard`: `SecretLeakValidator` and `PIIValidator` are replaced by one `DlpValidator` built from the policy |
| `tool_args` | Every string in a tool call's arguments, keys included, walked as the audit logger walks them | `ToolGuard.evaluate`, so the gateway model path, the gateway MCP path and library users all get it. The gateway's separate `argument_guard` keeps only the protected-string check |
| `tool_results` | MCP tool results (text, structured content, resource text) | `mcp.py` `_screen`, using the policy instead of `argument_guard` |
| `upstream` | The whole request the gateway sends to a model upstream | `_screen_outbound`; `outbound.on_secret` becomes a per-upstream override of this surface (see "Configuration") |

Putting the argument check in `ToolGuard.evaluate` closes the two gaps in the table above (MCP path and library). A DLP `block` there becomes a deny reason, so the existing machinery does the rest with no new code: in gateway `enforce` mode the model-path call is stripped and the MCP call returns an error; in `monitor` mode the call goes ahead and the decision is audited.

## Mode semantics

| Mode | What happens to the data | Audit |
|---|---|---|
| `monitor` | Delivered unchanged | `dlp_match` with `action: monitor` |
| `redact` | Each matched span becomes `[REDACTED:<kind>]`; the rest is delivered | `dlp_match` with `action: redact` |
| `block` | The whole unit is withheld: the answer (replaced by `blocked_message`), the tool call (denied), the tool result (MCP error), the upstream request (HTTP 400 `outbound_blocked`) | `dlp_match` with `action: block` |

Rules:

1. **Strictest wins.** Within one unit, any `block` finding blocks the unit; otherwise any `redact` finding redacts. Monitor findings in a unit that is also redacted are still recorded.
2. **Redact in tool arguments means block.** Rewriting an argument changes the action (an email goes to `[REDACTED:email]`, a payment goes to the wrong account). This keeps the current gateway behaviour ("withheld rather than rewritten"). A `redact` setting under `tool_args` is accepted and treated as `block`, and the config loader logs that once.
3. **Group `mode: monitor` overrides.** A gateway group in monitor mode never changes traffic: every finding is recorded with `enforced: false` and the action enforce would have taken, as every other gateway check does today.
4. **Fail closed.** If a redacted unit still has a finding when rescanned (an overlap the redactor could not remove), it is blocked, as `OutputGuard` already does. If text is over the scan limit and any category is `redact` or `block` on that surface, the unit is blocked; if all are `monitor`, it is delivered and `dlp_scan_limit` is audited. A detector exception blocks the unit.
5. **No `off` mode.** `monitor` is the floor. A category nobody can see is how leaks go unnoticed for months; the allowlist is how legitimate traffic is let through.

## Configuration

One `dlp` section. In the gateway it sits in each bundle group entry (next to `output` and `input`), or at the top level of `gateway.yaml` in single-policy mode. Library users build it with `DlpPolicy.from_dict()` and pass it to `OutputGuard.default(dlp=...)` and `ToolGuard(dlp=...)`. Loading is strict like the rest of the policy: unknown keys, categories, surfaces or modes are errors.

```yaml
dlp:
  categories:
    credentials: {output: redact, tool_args: block, tool_results: redact, upstream: redact}
    nhi:         {output: redact, tool_args: block, tool_results: redact, upstream: block}
    pii:
      output: redact
      tool_args: monitor
      tool_results: monitor
      upstream: monitor
      kinds:                       # optional per-kind override of the category mode
        email: {output: monitor}
  detectors: []                    # custom detectors, see above
  allow: []                        # see "False positives and the allowlist"
  fingerprint_key: env:AGENTSEC_DLP_FINGERPRINT_KEY   # see "Audit records"
```

Per upstream, `upstreams.<name>.outbound.on_secret` keeps working and means "this mode for `credentials` and `nhi` on the `upstream` surface for this upstream". A new optional `upstreams.<name>.outbound.on_pii` does the same for `pii`. That lets an operator block PII to a third-party provider while allowing it to a self-hosted model.

### Defaults

With no `dlp` section, behaviour matches 0.12.0 except where 0.12.0 had a gap:

| | output | tool_args | tool_results | upstream |
|---|---|---|---|---|
| `credentials` | redact | block | redact | as `on_secret` (default off = monitor) |
| `nhi` | redact | block | redact | as `on_secret` |
| `pii` (`us_ssn`, `payment_card`) | redact | **monitor** (new) | **monitor** (new) | monitor |
| `pii` (`email`, new) | **monitor** | monitor | monitor | monitor |

Changes a 0.12.x user will see: secrets in MCP tool arguments and library tool arguments are now denied (they were not checked), and PII in arguments and results now shows up in audit. Email is monitor-only by default because answers and tool calls legitimately contain addresses (`send_email`); switching it to `redact` in output is one line.

## False positives and the allowlist

Pattern detection will hit test data, documentation examples and legitimate business values. Three layers, in order:

1. **Better detectors** (issuer prefixes and separator rules for cards, context for bare SSNs, above).
2. **Built-in documentation values.** Published example values that are never real: `AKIAIOSFODNN7EXAMPLE` and its documented secret key, the Stripe/Visa/Mastercard test card numbers (`4242 4242 4242 4242` and friends), SSN `078-05-1120`, `example.com`/`example.org`/`example.net` and `.test`/`.invalid` email domains. They are still audited with `allowed_by: builtin`, so a model that leaks a real key next to the example one is still caught.
3. **Operator allowlist**, scoped and expiring:

```yaml
dlp:
  allow:
    - id: support-mailbox            # required, unique; appears in audit
      reason: "replies go to our shared support address"
      owner: platform-security        # required
      expires: 2027-02-28             # required, at most 180 days after the policy's issue date
      kinds: [email]                  # required, at least one
      surfaces: [output, tool_args]   # optional, default all
      tools: [send_email]             # optional, tool_args/tool_results only
      match:                          # exactly one of:
        email_domain: support.example.com
        # sha256: "<hex of the exact matched value>"   for a specific token or number
        # pattern: '...'                                pii kinds only, full match
```

- **No plaintext secrets in config.** A specific credential or NHI value can only be allowlisted by `sha256` of the matched span (`agentsec dlp hash` reads it from stdin and prints the hash). `pattern` is refused for `credentials` and `nhi`, because a pattern broad enough to be useful there is an off switch.
- **Expiry is enforced.** An expired entry stops matching and the gateway audits `dlp_allow_expired` once per reload; `agentsec policy check` warns 14 days ahead. The limit keeps forgotten exceptions from becoming permanent holes.
- **Every allowlisted hit is audited** as a `dlp_match` with `action: allowed` and `allowed_by: <id>`. The allowlist suppresses the action, never the record.
- **Changes are reviewable.** The allowlist lives in the signed policy bundle, so every change has a revision and a signature, and `policy_rev` on each request ties a decision to the allowlist that made it.

## Audit records

The audit log must show what was found, where and what was done, without becoming a second copy of the data. One `dlp_match` event per finding (capped at 50 per unit, then one `dlp_match_overflow` with the count), bound to the request logger so it carries `actor`, `session_id`, `policy_rev` and `token_id`:

| Field | Example | Note |
|---|---|---|
| `surface` | `tool_args` | |
| `category` | `nhi` | |
| `kind` | `aws_access_key_id` | |
| `tool` | `http_post` | null for `output` and `upstream` |
| `location` | `arguments.headers.Authorization` or `messages[3].content` | JSON path, never content. Keys that themselves match a detector are redacted in the path |
| `offset`, `length` | `112`, `20` | position in that string |
| `fingerprint` | `hmac-sha256:5be0c1d9a2f7e3b4` | see below |
| `action` | `block` | `monitor`, `redact`, `block` or `allowed` |
| `allowed_by` | `support-mailbox` | only for `allowed` |
| `enforced` | `true` | false under group `mode: monitor` |

What is never recorded: the value, any prefix or suffix of it (`Finding.preview()`, which shows four characters, is not used: four digits of an SSN or card are themselves regulated), or the surrounding text. The existing audit rules also still apply: `MODEL_OUTPUT` records the text after DLP, and the logger's own redaction runs on every field.

**Fingerprint.** Analysts need to tell "the same key leaked 40 times" from "40 different keys". A plain SHA-256 cannot be used: there are only about 10^9 SSNs and a similar number of plausible card numbers, so an unkeyed hash is reversed by brute force in minutes. The fingerprint is HMAC-SHA256 of the matched span with `fingerprint_key` (an `env:` or `file:` reference resolved by the existing `resolve_secret`, at least 32 bytes), truncated to 64 bits. Without a key, the `fingerprint` field is omitted and the gateway logs a startup warning; it does not invent a per-process key, because fingerprints that change on restart mislead more than they help. Rotating the key breaks correlation across the rotation, which is acceptable and documented.

**Email in the audit log.** The audit logger's always-on redaction does not gain the `email` rule, because the OIDC user (`actor`) is often an email address and redacting it would break attribution. Instead, email addresses in logged content (data values, not `actor`, `session_id` or `event`) are replaced. With `fingerprint_key` set they become `[EMAIL:hmac-sha256:<16 hex>]`, the same value as that address's DLP fingerprint, so repeats correlate. Without a key they become `[REDACTED:email]`, never an unkeyed hash, which anyone who guesses an address could confirm. Approved by Dusty on 2026-11-23.

**SIEM and metrics.** CEF severity: `dlp_match` 7 when `action` is `block`, 5 for `redact`, 3 for `monitor` and `allowed`. Metrics: `agentsec_dlp_matches_total{category,surface,action}` (no `kind` label, to keep cardinality bounded with custom detectors). The dashboard gets one row per category with block/redact/monitor counts.

## Performance limits

Measured on the cloud dev container (Python 3.13) with the current rule set: `find_sensitive` costs about 0.56 ms per KB of prose (5.6 ms for 10 KB, 114 ms at the 200,000-character cap), and about 1 ms per KB for digit-heavy text, where the card rule does the most work.

- **One pass per string** (above), instead of up to six for an answer today.
- **Per-string cap** stays at `DEFAULT_MAX_SCAN_CHARS` (200,000).
- **Per-unit cap**: 1,000,000 characters in total across all strings in one tool call, result or upstream request, and at most 10,000 strings. Past either cap the unit is handled as over the scan limit (blocked if any category is `redact`/`block` on that surface).
- **Streaming**: DLP runs inside `OutputGuard`, so holdback streaming works unchanged. The longest match a detector can produce must fit in the holdback window, or a value could be partly released before it is complete. Config load rejects `holdback_chars` below 256 when `email` is `redact` or `block` on `output` (an address can be 254 characters); the other built-in PII kinds fit in the 32-character minimum.
- **Budget, enforced in CI**: added p95 latency at most 2 ms for a 10 KB answer and at most 15 ms for a 100 KB tool result, measured by new rows in `scripts/bench_overhead.py` and recorded in the release evidence report. A regression past the budget fails the benchmark job.

## Limits

- **Encoding and splitting.** A model told to base64 a key, space out a card number, or send an SSN in two tool calls defeats any pattern check. Taint gating (deny side-effecting tools after untrusted input) and egress rules remain the main controls against a determined injection. DLP stops the common accidental and naive cases and leaves an audit trail.
- **Context-dependent credentials.** A password with no `password=` or flag around it looks like any other string.
- **Redaction changes meaning.** A redacted answer can be confusing ("your key is [REDACTED:aws_access_key_id]"). That is preferable to the leak, and `block` is available where it is not.
- **US-centric PII.** SSN and US card networks only at first. Other national IDs (UK NINO, IBAN, Aadhaar) can be added as built-in or custom detectors as deployments need them.

## Test plan

All hermetic. Every secret-looking test value is built at test time (concatenation or a generator), never committed as a literal, so GitHub push protection and secret scanners do not trip on the repository.

- **Detectors**: positive and negative fixtures per kind, including each new card rule (issuer prefixes, lengths, mixed separators refused), SSN spaced form and keyword context, email length bounds and IDN/punycode domains, every new NHI format. A property test generates random Luhn-valid numbers with and without issuer prefixes and checks only the prefixed ones match.
- **Category map**: every kind in `_RULES` and every custom kind has exactly one category.
- **ReDoS**: each new rule against adversarial inputs (`a@a@a@...`, long digit runs with alternating separators, `SG.SG.SG...`) under a time bound, and the custom-detector load check rejecting a known catastrophic pattern.
- **Mode matrix**: for each surface × category × mode × group mode (`enforce`/`monitor`), assert what the client, the tool or the upstream receives and what the audit says. Includes strictest-wins with mixed findings, `redact` under `tool_args` behaving as block, and per-kind overrides.
- **Fail closed**: redaction that leaves a finding is blocked; over-limit strings and units under each mode; a detector that raises.
- **Paths**: the same secret in a tool argument is denied on the gateway model path, the gateway MCP path (no upstream call is made) and through `ToolGuard` directly; holdback streaming with a card number and an email split across chunks.
- **Allowlist**: scope by kind, surface and tool; `sha256` and `email_domain` and `pattern` matching; `pattern` refused for credentials/NHI; expired entries stop matching and are audited; built-in examples audited as allowed; an allowlisted value next to a real one still catches the real one.
- **No value in audit**: run every test above with a file sink, then search the raw log bytes for each sensitive value, its first and last four characters, and its base64 and hex forms. Any hit fails.
- **Fingerprint**: stable for one key, different across keys, absent without a key, and the key itself never logged.
- **Backward compatibility**: the existing `tests/test_redact_and_validators.py`, `tests/test_audit*.py` and gateway suites pass unchanged with no `dlp` section, except the tests that assert the two closed gaps, which are updated deliberately.
- **Fuzzing**: add a DLP category to the fuzzer payloads (secret and PII exfiltration through tool arguments and answers) so `agentsec fuzz` reports leaks against `GuardedAgent`.
- **Performance**: the benchmark rows and budget above.

## Phasing

Phase 1 shipped in #148 (detectors, `DlpPolicy`, allowlist, `output` and `tool_args`, gateway config). Phase 2 adds the `tool_results` and `upstream` surfaces, `on_pii`, metrics and per-group email keys in the audit log; the dashboard row and custom detectors are in; `agentsec dlp hash` remains.

1. `dlp.py` (category map, `DlpPolicy`, single-pass scan, audit events, fingerprint), detector changes, `ToolGuard(dlp=...)` and `OutputGuard.default(dlp=...)` for library users, with tests and benchmarks.
2. Gateway: `dlp` in bundle entries and single-policy config, `tool_results` and `upstream` surfaces, `on_pii`, metrics, CEF, dashboard row.
3. Allowlist (bundle schema, expiry, `agentsec dlp hash`, `policy check` warning) and custom detectors.
4. Docs: GATEWAY.md and REFERENCE.md sections, a PRODUCTION.md note on rolling out in `monitor` first, CHANGELOG entry describing the two closed gaps.

## Decisions

Approved by Dusty on 2026-11-23 (the proposed answer to each open question):

1. **Email in answers**: `monitor` by default. Operators switch it to `redact` per kind.
2. **Redact in tool arguments**: always treated as `block`. There is no per-tool opt-in.
3. **Fingerprints**: recorded only with an operator-supplied `fingerprint_key`. Without one the field is omitted and the gateway warns at startup. There is no default key.
4. **PII to model providers**: the `upstream` surface defaults to `monitor` for PII. Operators block it per upstream with `outbound.on_pii`.
5. **Allowlist expiry**: required on every entry, at most 180 days after the policy's issue date.
6. **Phase 1 scope**: the new detectors (email, card issuer prefixes, spaced SSN, new NHI formats) ship in phase 1 together with the policy wiring.
