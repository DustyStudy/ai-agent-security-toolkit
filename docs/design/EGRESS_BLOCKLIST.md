# Design: egress blocklist for known-bad IPs and domains

Status: design approved 2026-11-23, not implemented. Owner: TBD.

## Problem

An injected model can ask for a tool call that fetches from, or sends data to, an attacker's server. The URL rules in a policy already refuse private and metadata addresses (SSRF) and can pin a tool to a host allowlist. A tool that legitimately needs the open web (`fetch_url`, `web_search`) cannot have an allowlist, so today nothing stops it from reaching a host that public threat feeds already list as malicious: botnet C2, malware distribution, hijacked netblocks.

This design adds a deny check against configurable blocklists of IP networks and domains, at the point where the toolkit already judges URL arguments.

## Non-goals

- **DNS filtering.** It acts on names at the resolver and covers every process on the host, not just tool calls. It belongs in the deployment (a filtering resolver such as Quad9, or RPZ on the company resolver) and will be documented in docs/PRODUCTION.md as a recommendation. The toolkit does not run a resolver.
- **Fetching feeds.** The toolkit reads feed files that something else puts on disk. It makes no network calls of its own for this (see "Feeds are read-only").
- **Network enforcement.** A blocklist check on an argument is not an egress firewall. The tool or client still connects on its own (see "Limits").
- **Checking operator-configured upstreams.** Model and MCP upstream URLs come from `gateway.yaml`, not from a model, and are trusted.

## Hook point

Every URL a model can put in a tool call is judged in one function:

```
gateway model path:  app.py _check_response -> AgentMiddleware.authorize_tool ─┐
gateway MCP path:    mcp.py _client -> GuardedMCPClient.call_tool ──────────────┤
library users:       ToolGuard.authorize / execute ─────────────────────────────┤
                                                                                 v
                     ToolGuard.evaluate -> check_arg -> check_url (sandbox/validators.py)
```

`check_url` already normalises the host the way a fetcher would (`_ascii_host`: trailing dot, case, IDNA refusal, legacy IP literals such as `0x7f000001` via `_parse_ip_literal`) and, when DNS checks are on, resolves it once. The blocklist check goes there, after the existing checks, and uses the same normalised host and the same resolved addresses. That keeps one definition of "the host" across SSRF and blocklist checks, so the two cannot disagree about a tricky URL.

Plumbing follows the existing `resolver` argument:

- `ToolGuard(policy, ..., blocklist=None)` passes it to `check_arg(..., blocklist=...)` and on to `check_url`.
- The gateway builds one `Blocklist` and passes it at its two `ToolGuard` constructions (`app.py` `_complete`, `mcp.py` `_client`).
- `_blocking_eval` becomes true when a blocklist needs DNS, so the async API resolves off the event loop as it already does for DNS-checking rules.

A match adds a reason such as `host 'x.example' is on blocklist 'urlhaus' (matched 'example')`. A reason makes the decision `deny`, so the existing behaviour follows with no new code: in `enforce` mode the gateway strips the call (model path) or returns an MCP error (MCP path), and in `monitor` mode it audits and keeps the call.

### Matching

- **Domains**: the normalised host and every parent suffix are looked up in a set, so `evil.example` blocks `a.b.evil.example` but not `notevil.example`. One set lookup per label.
- **IPs**: networks from the feeds are grouped by prefix length. An address is checked by masking it to each prefix length present and looking up the result, so the cost is one lookup per distinct prefix length (a few dozen at most), whatever the feed size. IPv4-mapped IPv6 addresses are checked as IPv4, as `_is_nonpublic` already does.
- **What is checked**: an IP literal in the URL directly; for a name, the name against domain lists and every address it resolves to against IP lists. If any address matches, the call is denied (an attacker controls which of several A records the client picks).

### When the host is resolved

Today a URL rule resolves only when `dns_check_enabled(rule)` is true (`block_private` on and no host allowlist). With IP blocklists loaded, a name is resolved whenever the rule has no host allowlist, even if `resolve_dns` is false, because an IP list cannot match a name without its addresses. A rule with a host allowlist is not resolved for the blocklist: the allowlist is already the stronger control, and an operator who wants both sets `resolve_dns: true`.

A name that does not resolve is denied (fail closed), as the private-address check already does. Otherwise an attacker could use a name that fails at the gateway but resolves for the client.

## Config shape

A new top-level `egress` section in `gateway.yaml`, strict like the rest of the file (unknown keys are an error):

```yaml
egress:
  blocklists:
    - name: spamhaus-drop        # appears in reasons, audit records and metrics
      kind: ip                   # ip | domain
      file: /etc/agentsec/feeds/drop_v4.txt
      max_age_h: 48              # older than this is stale (default 48)
    - name: urlhaus
      kind: domain
      file: /etc/agentsec/feeds/urlhaus-hosts.txt
  except_hosts: ["files.example.com"]   # optional: never blocked by a feed (false-positive escape hatch)
  on_stale: warn                 # warn | deny  (see "Stale or missing feeds")
  public_key_file: /etc/agentsec/feeds.pub   # required: Ed25519 key that feed signatures must verify against
  check_model_links: true        # default true: also match links in model answers (see "Links in model answers")
```

Each `file` must have a signature beside it (`drop_v4.txt.sig`); see "Feed signatures".

File format, one entry per line, kept deliberately small so most feeds work unchanged or with one `jq`/`cut` in the fetch job:

- Blank lines and lines starting with `#` or `;` are ignored, and anything after ` ;` or ` #` on a line is a comment (covers Spamhaus `drop.txt` style `1.2.3.0/24 ; SBL123`).
- `kind: ip`: an address or CIDR. A CIDR with host bits set is an error, not silently widened.
- `kind: domain`: a hostname, or a hosts-file line (`0.0.0.0 evil.example`, `127.0.0.1 evil.example`), in which case the last field is taken. Names are lowercased, a trailing dot is dropped, and non-ASCII names are an error (feeds must use punycode, matching `_ascii_host`).
- Any malformed line makes the whole file invalid. A partly parsed feed hides how much was lost.

Library users build the same object in code: `Blocklist.from_files([...])`, or from in-memory sets for tests.

Per-group blocklists are not in this proposal: a known-bad host is bad for every group. Groups still differ through `mode` (enforce or monitor).

## Feeds are read-only

The toolkit only reads feed files. Fetching them is the operator's job, with whatever they already use for scheduled jobs (cron, a systemd timer, a Kubernetes CronJob writing to a shared volume). Reasons:

- The gateway stays free of outbound internet access, which is part of its own threat model (a compromised gateway with internet egress is a better exfiltration point).
- Feed providers have their own terms, rate limits and authentication (some abuse.ch feeds now need an Auth-Key). Those belong to the operator's account and job, not to the toolkit.
- The update path can be reviewed, pinned and monitored separately from the gateway.

The docs will include an example fetch script (outside the package, in `examples/`). It downloads a feed, validates it with `agentsec egress check-feed FILE --kind ip` (a new read-only CLI check using the same parser), signs it, and replaces the file and its `.sig` with atomic renames, so the gateway never reads a half-written file. The gateway accepts a file only when the pair matches. A mismatch caught mid-swap counts as a failed refresh and is retried on the next tick.

The first two feeds documented are **Spamhaus DROP** (`kind: ip`) and an **abuse.ch host list** such as URLhaus (`kind: domain`). The docs link to each provider's own pages for current URLs, formats and terms, and do not copy them. Some abuse.ch downloads now require an Auth-Key. Accepting those terms is the operator's decision.

### Feed signatures

Decision: feeds are signed, and an unsigned or badly signed feed is refused. A deny list that anyone with write access to its folder can empty would let one file write silently switch the control off, so the feed gets the same treatment as policy.

Feeds are not put inside the policy bundle. They are signed separately, with their own key:

- The fetch job signs each file with `agentsec egress sign-feed FILE --key feeds.key --name urlhaus`. That writes `FILE.sig`: JSON with the list name, the file's SHA-256, `issued_at` (UTC, set at signing) and an Ed25519 signature over those three fields. The code reuses the bundle signing helpers in `gateway/bundle.py`.
- The gateway verifies the signature before parsing, checks the hash against the bytes it read, and refuses a `.sig` whose list name differs from the configured `name` (so a signed host list cannot be swapped in as the IP list).
- **Feed age comes from the signed `issued_at`, not the file's mtime.** Anyone can reset an mtime. A signed time cannot be faked without the key.
- **No rollbacks.** A refresh whose `issued_at` is older than the list already loaded is refused. Otherwise someone could replay an old, smaller feed. The highest accepted `issued_at` per list is written to the bundle `state_file` when one is configured, so the rule survives a restart, as bundle revisions already do.

Why a separate key and not the bundle:

| | Feeds in the policy bundle | Separately signed feeds (chosen) |
|---|---|---|
| Integrity | Signed | Signed |
| Refresh | Re-sign the whole policy bundle on every feed update (hourly for some feeds) | Sign only the feed file |
| Key exposure | The unattended fetch job would hold the **policy** signing key, so a compromised job could ship any policy | The fetch job holds only the feed key. The worst it can do is publish a bad deny list, which can block traffic but never allow more than policy does |
| Policy review | Feed churn buries policy changes in bundle diffs | Policy bundles change only when policy changes |

Trade-off: the operator manages a second key, and the gateway refuses to start until feeds are signed, so a first install takes one more step. The fetch job still needs the feed key on the machine that runs it. Keep it off the gateway host, and never give it the policy key.

Feed files are still root-owned and not writable by the gateway user. That is a second layer behind the signature.

## Loading and refresh

- **Startup**: every configured file is verified, then parsed. A missing, unsigned, badly signed, unreadable or invalid file refuses startup, like a missing policy. `gateway_start` records each list's name, entry count, SHA-256 and `issued_at`.
- **Refresh**: on the same schedule and lock as bundle reload (`_maybe_reload`, every `reload_interval_s`, default 10 s, off the event loop), the gateway `stat`s each file and its `.sig`. If either changed, it verifies and parses into a new immutable `Blocklist` and swaps one reference, as `PolicySet` does. A request in flight keeps the list it started with. Without a bundle, the same timer runs for feeds alone.
- **Failed refresh** (file vanished, bad signature, rollback, invalid, unreadable): keep the last good list, audit `gateway_blocklist_reload_failed` with the reason, and keep counting age from the last good `issued_at`, so a broken fetch job eventually shows up as stale.
- **Feed age** is now minus the signed `issued_at`.

Memory: Spamhaus DROP is about 1,500 networks and URLhaus host lists are tens of thousands of names, so a set of strings and a dict of integer networks per prefix length fit in a few MB. Parsing runs off the event loop, so a 100k-line file does not stall requests.

## Stale or missing feeds: fail open or closed

| Situation | Behaviour | Why |
|---|---|---|
| File missing or invalid at startup | Refuse to start | Same as policy: never run without the configured controls |
| File invalid or missing on refresh | Keep last good list; audit; metric | Availability without trusting bad input |
| Feed unsigned, badly signed, or older than the loaded one | Startup: refuse. Refresh: keep last good; audit; metric | A feed is only trusted with a valid signature |
| Feed older than `max_age_h`, `on_stale: warn` (default) | Keep enforcing the last good list; `gateway_blocklist_stale` audit record once per list per hour; `/readyz` stays 200 but lists `blocklist_stale`; dashboard flag | A stale deny list still blocks everything it blocked yesterday; it only misses new entries. Failing every URL tool call because a cron job died is an outage the blocklist does not justify. |
| Feed older than `max_age_h`, `on_stale: deny` | Every tool call with a `url` argument that would be checked against that list is denied with reason `blocklist 'x' is stale` | For deployments that prefer outage to an unknown gap |
| Name does not resolve when the blocklist needs its addresses | Deny the call | Fail closed, matches the private-address check |
| Lookup code raises | Deny the call | Existing rule: scanner or validator raising fails closed |

Decision: `warn` is the default (approved 2026-11-23). This differs from the existing precedent, where a bundle past `expires` fails closed. The difference is that a bundle is the allow policy, while a feed is an extra deny list. Deployments that prefer an outage to an unknown gap set `on_stale: deny`.

## Links in model answers

Decision: on by default (`check_model_links: true`). The output guard's `ExfilLinkValidator` already redacts every link to a host outside `output.allowed_hosts`, and with an empty allowlist that means every external link. The blocklist adds a layer where that check passes a link:

- a host inside an allowed wildcard (`*.github.io`, `*.blob.core.windows.net`) that a feed lists;
- a group whose `links_action` lets plain links through.

A listed link is redacted in the same way as an exfiltration link: under the same `ExfilLinkValidator` rules and holdback window, using the same `_fetch_host` parsing, so the two checks agree on the host. It is audited as `egress_blocked` with `argument: null` and `source: "model_text"`. Only domain lists and IP literals are matched. Hosts in model text are **not** resolved through DNS: resolving every link would add a lookup per link to every answer, and would let a model trigger DNS queries to attacker domains from the gateway, which is itself a known exfiltration channel.

Trade-off: a feed false positive now also removes a link from an answer the user reads. That is visible and audited. `except_hosts` applies here too, and monitor mode shows the impact before enforcing.

## Audit fields

The deny already appears in the tool-call audit record through the decision's reasons. A dedicated event makes blocklist hits queryable in the SIEM without parsing reason strings:

`egress_blocked` (one per matching argument), bound to the request's logger so it already carries `actor`, `session_id`, `policy_rev` and `token_id`:

| Field | Example | Note |
|---|---|---|
| `source` | `tool_call` or `model_text` | |
| `tool` | `fetch_url` | null for `model_text` |
| `argument` | `url` | null for `model_text` |
| `host` | `a.evil.example` | normalised ASCII host, never the full URL |
| `url_sha256` | `9f2c...` | full URL hashed: query strings can carry secrets or tokens |
| `matched` | `domain` or `ip` | |
| `match_value` | `evil.example` or `203.0.113.7` | what was looked up |
| `entry` | `evil.example` or `203.0.113.0/24` | the feed line that matched |
| `list` | `urlhaus` | |
| `list_sha256` | `4be1...` | which version of the feed |
| `list_age_s` | `5400` | |
| `resolved` | `["203.0.113.7"]` | addresses the gateway saw, for comparison with firewall logs |
| `enforced` | `true` | false in monitor mode |

Lifecycle events: `gateway_blocklist_loaded` (name, entries, sha256, issued_at), `gateway_blocklist_reload_failed` (name, error), `gateway_blocklist_stale` (name, age_s). CEF mapping follows the existing `severity()` table: `egress_blocked` high, stale and reload failure medium.

Metrics: `agentsec_egress_blocked_total{list}` and `agentsec_blocklist_age_seconds{list}`; the dashboard shows each list's age and entry count.

## Limits

- **Check, not connection.** The gateway approves an argument; the client (model path) or the MCP upstream server (MCP path) resolves and connects later. DNS can change in between, and an attacker who controls a domain can return a clean address to the gateway and a listed one to the client. IP blocking at the network edge with the same feeds, plus DNS filtering, is what actually stops the connection. This check catches the common case early and leaves an audit trail tied to the user and tool.
- **Only `type: url` arguments.** A URL inside a free-form string argument, a command line, or a file the tool reads is not seen. Policies should type URL arguments as `url`.
- **Redirects.** A clean URL that redirects to a listed host is not caught; that is the fetching tool's or the network's job.
- **Feeds lag.** New infrastructure is not listed for hours or days. This is defence in depth, not a primary control.
- **False positives.** Shared hosting and CDN addresses can appear in IP feeds. `except_hosts` covers known cases; monitor mode lets a team measure impact before enforcing.

## Test plan

All hermetic: in-memory feeds, temp files, an injected resolver and clock. No network.

- **Signatures**: missing `.sig`, wrong key, hash mismatch (one byte flipped), list name swapped between two signed feeds, rollback to an older `issued_at` (also across a restart with `state_file`), file and `.sig` from different refreshes, `issued_at` in the future beyond clock skew.
- **Parser**: comments in each style, hosts-file lines, CIDR with host bits set (error), IPv6, non-ASCII domain (error), one bad line refuses the file, empty file allowed but audited with zero entries.
- **Matcher**: exact domain, parent suffix, no partial-label match (`notevil.example`), trailing dot, upper case, IP literal in URL, legacy literal forms (`0x7f000001`, `2130706433`) matched as the address they reach, IPv4-mapped IPv6, CIDR edge addresses, `except_hosts` wins.
- **`check_url` integration**: a name resolving to one listed address among several is denied; a resolution failure is denied; a rule with a host allowlist does not resolve for the blocklist; `resolve_dns: false` still resolves when IP lists are loaded; blocklist and private-address checks share one lookup (resolver called once).
- **Gateway**: model path strips the call in enforce and keeps it in monitor, MCP path returns an error and never calls the upstream; `egress_blocked` has every field above and never the raw URL; startup refuses a missing file.
- **Model text**: a listed host in a link, in a markdown image, and under an allowed wildcard is redacted, including when split across stream chunks in holdback mode. No DNS lookup happens for model text (the resolver is never called).
- **Refresh**: changed file swaps the list; invalid file keeps last good and audits; in-flight requests keep their list; staleness with a fake clock under `warn` and `deny`; `/readyz` payload.
- **Fuzzing**: extend the `url` target in `fuzz/targets.py` so the blocklist and the SSRF check agree on the host for every generated URL (a host the fuzzer reaches as listed must be denied).
- **Performance**: `scripts/bench_overhead.py` with 100k domains and 10k networks: lookup under 0.05 ms per URL, load time and memory recorded in the evidence report.

## Phasing

1. `Blocklist` (parser, matcher, signature check) and `check_url`/`ToolGuard` wiring for library users, with tests.
2. Gateway config section, startup load, refresh, rollback state, audit events, metrics, dashboard line.
3. Links in model answers through the output guard.
4. Docs and tooling: GATEWAY.md section, PRODUCTION.md DNS filtering and egress firewall recommendation, `agentsec egress check-feed` and `sign-feed`, and the `examples/` fetch job for Spamhaus DROP and an abuse.ch host list.

## Decisions

Approved by Dusty on 2026-11-23 ("security is our top priority"):

1. Stale feeds: keep enforcing the last good list and warn (`on_stale: warn`). `deny` is available.
2. Feed integrity: feeds must be signed, with a feed key kept separate from the policy bundle key (see "Feed signatures").
3. Links in model answers: checked against domain lists and IP literals by default, without DNS (see "Links in model answers").
4. First feeds documented: Spamhaus DROP and an abuse.ch host list.
