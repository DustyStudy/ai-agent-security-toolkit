# Design: egress blocklist for known-bad IPs and domains

Status: proposal, not implemented. Owner: TBD.

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
```

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

The docs will include an example fetch script (outside the package, in `examples/`) that downloads, validates with `agentsec egress check-feed FILE --kind ip` (a new read-only CLI check using the same parser), and replaces the file atomically with a rename, so the gateway never reads a half-written file.

Feed integrity: feed files get the same trust as `gateway.yaml` (root-owned, not writable by the gateway user). They are not signed. Carrying them in the signed policy bundle is possible but would mean re-signing a bundle on every feed refresh (hourly for some feeds); see open questions.

## Loading and refresh

- **Startup**: every configured file is parsed. A missing, unreadable or invalid file refuses startup, like a missing policy. `gateway_start` records each list's name, entry count, SHA-256 and age.
- **Refresh**: on the same schedule and lock as bundle reload (`_maybe_reload`, every `reload_interval_s`, default 10 s, off the event loop), the gateway `stat`s each file. If the mtime or size changed, it parses the file into a new immutable `Blocklist` and swaps one reference, as `PolicySet` does. A request in flight keeps the list it started with. Without a bundle, the same timer runs for feeds alone.
- **Failed refresh** (file vanished, invalid, unreadable): keep the last good list, audit `gateway_blocklist_reload_failed`, and keep counting its age from the last good load, so a broken fetch job eventually shows up as stale.
- **Feed age** is the file's mtime. The fetch job must preserve or set it to the download time (the atomic rename does).

Memory: Spamhaus DROP is about 1,500 networks and URLhaus host lists are tens of thousands of names, so a set of strings and a dict of integer networks per prefix length fit in a few MB. Parsing runs off the event loop, so a 100k-line file does not stall requests.

## Stale or missing feeds: fail open or closed

| Situation | Behaviour | Why |
|---|---|---|
| File missing or invalid at startup | Refuse to start | Same as policy: never run without the configured controls |
| File invalid or missing on refresh | Keep last good list; audit; metric | Availability without trusting bad input |
| Feed older than `max_age_h`, `on_stale: warn` (proposed default) | Keep enforcing the last good list; `gateway_blocklist_stale` audit record once per list per hour; `/readyz` stays 200 but lists `blocklist_stale`; dashboard flag | A stale deny list still blocks everything it blocked yesterday; it only misses new entries. Failing every URL tool call because a cron job died is an outage the blocklist does not justify. |
| Feed older than `max_age_h`, `on_stale: deny` | Every tool call with a `url` argument that would be checked against that list is denied with reason `blocklist 'x' is stale` | For deployments that prefer outage to an unknown gap |
| Name does not resolve when the blocklist needs its addresses | Deny the call | Fail closed, matches the private-address check |
| Lookup code raises | Deny the call | Existing rule: scanner or validator raising fails closed |

The default is the main decision for review (open question 1). Note that the existing precedent, a bundle past `expires`, fails closed; the difference is that a bundle is the allow policy, and a feed is an extra deny list.

## Audit fields

The deny already appears in the tool-call audit record through the decision's reasons. A dedicated event makes blocklist hits queryable in the SIEM without parsing reason strings:

`egress_blocked` (one per matching argument), bound to the request's logger so it already carries `actor`, `session_id`, `policy_rev` and `token_id`:

| Field | Example | Note |
|---|---|---|
| `tool` | `fetch_url` | |
| `argument` | `url` | |
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

Lifecycle events: `gateway_blocklist_loaded` (name, entries, sha256, mtime), `gateway_blocklist_reload_failed` (name, error), `gateway_blocklist_stale` (name, age_s). CEF mapping follows the existing `severity()` table: `egress_blocked` high, stale and reload failure medium.

Metrics: `agentsec_egress_blocked_total{list}` and `agentsec_blocklist_age_seconds{list}`; the dashboard shows each list's age and entry count.

## Limits

- **Check, not connection.** The gateway approves an argument; the client (model path) or the MCP upstream server (MCP path) resolves and connects later. DNS can change in between, and an attacker who controls a domain can return a clean address to the gateway and a listed one to the client. IP blocking at the network edge with the same feeds, plus DNS filtering, is what actually stops the connection. This check catches the common case early and leaves an audit trail tied to the user and tool.
- **Only `type: url` arguments.** A URL inside a free-form string argument, a command line, or a file the tool reads is not seen. Policies should type URL arguments as `url`.
- **Redirects.** A clean URL that redirects to a listed host is not caught; that is the fetching tool's or the network's job.
- **Feeds lag.** New infrastructure is not listed for hours or days. This is defence in depth, not a primary control.
- **False positives.** Shared hosting and CDN addresses can appear in IP feeds. `except_hosts` covers known cases; monitor mode lets a team measure impact before enforcing.

## Test plan

All hermetic: in-memory feeds, temp files, an injected resolver and clock. No network.

- **Parser**: comments in each style, hosts-file lines, CIDR with host bits set (error), IPv6, non-ASCII domain (error), one bad line refuses the file, empty file allowed but audited with zero entries.
- **Matcher**: exact domain, parent suffix, no partial-label match (`notevil.example`), trailing dot, upper case, IP literal in URL, legacy literal forms (`0x7f000001`, `2130706433`) matched as the address they reach, IPv4-mapped IPv6, CIDR edge addresses, `except_hosts` wins.
- **`check_url` integration**: a name resolving to one listed address among several is denied; a resolution failure is denied; a rule with a host allowlist does not resolve for the blocklist; `resolve_dns: false` still resolves when IP lists are loaded; blocklist and private-address checks share one lookup (resolver called once).
- **Gateway**: model path strips the call in enforce and keeps it in monitor, MCP path returns an error and never calls the upstream; `egress_blocked` has every field above and never the raw URL; startup refuses a missing file.
- **Refresh**: changed file swaps the list; invalid file keeps last good and audits; in-flight requests keep their list; staleness with a fake clock under `warn` and `deny`; `/readyz` payload.
- **Fuzzing**: extend the `url` target in `fuzz/targets.py` so the blocklist and the SSRF check agree on the host for every generated URL (a host the fuzzer reaches as listed must be denied).
- **Performance**: `scripts/bench_overhead.py` with 100k domains and 10k networks: lookup under 0.05 ms per URL, load time and memory recorded in the evidence report.

## Phasing

1. `Blocklist` (parser, matcher) and `check_url`/`ToolGuard` wiring for library users, with tests.
2. Gateway config section, startup load, refresh, audit events, metrics, dashboard line.
3. Docs: GATEWAY.md section, PRODUCTION.md DNS filtering and egress firewall recommendation, `examples/` fetch job, `agentsec egress check-feed`.

## Open questions

1. **Default for stale feeds**: `warn` (proposed) or `deny`?
2. **Feeds in the signed bundle**: worth the re-signing cost for integrity, or are root-owned local files enough?
3. **Links in model text**: should the output guard's link check (exfiltration links in the answer) also consult the blocklist, or stay with tool-call arguments only?
4. **Which feeds to document first**: Spamhaus DROP (IP) and an abuse.ch host list (domain) are proposed. Their terms of use and any Auth-Key requirement are the operator's to accept; the docs will say so rather than pick for them.
