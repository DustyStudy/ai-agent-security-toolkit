"""``agentsec`` command line interface."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agentsec import __version__
from agentsec.configscan import (
    ConfigFinding,
    acceptance,
    check_pins,
    load_accepted,
    load_pins,
    save_pins,
    scan_config,
    show,
    split_accepted,
)
from agentsec.fuzzer import CORPUS, MUTATORS, FuzzConfig, load_target, run
from agentsec.fuzzer.formats import clean
from agentsec.fuzzer.harness import DEFAULT_SCENARIOS, NOT_RUN_PREFIX, SCENARIOS, build_cases
from agentsec.fuzzer.payloads import categories
from agentsec.fuzzer.targets import redact_spec
from agentsec.middleware.audit import VerifyResult, read_records, verify_file
from agentsec.middleware.dlp import DlpConfigError, allow_digest, resolve_key
from agentsec.middleware.redact import find_sensitive
from agentsec.sandbox import Policy, PolicyError, ToolGuard
from agentsec.threatmodel import (
    SYSTEM_TEMPLATE,
    SystemSpecError,
    crosswalk_markdown,
    load_catalog,
    load_system,
    render_markdown,
)
from agentsec.types import ToolCall

if TYPE_CHECKING:
    from agentsec.gateway.tokens import TokenSettings


def _csv(value: str | None) -> list[str] | None:
    return [v.strip() for v in value.split(",") if v.strip()] if value else None


def cmd_fuzz(args: argparse.Namespace) -> int:
    config = FuzzConfig(
        seed=args.seed,
        scenarios=_csv(args.scenarios) or list(DEFAULT_SCENARIOS),
        mutators=_csv(args.mutators),
        categories=_csv(args.categories),
        max_cases=args.max_cases,
    )
    # A misspelt name must not shrink the matrix silently: an unknown category selects nothing.
    for kind, given, valid in (
        ("scenario", config.scenarios, SCENARIOS),
        ("mutator", config.mutators, MUTATORS),
        ("category", config.categories, categories()),
    ):
        unknown = [name for name in given or [] if name not in valid]
        if unknown:
            print(
                f"error: unknown {kind}(s): {unknown}; choose from {list(valid)}", file=sys.stderr
            )
            return 2
    if args.list:
        cases = build_cases(config)
        print(
            f"{len(CORPUS)} payloads x {len(MUTATORS)} mutators x {len(config.scenarios)} scenarios"
        )
        print(f"selected: {len(cases)} cases")
        print("mutators:", ", ".join(MUTATORS))
        return 0
    if args.timeout is not None and not 0 < args.timeout < float("inf"):
        print("error: --timeout must be a positive number of seconds", file=sys.stderr)
        return 2
    try:
        target = load_target(args.target, timeout=args.timeout)
        report = run(target, config)
    except (ValueError, ImportError, AttributeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        Path(args.json).write_text(report.to_json(), encoding="utf-8", newline="\n")
    if args.md:
        Path(args.md).write_text(report.to_markdown(), encoding="utf-8", newline="\n")
    if args.sarif:
        Path(args.sarif).write_text(
            report.to_sarif(artifact_uri=args.sarif_artifact, target=redact_spec(args.target)),
            encoding="utf-8",
            newline="\n",
        )
    if args.junit:
        Path(args.junit).write_text(report.to_junit(), encoding="utf-8", newline="\n")
    print(
        f"{report.successes}/{report.total - report.errors} attacks succeeded "
        f"(ASR {report.asr:.1%}); {report.blocked} blocked, {report.errors} errors"
    )
    if not args.quiet:
        print()
        print(report.to_markdown(max_bypasses=8))
    not_run = [r.error for r in report.results if r.error and r.error.startswith(NOT_RUN_PREFIX)]
    if not_run:  # the target refused the run (credentials, quota): the rest were not attempted
        stop = clean(not_run[0].removeprefix(NOT_RUN_PREFIX), 300)
        print(f"warning: {stop}; {len(not_run)} case(s) not run", file=sys.stderr)
    if report.total and report.errors == report.total:
        # Zero successes out of zero scored cases would pass any --max-asr gate.
        print("FAIL: every case errored; nothing was evaluated", file=sys.stderr)
        return 2
    if args.max_asr is not None and (report.errors or not report.total):
        # An unscored case could be a bypass, so ASR over the rest proves nothing.
        print(
            f"FAIL: --max-asr could not be evaluated fully: {report.errors} of {report.total} "
            "case(s) errored",
            file=sys.stderr,
        )
        return 2
    if args.max_asr is not None and report.exceeds(args.max_asr):
        print(f"FAIL: ASR {report.asr:.1%} exceeds --max-asr {args.max_asr:.1%}", file=sys.stderr)
        return 1
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    try:
        policy = Policy.from_yaml(args.file)
    except (PolicyError, OSError, ValueError) as exc:
        print(f"invalid policy: {exc}", file=sys.stderr)
        return 2
    if args.action == "validate":
        notes = policy.lint()
        print(f"OK: {len(policy.tools)} tool(s) defined")
        for n in notes:
            print(f"  warning: {n}")
        return 1 if (notes and args.strict) else 0
    try:
        call_args: Any = json.loads(args.args or "{}")
    except json.JSONDecodeError as exc:
        print(f"--args is not valid JSON: {exc}", file=sys.stderr)
        return 2
    guard = ToolGuard(policy)
    if args.tainted:
        guard.default_session.mark_untrusted("cli")
    decision = guard.evaluate(ToolCall(name=args.tool, arguments=call_args))
    print(f"{decision.verdict.value.upper()}: {decision.message()}")
    return 0 if decision.allowed else 1


def cmd_audit(args: argparse.Namespace) -> int:
    try:
        if args.action == "summary":
            return _audit_summary(args)
        result = verify_file(args.file)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if result.ok and not result.records_checked and not args.allow_empty:
        # A log truncated to nothing has no broken link to find.
        print("FAIL: no records to verify; pass --allow-empty if expected", file=sys.stderr)
        return 2
    if result.ok:
        print(f"OK: {result.records_checked} record(s), chain intact")
        return 0
    _print_tampered(result)
    return 1


def _print_tampered(result: VerifyResult) -> None:
    print(
        f"TAMPERED: {clean(result.reason)} (first bad seq: {clean(str(result.first_bad_seq))}, "
        f"{result.records_checked} valid before it)",
        file=sys.stderr,
    )


def _iso(text: str) -> datetime:
    when = datetime.fromisoformat(text)
    return when if when.tzinfo else when.replace(tzinfo=UTC)  # the logger writes UTC


def _decision(data: dict[str, Any]) -> str | None:
    """The decision a record carries: the guard's ``verdict``, or the MCP gateway's ``allowed``."""
    verdict, allowed = data.get("verdict"), data.get("allowed")
    if isinstance(verdict, str):
        return verdict
    if isinstance(allowed, bool):
        return "allow" if allowed else "deny"
    return None


_TOP = 10


def _audit_summary(args: argparse.Namespace) -> int:
    events: Counter[str] = Counter()
    decisions: Counter[str] = Counter()
    denied_tools: Counter[str] = Counter()
    denied_actors: Counter[str] = Counter()
    total = 0

    def tally(records: Iterator[Any]) -> Iterator[Any]:
        nonlocal total
        for rec in records:
            # Counted only when the verifier asks for the next record, which it does not do
            # after one that fails: nothing at or past the first bad record is summarised.
            yield rec
            total += 1
            if not isinstance(rec, dict):
                continue
            # Log values are untrusted text: bounded and de-fanged before they are kept.
            if args.actor not in (None, rec.get("actor")):  # filters match the raw value
                continue
            if args.event not in (None, rec.get("event")):
                continue
            actor, event = clean(str(rec.get("actor"))), clean(str(rec.get("event")))
            if args.since or args.until:
                try:
                    when = _iso(str(rec.get("ts")))
                except ValueError:
                    continue
                if (args.since and when < args.since) or (args.until and when >= args.until):
                    continue
            events[event] += 1
            data = rec.get("data")
            if not isinstance(data, dict):
                continue
            decision = _decision(data)
            if decision is None:
                continue
            decisions[clean(decision)] += 1
            if decision == "deny":
                denied_actors[actor] += 1
                tool = data.get("tool")
                if isinstance(tool, str):  # an output validation names no tool
                    denied_tools[clean(tool)] += 1

    if args.no_verify:
        bad: list[str] = []
        for _ in tally(read_records(args.file, bad)):
            pass
        if bad:
            print(f"warning: stopped reading: {bad[0]}", file=sys.stderr)
    else:
        result = verify_file(args.file, tally)
        if not result.ok:
            _print_tampered(result)
            print(
                "No summary: the log failed verification. --no-verify summarises it anyway.",
                file=sys.stderr,
            )
            return 1

    sections = {
        "events": dict(events.most_common()),
        "decisions": dict(decisions.most_common()),
        "denied_tools": dict(denied_tools.most_common(_TOP)),
        "denied_actors": dict(denied_actors.most_common(_TOP)),
    }
    matched = sum(events.values())
    if args.json:
        summary = {"verified": not args.no_verify, "records": total, "matched": matched}
        print(json.dumps({**summary, **sections}, indent=2))
        return 0
    status = "UNVERIFIED (--no-verify)" if args.no_verify else "OK: chain intact"
    print(f"{status}, {total} record(s), {matched} matched")
    titles = ("By event", "By decision", f"Top {_TOP} denied tools", f"Top {_TOP} denied actors")
    for title, counts in zip(titles, sections.values(), strict=True):
        if counts:
            width = max(map(len, counts))
            print(f"\n{title}:")
            for name, n in counts.items():
                print(f"  {name:<{width}}  {n}")
    return 0


def cmd_scan_config(args: argparse.Namespace) -> int:
    if args.update_pins and not args.pins:
        print("error: --update-pins needs --pins FILE", file=sys.stderr)
        return 2
    if args.accept and not args.update_pins:
        print("error: --accept needs --pins FILE and --update-pins", file=sys.stderr)
        return 2
    if args.accept and not (args.reason or "").strip():
        print("error: --accept needs --reason TEXT", file=sys.stderr)
        return 2
    pins_path = args.pins and Path(args.pins)
    accepted: dict[str, dict[str, str]] = {}
    pin_findings = []
    try:
        scan = scan_config(args.path)
        if pins_path and not (args.update_pins and not pins_path.exists()):
            pin_findings = check_pins(scan, load_pins(pins_path))
            # Acceptances come from the reviewed pin file only, never from the scanned tree.
            accepted = load_accepted(pins_path)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    flagged = {f.item for f in scan.findings if f.kind == "injection"}
    for item_id in args.accept or []:
        if item_id not in flagged or item_id not in scan.items:
            print(f"error: --accept {show(item_id)}: no injection finding on it", file=sys.stderr)
            return 2
        accepted[item_id] = acceptance(scan.items[item_id].fingerprint, args.reason)
    blocking, waived = split_accepted(scan, accepted)
    findings = blocking + pin_findings

    def rows(found: list[ConfigFinding]) -> list[dict[str, str]]:
        # An item id holds names from the scanned files, so it is redacted and escaped too.
        return [{"item": show(f.item), "kind": f.kind, "detail": f.detail} for f in found]

    if args.json:
        waived_rows = [
            row | {k: show(accepted[f.item][k]) for k in ("reason", "accepted_at")}
            for row, f in zip(rows(waived), waived, strict=True)
        ]
        report = {"items": len(scan.items), "findings": rows(findings), "accepted": waived_rows}
        print(json.dumps(report, indent=2))
    else:
        if not pins_path:
            for item in scan.items.values():
                print(f"  {item.kind:<12} {show(item.id)}  {item.summary}")
        for f in findings:
            print(f"{f.kind.upper():<9} {show(f.item)}: {f.detail}")
        for f in waived:
            # The reason comes from the pin file, so it is escaped like everything else.
            why = accepted[f.item]
            print(
                f"ACCEPTED  {show(f.item)}: {f.kind}, {f.detail} "
                f"(reason: {show(why['reason'])}; accepted {show(why['accepted_at'])})"
            )
        tail = f", {len(waived)} accepted" if waived else ""
        print(f"{len(scan.items)} item(s), {len(findings)} finding(s){tail}")
    if not args.update_pins:
        return 1 if findings else 0
    if blocking:
        # A flagged entry must not become trusted, and a tree that could not be read in full
        # would drop the pins of what was missed.
        print("pins not written: fix the findings above first", file=sys.stderr)
        return 1
    try:
        # Only acceptances still in use are kept: one whose entry changed has lapsed.
        save_pins(args.pins, scan.fingerprints, {f.item: accepted[f.item] for f in waived})
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"pinned {len(scan.items)} item(s) to {args.pins}", file=sys.stderr)
    return 0


def cmd_scan_workflows(args: argparse.Namespace) -> int:
    from agentsec.workflowscan import scan_workflows, workflow_files

    try:
        scanned = len(workflow_files(args.path))
        findings = scan_workflows(args.path)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        rows = [{"item": show(f.item), "kind": f.kind, "detail": f.detail} for f in findings]
        print(json.dumps({"files_scanned": scanned, "findings": rows}, indent=2))
    else:
        for f in findings:
            print(f"{f.kind.upper()} {show(f.item)}: {f.detail}")
        print(f"{scanned} file(s) scanned, {len(findings)} finding(s)")
    return 1 if findings else 0


def cmd_hook(args: argparse.Namespace) -> int:
    # Every failure must end in exit code 2: any other code lets the tool call through.
    try:
        from agentsec.integrations.claude_code import handle

        event = json.loads(sys.stdin.buffer.read())
        if not isinstance(event, dict):
            raise ValueError("hook input must be a JSON object")
        policy = Policy.from_yaml(args.policy)
        result = handle(
            event, policy, args.state_dir, audit=args.audit, block_approvals=args.block_approvals
        )
        # Written and flushed inside the try: an "ask" that never reaches Claude Code would
        # otherwise read as "no decision", and a flush error at exit is not exit code 2.
        if result.stdout:
            print(result.stdout, flush=True)
        if result.stderr:
            print(result.stderr, file=sys.stderr, flush=True)
        return result.exit_code
    except Exception as exc:
        try:
            print(f"agentsec hook: blocked, {type(exc).__name__}: {exc}", file=sys.stderr)
        except OSError:
            pass  # stderr is gone; the exit code still blocks
        return 2


def cmd_threatmodel(args: argparse.Namespace) -> int:
    if args.action == "init":
        out = Path(args.output) if args.output else None
        if out:
            out.write_text(SYSTEM_TEMPLATE, encoding="utf-8", newline="\n")
            print(f"wrote {out}")
        else:
            print(SYSTEM_TEMPLATE, end="")
        return 0
    if args.action == "crosswalk":
        print(crosswalk_markdown(), end="")
        return 0
    if args.action == "catalog":
        for t in load_catalog():
            print(f"{t.id}  {t.stride:<24} {t.title}")
        return 0
    try:
        doc = render_markdown(load_system(args.system), load_catalog())
    except (SystemSpecError, OSError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.output:
        Path(args.output).write_text(doc, encoding="utf-8", newline="\n")
        print(f"wrote {args.output}")
    else:
        print(doc)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from agentsec.gateway import ConfigError, load_config, serve
    from agentsec.sandbox.policy import PolicyError

    try:
        config = load_config(args.config)
    except (ConfigError, PolicyError, OSError) as e:
        print(f"invalid gateway config: {e}", file=sys.stderr)
        return 2
    if config.egress is not None:
        from agentsec.gateway.feeds import FeedError, verify_feed
        from agentsec.sandbox.blocklist import parse_feed

        try:
            # Read-only here; the gateway also refuses to start on a bad feed.
            for fc in config.egress.feeds:
                data, _ = verify_feed(fc.file, fc.name, config.egress.public_key, time.time())
                parse_feed(data, fc.kind, fc.name)
        except (FeedError, ValueError) as e:
            print(f"invalid gateway config: egress: {e}", file=sys.stderr)
            return 2
    if args.check:
        print(f"config ok: {len(config.upstreams)} upstream(s), policy {config.policies.revision}")
        return 0
    if config.bundle is not None and config.bundle.state_file is not None:
        from agentsec.gateway.bundle import write_state

        try:
            # Before the bundle is enforced, and only here: load_config has other callers.
            write_state(config.bundle.state_file, config.policies)
        except OSError as e:
            print(f"invalid gateway config: bundle: {e}", file=sys.stderr)
            return 2
    serve(config)
    return 0


def cmd_probe_isolation(args: argparse.Namespace) -> int:
    from agentsec.gateway.config import ConfigError, load_config
    from agentsec.gateway.probe import probe_isolation

    try:
        rows = probe_isolation(load_config(args.config), args.timeout, args.gateway_host)
    except (ConfigError, PolicyError, OSError, ValueError) as e:  # ValueError: a bad port or host
        print(f"invalid gateway config: {e}", file=sys.stderr)
        return 2
    status = Counter(str(r["status"]) for r in rows)
    if args.json:
        print(json.dumps({"upstreams": rows}, indent=2))
    else:
        for r in rows:
            print(f"{str(r['status']).upper()} {r['kind']} {r['name']} "
                  f"{r['host']}:{r['port']}: {r['detail']}")  # fmt: skip
        print(f"{status['reachable']} reachable, {status['isolated']} isolated, "
              f"{status['unchecked']} unchecked")  # fmt: skip
    # Reachable is the finding; unchecked is not a pass either.
    return 1 if status["reachable"] else 2 if status["unchecked"] else 0


def _verify_key_resolver(unavailable: list[str]) -> Callable[[str], str]:
    """For ``bundle verify``: resolve ``dlp.fingerprint_key`` normally, but when the key is
    only readable on the gateway host (unset variable, missing or unreadable file), record the
    reference and stand in a placeholder. Signature, hashes and every other check still run;
    a malformed reference or a key that is present but too short still fails."""
    from agentsec.middleware.dlp import _resolve

    def resolve(ref: str) -> str:
        kind, _, value = ref.partition(":")
        try:
            return _resolve(ref)
        except (FileNotFoundError, PermissionError):
            if kind != "file":
                raise
        except DlpConfigError:
            if kind != "env" or os.environ.get(value):
                raise
        unavailable.append(ref)
        return "x" * 32  # never used to fingerprint anything: verify only parses

    return resolve


def cmd_bundle(args: argparse.Namespace) -> int:
    from agentsec.gateway.bundle import BundleError, load_bundle, load_public_key, sign_bundle
    from agentsec.gateway.config import ConfigError, resolve_secret

    try:
        if args.action == "sign":
            # A reference, never the key on the command line: argv is visible to other users.
            out = sign_bundle(args.dir, resolve_secret(args.key).encode())
            print(f"signed: {out}")
        else:
            unavailable: list[str] = []
            with open(args.public_key, "rb") as fh:
                policies = load_bundle(
                    args.dir,
                    load_public_key(fh.read()),
                    resolve_secret=_verify_key_resolver(unavailable),
                )
            groups = ", ".join(g.group for g in policies.groups)
            print(f"bundle ok: {policies.revision}, expires {policies.expires}, groups {groups}")
            for ref in dict.fromkeys(unavailable):
                print(
                    f"  note: dlp.fingerprint_key {ref} is not readable here; the gateway "
                    "checks it when it loads the bundle"
                )
            for g in policies.groups:
                expired, soon = g.dlp.allow_expiry()
                for e in expired:
                    print(f"  warning: {g.group}: dlp.allow {e.id} expired {e.expires}")
                for e in soon:
                    print(f"  warning: {g.group}: dlp.allow {e.id} expires {e.expires}")
    except (BundleError, ConfigError, OSError, ValueError) as e:
        print(f"bundle {args.action} failed: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_egress(args: argparse.Namespace) -> int:
    from agentsec.gateway.bundle import BundleError, load_public_key
    from agentsec.gateway.config import ConfigError, resolve_secret
    from agentsec.gateway.feeds import FeedError, sign_feed, verify_feed
    from agentsec.sandbox.blocklist import parse_feed

    try:
        if args.action == "sign-feed":
            with open(args.file, "rb") as fh:
                parse_feed(
                    fh.read(), args.kind, args.name
                )  # never sign a file the gateway would refuse
            out = sign_feed(args.file, resolve_secret(args.key).encode(), args.name)
            print(f"signed: {out}")
        else:
            if args.public_key:
                with open(args.public_key, "rb") as fh:
                    key = load_public_key(fh.read())
                data, _ = verify_feed(args.file, args.name, key, time.time())
            else:
                with open(args.file, "rb") as fh:
                    data = fh.read()
            feed = parse_feed(data, args.kind, args.name)
            print(f"feed ok: {feed.entries} entries, sha256 {feed.sha256}")
    except (FeedError, BundleError, ConfigError, OSError, ValueError) as e:
        print(f"egress {args.action} failed: {e}", file=sys.stderr)
        return 1
    return 0


def _token_settings(path: str) -> TokenSettings:
    """Only the tokens section: a token command must not depend on the bundle or the policy."""
    import yaml

    from agentsec.gateway.config import ConfigError, _tokens

    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ConfigError(f"{path} is not valid YAML: {e}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: config must be a mapping")
    tokens = _tokens(data, Path(path).parent)
    if tokens is None:
        raise ConfigError(f"{path} has no tokens section")
    return tokens


def cmd_dlp_hash(args: argparse.Namespace) -> int:
    """HMAC-SHA256 of one value from stdin under the policy's ``fingerprint_key``, for a
    ``dlp.allow`` entry's ``match.hmac_sha256``. Keyed, because a plain hash of a password or
    SSN in the policy bundle is reversed by trying every value.

    The value is never echoed or printed: from a terminal it is read without echo (so it is
    not in shell history), and only the digest goes to stdout.
    """
    try:
        key = resolve_key(args.key)
    except (DlpConfigError, OSError) as e:
        print(f"error: --key: {e}", file=sys.stderr)
        return 2
    if sys.stdin.isatty():
        value = getpass.getpass("value to hash (not echoed): ")
    else:
        # Bytes, decoded as UTF-8: the gateway hashes value.encode(), whatever the locale.
        value = sys.stdin.buffer.read().decode("utf-8")
        # One trailing newline is the shell's (echo, a file's last line), not the value's.
        value = value[:-2] if value.endswith("\r\n") else value.removesuffix("\n")
    if not value:
        print("error: no value on stdin", file=sys.stderr)
        return 2
    print(allow_digest(key, value))
    kinds = [
        f.kind
        for f in find_sensitive(value, include_email=True, max_scan_chars=len(value))
        if f.start == 0 and f.end == len(value)
    ]
    if kinds:
        print(f"matches built-in kind {kinds[0]}", file=sys.stderr)
    else:
        print(
            "warning: no built-in detector matches the whole value (custom detectors are not "
            "checked here). The allowlist compares the exact span a detector matched: for "
            "cards and SSNs that includes the spaces or dashes.",
            file=sys.stderr,
        )
    return 0


def cmd_token(args: argparse.Namespace) -> int:
    from datetime import UTC, datetime

    from agentsec.gateway.config import ConfigError
    from agentsec.gateway.tokens import TokenStore

    try:
        store = TokenStore(_token_settings(args.config).store)
    except (ConfigError, OSError, ValueError) as e:
        print(f"token {args.action} failed: {e}", file=sys.stderr)
        return 1

    def when(ts: float | None) -> str:
        return "-" if ts is None else datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M")

    # No issue command: a token is issued only after an SSO sign-in (POST /tokens). Revocations
    # are recorded in the store; the gateway's audit chain belongs to the gateway process.
    if args.action == "list":
        for t in store.list(user=args.user):
            state = "revoked" if t.revoked else "live"
            print(f"{t.id}  {t.user:<24} {state:<7} expires {when(t.expires)}  "
                  f"last used {when(t.last_used)}  {t.name}")  # fmt: skip
        return 0
    if args.action == "enable":
        # Undoes only the block that offboarding recorded; revoked tokens stay revoked.
        enabled = store.enable_user(args.user)
        print(f"{args.user}: {'enabled' if enabled else 'was not disabled'}")
        return 0 if enabled else 1
    if (args.id is None) == (args.user is None):
        print("token revoke takes --id ID or --user USER", file=sys.stderr)
        return 2
    count = int(store.revoke(args.id)) if args.id else store.revoke_user(args.user)
    print(f"revoked {count} token(s)")
    return 0 if count else 1  # a mistyped id or user must not look like a revocation


def cmd_token_offboard(args: argparse.Namespace) -> int:
    """Exit 0: nothing overdue; 1: bad input, an unreadable config or a missing store;
    3: a revocation is pending past its deadline."""
    from agentsec.gateway import offboard
    from agentsec.gateway.config import ConfigError

    try:
        text = (
            sys.stdin.read()
            if args.events == "-"
            else (Path(args.events).read_text(encoding="utf-8") if args.events else "")
        )
        events = offboard.parse_events(text) if text.strip() else []
        # Before any config is read: stdin cannot be replayed, a broken gateway config can.
        offboard.record(args.ledger, events)
        settings, unread = [], {}
        for path in args.config:
            try:
                settings.append(_token_settings(path))
            except (ConfigError, OSError, ValueError) as e:
                unread[path] = f"{type(e).__name__}: {e}"[:200]
                print(f"token offboard: config not read: {e}", file=sys.stderr)
        deadline = args.deadline_s or min(
            (t.offboarding_deadline_s for t in settings), default=offboard.DEFAULT_DEADLINE_S
        )
        out = offboard.run(
            args.ledger, [t.store for t in settings], [], deadline_s=deadline, unread=unread
        )
        if args.metrics_file:
            Path(args.metrics_file).write_text(offboard.metrics_text(out), encoding="utf-8")
    except (ConfigError, offboard.OffboardError, OSError, ValueError) as e:
        print(f"token offboard failed: {e}", file=sys.stderr)
        return 1
    print(f"revoked {out.revoked} token(s); {len(out.pending)} pending, {len(out.overdue)} overdue")
    for (kind, user, group), count in out.counts.items():
        what = f"user {user}" if kind == "user" else f"user {user}, group {group}"
        print(f"  {what}: revoked {count} token(s)")
    for kind, user, group in out.unmatched:
        what = f"user {user}" if kind == "user" else f"user {user}, group {group}"
        print(
            f"warning: {what} matched no token in any store (names are compared exactly)",
            file=sys.stderr,
        )
    for store in out.missing:
        print(f"token offboard: token store {store} does not exist on this host", file=sys.stderr)
    for ev in offboard.audit_events(out):
        print(json.dumps(ev), file=sys.stderr)
    return 3 if out.overdue else 1 if unread or out.missing else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentsec", description="Security toolkit for LLM agents.")
    p.add_argument("--version", action="version", version=f"agentsec {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    f = sub.add_parser("fuzz", help="Run the prompt-injection fuzzer against a target.")
    f.add_argument(
        "--target",
        default="builtin:guarded",
        help="builtin:naive | builtin:guarded | builtin:guarded-noscanner | http(s)://URL | "
        "anthropic:MODEL | ollama:MODEL | openai-compat:URL#model=NAME[&token=env:VAR][&stream=1] "
        "| guarded:<model target> | package.module:callable",
    )
    f.add_argument(
        "--scenarios",
        help=f"comma list from {list(SCENARIOS)} (default: {','.join(DEFAULT_SCENARIOS)})",
    )
    f.add_argument("--mutators", help=f"comma list from {list(MUTATORS)} (default: all)")
    f.add_argument("--categories", help="comma list of payload categories (default: all)")
    f.add_argument("--seed", type=int, default=0)
    f.add_argument("--max-cases", type=int, help="randomly sample at most N cases")
    f.add_argument("--max-asr", type=float, help="exit 1 if attack-success rate exceeds this (0-1)")
    f.add_argument(
        "--timeout",
        type=float,
        help="wall-clock seconds per case for HTTP, model and module:callable targets, retries "
        "included (default: 60 for http(s)://, 300 for ollama:, openai-compat: and "
        "module:callable; per request for anthropic:)",
    )
    f.add_argument("--json", help="write full JSON report to this path")
    f.add_argument("--md", help="write Markdown report to this path")
    f.add_argument("--sarif", help="write a SARIF 2.1.0 report (GitHub code scanning)")
    f.add_argument(
        "--sarif-artifact",
        default="agent",
        help="repo-relative path of the file that defines the agent; SARIF alerts attach to it",
    )
    f.add_argument("--junit", help="write a JUnit XML report to this path")
    f.add_argument("--quiet", action="store_true", help="only print the one-line summary")
    f.add_argument("--list", action="store_true", help="show the test matrix and exit")
    f.set_defaults(func=cmd_fuzz)

    pol = sub.add_parser("policy", help="Validate a tool policy or test a call against it.")
    pol_sub = pol.add_subparsers(dest="action", required=True)
    pv = pol_sub.add_parser("validate", help="Load and lint a policy file.")
    pv.add_argument("file")
    pv.add_argument("--strict", action="store_true", help="exit 1 on lint warnings")
    pc = pol_sub.add_parser("check", help="Evaluate one tool call against a policy.")
    pc.add_argument("file")
    pc.add_argument("--tool", required=True)
    pc.add_argument("--args", help="JSON object of arguments")
    pc.add_argument(
        "--tainted", action="store_true", help="evaluate as if untrusted content was read"
    )
    pol.set_defaults(func=cmd_policy)

    a = sub.add_parser("audit", help="Audit-log utilities.")
    a_sub = a.add_subparsers(dest="action", required=True)
    av = a_sub.add_parser("verify", help="Verify a hash-chained JSONL audit log.")
    av.add_argument("file")
    av.add_argument(
        "--allow-empty",
        action="store_true",
        help="exit 0 for a log with zero records (default: exit 2, as a truncated log has none)",
    )
    asum = a_sub.add_parser(
        "summary",
        help="Count events, decisions and denials in an audit log (verifies the chain first).",
    )
    asum.add_argument("file")
    asum.add_argument("--since", type=_iso, help="ISO timestamp; keep records at or after it")
    asum.add_argument("--until", type=_iso, help="ISO timestamp; keep records before it")
    asum.add_argument("--actor", help="keep records of this actor")
    asum.add_argument("--event", help="keep records of this event type")
    asum.add_argument("--json", action="store_true", help="print JSON instead of a table")
    asum.add_argument(
        "--no-verify",
        action="store_true",
        help="summarise a log that fails chain verification; the result is not trustworthy",
    )
    a.set_defaults(func=cmd_audit)

    sc = sub.add_parser(
        "scan-config",
        help="Scan and pin agent configuration (MCP servers, hooks, settings, instruction files).",
    )
    sc.add_argument("path", nargs="?", default=".", help="Directory or file to scan (default: .).")
    sc.add_argument("--pins", help="Pin file: report entries added, changed or removed since.")
    sc.add_argument(
        "--update-pins", action="store_true", help="Write the current entries to --pins."
    )
    sc.add_argument(
        "--accept",
        action="append",
        metavar="ITEM_ID",
        help="With --pins and --update-pins: record this entry's injection finding as a reviewed "
        "false positive, until the entry changes. Repeat for more entries. Needs --reason.",
    )
    sc.add_argument(
        "--reason",
        metavar="TEXT",
        help="With --accept: why the finding is a false positive. Stored in the pin file.",
    )
    sc.add_argument("--json", action="store_true", help="Print findings as JSON.")
    sc.set_defaults(func=cmd_scan_config)

    sw = sub.add_parser(
        "scan-workflows",
        help="Find GitHub Actions jobs that run an AI agent on text an outsider controls.",
    )
    sw.add_argument(
        "path", nargs="?", default=".", help="Repository or workflow file (default: .)."
    )
    sw.add_argument("--json", action="store_true", help="Print findings as JSON.")
    sw.set_defaults(func=cmd_scan_workflows)

    hk = sub.add_parser(
        "hook",
        help="Claude Code PreToolUse hook: apply a tool policy and taint tracking (reads stdin).",
    )
    hk.add_argument("--policy", required=True, help="Tool policy (YAML).")
    hk.add_argument(
        "--state-dir", required=True, help="Directory for per-session taint and call counts."
    )
    hk.add_argument("--audit", help="Append decisions to this hash-chained audit log.")
    hk.add_argument(
        "--block-approvals",
        action="store_true",
        help="Block (exit code 2) a call that needs approval instead of answering 'ask'.",
    )
    hk.set_defaults(func=cmd_hook)

    tm = sub.add_parser("threatmodel", help="STRIDE-for-agents threat modeling.")
    tm_sub = tm.add_subparsers(dest="action", required=True)
    ti = tm_sub.add_parser("init", help="Print or write a starter system description.")
    ti.add_argument("-o", "--output")
    tr = tm_sub.add_parser("render", help="Generate a threat model from a system description.")
    tr.add_argument("system", help="system description YAML")
    tr.add_argument("-o", "--output")
    tm_sub.add_parser("catalog", help="List the threat catalog.")
    tm_sub.add_parser(
        "crosswalk", help="Map the catalog to OWASP Agentic Top 10 and MITRE ATLAS (Markdown)."
    )
    tm.set_defaults(func=cmd_threatmodel)

    sv = sub.add_parser("serve", help="Run the policy-enforcing gateway (the gateway extra).")
    sv.add_argument("--config", required=True, help="gateway YAML config")
    sv.add_argument("--check", action="store_true", help="validate the config and exit")
    sv.set_defaults(func=cmd_serve)

    pi = sub.add_parser(
        "probe-isolation",
        help="From a client or CI runner (not the gateway host): check that the gateway's "
        "upstreams refuse direct TCP connections. Exit 1 if any is reachable.",
    )
    pi.add_argument("--config", required=True, help="gateway YAML config")
    pi.add_argument("--timeout", type=float, default=3.0, help="seconds per connect (default 3)")
    pi.add_argument(
        "--gateway-host",
        help="the gateway's address as clients see it: upstreams with a loopback URL are "
        "probed there (without it they are unchecked, exit 2)",
    )
    pi.add_argument("--json", action="store_true", help="print JSON instead of lines")
    pi.set_defaults(func=cmd_probe_isolation)

    b = sub.add_parser("bundle", help="Sign or verify a gateway policy bundle.")
    b_sub = b.add_subparsers(dest="action", required=True)
    bs = b_sub.add_parser("sign", help="Write manifest.sig for a bundle directory.")
    bs.add_argument("dir")
    bs.add_argument(
        "--key", required=True, help="Ed25519 private key PEM as env:NAME or file:/path"
    )
    bv = b_sub.add_parser("verify", help="Verify a bundle's signature, hashes and contents.")
    bv.add_argument("dir")
    bv.add_argument("--public-key", required=True, help="Ed25519 public key PEM file")
    b.set_defaults(func=cmd_bundle)

    eg = sub.add_parser("egress", help="Sign or check a gateway egress blocklist feed.")
    eg_sub = eg.add_subparsers(dest="action", required=True)
    for action, help_text in (
        ("sign-feed", "Validate a feed file and write FILE.sig (run where the feed key lives)."),
        ("check-feed", "Parse a feed file, and verify FILE.sig when --public-key is given."),
    ):
        ep = eg_sub.add_parser(action, help=help_text)
        ep.add_argument("file")
        ep.add_argument("--kind", required=True, choices=["ip", "domain"])
        ep.add_argument("--name", required=True, help="the list name in egress.blocklists")
        if action == "sign-feed":
            ep.add_argument(
                "--key", required=True, help="Ed25519 private key PEM as env:NAME or file:/path"
            )
        else:
            ep.add_argument("--public-key", help="Ed25519 public key PEM file of the feed key")
    eg.set_defaults(func=cmd_egress)

    d = sub.add_parser("dlp", help="Data-loss prevention utilities.")
    d_sub = d.add_subparsers(dest="action", required=True)
    dh = d_sub.add_parser(
        "hash", help="Print the keyed hash of a value from stdin, for dlp.allow match.hmac_sha256."
    )
    dh.add_argument(
        "--key", required=True, help="the policy's dlp.fingerprint_key, as env:NAME or file:/path"
    )
    dh.set_defaults(func=cmd_dlp_hash)

    t = sub.add_parser("token", help="List or revoke gateway access tokens (admin).")
    t_sub = t.add_subparsers(dest="action", required=True)
    tl = t_sub.add_parser("list", help="List tokens (never the token values).")
    tl.add_argument("--config", required=True, help="the gateway config with a tokens section")
    tl.add_argument("--user", help="only this user's tokens")
    tr = t_sub.add_parser("revoke", help="Revoke one token, or every token of a user.")
    tr.add_argument("--config", required=True, help="the gateway config with a tokens section")
    tr.add_argument("--id", help="the token id")
    tr.add_argument("--user", help="revoke all of this user's tokens")
    te = t_sub.add_parser("enable", help="Let a user that offboarding disabled mint tokens again.")
    te.add_argument("--config", required=True, help="the gateway config with a tokens section")
    te.add_argument("--user", required=True)
    t.set_defaults(func=cmd_token)
    to = t_sub.add_parser(
        "offboard",
        help="Revoke tokens of IdP-disabled users or removed groups on every gateway; retry; alert.",
    )
    to.add_argument(
        "--config", action="append", required=True, help="a gateway config; repeat per gateway"
    )
    to.add_argument("--ledger", required=True, help="SQLite file of pending and done revocations")
    to.add_argument(
        "--events",
        help='JSON file, or - for stdin: {"disabled_users": [], "removed_groups": []}; omit to only retry',
    )
    to.add_argument("--deadline-s", type=float, help="override tokens.offboarding_deadline_s")
    to.add_argument("--metrics-file", help="write Prometheus textfile metrics here")
    to.set_defaults(func=cmd_token_offboard)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
