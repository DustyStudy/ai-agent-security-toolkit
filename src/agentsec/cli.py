"""``agentsec`` command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from agentsec import __version__
from agentsec.configscan import check_pins, load_pins, save_pins, scan_config, show
from agentsec.fuzzer import CORPUS, MUTATORS, FuzzConfig, load_target, run
from agentsec.fuzzer.harness import SCENARIOS, build_cases
from agentsec.middleware.audit import verify_file
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


def _csv(value: str | None) -> list[str] | None:
    return [v.strip() for v in value.split(",") if v.strip()] if value else None


def cmd_fuzz(args: argparse.Namespace) -> int:
    config = FuzzConfig(
        seed=args.seed,
        scenarios=_csv(args.scenarios) or list(SCENARIOS),
        mutators=_csv(args.mutators),
        categories=_csv(args.categories),
        max_cases=args.max_cases,
    )
    if args.list:
        cases = build_cases(config)
        print(f"{len(CORPUS)} payloads x {len(MUTATORS)} mutators x {len(SCENARIOS)} scenarios")
        print(f"selected: {len(cases)} cases")
        print("mutators:", ", ".join(MUTATORS))
        return 0
    try:
        target = load_target(args.target)
        report = run(target, config)
    except (ValueError, ImportError, AttributeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        Path(args.json).write_text(report.to_json(), encoding="utf-8", newline="\n")
    if args.md:
        Path(args.md).write_text(report.to_markdown(), encoding="utf-8", newline="\n")
    if args.sarif:
        Path(args.sarif).write_text(
            report.to_sarif(artifact_uri=args.sarif_artifact, target=args.target),
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
    if report.total and report.errors == report.total:
        # Zero successes out of zero scored cases would pass any --max-asr gate.
        print("FAIL: every case errored; nothing was evaluated", file=sys.stderr)
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
        result = verify_file(args.file)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if result.ok:
        print(f"OK: {result.records_checked} record(s), chain intact")
        return 0
    print(
        f"TAMPERED: {result.reason} (first bad seq: {result.first_bad_seq}, "
        f"{result.records_checked} valid before it)",
        file=sys.stderr,
    )
    return 1


def cmd_scan_config(args: argparse.Namespace) -> int:
    if args.update_pins and not args.pins:
        print("error: --update-pins needs --pins FILE", file=sys.stderr)
        return 2
    pins_path = args.pins and Path(args.pins)
    try:
        scan = scan_config(args.path)
        findings = list(scan.findings)
        if pins_path and not (args.update_pins and not pins_path.exists()):
            findings += check_pins(scan, load_pins(pins_path))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        # An item id holds names from the scanned files, so it is redacted and escaped too.
        rows = [{"item": show(f.item), "kind": f.kind, "detail": f.detail} for f in findings]
        print(json.dumps({"items": len(scan.items), "findings": rows}, indent=2))
    else:
        if not pins_path:
            for item in scan.items.values():
                print(f"  {item.kind:<12} {show(item.id)}  {item.summary}")
        for f in findings:
            print(f"{f.kind.upper():<9} {show(f.item)}: {f.detail}")
        print(f"{len(scan.items)} item(s), {len(findings)} finding(s)")
    if not args.update_pins:
        return 1 if findings else 0
    if scan.findings:
        # A flagged entry must not become trusted, and a tree that could not be read in full
        # would drop the pins of what was missed.
        print("pins not written: fix the findings above first", file=sys.stderr)
        return 1
    try:
        save_pins(args.pins, scan.fingerprints)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"pinned {len(scan.items)} item(s) to {args.pins}", file=sys.stderr)
    return 0


def cmd_hook(args: argparse.Namespace) -> int:
    # Every failure must end in exit code 2: any other code lets the tool call through.
    try:
        from agentsec.integrations.claude_code import handle

        event = json.loads(sys.stdin.buffer.read())
        if not isinstance(event, dict):
            raise ValueError("hook input must be a JSON object")
        policy = Policy.from_yaml(args.policy)
        result = handle(event, policy, args.state_dir, audit=args.audit)
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
    if args.check:
        print(f"config ok: {len(config.upstreams)} upstream(s), policy {config.policies.revision}")
        return 0
    serve(config)
    return 0


def cmd_bundle(args: argparse.Namespace) -> int:
    from agentsec.gateway.bundle import BundleError, load_bundle, load_public_key, sign_bundle
    from agentsec.gateway.config import ConfigError, resolve_secret

    try:
        if args.action == "sign":
            # A reference, never the key on the command line: argv is visible to other users.
            out = sign_bundle(args.dir, resolve_secret(args.key).encode())
            print(f"signed: {out}")
        else:
            with open(args.public_key, "rb") as fh:
                policies = load_bundle(args.dir, load_public_key(fh.read()))
            groups = ", ".join(g.group for g in policies.groups)
            print(f"bundle ok: {policies.revision}, expires {policies.expires}, groups {groups}")
    except (BundleError, ConfigError, OSError, ValueError) as e:
        print(f"bundle {args.action} failed: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_token(args: argparse.Namespace) -> int:
    from datetime import UTC, datetime

    from agentsec.gateway.config import ConfigError, load_config
    from agentsec.gateway.tokens import TokenStore

    try:
        settings = load_config(args.config).tokens
        if settings is None:
            raise ConfigError("the config has no tokens section")
        store = TokenStore(settings.store)
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
    if (args.id is None) == (args.user is None):
        print("token revoke takes --id ID or --user USER", file=sys.stderr)
        return 2
    count = int(store.revoke(args.id)) if args.id else store.revoke_user(args.user)
    print(f"revoked {count} token(s)")
    return 0


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
    f.add_argument("--scenarios", help=f"comma list from {list(SCENARIOS)} (default: all)")
    f.add_argument("--mutators", help=f"comma list from {list(MUTATORS)} (default: all)")
    f.add_argument("--categories", help="comma list of payload categories (default: all)")
    f.add_argument("--seed", type=int, default=0)
    f.add_argument("--max-cases", type=int, help="randomly sample at most N cases")
    f.add_argument("--max-asr", type=float, help="exit 1 if attack-success rate exceeds this (0-1)")
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
    sc.add_argument("--json", action="store_true", help="Print findings as JSON.")
    sc.set_defaults(func=cmd_scan_config)

    hk = sub.add_parser(
        "hook",
        help="Claude Code PreToolUse hook: apply a tool policy and taint tracking (reads stdin).",
    )
    hk.add_argument("--policy", required=True, help="Tool policy (YAML).")
    hk.add_argument(
        "--state-dir", required=True, help="Directory for per-session taint and call counts."
    )
    hk.add_argument("--audit", help="Append decisions to this hash-chained audit log.")
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

    t = sub.add_parser("token", help="List or revoke gateway access tokens (admin).")
    t_sub = t.add_subparsers(dest="action", required=True)
    tl = t_sub.add_parser("list", help="List tokens (never the token values).")
    tl.add_argument("--config", required=True, help="the gateway config with a tokens section")
    tl.add_argument("--user", help="only this user's tokens")
    tr = t_sub.add_parser("revoke", help="Revoke one token, or every token of a user.")
    tr.add_argument("--config", required=True, help="the gateway config with a tokens section")
    tr.add_argument("--id", help="the token id")
    tr.add_argument("--user", help="revoke all of this user's tokens")
    t.set_defaults(func=cmd_token)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
