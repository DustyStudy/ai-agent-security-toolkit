"""``agentsec`` command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from agentsec import __version__
from agentsec.fuzzer import CORPUS, MUTATORS, FuzzConfig, load_target, run
from agentsec.fuzzer.harness import SCENARIOS, build_cases
from agentsec.middleware.audit import verify_file
from agentsec.sandbox import Policy, PolicyError, ToolGuard
from agentsec.threatmodel import (
    SYSTEM_TEMPLATE,
    SystemSpecError,
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
        Path(args.json).write_text(report.to_json(), encoding="utf-8")
    if args.md:
        Path(args.md).write_text(report.to_markdown(), encoding="utf-8")
    if args.sarif:
        Path(args.sarif).write_text(
            report.to_sarif(artifact_uri=args.sarif_artifact, target=args.target),
            encoding="utf-8",
        )
    if args.junit:
        Path(args.junit).write_text(report.to_junit(), encoding="utf-8")
    print(
        f"{report.successes}/{report.total - report.errors} attacks succeeded "
        f"(ASR {report.asr:.1%}); {report.blocked} blocked, {report.errors} errors"
    )
    if not args.quiet:
        print()
        print(report.to_markdown(max_bypasses=8))
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


def cmd_threatmodel(args: argparse.Namespace) -> int:
    if args.action == "init":
        out = Path(args.output) if args.output else None
        if out:
            out.write_text(SYSTEM_TEMPLATE, encoding="utf-8")
            print(f"wrote {out}")
        else:
            print(SYSTEM_TEMPLATE, end="")
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
        Path(args.output).write_text(doc, encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        print(doc)
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
        "anthropic:MODEL | package.module:callable",
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

    tm = sub.add_parser("threatmodel", help="STRIDE-for-agents threat modeling.")
    tm_sub = tm.add_subparsers(dest="action", required=True)
    ti = tm_sub.add_parser("init", help="Print or write a starter system description.")
    ti.add_argument("-o", "--output")
    tr = tm_sub.add_parser("render", help="Generate a threat model from a system description.")
    tr.add_argument("system", help="system description YAML")
    tr.add_argument("-o", "--output")
    tm_sub.add_parser("catalog", help="List the threat catalog.")
    tm.set_defaults(func=cmd_threatmodel)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
