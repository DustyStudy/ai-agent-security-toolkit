"""Measure the per-call overhead the toolkit adds to an agent loop.

    python scripts/bench_overhead.py            # prints a Markdown table
    python scripts/bench_overhead.py --json out.json

Each row is the median of several batches, in microseconds per operation, plus the 95th
percentile of the batch means. Numbers depend on the machine and Python version, so treat
them as indicative and re-run on your own hardware. What matters for capacity planning is the
order of magnitude next to a model call (hundreds of milliseconds to seconds).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from agentsec import __version__
from agentsec.fuzzer.mock_agents import demo_policy
from agentsec.middleware import (
    AgentMiddleware,
    AuditLogger,
    FileSink,
    InjectionScanner,
    MemorySink,
    OutputGuard,
    redact_text,
)
from agentsec.sandbox import Session, ToolGuard
from agentsec.types import ToolCall

BATCHES = 15
BENIGN = (
    "Quarterly operations review: revenue grew in the second half, support tickets fell, and "
    "the migration to the new billing platform finished on schedule. "
)


def _measure(fn: Callable[[], object], iterations: int) -> tuple[float, float]:
    """Return (median, p95) microseconds per call across batches."""
    fn()  # warm up
    means = []
    for _ in range(BATCHES):
        start = time.perf_counter_ns()
        for _ in range(iterations):
            fn()
        means.append((time.perf_counter_ns() - start) / iterations / 1000)
    means.sort()
    return statistics.median(means), means[int(0.95 * (len(means) - 1))]


def _measure_async(coro_fn: Callable[[], object], iterations: int) -> tuple[float, float]:
    async def batch() -> float:
        start = time.perf_counter_ns()
        for _ in range(iterations):
            await coro_fn()  # type: ignore[misc]
        return (time.perf_counter_ns() - start) / iterations / 1000

    async def run() -> list[float]:
        await batch()  # warm up
        return sorted([await batch() for _ in range(BATCHES)])

    means = asyncio.run(run())
    return statistics.median(means), means[int(0.95 * (len(means) - 1))]


def run_benchmarks() -> list[tuple[str, float, float]]:
    rows: list[tuple[str, float, float]] = []

    policy = demo_policy()
    call = ToolCall("search_docs", {"query": "Q3 revenue"})
    url_call = ToolCall(
        "http_request", {"url": "https://api.corp.example/v1/items", "method": "GET"}
    )

    guard = ToolGuard(policy)
    rows.append(
        ("ToolGuard.evaluate (allowed call)", *_measure(lambda: guard.evaluate(call), 20000))
    )
    rows.append(
        (
            "ToolGuard.evaluate (URL argument checks)",
            *_measure(lambda: guard.evaluate(url_call), 20000),
        )
    )

    def execute_plain() -> object:
        return guard.execute(call, lambda query: "ok", Session())

    rows.append(("ToolGuard.execute, no audit", *_measure(execute_plain, 10000)))

    audited = ToolGuard(policy, audit=AuditLogger(MemorySink()))

    def execute_audited() -> object:
        return audited.execute(call, lambda query: "ok", Session())

    rows.append(("ToolGuard.execute + audit (memory sink)", *_measure(execute_audited, 5000)))

    async def aexecute() -> object:
        return await guard.aexecute(call, _async_tool, Session())

    async def _async_tool(query: str) -> str:
        return "ok"

    rows.append(("ToolGuard.aexecute (async tool)", *_measure_async(aexecute, 5000)))

    scanner = InjectionScanner()
    for size in (1_000, 10_000):
        text = (BENIGN * (size // len(BENIGN) + 1))[:size]
        rows.append(
            (
                f"InjectionScanner.scan ({size // 1000} KB benign)",
                *_measure(lambda t=text: scanner.scan(t), 300),
            )
        )

    output = OutputGuard.default(allowed_hosts=["corp.example"])
    text = (BENIGN * 40)[:4000]
    rows.append(
        ("OutputGuard.default().process (4 KB)", *_measure(lambda: output.process(text), 300))
    )
    rows.append(("redact_text (4 KB)", *_measure(lambda: redact_text(text), 300)))

    middleware = AgentMiddleware(
        guard=guard, scanner=scanner, output_guard=output, audit=AuditLogger(MemorySink())
    )
    rows.append(
        (
            "AgentMiddleware.screen_input (1 KB, audited)",
            *_measure(
                lambda: middleware.screen_input(BENIGN * 7, source="user", session=Session()), 300
            ),
        )
    )

    rows.append(("AuditLogger.log (memory sink)", *_measure(_logger(MemorySink()), 5000)))
    with tempfile.TemporaryDirectory() as tmp:
        rows.append(
            (
                "AuditLogger.log (file sink, no fsync)",
                *_measure(_logger(FileSink(Path(tmp) / "a.jsonl")), 2000),
            )
        )
    return rows


def _logger(sink: object) -> Callable[[], object]:
    audit = AuditLogger(sink)  # type: ignore[arg-type]
    return lambda: audit.log("tool_request", tool="search_docs", arguments={"query": "Q3 revenue"})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", help="also write the results to this path")
    args = parser.parse_args()
    rows = run_benchmarks()
    env = f"agentsec {__version__}, Python {sys.version.split()[0]}, {platform.platform()}"
    print(f"Measured on: {env}\n")
    print("| Operation | median (us) | p95 (us) |")
    print("|---|---:|---:|")
    for name, median, p95 in rows:
        print(f"| {name} | {median:,.1f} | {p95:,.1f} |")
    if args.json:
        payload = {
            "environment": env,
            "rows": [{"operation": n, "median_us": m, "p95_us": p} for n, m, p in rows],
        }
        Path(args.json).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
