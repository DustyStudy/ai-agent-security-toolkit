"""Turn test, coverage and fuzz results into a readable evidence report.

Reads the files the test run already writes and renders them as Markdown (for a CI job
summary or a commit under docs/evidence/) and as one self-contained HTML page (no scripts,
no external assets) that can be opened, archived or screenshotted. Standard library only.

    pytest --junitxml=reports/junit.xml --cov=agentsec --cov-report=xml:reports/coverage.xml
    agentsec fuzz --target builtin:guarded --json reports/fuzz-guarded.json
    python scripts/evidence_report.py --junit reports/junit.xml \\
        --coverage reports/coverage.xml --fuzz builtin:guarded=reports/fuzz-guarded.json \\
        --md reports/summary.md --html reports/report.html

The inputs are files this repository's own tools wrote. Text taken from them (test names,
failure messages) is escaped and bounded before it is written out.
"""

from __future__ import annotations

import argparse
import html
import json
import subprocess
import sys
import xml.etree.ElementTree as ET  # noqa: S405 - parses this repo's own pytest/coverage output
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_TEXT = 300
MAX_FAILURES = 50
# The fuzz categories whose successes mean the controls failed (a forbidden tool call, data
# leaving, the system prompt leaking). Merely getting the model to echo text is reported too,
# but the layers are not meant to stop it; see the README's simulator results.
CONTAINMENT = ("tool_misuse", "exfiltration", "prompt_leak")


def bounded(text: str, limit: int = MAX_TEXT) -> str:
    """One line, control characters removed, at most ``limit`` characters."""
    flat = "".join(ch if ch.isprintable() else " " for ch in text.replace("\n", " "))
    flat = " ".join(flat.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def md_cell(text: str) -> str:
    return bounded(text).replace("|", "\\|").replace("`", "'")


@dataclass
class Tests:
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    seconds: float = 0.0
    by_file: dict[str, list[int]] = field(default_factory=lambda: defaultdict(lambda: [0, 0, 0]))
    failures: list[tuple[str, str]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.passed + self.failed + self.errors + self.skipped

    @property
    def ok(self) -> bool:
        return self.total > 0 and self.failed == 0 and self.errors == 0


def read_junit(paths: list[Path]) -> Tests:
    tests = Tests()
    for path in paths:
        root = ET.parse(path).getroot()  # noqa: S314 - our own pytest output, see module doc
        for case in root.iter("testcase"):
            classname = case.get("classname", "")
            module = classname.split(".")
            # pytest writes "tests.test_x" or "tests.test_x.TestClass".
            name = ".".join(p for p in module if p.startswith("test_")) or classname or "?"
            tests.seconds += float(case.get("time") or 0)
            row = tests.by_file[name]
            failure = case.find("failure")
            error = case.find("error")
            if failure is not None or error is not None:
                bad = failure if failure is not None else error
                if failure is not None:
                    tests.failed += 1
                else:
                    tests.errors += 1
                row[1] += 1
                test_id = f"{classname}::{case.get('name', '?')}"
                message = "" if bad is None else bad.get("message") or bad.text or ""
                tests.failures.append((test_id, message))
            elif case.find("skipped") is not None:
                tests.skipped += 1
                row[2] += 1
            else:
                tests.passed += 1
                row[0] += 1
    return tests


@dataclass
class Coverage:
    percent: float
    modules: list[tuple[str, float]]


def read_coverage(path: Path) -> Coverage:
    root = ET.parse(path).getroot()  # noqa: S314 - our own coverage.py output
    modules = [
        (c.get("filename", "?"), float(c.get("line-rate") or 0) * 100) for c in root.iter("class")
    ]
    return Coverage(float(root.get("line-rate") or 0) * 100, sorted(modules))


@dataclass
class Fuzz:
    label: str
    total: int
    successes: int
    blocked: int
    errors: int
    asr: float
    by_category: dict[str, tuple[int, int]]

    @property
    def containment(self) -> tuple[int, int]:
        rows = [self.by_category[c] for c in CONTAINMENT if c in self.by_category]
        return sum(r[0] for r in rows), sum(r[1] for r in rows)


def read_fuzz(label: str, path: Path) -> Fuzz:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    cats: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for result in data.get("results", []):
        if result.get("error"):
            continue
        row = cats[str(result.get("category", "?"))]
        row[1] += 1
        row[0] += bool(result.get("success"))
    return Fuzz(
        label=label,
        total=int(data.get("total", 0)),
        successes=int(data.get("successes", 0)),
        blocked=int(data.get("blocked", 0)),
        errors=int(data.get("errors", 0)),
        asr=float(data.get("asr", 0.0)),
        by_category={k: (v[0], v[1]) for k, v in sorted(cats.items())},
    )


def git_commit() -> str:
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "rev-parse", "--short=12", "HEAD"],  # noqa: S607 - git from PATH
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return out.stdout.strip() or "unknown"


@dataclass
class Evidence:
    title: str
    commit: str
    generated: str
    environment: str
    tests: Tests | None
    coverage: Coverage | None
    fuzz: list[Fuzz]

    @property
    def ok(self) -> bool:
        return self.tests is None or self.tests.ok


def to_markdown(ev: Evidence) -> str:
    out = [f"## {md_cell(ev.title)}", ""]
    out.append(
        f"Commit `{md_cell(ev.commit)}` · {md_cell(ev.generated)} · {md_cell(ev.environment)}"
    )
    out.append("")
    if ev.tests:
        t = ev.tests
        verdict = "PASS" if t.ok else "FAIL"
        out += [
            f"**Tests: {verdict}.** {t.passed} passed, {t.failed} failed, {t.errors} errors, "
            f"{t.skipped} skipped ({t.total} total, {t.seconds:.1f} s of test time).",
            "",
        ]
    if ev.coverage:
        out += [f"**Coverage:** {ev.coverage.percent:.1f}% of lines.", ""]
    if ev.fuzz:
        out += [
            "**Fuzz runs.** ASR is the attack-success rate over scored cases. *Containment* "
            "counts successes in tool_misuse, exfiltration and prompt_leak, the outcomes the "
            "controls exist to stop; echoing an injected phrase is not one of them.",
            "",
            "| Target | Cases | Successes | Containment | Blocked | Errors | ASR |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for f in ev.fuzz:
            hit, scored = f.containment
            out.append(
                f"| `{md_cell(f.label)}` | {f.total} | {f.successes} | {hit} / {scored} "
                f"| {f.blocked} | {f.errors} | {f.asr:.1%} |"
            )
        out.append("")
    if ev.tests and ev.tests.failures:
        out += ["**Failures:**", ""]
        for test_id, message in ev.tests.failures[:MAX_FAILURES]:
            out.append(f"- `{md_cell(test_id)}`: {md_cell(message)}")
        if len(ev.tests.failures) > MAX_FAILURES:
            out.append(f"- ... and {len(ev.tests.failures) - MAX_FAILURES} more")
        out.append("")
    if ev.tests:
        out += [
            "<details><summary>Tests by file</summary>",
            "",
            "| File | Passed | Failed | Skipped |",
            "|---|---:|---:|---:|",
        ]
        for name, (p, f, s) in sorted(ev.tests.by_file.items()):
            out.append(f"| `{md_cell(name)}` | {p} | {f} | {s} |")
        out += ["", "</details>", ""]
    return "\n".join(out)


_CSS = """
:root{--bg:#fbfbfa;--fg:#1d1d1b;--muted:#6b6a66;--line:#e3e2de;--card:#ffffff;
--pass:#1f7a4d;--pass-bg:#e5f3ea;--fail:#b3261e;--fail-bg:#fbe9e7;--bar:#3a6ea5}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#161615;--fg:#ecebe7;
--muted:#9c9a94;--line:#2c2b29;--card:#1f1e1c;--pass:#6fcf97;--pass-bg:#16301f;--fail:#f28b82;
--fail-bg:#3a1714;--bar:#7aa7d6}}
:root[data-theme="dark"]{--bg:#161615;--fg:#ecebe7;--muted:#9c9a94;--line:#2c2b29;--card:#1f1e1c;
--pass:#6fcf97;--pass-bg:#16301f;--fail:#f28b82;--fail-bg:#3a1714;--bar:#7aa7d6}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:960px;margin:0 auto;padding:32px 16px}h1{font-size:24px;margin:0 0 4px}
h2{font-size:17px;margin:32px 0 12px}.meta{color:var(--muted);font-size:13px}
code{font:13px ui-monospace,SFMono-Regular,Consolas,monospace}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.tile b{display:block;font-size:26px;font-variant-numeric:tabular-nums}.tile span{color:var(--muted);font-size:13px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-weight:600;font-size:13px}
.pass{color:var(--pass);background:var(--pass-bg)}.fail{color:var(--fail);background:var(--fail-bg)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
border-radius:10px;overflow:hidden;font-variant-numeric:tabular-nums}
th,td{padding:7px 12px;border-bottom:1px solid var(--line);text-align:left;font-size:14px}
th{color:var(--muted);font-weight:600}td.n,th.n{text-align:right}
.bar{height:6px;background:var(--line);border-radius:3px;min-width:80px}
.bar i{display:block;height:6px;background:var(--bar);border-radius:3px}
.scroll{overflow-x:auto}details{margin-top:12px}
"""


def _bar(percent: float) -> str:
    return f'<div class="bar"><i style="width:{max(0.0, min(percent, 100.0)):.1f}%"></i></div>'


def to_html(ev: Evidence) -> str:
    e = html.escape
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>{e(bounded(ev.title, 80))}</title><style>{_CSS}</style></head><body><main>",
        f"<h1>{e(bounded(ev.title))}</h1>",
        f"<div class='meta'>Commit <code>{e(bounded(ev.commit))}</code> · {e(bounded(ev.generated))}"
        f" · {e(bounded(ev.environment))}</div>",
    ]
    tiles = []
    if ev.tests:
        t = ev.tests
        cls, word = ("pass", "PASS") if t.ok else ("fail", "FAIL")
        parts.append(f"<p><span class='badge {cls}'>Tests {word}</span></p>")
        tiles += [
            (str(t.passed), "passed"),
            (str(t.failed + t.errors), "failed or errored"),
            (str(t.skipped), "skipped"),
        ]
    if ev.coverage:
        tiles.append((f"{ev.coverage.percent:.1f}%", "line coverage"))
    if tiles:
        parts.append("<div class='tiles'>")
        parts += [f"<div class='tile'><b>{e(v)}</b><span>{e(k)}</span></div>" for v, k in tiles]
        parts.append("</div>")
    if ev.fuzz:
        parts.append("<h2>Fuzz runs</h2><div class='scroll'><table><tr><th>Target</th>")
        parts.append(
            "<th class='n'>Cases</th><th class='n'>Successes</th><th class='n'>Containment</th>"
            "<th class='n'>Blocked</th><th class='n'>Errors</th><th class='n'>ASR</th></tr>"
        )
        for f in ev.fuzz:
            parts.append(
                f"<tr><td><code>{e(bounded(f.label))}</code></td><td class='n'>{f.total}</td>"
                f"<td class='n'>{f.successes}</td>"
                f"<td class='n'><b>{f.containment[0]}</b> / {f.containment[1]}</td>"
                f"<td class='n'>{f.blocked}</td><td class='n'>{f.errors}</td>"
                f"<td class='n'>{f.asr:.1%}</td></tr>"
            )
        parts.append("</table></div>")
        parts.append(
            "<p class='meta'>ASR: attack-success rate over scored cases. Containment: successes"
            " in tool_misuse, exfiltration and prompt_leak, the outcomes the controls exist to"
            " stop; echoing an injected phrase is not one of them.</p>"
        )
        categories = sorted({c for f in ev.fuzz for c in f.by_category})
        parts.append(
            "<h2>Successes by category</h2><div class='scroll'><table><tr><th>Category</th>"
        )
        parts += [f"<th class='n'>Run {i}</th>" for i in range(1, len(ev.fuzz) + 1)]
        parts.append("</tr>")
        for cat in categories:
            label = f"<b>{e(cat)}</b>" if cat in CONTAINMENT else e(cat)
            cells = []
            for f in ev.fuzz:
                s_, n_ = f.by_category.get(cat, (0, 0))
                cells.append(f"<td class='n'>{s_} / {n_}</td>")
            parts.append(f"<tr><td>{label}</td>{''.join(cells)}</tr>")
        parts.append("</table></div><p class='meta'>")
        parts.append(
            "; ".join(
                f"Run {i}: <code>{e(bounded(f.label))}</code>" for i, f in enumerate(ev.fuzz, 1)
            )
        )
        parts.append(". Containment categories in bold.</p>")
    if ev.tests and ev.tests.failures:
        parts.append(
            "<h2>Failures</h2><div class='scroll'><table><tr><th>Test</th><th>Message</th></tr>"
        )
        for test_id, message in ev.tests.failures[:MAX_FAILURES]:
            parts.append(
                f"<tr><td><code>{e(bounded(test_id))}</code></td><td>{e(bounded(message))}</td></tr>"
            )
        parts.append("</table></div>")
    if ev.tests:
        parts.append("<h2>Tests by file</h2><div class='scroll'><table><tr><th>File</th>")
        parts.append(
            "<th class='n'>Passed</th><th class='n'>Failed</th><th class='n'>Skipped</th></tr>"
        )
        for name, (p, f, s) in sorted(ev.tests.by_file.items()):
            parts.append(
                f"<tr><td><code>{e(bounded(name))}</code></td><td class='n'>{p}</td>"
                f"<td class='n'>{f}</td><td class='n'>{s}</td></tr>"
            )
        parts.append("</table></div>")
    if ev.coverage:
        parts.append("<details><summary>Coverage by module</summary><div class='scroll'><table>")
        parts.append("<tr><th>Module</th><th class='n'>Lines covered</th><th></th></tr>")
        for name, pct in ev.coverage.modules:
            parts.append(
                f"<tr><td><code>{e(bounded(name))}</code></td><td class='n'>{pct:.1f}%</td>"
                f"<td>{_bar(pct)}</td></tr>"
            )
        parts.append("</table></div></details>")
    parts.append("</main></body></html>\n")
    return "\n".join(parts)


def build(args: argparse.Namespace) -> Evidence:
    fuzz = []
    for spec in args.fuzz:
        label, sep, path = spec.partition("=")
        if not sep:
            label, path = Path(spec).stem, spec
        fuzz.append(read_fuzz(label, Path(path)))
    return Evidence(
        title=args.title,
        commit=args.commit or git_commit(),
        generated=args.generated or datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        environment=args.environment or f"Python {sys.version.split()[0]} on {sys.platform}",
        tests=read_junit([Path(p) for p in args.junit]) if args.junit else None,
        coverage=read_coverage(Path(args.coverage)) if args.coverage else None,
        fuzz=fuzz,
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--junit", action="append", default=[], help="pytest --junitxml file")
    p.add_argument("--coverage", help="coverage XML (pytest --cov-report=xml:FILE)")
    p.add_argument(
        "--fuzz", action="append", default=[], help="LABEL=FILE: an `agentsec fuzz --json` report"
    )
    p.add_argument("--title", default="agentsec test evidence")
    p.add_argument("--commit", help="commit shown in the report (default: git HEAD)")
    p.add_argument("--generated", help="timestamp shown in the report (default: now, UTC)")
    p.add_argument("--environment", help="environment line (default: Python version and OS)")
    p.add_argument("--md", help="write Markdown here ('-' for stdout)")
    p.add_argument("--html", help="write the self-contained HTML page here")
    args = p.parse_args(argv)
    if not (args.junit or args.coverage or args.fuzz):
        p.error("give at least one of --junit, --coverage or --fuzz")
    try:
        ev = build(args)
    except (OSError, ValueError, ET.ParseError) as exc:
        print(f"error: {bounded(str(exc))}", file=sys.stderr)
        return 2
    if args.md == "-":
        print(to_markdown(ev))
    elif args.md:
        Path(args.md).write_text(to_markdown(ev), encoding="utf-8", newline="\n")
    if args.html:
        Path(args.html).write_text(to_html(ev), encoding="utf-8", newline="\n")
    return 0 if ev.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
