"""A read-only HTML status page for the admin listener (``GET /dashboard``).

It shows what /readyz and /metrics already expose, the policy group names and modes, and the
summary of one fuzz report (flagged stale after a day), and links to the evidence pages in
``admin.evidence_dir``. Rendered on the server with no JavaScript: the page reloads
itself every few seconds, and a strict CSP forbids scripts, frames, forms and every fetch.

The fuzz report is read through an allowlist of summary fields. Its per-case ``results`` (the
attack payloads and agent replies, which can hold canary secrets) are dropped on load and never shown.
"""

from __future__ import annotations

import json
import logging
import math
import re
from datetime import UTC, datetime, timedelta
from html import escape
from pathlib import Path
from typing import Any

from agentsec.gateway.policyset import PolicySet

_LOG = logging.getLogger("agentsec.gateway")

REFRESH_S = 5
MAX_REPORT_BYTES = 50 * 1024 * 1024  # a fuzz report this size is not one we wrote
STALE_AFTER = timedelta(days=1)
# Evidence files served from admin.evidence_dir: <release>/<file>, one level, plain names only.
EVIDENCE_TYPES = {".html": b"text/html; charset=utf-8", ".png": b"image/png"}
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")

DASHBOARD_HEADERS = [
    (b"cache-control", b"no-store"),
    (
        b"content-security-policy",
        b"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; "
        b"frame-ancestors 'none'",
    ),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
]

_SUMMARY_FIELDS = ("generated_at", "seed", "total", "successes", "blocked", "errors", "asr")


def load_fuzz_summary(path: str | None) -> dict[str, Any] | None:
    """The summary fields of an ``agentsec fuzz --json`` report, or an ``error`` entry."""
    if path is None:
        return None
    try:
        p = Path(path)
        if p.stat().st_size > MAX_REPORT_BYTES:
            return {"error": "report too large"}
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        # The file may be mid-write or missing; the page says so instead of failing.
        _LOG.warning("dashboard: cannot read fuzz report: %s", type(e).__name__)
        return {"error": "report unreadable"}
    if not isinstance(data, dict):
        return {"error": "not a fuzz report"}
    summary: dict[str, Any] = {k: data.get(k) for k in _SUMMARY_FIELDS}
    summary["stale"] = _stale(data.get("generated_at"))
    cats = data.get("by_category")
    summary["by_category"] = {
        str(name): {k: row.get(k) for k in ("cases", "successes", "asr")}
        for name, row in (cats.items() if isinstance(cats, dict) else ())
        if isinstance(row, dict)
    }
    return summary


def _stale(generated_at: Any) -> bool:
    """Older than STALE_AFTER, or a time that cannot be read (so it cannot vouch for itself)."""
    try:
        when = datetime.fromisoformat(str(generated_at))
    except ValueError:
        return True
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return datetime.now(UTC) - when > STALE_AFTER


def list_evidence(root: str | None) -> list[tuple[str, list[str]]] | None:
    """Release folders under ``root`` (newest name first) and the files /evidence can serve."""
    if root is None:
        return None
    try:
        releases = [d for d in Path(root).iterdir() if d.is_dir() and _NAME.fullmatch(d.name)]
        return [
            (d.name, sorted(f.name for f in d.iterdir() if _servable(Path(root), d.name, f.name)))
            for d in sorted(releases, key=lambda d: d.name, reverse=True)
        ]
    except OSError as e:
        _LOG.warning("dashboard: cannot list evidence: %s", type(e).__name__)
        return []


def read_evidence(root: str | None, path: str) -> tuple[bytes, bytes] | None:
    """(content type, body) for ``/evidence/<release>/<file>``, or None for anything else."""
    parts = path.removeprefix("/evidence/").split("/")
    if root is None or len(parts) != 2 or not _servable(Path(root), *parts):
        return None
    try:
        return EVIDENCE_TYPES[Path(parts[1]).suffix], (
            Path(root) / parts[0] / parts[1]
        ).read_bytes()
    except OSError:
        return None


def _servable(root: Path, release: str, name: str) -> bool:
    if not (_NAME.fullmatch(release) and _NAME.fullmatch(name)) or ".." in release + name:
        return False
    if Path(name).suffix not in EVIDENCE_TYPES:
        return False
    try:
        f = (root / release / name).resolve(strict=True)
        # resolve() follows symlinks: a link out of the evidence folder is refused.
        return (
            f.is_relative_to(root.resolve(strict=True))
            and f.is_file()
            and f.stat().st_size <= MAX_REPORT_BYTES
        )
    except OSError:
        return False


def render_dashboard(
    ready: dict[str, Any],
    policies: PolicySet,
    snap: dict[str, Any],
    report: dict[str, Any] | None,
    evidence: list[tuple[str, list[str]]] | None = None,
    feeds: list[dict[str, Any]] | None = None,
) -> str:
    status = str(ready["status"])
    events: dict[str, int] = snap["events"]
    responses: dict[int, int] = snap["responses"]
    expires = policies.expires.isoformat() if policies.expires else "never"
    groups = "".join(
        f"<tr><td>{_e(g.group)}</td><td>{_e(g.mode)}</td></tr>" for g in policies.groups
    )
    cards = "".join(
        f'<div class="card"><div class="k">{_e(k)}</div><div class="v">{_e(v)}</div></div>'
        for k, v in (
            ("Requests answered", sum(responses.values())),
            ("Denied (4xx)", sum(v for s, v in responses.items() if 400 <= s < 500)),
            ("Audit write failures", snap["write_failures"]),
            ("SIEM backlog", snap["siem_backlog"]),
        )
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="{REFRESH_S}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agentsec gateway</title>
<style>{_CSS}</style></head>
<body><main>
<header><h1>agentsec gateway</h1>
<span class="pill {"ok" if status == "ready" else "bad"}">{_e(status)}</span></header>
<p class="muted">Read-only. Refreshes every {REFRESH_S}s. Policy <code>{_e(policies.revision)}</code>,
expires {_e(expires)}.</p>
<section class="cards">{cards}</section>
<section><h2>Policy groups</h2>
<table><tr><th>Group</th><th>Mode</th></tr>{groups}</table></section>
<section><h2>Audit events</h2>{_table(("Event", "Count"), sorted(events.items()))}</section>
<section><h2>Responses</h2>{_table(("Status", "Count"), sorted(responses.items()))}</section>
<section><h2>Egress feeds</h2>{_feeds(feeds)}</section>
<section><h2>Containment (fuzz report)</h2>{_report(report)}</section>
<section><h2>Evidence reports</h2>{_evidence(evidence)}</section>
</main></body></html>
"""


def _report(report: dict[str, Any] | None) -> str:
    if report is None:
        return (
            '<p class="muted">None configured. Set <code>admin.fuzz_report</code> to the file '
            "written by <code>agentsec fuzz --json</code>.</p>"
        )
    if "error" in report:
        return f'<p class="bad-text">{_e(report["error"])}</p>'
    stale = (
        f'<p><span class="pill bad">stale</span> Generated more than {STALE_AFTER.days} day ago '
        "(or at an unreadable time). Re-run <code>agentsec fuzz --json</code>.</p>"
        if report["stale"]
        else ""
    )
    head = stale + _table(
        ("Generated", "Cases", "Blocked", "Bypasses", "Errors", "Attack success rate"),
        [(report["generated_at"], report["total"], report["blocked"], report["successes"],
          report["errors"], _pct(report["asr"]))],
    )  # fmt: skip
    rows = [
        (n, r["cases"], r["successes"], _pct(r["asr"])) for n, r in report["by_category"].items()
    ]
    return head + _table(("Category", "Cases", "Bypasses", "Attack success rate"), rows)


def _feeds(feeds: list[dict[str, Any]] | None) -> str:
    if feeds is None:
        return '<p class="muted">None configured. See <code>egress</code> in docs/GATEWAY.md.</p>'
    rows = "".join(
        f"<tr><td>{_e(f['list'])}</td><td>{_e(f['kind'])}</td><td>{_e(f['entries'])}</td>"
        f"<td>{_e(round(f['age_s'] / 3600, 1))} h</td><td>"
        + (
            f'<span class="pill bad">stale ({_e(f["on_stale"])})</span>'
            if f["stale"]
            else '<span class="pill ok">fresh</span>'
        )
        + "</td></tr>"
        for f in feeds
    )
    head = "<tr><th>List</th><th>Kind</th><th>Entries</th><th>Age</th><th>Status</th></tr>"
    return f"<table>{head}{rows}</table>"


def _evidence(evidence: list[tuple[str, list[str]]] | None) -> str:
    if evidence is None:
        return (
            '<p class="muted">None configured. Set <code>admin.evidence_dir</code> to a folder '
            "such as <code>docs/evidence</code>.</p>"
        )
    rows = [
        "<tr><td>" + _e(rel) + "</td><td>"
        + " · ".join(f'<a href="/evidence/{_e(rel)}/{_e(f)}">{_e(f)}</a>' for f in files)
        + "</td></tr>"
        for rel, files in evidence
        if files
    ]  # fmt: skip
    if not rows:
        return '<p class="muted">None yet.</p>'
    return f"<table><tr><th>Release</th><th>Reports</th></tr>{''.join(rows)}</table>"


def _table(head: tuple[str, ...], rows: Any) -> str:
    rows = list(rows)
    if not rows:
        return '<p class="muted">None yet.</p>'
    th = "".join(f"<th>{_e(h)}</th>" for h in head)
    body = "".join("<tr>" + "".join(f"<td>{_e(c)}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><tr>{th}</tr>{body}</table>"


def _pct(v: Any) -> str:
    return f"{v * 100:.1f}%" if isinstance(v, int | float) and math.isfinite(v) else "?"


def _e(v: Any) -> str:
    return escape(str(v), quote=True)


_CSS = """
:root{--bg:#f7f7f8;--fg:#1b1b1f;--muted:#666;--card:#fff;--line:#e3e3e8;--ok:#1a7f37;--bad:#c62828}
@media (prefers-color-scheme:dark){:root{--bg:#141417;--fg:#ececf1;--muted:#9a9aa5;--card:#1d1d22;
--line:#2e2e36;--ok:#3fb950;--bad:#f85149}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}
main{max-width:960px;margin:0 auto;padding:16px}
header{display:flex;align-items:center;gap:12px}h1{font-size:20px;margin:8px 0}
h2{font-size:15px;margin:24px 0 8px}.muted{color:var(--muted)}.bad-text{color:var(--bad)}
.pill{padding:2px 10px;border-radius:999px;color:#fff;font-weight:600}
.pill.ok{background:var(--ok)}.pill.bad{background:var(--bad)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}
.k{color:var(--muted);font-size:12px}.v{font-size:24px;font-weight:600}
table{width:100%;border-collapse:collapse;background:var(--card);margin-bottom:8px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line)}
code{font-size:12px;word-break:break-all}a{color:inherit}
"""
