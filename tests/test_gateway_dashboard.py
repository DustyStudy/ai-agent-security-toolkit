"""The read-only /dashboard page on the admin listener."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import pytest

from agentsec.gateway import Gateway
from tests.test_gateway import USER, FakeUpstream, MemorySink, call, chat, gateway, write_config

CANARY = "CANARY-7f3a9c"


def admin(app, path="/dashboard", method="GET", headers=()):
    scope = {"type": "http", "method": method, "path": path, "headers": list(headers),
             "client": ("127.0.0.1", 1)}  # fmt: skip
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app.admin(scope, receive, send))
    body = b"".join(m.get("body", b"") for m in sent[1:]).decode(errors="replace")
    return sent[0]["status"], dict(sent[0]["headers"]), body


def report(tmp_path, **over):
    data = {
        "generated_at": datetime.now(UTC).isoformat(), "seed": 1, "total": 10, "successes": 1,
        "blocked": 9, "errors": 0, "asr": 0.1,
        "by_category": {"exfiltration": {"cases": 10, "successes": 1, "asr": 0.1}},
        "results": [{"payload": f"leak {CANARY}", "response": f"here is {CANARY}"}],
    } | over  # fmt: skip
    (tmp_path / "fuzz.json").write_text(json.dumps(data))
    return "admin: {port: 9090, fuzz_report: fuzz.json}\n"


def test_dashboard_shows_live_status_counters_and_report(tmp_path):
    app, _ = gateway(tmp_path, extra=report(tmp_path), mode="monitor")
    assert call(app, body=chat())[0] == 200
    status, headers, html = admin(app)
    assert status == 200
    assert headers[b"content-type"] == b"text/html; charset=utf-8"
    assert ">ready<" in html
    assert app._policies.revision in html
    assert "gateway_request" in html
    assert "exfiltration" in html and "10.0%" in html
    assert '<meta http-equiv="refresh"' in html


def test_dashboard_is_locked_down(tmp_path):
    app, _ = gateway(tmp_path)
    _, headers, html = admin(app)
    csp = headers[b"content-security-policy"].decode()
    assert "default-src 'none'" in csp and "form-action 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert headers[b"cache-control"] == b"no-store"
    assert headers[b"x-frame-options"] == b"DENY"
    for tag in ("<script", "<form", "<iframe", "<input", " on"):
        assert tag not in html.lower()


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_dashboard_has_no_write_methods(tmp_path, method):
    app, _ = gateway(tmp_path)
    assert admin(app, method=method)[0] == 404


def test_dashboard_changes_nothing(tmp_path):
    app, sink = gateway(tmp_path)
    before = (len(sink.records), app._policies, app.metrics.snapshot())
    for _ in range(3):
        assert admin(app)[0] == 200
    assert (len(sink.records), app._policies, app.metrics.snapshot()) == before


def test_main_listener_does_not_serve_the_dashboard(tmp_path):
    app, _ = gateway(tmp_path)
    assert call(app, path="/dashboard", method="GET", headers=USER)[0] == 404


@pytest.mark.parametrize(
    "headers",
    [[(b"origin", b"https://evil.example")], [(b"host", b"evil.example")]],
)
def test_dashboard_refuses_cross_site_and_rebinding(tmp_path, headers):
    app, _ = gateway(tmp_path)
    assert admin(app, headers=headers)[0] == 403


def test_dashboard_does_not_expose_secrets_or_content(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSEC_TEST_DASH_KEY", f"sk-{CANARY}")
    extra = report(tmp_path) + (
        "upstreams:\n  local:\n    url: http://127.0.0.1:11434/v1\n    model: llama3.1:8b\n"
        "    api_key: env:AGENTSEC_TEST_DASH_KEY\n"
    )
    app = Gateway(write_config(tmp_path, extra=extra), transport=FakeUpstream(), sink=MemorySink())
    user = [(b"x-auth-request-user", f"user-{CANARY}".encode())]
    assert call(app, body=chat(f"prompt {CANARY}"), headers=user)[0] == 200
    html = admin(app)[2]
    assert CANARY not in html
    assert "11434" not in html and "api_key" not in html


def test_report_values_are_escaped(tmp_path):
    evil = "<script>alert(1)</script>"
    extra = report(tmp_path, generated_at=evil,
                   by_category={evil: {"cases": evil, "successes": 0, "asr": evil}})  # fmt: skip
    app, _ = gateway(tmp_path, extra=extra)
    html = admin(app)[2]
    assert "<script" not in html
    assert "&lt;script&gt;" in html


@pytest.mark.parametrize("content", [None, "{not json", "[1, 2]"])
def test_a_bad_or_missing_report_does_not_break_the_page(tmp_path, content):
    extra = report(tmp_path)
    path = tmp_path / "fuzz.json"
    if content is None:
        path.unlink()
    else:
        path.write_text(content)
    app, _ = gateway(tmp_path, extra=extra)
    status, _, html = admin(app)
    assert status == 200
    assert "report unreadable" in html or "not a fuzz report" in html


@pytest.mark.parametrize(
    ("generated_at", "stale"),
    [
        (lambda: datetime.now(UTC).isoformat(), False),
        (lambda: (datetime.now(UTC) - timedelta(days=2)).isoformat(), True),
        (lambda: "not a time", True),
    ],
)
def test_an_old_fuzz_report_is_flagged_stale(tmp_path, generated_at, stale):
    app, _ = gateway(tmp_path, extra=report(tmp_path, generated_at=generated_at()))
    assert ('class="pill bad">stale<' in admin(app)[2]) is stale


def evidence(tmp_path):
    rel = tmp_path / "evidence" / "v0.12.0"
    rel.mkdir(parents=True)
    (rel / "tests.html").write_text("<html><body>tests PASS</body></html>")
    (rel / "tests.png").write_bytes(b"\x89PNG fake")
    (rel / "tests.md").write_text("markdown")  # not served: the HTML page is the view
    (tmp_path / "secret.html").write_text(CANARY)
    (rel / "link.html").symlink_to(tmp_path / "secret.html")
    return "admin: {port: 9090, evidence_dir: evidence}\n"


def test_dashboard_links_evidence_reports_and_serves_them_locked_down(tmp_path):
    app, _ = gateway(tmp_path, extra=evidence(tmp_path))
    html = admin(app)[2]
    assert 'href="/evidence/v0.12.0/tests.html"' in html
    assert 'href="/evidence/v0.12.0/tests.png"' in html
    assert "tests.md" not in html and "link.html" not in html
    status, headers, body = admin(app, "/evidence/v0.12.0/tests.html")
    assert (status, body) == (200, "<html><body>tests PASS</body></html>")
    assert headers[b"content-type"] == b"text/html; charset=utf-8"
    assert b"default-src 'none'" in headers[b"content-security-policy"]
    assert admin(app, "/evidence/v0.12.0/tests.png")[1][b"content-type"] == b"image/png"


@pytest.mark.parametrize(
    "path",
    [
        "/evidence/v0.12.0/link.html",  # symlink out of the folder
        "/evidence/v0.12.0/tests.md",
        "/evidence/../secret.html",
        "/evidence/v0.12.0/../../secret.html",
        "/evidence/v0.12.0/..",
        "/evidence/..",
        "/evidence/v0.12.0",
        "/evidence/v0.12.0/",
        "/evidence/v0.12.0/missing.html",
        "/evidence/v0.12.0/sub/tests.html",
        "/evidence/.v/tests.html",
        "/evidence//etc/passwd",
        "/evidence/v0.12.0/tests.html/",
    ],
)
def test_evidence_serves_nothing_outside_its_allowlist(tmp_path, path):
    app, _ = gateway(tmp_path, extra=evidence(tmp_path))
    status, _, body = admin(app, path)
    assert status == 404
    assert CANARY not in body


def test_evidence_is_get_only_and_off_without_config(tmp_path):
    app, _ = gateway(tmp_path, extra=evidence(tmp_path))
    assert admin(app, "/evidence/v0.12.0/tests.html", method="POST")[0] == 404
    app, _ = gateway(tmp_path)
    assert admin(app, "/evidence/v0.12.0/tests.html")[0] == 404
    assert "admin.evidence_dir" in admin(app)[2]


def test_dashboard_shows_dlp_findings_per_category_without_values(tmp_path):
    ssn = "123-45-" + "6789"
    app, _ = gateway(tmp_path, extra="admin: {port: 9090}\n")
    _, _, before = admin(app)
    assert "Data-loss prevention" in before and "None yet." in before
    body = {"model": "local", "messages": [{"role": "user", "content": f"my ssn is {ssn}"}]}
    assert call(app, body=body)[0] == 200
    _, _, html = admin(app)
    section = html.split("Data-loss prevention", 1)[1].split("</section>", 1)[0]
    assert "<th>Block</th><th>Redact</th><th>Monitor</th><th>Allowed</th>" in section
    assert "<tr><td>pii</td><td>0</td><td>0</td><td>1</td><td>0</td></tr>" in section
    assert ssn not in html and "6789" not in html
