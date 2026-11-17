"""Gateway access tokens: issued after SSO, stored hashed, short-lived, revocable."""

from __future__ import annotations

import json
import os
import sys

import pytest

from agentsec.cli import main as cli
from agentsec.gateway import ConfigError, Gateway
from agentsec.gateway.tokens import TokenStore
from agentsec.middleware.audit import MemorySink
from tests.test_gateway import USER, FakeUpstream, call, chat, write_config

TOKENS = "tokens:\n  store: tokens.db\n  max_ttl_days: 10\n  max_per_user: 3\n"
JSON = [(b"content-type", b"application/json")]


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now


def gateway(tmp_path, extra=TOKENS):
    sink, clock = MemorySink(), Clock()
    cfg = write_config(tmp_path, extra)
    app = Gateway(cfg, transport=FakeUpstream(), sink=sink, wall_clock=clock)
    return app, sink, clock


def issue(app, body=None, headers=USER):
    return call(app, "/tokens", body=body or {"name": "cursor"}, headers=[*headers, *JSON])


def bearer(token):
    return [(b"authorization", f"Bearer {token}".encode())]


def events(sink, name):
    return [r for r in sink.records if r["event"] == name]


def test_issue_use_and_revoke(tmp_path):
    app, sink, _ = gateway(tmp_path)
    status, issued = issue(app)
    assert status == 201 and issued["token"].startswith("agt_") and issued["name"] == "cursor"
    assert events(sink, "gateway_token_issued")[0]["data"]["token_id"] == issued["id"]

    # Accepted from any address, like an IDE on a laptop: no auth proxy involved.
    status, models = call(app, "/v1/models", method="GET", headers=bearer(issued["token"]),
                          peer="10.20.30.40")  # fmt: skip
    assert status == 200 and models["data"]
    status, _ = call(app, body=chat(), headers=bearer(issued["token"]), peer="10.20.30.40")
    assert status == 200
    request = events(sink, "gateway_request")[-1]
    assert request["actor"] == "alice" and request["data"]["token_id"] == issued["id"]

    status, listed = call(app, "/tokens", method="GET", headers=USER)
    assert status == 200 and [t["id"] for t in listed["data"]] == [issued["id"]]
    assert "token" not in listed["data"][0] and "hash" not in listed["data"][0]

    status, _ = call(app, f"/tokens/{issued['id']}", method="DELETE", headers=USER)
    assert status == 200
    status, _ = call(app, body=chat(), headers=bearer(issued["token"]), peer="10.20.30.40")
    assert status == 401
    assert "revoked" in events(sink, "gateway_auth_failed")[-1]["data"]["reason"]


def test_an_all_digit_token_id_is_not_redacted_as_a_card_number(tmp_path, monkeypatch):
    """16 hex characters are sometimes 16 digits that pass the Luhn check."""
    monkeypatch.setattr("agentsec.gateway.tokens.secrets.token_hex", lambda n: "6889113356693782")
    app, sink, _ = gateway(tmp_path)
    issued = issue(app)[1]
    assert issued["id"] == "tok_6889113356693782"
    assert events(sink, "gateway_token_issued")[0]["data"]["token_id"] == issued["id"]
    call(app, f"/tokens/{issued['id']}", method="DELETE", headers=USER)
    call(app, body=chat(), headers=bearer(issued["token"]), peer="10.20.30.40")
    assert issued["id"] in events(sink, "gateway_auth_failed")[-1]["data"]["reason"]


def test_only_a_hash_is_stored(tmp_path):
    app, _, _ = gateway(tmp_path)
    token = issue(app)[1]["token"]
    raw = (tmp_path / "tokens.db").read_bytes()
    assert token.encode() not in raw and token[4:].encode() not in raw


def test_a_token_cannot_manage_tokens(tmp_path):
    app, _, _ = gateway(tmp_path)
    issued = issue(app)[1]
    auth = [*bearer(issued["token"]), *JSON]
    assert call(app, "/tokens", body={"name": "x"}, headers=auth)[0] == 403
    assert call(app, "/tokens", method="GET", headers=auth)[0] == 403
    assert call(app, f"/tokens/{issued['id']}", method="DELETE", headers=auth)[0] == 403


def test_tokens_expire(tmp_path):
    app, sink, clock = gateway(tmp_path)
    token = issue(app, {"name": "short", "ttl_days": 1})[1]["token"]
    clock.now += 86400 + 1
    assert call(app, body=chat(), headers=bearer(token), peer="10.0.0.9")[0] == 401
    assert "expired" in events(sink, "gateway_auth_failed")[-1]["data"]["reason"]


def test_dead_tokens_are_pruned_a_week_later(tmp_path):
    app, _, clock = gateway(tmp_path)
    revoked = issue(app, {"name": "old", "ttl_days": 10})[1]["id"]
    call(app, f"/tokens/{revoked}", method="DELETE", headers=USER)
    issue(app, {"name": "expires", "ttl_days": 1})
    clock.now += 8 * 86400 + 1  # one revoked 8 days ago, one expired 7 days ago
    kept = issue(app, {"name": "new"})[1]["id"]
    listed = call(app, "/tokens", method="GET", headers=USER)[1]["data"]
    assert [t["id"] for t in listed] == [kept]


def test_a_user_cannot_revoke_someone_elses_token(tmp_path):
    app, _, _ = gateway(tmp_path)
    issued = issue(app)[1]
    bob = [(b"x-auth-request-user", b"bob"), (b"x-auth-request-groups", b"eng")]
    assert call(app, f"/tokens/{issued['id']}", method="DELETE", headers=bob)[0] == 404
    assert call(app, body=chat(), headers=bearer(issued["token"]), peer="10.0.0.9")[0] == 200


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"name": "x", "ttl_days": 11}, 400),  # above max_ttl_days
        ({"name": "x", "ttl_days": 0}, 400),
        ({"name": "x", "ttl_days": "7"}, 400),
        ({"name": "x" * 65}, 400),
        ({"name": "line\nbreak"}, 400),
        ({"name": "x", "scope": "admin"}, 400),
    ],
)
def test_issue_requests_are_checked(tmp_path, body, status):
    app, _, _ = gateway(tmp_path)
    assert issue(app, body)[0] == status


def test_issue_needs_a_json_content_type(tmp_path):
    app, _, _ = gateway(tmp_path)
    form = [(b"content-type", b"application/x-www-form-urlencoded")]
    assert call(app, "/tokens", body={"name": "x"}, headers=[*USER, *form])[0] == 415


def test_live_tokens_per_user_are_capped(tmp_path):
    app, _, _ = gateway(tmp_path)
    assert [issue(app)[0] for _ in range(4)] == [201, 201, 201, 409]


@pytest.mark.parametrize("token", ["agt_short", "agt_" + "A" * 43, "agt_" + "*" * 43])
def test_unknown_or_malformed_tokens_are_refused(tmp_path, token):
    app, sink, _ = gateway(tmp_path)
    assert call(app, body=chat(), headers=bearer(token), peer="10.0.0.9")[0] == 401
    assert events(sink, "gateway_auth_failed")


def test_a_token_carries_the_groups_it_was_issued_with(tmp_path):
    app, _, _ = gateway(tmp_path, TOKENS + "identity:\n  trusted_proxies: [127.0.0.1/32]\n"
                        "  allowed_groups: [eng]\n")  # fmt: skip
    token = issue(app)[1]["token"]  # alice is in eng and ml
    assert call(app, body=chat(), headers=bearer(token), peer="10.0.0.9")[0] == 200
    ops = [(b"x-auth-request-user", b"carol"), (b"x-auth-request-groups", b"ops"), *JSON]
    assert call(app, "/tokens", body={"name": "x"}, headers=ops)[0] == 403


def test_without_a_tokens_section_there_are_no_tokens(tmp_path):
    app, _, _ = gateway(tmp_path, extra="")
    assert issue(app)[0] == 404
    assert call(app, body=chat(), headers=bearer("agt_" + "A" * 43), peer="10.0.0.9")[0] == 401


@pytest.mark.parametrize(
    "extra",
    [
        "tokens:\n  max_ttl_days: 10\n",
        "tokens:\n  store: t.db\n  default_ttl_days: 20\n  max_ttl_days: 10\n",
        "tokens:\n  store: t.db\n  max_ttl_days: 365\n",
        "tokens:\n  store: t.db\n  scopes: [all]\n",
    ],
)
def test_token_config_is_validated(tmp_path, extra):
    with pytest.raises(ConfigError):
        write_config(tmp_path, extra)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_the_store_is_owner_only(tmp_path):
    TokenStore(tmp_path / "t.db")
    assert os.stat(tmp_path / "t.db").st_mode & 0o077 == 0


def test_admin_cli_lists_and_revokes(tmp_path, capsys):
    app, _, _ = gateway(tmp_path)
    issued = issue(app)[1]
    issue(app, {"name": "second"})
    cfg = str(tmp_path / "gateway.yaml")
    assert cli(["token", "list", "--config", cfg, "--user", "alice"]) == 0
    out = capsys.readouterr().out
    assert issued["id"] in out and issued["token"] not in out
    assert cli(["token", "revoke", "--config", cfg, "--id", issued["id"]]) == 0
    assert call(app, body=chat(), headers=bearer(issued["token"]), peer="10.0.0.9")[0] == 401
    assert cli(["token", "revoke", "--config", cfg, "--user", "alice"]) == 0
    assert "revoked 1 token(s)" in capsys.readouterr().out
    assert cli(["token", "revoke", "--config", cfg]) == 2


def test_admin_cli_needs_a_tokens_section(tmp_path, capsys):
    write_config(tmp_path)
    assert cli(["token", "list", "--config", str(tmp_path / "gateway.yaml")]) == 1
    assert "no tokens section" in capsys.readouterr().err


# ---------------------------------------------------------------- the IDE flow, over MCP


def test_an_mcp_client_connects_with_a_token(tmp_path, monkeypatch):
    pytest.importorskip("mcp")
    import asyncio

    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    from tests.test_gateway_mcp import Upstreams, docs_server, mail_server, serving
    from tests.test_gateway_mcp import write_config as mcp_config

    mcp_config(tmp_path, TOKENS)
    from agentsec.gateway import load_config

    sink = MemorySink()
    ups = Upstreams(docs=docs_server(), mail=mail_server())
    app = Gateway(load_config(tmp_path / "gateway.yaml"), sink=sink, mcp_connector=ups.connect)
    token = issue(app)[1]["token"]
    with serving(app) as url:

        async def main():
            # Exactly what an IDE MCP config holds: a URL and one fixed header.
            async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}) as http:
                async with Client(streamable_http_client(url, http_client=http)) as c:
                    names = sorted(t.name for t in (await c.list_tools()).tools)
                    sent = await c.call_tool("mail__send", {"to": "bob@corp.example"})
                    return names, sent

        names, sent = asyncio.run(main())
    assert names == ["docs__search", "mail__send"] and not sent.is_error
    record = [r for r in sink.records if r["event"] == "gateway_mcp_call"][-1]
    assert record["actor"] == "alice" and record["data"]["token_id"]
    assert json.dumps(record).find(token) == -1  # the token itself is never logged


# ------------------------------------------------------------ review regressions (Codex)


def test_the_per_user_cap_holds_across_processes_sharing_the_store(tmp_path):
    import threading

    stores = [TokenStore(tmp_path / "shared.db") for _ in range(4)]  # four gateway processes
    issued, barrier = [], threading.Barrier(len(stores))

    def mint(store):
        barrier.wait()
        try:
            issued.append(store.issue("alice", ("eng",), "x", 3600, max_per_user=1))
        except Exception:  # noqa: BLE001 - the cap (or a busy database) refusing is the point
            pass

    threads = [threading.Thread(target=mint, args=(s,)) for s in stores]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert len(issued) == 1
    assert len([t for t in stores[0].list(user="alice") if t.revoked is None]) == 1


def test_a_huge_ttl_is_a_validation_error(tmp_path):
    app, _, _ = gateway(tmp_path)
    raw = b'{"name": "x", "ttl_days": 1' + b"0" * 309 + b"}"
    import asyncio

    scope = {"type": "http", "method": "POST", "path": "/tokens", "client": ("127.0.0.1", 1),
             "headers": [*USER, *JSON]}  # fmt: skip
    sent = []

    async def receive():
        return {"type": "http.request", "body": raw, "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    assert sent[0]["status"] == 400
