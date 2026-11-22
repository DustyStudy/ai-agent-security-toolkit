"""Offboarding must not report success for work it did not do."""

from __future__ import annotations

import io
import json
import sqlite3

import pytest

from agentsec.cli import main as cli
from agentsec.gateway import load_config, offboard
from agentsec.gateway.tokens import TokenError, TokenStore
from tests.test_gateway import call, chat
from tests.test_gateway_tokens import _live, _two_gateways, bearer, gateway, issue


def _events(tmp_path, doc):
    path = tmp_path / "ev.json"
    path.write_text(json.dumps(doc))
    return str(path)


def _offboard(tmp_path, cfgs, *extra):
    args = ["token", "offboard", "--ledger", str(tmp_path / "ledger.db"), *extra]
    for c in cfgs:
        args += ["--config", c]
    return cli(args)


# ---------------------------------------------------------------- T1: missing store
def test_a_missing_store_stays_pending_and_is_not_created(tmp_path, capsys):
    gone = tmp_path / "not-mounted" / "tokens.db"
    out = offboard.run(tmp_path / "l.db", [str(gone)], [("user", "alice", "")])
    assert len(out.pending) == 1 and out.missing == [str(gone)] and out.revoked == 0
    assert "does not exist" in (out.pending[0].error or "")
    assert not gone.exists() and not gone.parent.exists()

    cfgs, stores = _two_gateways(tmp_path)
    stores[1].unlink()  # the volume of the second gateway is not mounted on this host
    ev = _events(tmp_path, {"disabled_users": ["alice"]})
    assert _offboard(tmp_path, cfgs, "--events", ev) == 1
    captured = capsys.readouterr()
    assert "1 pending" in captured.out and "does not exist" in captured.err
    assert not stores[1].exists() and _live(stores[0], "alice") == []


def test_an_existing_store_opens_without_create(tmp_path):
    TokenStore(tmp_path / "t.db").close()
    TokenStore(tmp_path / "t.db", create=False).close()
    with pytest.raises(FileNotFoundError):
        TokenStore(tmp_path / "other.db", create=False)
    assert not (tmp_path / "other.db").exists()


# ---------------------------------------------------------------- T2: disabled users
def test_a_disabled_user_cannot_mint_or_use_tokens_until_enabled(tmp_path, capsys):
    app, _, _ = gateway(tmp_path)
    cfg = str(tmp_path / "gateway.yaml")
    old = issue(app)[1]["token"]
    ev = _events(tmp_path, {"disabled_users": ["alice", "carol"]})
    assert _offboard(tmp_path, [cfg], "--events", ev) == 0
    assert issue(app)[0] == 409  # no new token after offboarding
    assert call(app, body=chat(), headers=bearer(old), peer="10.0.0.9")[0] == 401

    store = TokenStore(tmp_path / "tokens.db")
    try:
        # carol had no token: she is recorded all the same.
        assert store.is_user_disabled("alice") and store.is_user_disabled("carol")
        assert not store.is_user_disabled("bob")
        with pytest.raises(TokenError, match="disabled"):
            store.issue("carol", (), "n", 60, 5)
        # A token that is live in a disabled user's name is refused as well.
        _, token = store.issue("bob", (), "n", 60, 5)
        with sqlite3.connect(tmp_path / "tokens.db") as db:
            db.execute("INSERT INTO disabled_users VALUES ('bob', 0)")
        with pytest.raises(TokenError, match="disabled user"):
            store.verify(token)
    finally:
        store.close()

    assert cli(["token", "enable", "--config", cfg, "--user", "alice"]) == 0
    assert cli(["token", "enable", "--config", cfg, "--user", "alice"]) == 1  # nothing to undo
    assert issue(app)[0] == 201
    assert call(app, body=chat(), headers=bearer(old), peer="10.0.0.9")[0] == 401  # stays revoked


# ---------------------------------------------------------------- T3: no match
def test_an_event_that_matches_no_token_warns_and_counts_are_per_event(tmp_path, capsys):
    cfgs, _ = _two_gateways(tmp_path)
    doc = {"disabled_users": ["Alice"], "removed_groups": [{"user": "bob", "group": "admins"}]}
    assert _offboard(tmp_path, cfgs, "--events", _events(tmp_path, doc)) == 0
    captured = capsys.readouterr()
    assert "user Alice: revoked 0 token(s)" in captured.out
    assert "user bob, group admins: revoked 2 token(s)" in captured.out
    assert "warning: user Alice matched no token" in captured.err
    assert "bob" not in captured.err


# ---------------------------------------------------------------- T4: revoke of nothing
def test_revoke_exits_1_when_nothing_was_revoked(tmp_path, capsys):
    app, _, _ = gateway(tmp_path)
    cfg = str(tmp_path / "gateway.yaml")
    issued = issue(app)[1]
    assert cli(["token", "revoke", "--config", cfg, "--id", "tok_typo"]) == 1
    assert cli(["token", "revoke", "--config", cfg, "--user", "nobody"]) == 1
    assert cli(["token", "revoke", "--config", cfg, "--id", issued["id"]]) == 0
    assert cli(["token", "revoke", "--config", cfg, "--id", issued["id"]]) == 1  # already revoked


# ---------------------------------------------------------------- T5: events first
def test_token_commands_do_not_need_the_policy_or_bundle(tmp_path):
    cfgs, stores = _two_gateways(tmp_path)
    (tmp_path / "gw2" / "policy.yaml").unlink()  # the full load_config fails for gw2
    ev = _events(tmp_path, {"disabled_users": ["alice"]})
    assert _offboard(tmp_path, cfgs, "--events", ev) == 0
    assert _live(stores[0], "alice") == [] and _live(stores[1], "alice") == []
    assert cli(["token", "list", "--config", cfgs[1]]) == 0


def test_stdin_events_survive_an_unreadable_config(tmp_path, monkeypatch, capsys):
    cfgs, stores = _two_gateways(tmp_path)
    good = (tmp_path / "gw2" / "gateway.yaml").read_text()
    (tmp_path / "gw2" / "gateway.yaml").write_text("tokens: [not, a, mapping")
    metrics = tmp_path / "m.prom"
    monkeypatch.setattr("sys.stdin", io.StringIO('{"disabled_users": ["alice"]}'))
    assert _offboard(tmp_path, cfgs, "--events", "-", "--metrics-file", str(metrics)) == 1
    assert "config not read" in capsys.readouterr().err
    assert "agentsec_offboarding_pending 1" in metrics.read_text()
    assert _live(stores[0], "alice") == [] and _live(stores[1], "alice") != []

    # Past the deadline the event that still waits for gw2 trips the alert.
    assert _offboard(tmp_path, cfgs, "--deadline-s", "0.000001") == 3
    # The config is repaired: a retry with no events finishes gw2 from the ledger.
    (tmp_path / "gw2" / "gateway.yaml").write_text(good)
    assert _offboard(tmp_path, cfgs, "--metrics-file", str(metrics)) == 0
    assert "agentsec_offboarding_pending 0" in metrics.read_text()
    assert _live(stores[1], "alice") == []


def test_only_serve_advances_the_bundle_state_file(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    from tests.test_gateway_bundle import make_bundle, write_config

    root = make_bundle(tmp_path / "b", revision=10)
    write_config(tmp_path, root, ", state_file: state.json")
    cfg = str(tmp_path / "gateway.yaml")
    state = tmp_path / "state.json"
    load_config(cfg)
    assert cli(["serve", "--config", cfg, "--check"]) == 0
    assert not state.exists()
    served = []
    monkeypatch.setattr("agentsec.gateway.serve", served.append)
    assert cli(["serve", "--config", cfg]) == 0
    assert len(served) == 1 and json.loads(state.read_text())["revision"] == 10
