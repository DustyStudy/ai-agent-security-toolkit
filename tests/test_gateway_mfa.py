"""identity.oidc.require_mfa: the IdP's amr/acr claims must show a multi-factor sign-in."""

from __future__ import annotations

import sqlite3

import pytest

pytest.importorskip("jwt")

from agentsec.gateway import ConfigError, Gateway, load_config  # noqa: E402
from agentsec.gateway.oidc import MfaRequired  # noqa: E402
from agentsec.gateway.tokens import TokenStore  # noqa: E402
from agentsec.middleware.audit import MemorySink  # noqa: E402
from tests.test_gateway import POLICY, FakeUpstream, call, chat  # noqa: E402
from tests.test_gateway_oidc import AUD, ISS, Fetcher, bearer, token, verifier  # noqa: E402

JSON = [(b"content-type", b"application/json")]


def mfa_gateway(tmp_path, oidc_extra="require_mfa: true", extra=""):
    (tmp_path / "policy.yaml").write_text(POLICY)
    (tmp_path / "gateway.yaml").write_text(
        "identity:\n"
        "  mode: oidc\n"
        f"  oidc: {{issuer: '{ISS}', audience: {AUD}, {oidc_extra},"
        " jwks_url: 'https://idp.corp.example/jwks'}\n"
        f"{extra}"
        "policy: policy.yaml\n"
        "upstreams: {local: {url: 'http://127.0.0.1:11434/v1', model: m}}\n"
        "audit: {file: audit.jsonl}\n"
    )
    sink = MemorySink()
    cfg = load_config(tmp_path / "gateway.yaml")
    return Gateway(cfg, transport=FakeUpstream(), sink=sink, jwks_fetch=Fetcher()), sink


def test_amr_or_acr_must_show_mfa_and_malformed_claims_fail_closed():
    v = verifier(require_mfa=True, mfa_acr=("urn:corp:loa:2",))
    assert v.verify(token(amr=["pwd", "mfa"]))[0] == "alice"
    assert v.verify(token(acr="urn:corp:loa:2"))[0] == "alice"
    for claims in (
        {},
        {"amr": ["pwd"]},
        {"amr": "mfa"},  # a string, not the RFC 8176 list
        {"amr": [["mfa"]]},
        {"acr": "1"},
        {"acr": ["urn:corp:loa:2"]},
        {"amr": ["MFA"]},  # values are case-sensitive
    ):
        with pytest.raises(MfaRequired) as e:
            v.verify(token(**claims))
        assert e.value.user == "alice"
    assert verifier().verify(token())[0] == "alice"  # off by default


def test_gateway_refuses_a_single_factor_sign_in_with_403_and_an_audit_record(tmp_path):
    app, sink = mfa_gateway(tmp_path)
    assert call(app, body=chat(), headers=bearer(token(amr=["pwd", "mfa"])))[0] == 200
    status, body = call(app, body=chat(), headers=bearer(token(amr=["pwd"])))
    assert status == 403 and body["error"]["code"] == "mfa_required"
    refused = [r for r in sink.records if r["event"] == "gateway_mfa_required"]
    assert len(refused) == 1 and refused[0]["actor"] == "alice"
    # A bad signature is still a plain 401, not an MFA answer.
    assert call(app, body=chat(), headers=bearer(token(amr=["mfa"])[:-4] + "AAAA"))[0] == 401


def test_access_tokens_need_an_mfa_sign_in_even_if_minted_earlier(tmp_path):
    tokens = "tokens:\n  store: tokens.db\n  max_ttl_days: 10\n  max_per_user: 3\n"
    # Minted while require_mfa was off: the store records it as issued without MFA.
    app, _ = mfa_gateway(tmp_path, "require_mfa: false", tokens)
    sso = bearer(token(amr=["pwd"]))
    old = call(app, "/tokens", body={"name": "old"}, headers=[*sso, *JSON])[1]["token"]
    app, sink = mfa_gateway(tmp_path, "require_mfa: true", tokens)
    status, body = call(app, body=chat(), headers=bearer(old))
    assert status == 403 and body["error"]["code"] == "mfa_required"
    assert any(r["event"] == "gateway_mfa_required" for r in sink.records)
    # Without MFA a user cannot mint a replacement; with it they can, and it works.
    assert call(app, "/tokens", body={"name": "x"}, headers=[*sso, *JSON])[0] == 403
    mfa = bearer(token(amr=["mfa"]))
    new = call(app, "/tokens", body={"name": "new"}, headers=[*mfa, *JSON])[1]["token"]
    assert call(app, body=chat(), headers=bearer(new))[0] == 200


def test_an_old_token_store_gets_the_mfa_column(tmp_path):
    db = sqlite3.connect(tmp_path / "t.db")
    db.execute(
        "CREATE TABLE tokens (id TEXT PRIMARY KEY, user TEXT NOT NULL, groups TEXT NOT NULL,"
        " hash TEXT NOT NULL UNIQUE, name TEXT NOT NULL, created REAL NOT NULL,"
        " expires REAL NOT NULL, revoked REAL, last_used REAL)"
    )
    db.execute("INSERT INTO tokens VALUES ('t1', 'alice', '[]', 'h', 'old', 0, 9e12, NULL, NULL)")
    db.commit()
    db.close()
    store = TokenStore(tmp_path / "t.db")
    assert store.list()[0].mfa is False
    info, _ = store.issue("bob", (), "n", 60, 3, mfa=True)
    assert {t.id: t.mfa for t in store.list()}[info.id] is True
    TokenStore(tmp_path / "t.db")  # a second open does not try to add it again


def test_config_checks_mfa_settings(tmp_path):
    for bad in ("require_mfa: 'yes'", "require_mfa: true, mfa_amr: [], mfa_acr: []",
                "mfa_amr: mfa"):  # fmt: skip
        with pytest.raises(ConfigError):
            mfa_gateway(tmp_path, bad)
