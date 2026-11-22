"""Follow-ups: disabled users are refused at sign-in, and gateway YAML refuses duplicate keys."""

from __future__ import annotations

import pytest

from agentsec.gateway import load_config
from agentsec.gateway.bundle import BundleError, sign_bundle
from agentsec.sandbox.policy import PolicyError
from tests.test_gateway import POLICY, USER, call, chat, write_config
from tests.test_gateway_bundle import KEY, load, make_bundle, manifest, pem
from tests.test_gateway_oidc import bearer, oidc_gateway, token
from tests.test_gateway_tokens import TOKENS, events, gateway, issue


def assert_refused_as_disabled(app, sink, headers):
    status, body = call(app, body=chat(), headers=headers)
    assert status == 403 and body["error"]["code"] == "user_disabled"
    record = events(sink, "gateway_rejected")[-1]
    assert record["actor"] == "alice" and record["data"]["code"] == "user_disabled"
    assert "eyJ" not in str(record)  # no bearer token in the audit record


def test_a_disabled_users_oidc_token_is_refused(tmp_path):
    app, sink = oidc_gateway(tmp_path, extra=TOKENS)
    assert call(app, body=chat(), headers=bearer(token()))[0] == 200
    app._tokens.disable_user("alice")
    assert_refused_as_disabled(app, sink, bearer(token()))
    assert call(app, body=chat(), headers=bearer(token(sub="bob")))[0] == 200
    app._tokens.enable_user("alice")
    assert call(app, body=chat(), headers=bearer(token()))[0] == 200


def test_a_disabled_users_trusted_header_is_refused(tmp_path):
    app, sink, _ = gateway(tmp_path)
    app._tokens.disable_user("alice")
    assert_refused_as_disabled(app, sink, USER)
    assert call(app, body=chat(), headers=[(b"x-auth-request-user", b"bob")])[0] == 200


def test_without_a_token_store_there_is_no_disabled_list(tmp_path):
    app, _ = oidc_gateway(tmp_path)
    assert app._tokens is None and call(app, body=chat(), headers=bearer(token()))[0] == 200


def test_token_issue_tells_disabled_from_the_per_user_limit(tmp_path):
    app, _, _ = gateway(tmp_path)
    assert [issue(app)[0] for _ in range(4)] == [201, 201, 201, 409]
    assert issue(app)[1]["error"]["code"] == "too_many_tokens"

    app._tokens.disable_user("alice")
    status, body = issue(app)
    assert status == 403 and body["error"]["code"] == "user_disabled"


def test_a_user_disabled_mid_request_is_not_told_too_many_tokens(tmp_path, monkeypatch):
    app, _, _ = gateway(tmp_path)
    app._tokens.disable_user("alice")
    answers = iter([False, True])  # sign-in saw an enabled user; issue() then refused
    monkeypatch.setattr(app._tokens, "is_user_disabled", lambda user: next(answers))
    status, body = issue(app)
    assert status == 403 and body["error"]["code"] == "user_disabled"


DUPLICATE = POLICY + "  search:\n    args: {}\n"  # a second block would drop the first's rules


def test_a_gateway_policy_with_a_duplicate_key_is_refused(tmp_path):
    write_config(tmp_path)
    (tmp_path / "policy.yaml").write_text(DUPLICATE)
    with pytest.raises(PolicyError, match="duplicate key"):
        load_config(tmp_path / "gateway.yaml")


def test_a_gateway_config_with_a_duplicate_key_is_refused(tmp_path):
    write_config(tmp_path)
    with (tmp_path / "gateway.yaml").open("a") as fh:
        fh.write("mode: monitor\n")
    with pytest.raises(PolicyError, match="duplicate key"):
        load_config(tmp_path / "gateway.yaml")


def test_a_merge_key_still_loads(tmp_path):
    write_config(tmp_path)
    (tmp_path / "policy.yaml").write_text(
        "version: 1\n"
        "tools:\n"
        "  search: &base\n"
        "    args:\n"
        "      q: {type: string}\n"
        "  lookup:\n"
        "    <<: *base\n"
        "    side_effects: true\n"
    )
    policy = load_config(tmp_path / "gateway.yaml").policies.groups[0].policy
    assert set(policy.tools["lookup"].args) == {"q"} and policy.tools["lookup"].side_effects


def test_bundle_duplicate_keys_are_refused_and_a_valid_bundle_loads(tmp_path):
    root = make_bundle(tmp_path / "b")
    assert load(root).revision.startswith("bundle:1:")

    (root / "policies" / "eng.yaml").write_text("version: 1\ntools:\n  search: {}\n  search: {}\n")
    sign_bundle(root, pem(KEY))
    with pytest.raises(BundleError, match="eng.yaml: duplicate key"):
        load(root)

    (root / "manifest.yaml").write_text(manifest(2) + "revision: 3\n")
    with pytest.raises(BundleError, match="manifest.yaml: duplicate key"):
        sign_bundle(root, pem(KEY))
