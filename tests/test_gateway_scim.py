"""SCIM 2.0 provisioning: what Entra ID and Okta send, and what deprovisioning must end."""

from __future__ import annotations

import asyncio
import json

import pytest

from agentsec.gateway import ConfigError, Gateway
from agentsec.middleware.audit import MemorySink
from tests.test_gateway import USER, FakeUpstream, call, chat, write_config

# Not named like a credential: CodeQL treats such names as secrets and follows them into
# the audit log the gateway writes, though these requests log no header.
SCIM_BEARER = "s" * 40
SCIM = "scim:\n  token: env:SCIM_TOKEN\n"
TOKENS = "tokens:\n  store: tokens.db\n"
PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
JSON = [(b"content-type", b"application/json")]


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("SCIM_TOKEN", SCIM_BEARER)


def scim_gateway(tmp_path, extra=""):
    sink = MemorySink()
    app = Gateway(
        write_config(tmp_path, SCIM + TOKENS + extra), transport=FakeUpstream(), sink=sink
    )
    return app, sink


def scim(app, method, path, body=None, presented=SCIM_BEARER, query=b""):
    headers = [(b"content-type", b"application/scim+json")]
    if presented:
        headers.append((b"authorization", f"Bearer {presented}".encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": "/scim/v2" + path,
        "query_string": query,
        "headers": headers,
        "client": ("127.0.0.1", 5555),
    }
    raw = json.dumps(body).encode() if body is not None else b""
    sent = []

    async def receive():
        return {"type": "http.request", "body": raw, "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    payload = b"".join(m.get("body", b"") for m in sent[1:])
    return sent[0]["status"], json.loads(payload) if payload else None


def as_user(name: str):
    return [(b"x-auth-request-user", name.encode()), (b"x-auth-request-groups", b"eng")]


def create(app, name="alice", **extra):
    return scim(app, "POST", "/Users", {"schemas": [USER_SCHEMA], "userName": name, **extra})


def events(sink, name):
    return [r for r in sink.records if r["event"] == name]


def test_the_scim_token_is_required(tmp_path):
    app, sink = scim_gateway(tmp_path)
    assert scim(app, "GET", "/Users", presented=None)[0] == 401
    assert scim(app, "GET", "/Users", presented="x" * 40)[0] == 401
    assert events(sink, "gateway_auth_failed")
    assert scim(app, "GET", "/ServiceProviderConfig")[1]["patch"]["supported"] is True


def test_create_find_and_uniqueness_as_entra_does(tmp_path):
    app, _ = scim_gateway(tmp_path)
    q = b"filter=userName+eq+%22Alice%22"
    assert scim(app, "GET", "/Users", query=q)[1]["totalResults"] == 0
    status, made = create(app, "alice", externalId="e-1", displayName="Alice A")
    assert status == 201 and made["active"] is True and made["externalId"] == "e-1"
    assert scim(app, "GET", f"/Users/{made['id']}")[1]["userName"] == "alice"
    found = scim(app, "GET", "/Users", query=q)[1]
    assert found["totalResults"] == 1 and found["Resources"][0]["id"] == made["id"]
    status, err = create(app, "ALICE")  # userName is case-insensitive
    assert status == 409 and err["scimType"] == "uniqueness"


def test_deactivation_ends_access_now_and_reactivation_restores_sign_in(tmp_path):
    app, sink = scim_gateway(tmp_path)
    user = create(app, "alice")[1]
    minted = call(app, "/tokens", body={"name": "ide"}, headers=[*USER, *JSON])[1]["token"]
    ide = [(b"authorization", f"Bearer {minted}".encode())]
    assert call(app, body=chat(), headers=ide)[0] == 200

    off = {
        "schemas": [PATCH],
        "Operations": [{"op": "Replace", "path": "active", "value": "False"}],
    }
    status, doc = scim(app, "PATCH", f"/Users/{user['id']}", off)
    assert status == 200 and doc["active"] is False
    assert call(app, body=chat(), headers=ide)[0] == 401  # the token was revoked
    for name in ("alice", "Alice", "ALICE"):  # any case of the name
        status, body = call(app, body=chat(), headers=as_user(name))
        assert status == 403 and body["error"]["code"] == "user_deprovisioned", name
    gone = events(sink, "gateway_user_deprovisioned")
    assert gone and gone[0]["data"]["user"] == "alice" and gone[0]["data"]["tokens_revoked"] == 1

    on = {"schemas": [PATCH], "Operations": [{"op": "replace", "value": {"active": True}}]}
    assert scim(app, "PATCH", f"/Users/{user['id']}", on)[1]["active"] is True
    assert call(app, body=chat(), headers=USER)[0] == 200
    assert call(app, body=chat(), headers=ide)[0] == 401  # revoked tokens stay revoked
    assert events(sink, "gateway_user_provisioned")


def test_delete_and_rename_end_the_old_identity(tmp_path):
    app, _ = scim_gateway(tmp_path)
    alice = create(app, "alice")[1]
    bob = create(app, "bob")[1]
    put = {"schemas": [USER_SCHEMA], "userName": "alice2", "active": True}
    assert scim(app, "PUT", f"/Users/{alice['id']}", put)[1]["userName"] == "alice2"
    assert call(app, body=chat(), headers=as_user("alice"))[0] == 403  # the old name is disabled
    assert call(app, body=chat(), headers=as_user("alice2"))[0] == 200
    assert scim(app, "DELETE", f"/Users/{bob['id']}") == (204, None)
    assert scim(app, "GET", f"/Users/{bob['id']}")[0] == 404
    status, body = call(app, body=chat(), headers=as_user("bob"))
    assert status == 403 and body["error"]["code"] == "user_disabled"


def test_require_provisioned_admits_only_the_directory(tmp_path):
    app = Gateway(
        write_config(tmp_path, SCIM + "  require_provisioned: true\n" + TOKENS),
        transport=FakeUpstream(),
        sink=MemorySink(),
    )
    status, body = call(app, body=chat(), headers=USER)
    assert status == 403 and body["error"]["code"] == "user_not_provisioned"
    create(app, "Alice")
    assert call(app, body=chat(), headers=USER)[0] == 200


@pytest.mark.parametrize(
    "method,path,body,query",
    [
        ("GET", "/Users", None, b"filter=userName+eq+%22a%22+or+1+eq+1"),
        ("GET", "/Users", None, b"filter=userName+sw+%22a%22"),
        ("GET", "/Users", None, b"filter=emails+eq+%22a%22"),
        ("GET", "/Users", None, b"count=-1"),
        ("POST", "/Users", {"userName": ""}, b""),
        ("POST", "/Users", {"userName": "a\nb"}, b""),
        ("POST", "/Users", {"userName": "x", "active": "maybe"}, b""),
        ("POST", "/Users", ["not", "an", "object"], b""),
        ("GET", "/Groups", None, b""),
    ],
)
def test_malformed_requests_are_refused(tmp_path, method, path, body, query):
    app, _ = scim_gateway(tmp_path)
    status, err = scim(app, method, path, body, query=query)
    assert 400 <= status < 500 and err["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]


def test_bad_patches_are_refused(tmp_path):
    app, _ = scim_gateway(tmp_path)
    rid = create(app, "alice")[1]["id"]
    for ops in (
        [{"op": "remove", "path": "userName"}],
        [{"op": "replace", "path": "password", "value": "x"}],
        [{"op": "move", "path": "active", "value": False}],
        [],
    ):
        status, _ = scim(app, "PATCH", f"/Users/{rid}", {"schemas": [PATCH], "Operations": ops})
        assert status == 400, ops
    assert scim(app, "PATCH", f"/Users/{rid}", {"Operations": []})[0] == 400  # no PatchOp schema
    assert scim(app, "GET", f"/Users/{rid}")[1]["active"] is True  # nothing changed


def test_config_checks(tmp_path, monkeypatch):
    with pytest.raises(ConfigError, match="tokens"):
        write_config(tmp_path, SCIM)
    with pytest.raises(ConfigError, match="reference"):
        write_config(tmp_path, "scim:\n  token: plaintext\n" + TOKENS)
    monkeypatch.setenv("SCIM_TOKEN", "short")
    with pytest.raises(ConfigError, match="32"):
        Gateway(write_config(tmp_path, SCIM + TOKENS), transport=FakeUpstream(), sink=MemorySink())


def test_no_bearer_value_reaches_the_audit_file(tmp_path):
    # The real file sink, not MemorySink: what an attacker with the log would read.
    app = Gateway(write_config(tmp_path, SCIM + TOKENS), transport=FakeUpstream())
    wrong = "w" * 40
    scim(app, "GET", "/Users", presented=wrong)
    rid = create(app, "alice")[1]["id"]
    minted = call(app, "/tokens", body={"name": "ide"}, headers=[*USER, *JSON])[1]["token"]
    ide = [(b"authorization", f"Bearer {minted}".encode())]
    assert call(app, body=chat(), headers=ide)[0] == 200
    scim(app, "DELETE", f"/Users/{rid}")
    assert call(app, body=chat(), headers=ide)[0] == 401
    log = (tmp_path / "audit.jsonl").read_text()
    assert "gateway_user_deprovisioned" in log and "gateway_auth_failed" in log
    for value in (SCIM_BEARER, wrong, minted, minted.split("_", 1)[1]):
        assert value not in log
