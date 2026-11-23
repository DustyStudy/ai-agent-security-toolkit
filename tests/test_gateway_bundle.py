"""Signed policy bundles: per-group policy, tamper and rollback refusal, hot reload."""

from __future__ import annotations

import json
import textwrap
from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from agentsec.gateway import ConfigError, Gateway, load_config  # noqa: E402
from agentsec.gateway.bundle import (  # noqa: E402
    BundleError,
    load_bundle,
    sign_bundle,
    write_state,
)
from agentsec.gateway.policyset import PolicySet  # noqa: E402
from agentsec.middleware.audit import MemorySink  # noqa: E402
from tests.test_gateway import FakeUpstream, call, chat, tool  # noqa: E402

KEY = Ed25519PrivateKey.generate()
OTHER = Ed25519PrivateKey.generate()


def pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def pub_pem(key):
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


ENG_POLICY = "version: 1\ntools:\n  search:\n    args:\n      q: {type: string}\n"
FIN_POLICY = "version: 1\ntools:\n  ledger: {}\n"


def manifest(revision=1, expires=None, extra_entries=""):
    expires = expires or (datetime.now(UTC) + timedelta(days=30)).isoformat()
    return textwrap.dedent(
        f"""\
        revision: {revision}
        expires: '{expires}'
        group_policies:
          - group: eng
            tools: policies/eng.yaml
            models: [local, big]
          - group: finance
            tools: policies/fin.yaml
            models: [local]
            output: {{protected: [FIN-CANARY]}}
        """
    ) + textwrap.dedent(extra_entries)


def make_bundle(root, revision=1, key=KEY, **kw):
    (root / "policies").mkdir(parents=True, exist_ok=True)
    (root / "policies" / "eng.yaml").write_text(ENG_POLICY)
    (root / "policies" / "fin.yaml").write_text(FIN_POLICY)
    (root / "manifest.yaml").write_text(manifest(revision, **kw))
    sign_bundle(root, pem(key))
    return root


def pub(tmp_path):
    path = tmp_path / "bundle.pub"
    path.write_bytes(pub_pem(KEY))
    return path


def load(root):
    from agentsec.gateway.bundle import load_public_key

    return load_bundle(root, load_public_key(pub_pem(KEY)), upstreams={"local", "big"})


# --------------------------------------------------------------------- verification


def test_a_signed_bundle_loads_and_resolves_groups(tmp_path):
    policies = load(make_bundle(tmp_path / "b"))
    assert policies.revision.startswith("bundle:1:")
    assert policies.resolve(["eng"]).group == "eng"
    assert policies.resolve(["finance", "eng"]).group == "eng"  # first match wins
    assert policies.resolve(["sales"]) is None  # no match and no "*": 403


@pytest.mark.parametrize(
    "tamper",
    [
        lambda b: (b / "policies" / "eng.yaml").write_text(ENG_POLICY + "  delete_repo: {}\n"),
        lambda b: (b / "manifest.yaml").write_text(manifest(99)),
        lambda b: (b / "manifest.sig").unlink(),
        lambda b: (b / "manifest.sig").write_text("{not json"),
        lambda b: sign_bundle(b, pem(OTHER)),
        lambda b: (b / "manifest.sig").write_text(
            json.dumps({**json.loads((b / "manifest.sig").read_text()), "files": {}})
        ),
    ],
    ids=["policy-edited", "manifest-edited", "no-sig", "bad-sig", "other-key", "files-dropped"],
)
def test_tampered_bundles_are_refused(tmp_path, tamper):
    root = make_bundle(tmp_path / "b")
    tamper(root)
    with pytest.raises(BundleError):
        load(root)


def test_expired_bundles_are_refused(tmp_path):
    past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    with pytest.raises(BundleError, match="expired"):
        load(make_bundle(tmp_path / "b", expires=past))


@pytest.mark.parametrize("bad", ["../outside.yaml", "/etc/passwd", "policies\\eng.yaml"])
def test_bundle_paths_must_stay_inside_the_bundle(tmp_path, bad):
    root = make_bundle(tmp_path / "b")
    (tmp_path / "outside.yaml").write_text(ENG_POLICY)
    (root / "manifest.yaml").write_text(manifest().replace("policies/eng.yaml", bad))
    with pytest.raises(BundleError, match="inside the bundle|escapes"):
        sign_bundle(root, pem(KEY))


def test_unknown_models_and_keys_are_refused(tmp_path):
    root = make_bundle(tmp_path / "b")
    (root / "manifest.yaml").write_text(manifest().replace("[local, big]", "[local, gpt-x]"))
    sign_bundle(root, pem(KEY))
    with pytest.raises(BundleError, match="unknown upstreams"):
        load(root)
    (root / "manifest.yaml").write_text(manifest() + "surprise: 1\n")
    sign_bundle(root, pem(KEY))
    with pytest.raises(BundleError, match="unknown manifest keys"):
        load(root)


# ---------------------------------------------------------------------- the gateway


def write_config(tmp_path, root, extra=""):
    (tmp_path / "gateway.yaml").write_text(
        "identity: {trusted_proxies: [127.0.0.1/32]}\n"
        f"bundle: {{dir: '{root.as_posix()}', public_key_file: bundle.pub{extra}}}\n"
        "upstreams:\n"
        "  local: {url: 'http://127.0.0.1:11434/v1', model: m}\n"
        "  big: {url: 'http://127.0.0.1:11435/v1', model: m2}\n"
        "audit: {file: audit.jsonl}\n"
    )
    pub(tmp_path)
    return load_config(tmp_path / "gateway.yaml")


def who(groups):
    return [(b"x-auth-request-user", b"alice"), (b"x-auth-request-groups", groups.encode())]


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def gateway(tmp_path, root, upstream=None, extra=""):
    sink, clock = MemorySink(), Clock()
    app = Gateway(
        write_config(tmp_path, root, extra),
        transport=upstream or FakeUpstream(),
        sink=sink,
        clock=clock,
    )
    return app, sink, clock


def test_each_group_gets_its_own_tools_models_and_output_rules(tmp_path):
    upstream = FakeUpstream({"role": "assistant", "content": "the FIN-CANARY value"})
    app, sink, _ = gateway(tmp_path, make_bundle(tmp_path / "b"), upstream)
    body = chat(tools=[tool("search"), tool("ledger")])
    assert call(app, body=body, headers=who("eng"))[0] == 200
    assert [t["function"]["name"] for t in upstream.requests[-1]["tools"]] == ["search"]
    status, out = call(app, body=body, headers=who("finance"))
    assert [t["function"]["name"] for t in upstream.requests[-1]["tools"]] == ["ledger"]
    assert "FIN-CANARY" not in json.dumps(out)  # finance's protected string
    big = {**chat(), "model": "big"}
    assert call(app, body=big, headers=who("eng"))[0] == 200
    assert call(app, body=big, headers=who("finance"))[0] == 404  # not in finance's models
    models = call(app, "/v1/models", method="GET", headers=who("finance"))[1]
    assert [m["id"] for m in models["data"]] == ["local"]
    assert call(app, body=chat(), headers=who("sales"))[0] == 403
    req = [r for r in sink.records if r["event"] == "gateway_request"][-1]
    assert req["data"]["policy_group"] == "eng" and req["data"]["policy_rev"].startswith(
        "bundle:1:"
    )


def rev_of_last_request(sink):
    return [r for r in sink.records if r["event"] == "gateway_request"][-1]["data"]["policy_rev"]


def test_a_newer_signed_bundle_is_picked_up_without_a_restart(tmp_path):
    root = make_bundle(tmp_path / "b")
    app, sink, clock = gateway(tmp_path, root)
    call(app, body=chat(), headers=who("eng"))
    assert rev_of_last_request(sink).startswith("bundle:1:")
    make_bundle(root, revision=2)
    call(app, body=chat(), headers=who("eng"))  # not due yet
    assert rev_of_last_request(sink).startswith("bundle:1:")
    clock.t = 11
    call(app, body=chat(), headers=who("eng"))
    assert rev_of_last_request(sink).startswith("bundle:2:")
    assert "gateway_bundle_loaded" in [r["event"] for r in sink.records]


@pytest.mark.parametrize("change", ["rollback", "tampered", "other-key"])
def test_bad_reloads_keep_the_last_good_bundle_and_are_audited_once(tmp_path, change):
    root = make_bundle(tmp_path / "b", revision=5)
    app, sink, clock = gateway(tmp_path, root)
    if change == "rollback":
        make_bundle(root, revision=4)  # validly signed, but older
    elif change == "tampered":
        (root / "policies" / "eng.yaml").write_text(ENG_POLICY + "  delete_repo: {}\n")
        (root / "manifest.yaml").write_text(manifest(6))  # changed, so the reload is attempted
    else:
        make_bundle(root, revision=6, key=OTHER)
    for t in (11, 22, 33):
        clock.t = t
        assert call(app, body=chat(), headers=who("eng"))[0] == 200
        assert rev_of_last_request(sink).startswith("bundle:5:")
    rejected = [r for r in sink.records if r["event"] == "gateway_bundle_rejected"]
    assert len(rejected) == 1


def test_an_expired_bundle_stops_service(tmp_path):
    app, _, _ = gateway(tmp_path, make_bundle(tmp_path / "b"))
    current = app._policies
    app._policies = PolicySet(
        current.revision, current.groups, datetime.now(UTC) - timedelta(seconds=1), 1
    )
    status, body = call(app, body=chat(), headers=who("eng"))
    assert status == 503 and body["error"]["code"] == "policy_expired"


@pytest.mark.parametrize(
    ("extra", "top", "match"),
    [
        ("", "policy: p.yaml\n", "put policy"),
        (", min_revision: 7", "", "min_revision"),
    ],
)
def test_unsafe_bundle_config_is_refused(tmp_path, extra, top, match):
    root = make_bundle(tmp_path / "b")
    (tmp_path / "gateway.yaml").write_text(
        "identity: {trusted_proxies: [127.0.0.1/32]}\n"
        + top
        + f"bundle: {{dir: '{root.as_posix()}', public_key_file: bundle.pub{extra}}}\n"
        "upstreams: {local: {url: 'http://127.0.0.1:1/v1'}, big: {url: 'http://127.0.0.1:2/v1'}}\n"
        "audit: {file: a.jsonl}\n"
    )
    pub(tmp_path)
    with pytest.raises(ConfigError, match=match):
        load_config(tmp_path / "gateway.yaml")


def test_the_gateway_will_not_start_on_a_bad_bundle(tmp_path):
    root = make_bundle(tmp_path / "b")
    (root / "policies" / "fin.yaml").write_text("version: 1\ntools: {}\n")
    with pytest.raises(ConfigError, match="signed hash"):
        write_config(tmp_path, root)


def test_cli_signs_and_verifies(tmp_path, monkeypatch, capsys):
    from agentsec.cli import main

    root = make_bundle(tmp_path / "b")
    (root / "manifest.sig").unlink()
    monkeypatch.setenv("AGENTSEC_TEST_BUNDLE_KEY", pem(KEY).decode())
    assert main(["bundle", "sign", str(root), "--key", "env:AGENTSEC_TEST_BUNDLE_KEY"]) == 0
    assert main(["bundle", "verify", str(root), "--public-key", str(pub(tmp_path))]) == 0
    assert "bundle ok: bundle:1:" in capsys.readouterr().out
    (root / "policies" / "eng.yaml").write_text("version: 1\n")
    assert main(["bundle", "verify", str(root), "--public-key", str(pub(tmp_path))]) == 1


def test_the_example_bundle_signs_and_loads(tmp_path):
    import shutil
    from pathlib import Path

    root = tmp_path / "bundle"
    shutil.copytree(Path(__file__).parents[1] / "examples" / "bundle", root)
    sign_bundle(root, pem(KEY))
    from agentsec.gateway.bundle import load_public_key

    policies = load_bundle(
        root,
        load_public_key(pub_pem(KEY)),
        upstreams={"llama3.1-8b"},
        now=datetime(2026, 11, 15, tzinfo=UTC),
    )
    assert [g.group for g in policies.groups] == ["ml-platform", "*"]


# ------------------------------------------------------------ review findings


def test_a_bundle_published_before_the_gateway_starts_is_still_picked_up(tmp_path):
    """The first fingerprint described the files on disk, not the bundle loaded at config time."""
    root = make_bundle(tmp_path / "b")
    config = write_config(tmp_path, root)  # loads revision 1
    make_bundle(root, revision=2)  # published before the Gateway is built
    sink, clock = MemorySink(), Clock()
    app = Gateway(config, transport=FakeUpstream(), sink=sink, clock=clock)
    clock.t = 11
    call(app, body=chat(), headers=who("eng"))
    assert rev_of_last_request(sink).startswith("bundle:2:")


def test_a_huge_signature_file_is_not_read_into_memory(tmp_path, monkeypatch):
    import agentsec.gateway.app as app_mod

    root = make_bundle(tmp_path / "b")
    app, sink, clock = gateway(tmp_path, root)
    monkeypatch.setattr(app_mod, "MAX_FILE_BYTES", 100)
    (root / "manifest.sig").write_bytes(b"x" * 10_000)
    reads = []
    real_open = type(root).open

    def tracking_open(self, *a, **kw):
        fh = real_open(self, *a, **kw)
        real_read = fh.read

        def read(n=-1):
            reads.append(n)
            return real_read(n)

        fh.read = read
        return fh

    monkeypatch.setattr(type(root), "open", tracking_open)
    app._bundle_fingerprint()
    assert reads and all(0 < n <= 101 for n in reads)


def test_a_malformed_but_signed_manifest_is_a_logged_rejection(tmp_path):
    root = make_bundle(tmp_path / "b")
    app, sink, clock = gateway(tmp_path, root)
    (root / "manifest.yaml").write_text(
        manifest(2).replace("group: eng", "group: eng\n    mode: []")
    )
    sign_bundle(root, pem(KEY))
    clock.t = 11
    assert call(app, body=chat(), headers=who("eng"))[0] == 200
    assert [r for r in sink.records if r["event"] == "gateway_bundle_rejected"]


def test_the_state_file_refuses_rollback_across_restarts(tmp_path):
    root = make_bundle(tmp_path / "b", revision=10)
    extra = ", state_file: state.json"
    # Accepts 10; `serve` records it (load_config alone only checks the state file).
    write_state(tmp_path / "state.json", write_config(tmp_path, root, extra).policies)
    assert json.loads((tmp_path / "state.json").read_text())["revision"] == 10
    make_bundle(root, revision=5)  # older but validly signed and unexpired
    with pytest.raises(ConfigError, match="rollback refused"):
        write_config(tmp_path, root, extra)
    make_bundle(root, revision=10)  # same number, different bundle (a new expiry)
    (root / "manifest.yaml").write_text(manifest(10).replace("FIN-CANARY", "OTHER"))
    sign_bundle(root, pem(KEY))
    with pytest.raises(ConfigError, match="rollback refused"):
        write_config(tmp_path, root, extra)
    make_bundle(root, revision=11)
    assert write_config(tmp_path, root, extra).policies.numeric_revision == 11


def test_reloads_record_the_state_before_enforcing(tmp_path):
    root = make_bundle(tmp_path / "b")
    app, sink, clock = gateway(tmp_path, root, extra=", state_file: state.json")
    make_bundle(root, revision=2)
    clock.t = 11
    call(app, body=chat(), headers=who("eng"))
    assert json.loads((tmp_path / "state.json").read_text())["revision"] == 2


# ------------------------------------------------------------------- MCP in bundles


def mcp_bundle(root, pins='{"version": 1, "tools": {"docs__search": "abc"}}', mcp="[docs]"):
    (root / "pins").mkdir(parents=True, exist_ok=True)
    (root / "pins" / "docs.json").write_text(pins)
    make_bundle(
        root,
        extra_entries="""\
        mcp_pins: {docs: pins/docs.json}
        """,
    )
    text = (
        (root / "manifest.yaml")
        .read_text()
        .replace("    models: [local, big]\n", f"    models: [local, big]\n    mcp: {mcp}\n")
    )
    (root / "manifest.yaml").write_text(text)
    sign_bundle(root, pem(KEY))
    return root


def load_mcp(root, mcp_upstreams=frozenset({"docs"})):
    from agentsec.gateway.bundle import load_public_key

    return load_bundle(
        root,
        load_public_key(pub_pem(KEY)),
        upstreams={"local", "big"},
        mcp_upstreams=set(mcp_upstreams),
    )


def test_a_bundle_carries_mcp_access_and_signed_pins(tmp_path):
    policies = load_mcp(mcp_bundle(tmp_path / "b"))
    eng, fin = policies.groups
    assert eng.mcp == frozenset({"docs"}) and fin.mcp == frozenset()
    assert policies.mcp_pins == {"docs": {"docs__search": "abc"}}


def test_a_tampered_pin_file_fails_the_signature(tmp_path):
    root = mcp_bundle(tmp_path / "b")
    (root / "pins" / "docs.json").write_text('{"version": 1, "tools": {}}')
    with pytest.raises(BundleError, match="signed hash"):
        load_mcp(root)


@pytest.mark.parametrize(
    ("kw", "upstreams", "error"),
    [
        ({"mcp": "[nope]"}, {"docs"}, "unknown mcp_upstreams"),
        ({}, set(), "unknown mcp_upstream"),
        ({"pins": "[]"}, {"docs"}, "pin file"),
        ({"pins": "not json"}, {"docs"}, "not JSON"),
    ],
)
def test_mcp_bundle_settings_are_validated(tmp_path, kw, upstreams, error):
    with pytest.raises(BundleError, match=error):
        load_mcp(mcp_bundle(tmp_path / "b", **kw), mcp_upstreams=upstreams)


def bundle_with_group(root, entry):
    make_bundle(root)
    with (root / "manifest.yaml").open("a") as f:  # group_policies is the last key
        f.write(entry)
    sign_bundle(root, pem(KEY))
    return root


def test_each_bundle_group_carries_its_own_dlp_policy(tmp_path):
    entry = (
        "  - group: support\n"
        "    tools: policies/eng.yaml\n"
        "    dlp: {categories: {pii: {tool_args: block}}}\n"
    )
    policies = load(bundle_with_group(tmp_path / "b", entry))
    assert policies.resolve(["support"]).dlp.mode("email", "tool_args") == "block"
    assert policies.resolve(["eng"]).dlp.mode("email", "tool_args") == "monitor"
    bad = "  - group: x\n    tools: policies/eng.yaml\n    dlp: {categories: {secrets: {}}}\n"
    with pytest.raises(BundleError, match="secrets|category"):
        load(bundle_with_group(tmp_path / "c", bad))
