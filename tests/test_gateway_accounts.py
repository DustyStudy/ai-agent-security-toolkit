"""identity.allowed_domains and identity.block_personal_domains: only company accounts."""

from __future__ import annotations

import pytest

from agentsec.gateway import ConfigError, Gateway
from agentsec.gateway.accounts import account_refusal
from agentsec.middleware.audit import MemorySink
from tests.test_gateway import FakeUpstream, call, chat, write_config


def _as(user: str):
    return [(b"x-auth-request-user", user.encode()), (b"x-auth-request-groups", b"eng")]


def _app(tmp_path, rules):
    sink = MemorySink()
    cfg = write_config(tmp_path, "identity:\n  trusted_proxies: [127.0.0.1/32]\n" + rules)
    return Gateway(cfg, transport=FakeUpstream(), sink=sink), sink


@pytest.mark.parametrize(
    ("user", "ok"),
    [
        ("alice@corp.example", True),
        ("ALICE@Corp.Example", True),
        ("bob@eu.corp.example", True),  # *.corp.example
        ("eve@gmail.com", False),
        ("eve@corp.example.evil.example", False),
        ("eve@evilcorp.example", False),
        ("corp.example@evil.example", False),
        ("eve@evil.example@corp.example", False),  # two @: parsers disagree on the domain
        ("alice", False),  # not an address
        ("eve@corp.exаmple", False),  # Cyrillic a: refused, not compared
    ],
)
def test_only_approved_domains_get_in(tmp_path, user, ok):
    app, sink = _app(tmp_path, "  allowed_domains: [corp.example, '*.corp.example']\n")
    status, body = call(app, body=chat(), headers=_as(user))
    assert (status == 200) is ok
    if not ok:
        assert status == 403 and body["error"]["code"] == "account_not_allowed"
        assert any(r["event"] == "gateway_account_refused" for r in sink.records)


@pytest.mark.parametrize("user", ["eve@gmail.com", "eve@Outlook.com", "eve@proton.me"])
def test_personal_mailboxes_are_refused(tmp_path, user):
    app, _ = _app(tmp_path, "  block_personal_domains: true\n")
    assert call(app, body=chat(), headers=_as(user))[0] == 403
    assert call(app, body=chat(), headers=_as("alice@corp.example"))[0] == 200


def test_off_by_default():
    assert account_refusal("alice", (), False) is None
    assert account_refusal("eve@gmail.com", (), False) is None


def test_personal_block_wins_even_when_the_domain_is_listed():
    assert account_refusal("eve@gmail.com", ("gmail.com",), True) == "personal email domain"


@pytest.mark.parametrize("bad", ["['corp example']", "[https://corp.example]", "['*corp.example']"])
def test_bad_domains_are_refused(tmp_path, bad):
    with pytest.raises(ConfigError, match="allowed_domains"):
        write_config(
            tmp_path, f"identity:\n  trusted_proxies: [127.0.0.1/32]\n  allowed_domains: {bad}\n"
        )
