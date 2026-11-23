"""Data-loss prevention: detectors, modes per surface, allowlist, audit without values.

Every secret-shaped value is built at run time so no scanner trips on this file.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import UTC, date, datetime, timedelta

import pytest

from agentsec.middleware import AgentMiddleware, AuditLogger, MemorySink, OutputGuard
from agentsec.middleware.cef import severity
from agentsec.middleware.dlp import (
    CATEGORY_OF,
    DlpConfigError,
    DlpPolicy,
)
from agentsec.middleware.redact import _RULES, find_sensitive
from agentsec.sandbox import Policy, ToolGuard
from agentsec.types import ToolCall

AWS_KEY = "AKIA" + "Q" * 16
GH_TOKEN = "ghp" + "_" + "a1B2" * 9
SSN = "219-09-" + "9999"
CARD = "4012 8888 8888 " + "1881"  # Visa, Luhn-valid, not on the built-in test list
EMAIL = "jane.doe" + "@corp-mail.com"
KEY = "k" * 32


def kinds(text: str) -> list[str]:
    return [f.kind for f in find_sensitive(text, include_email=True)]


def luhn_complete(prefix: str, length: int) -> str:
    for d in "0123456789":
        body = prefix + "7" * (length - len(prefix) - 1) + d
        total = 0
        for i, c in enumerate(reversed(body)):
            n = int(c) * (2 if i % 2 else 1)
            total += n - 9 if n > 9 else n
        if total % 10 == 0:
            return body
    raise AssertionError


# ------------------------------------------------------------------------ detectors


def test_every_detector_kind_has_a_category():
    assert {r.kind for r in _RULES} <= set(CATEGORY_OF)
    assert set(CATEGORY_OF.values()) == {"credentials", "nhi", "pii"}
    assert CATEGORY_OF["aws_access_key_id"] == "nhi"
    assert CATEGORY_OF["password_assignment"] == "credentials"
    assert CATEGORY_OF["email"] == "pii"


def test_cards_need_a_network_prefix_and_one_grouping():
    assert kinds(CARD) == ["payment_card"]
    assert kinds(CARD.replace(" ", "")) == ["payment_card"]
    amex = luhn_complete("34", 15)
    assert kinds(f"{amex[:4]} {amex[4:10]} {amex[10:]}") == ["payment_card"]
    # Luhn-valid, but no card network starts with 9 or 1.
    assert kinds(luhn_complete("9", 16)) == []
    assert kinds(luhn_complete("1", 16)) == []
    # Mixed separators and odd groupings are not how cards are written.
    assert kinds("4012-8888 8888-1881") == []
    assert kinds("40128 88888 881881") == []
    # Right prefix, wrong length for the network (Mastercard is 16 digits).
    assert kinds(luhn_complete("51", 19)) == []


def test_a_card_next_to_other_numbers_is_still_found():
    # The first candidate span fails the check; the search must retry inside it.
    assert kinds(f"ref 12 {CARD}") == ["payment_card"]
    assert kinds(f"{CARD} 2 items") == ["payment_card"]
    assert kinds(f"219-09-9999 {CARD}") == ["us_ssn", "payment_card"]


def test_ssn_dashed_spaced_and_labelled():
    assert kinds(SSN) == ["us_ssn"]
    assert kinds(SSN.replace("-", " ")) == ["us_ssn"]
    assert kinds("SSN: " + SSN.replace("-", "")) == ["us_ssn"]
    assert kinds("social security number 219099999") == ["us_ssn"]
    assert kinds("order 219099999 shipped") == []  # bare 9 digits need a label
    assert kinds("219-09 9999") == []  # separators must match


def test_email_is_found_only_when_asked():
    assert kinds(f"write to {EMAIL} today") == ["email"]
    assert find_sensitive(f"write to {EMAIL}") == []  # audit log redaction leaves it
    assert kinds("user@localhost") == []  # no TLD
    assert kinds("a@b.c") == []  # one-letter TLD


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("glrt-" + "x" * 20, "gitlab_token"),
        ("gldt-" + "x" * 20, "gitlab_token"),
        ("SG." + "a" * 22 + "." + "b" * 43, "sendgrid_api_key"),
        ("dop_v1_" + "a" * 64, "digitalocean_token"),
        ("shpat_" + "a" * 32, "shopify_token"),
        ("dapi" + "a" * 32, "databricks_token"),
    ],
)
def test_new_nhi_formats(value, kind):
    assert kinds(f"token {value} here") == [kind]
    assert CATEGORY_OF[kind] == "nhi"


def test_azure_storage_key_is_named_not_generic():
    conn = "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=" + "A" * 86 + "==;"
    assert kinds(conn) == ["azure_storage_key"]


@pytest.mark.parametrize(
    "attack",
    ["a@" * 50_000, "a." * 50_000 + "@", "4 " * 50_000, "SG." * 30_000, "ssn " * 25_000],
)
def test_new_rules_stay_linear(attack):
    start = time.perf_counter()
    find_sensitive(attack, include_email=True)
    assert time.perf_counter() - start < 2.0


# ---------------------------------------------------------------------------- modes


def test_default_output_redacts_secrets_and_ids_but_only_watches_email():
    text = f"key {AWS_KEY}, ssn {SSN}, mail {EMAIL}"
    result = DlpPolicy().scan(text, "output")
    assert result.action == "redact"
    assert result.text == (f"key [REDACTED:aws_access_key_id], ssn [REDACTED:us_ssn], mail {EMAIL}")
    assert {m.kind: m.action for m in result.matches} == {
        "aws_access_key_id": "redact",
        "us_ssn": "redact",
        "email": "monitor",
    }


def test_strictest_mode_wins_and_kinds_override_their_category():
    policy = DlpPolicy.from_dict(
        {"categories": {"pii": {"output": "block", "kinds": {"email": {"output": "redact"}}}}}
    )
    assert policy.scan(f"mail {EMAIL}", "output").text == "mail [REDACTED:email]"
    mixed = policy.scan(f"{EMAIL} {CARD}", "output")
    assert mixed.blocked


def test_redact_in_tool_arguments_means_block():
    policy = DlpPolicy.from_dict({"categories": {"pii": {"tool_args": "redact"}}})
    assert policy.mode("email", "tool_args") == "block"
    assert policy.scan_args({"to": EMAIL}, "send_email").blocked


def test_oversized_text_fails_closed_unless_everything_is_monitored():
    big = "x" * 200_001
    assert DlpPolicy().scan(big, "output").blocked
    watch = {c: dict.fromkeys(("output",), "monitor") for c in ("credentials", "nhi", "pii")}
    watched = DlpPolicy.from_dict({"categories": watch}).scan(big, "output")
    assert watched.action == "monitor" and watched.text == big
    assert DlpPolicy().scan_args({"a": ["y" * 100_000] * 11}, "t").blocked  # unit cap


def test_secret_references_are_not_secrets():
    found = DlpPolicy().scan_args(
        {"cmd": 'curl -H "Authorization: Bearer $API_TOKEN"', "env": "password=${DB_PASS}"},
        "run",
    )
    assert found.action is None


def test_config_is_strict():
    for bad in (
        {"categories": {"secrets": {}}},
        {"categories": {"pii": {"output": "off"}}},
        {"categories": {"pii": {"chat": "block"}}},
        {"categories": {"pii": {"kinds": {"jwt": {"output": "block"}}}}},
        {"mode": "block"},
    ):
        with pytest.raises(DlpConfigError):
            DlpPolicy.from_dict(bad)


# ------------------------------------------------------------------------ allowlist


KEY = "k" * 32


def allow(**over):
    entry = {
        "id": "support",
        "reason": "shared mailbox",
        "owner": "platform-security",
        "expires": (date.today() + timedelta(days=30)).isoformat(),
        "kinds": ["email"],
        "match": {"email_domain": "corp-mail.com"},
    }
    entry.update(over)
    return DlpPolicy.from_dict(
        {
            "categories": {"pii": {"output": "block"}},
            "allow": [entry],
            "fingerprint_key": "env:DLP_TEST_KEY",
        },
        resolve_secret=lambda ref: KEY,
    )


def test_allowlisted_values_pass_but_are_still_recorded():
    result = allow().scan(f"mail {EMAIL}", "output")
    assert result.action is None and result.text == f"mail {EMAIL}"
    assert [(m.action, m.allowed_by) for m in result.matches] == [("allowed", "support")]
    # A different domain next to it is still caught.
    assert allow().scan(f"{EMAIL} x@other-corp.com", "output").blocked


def test_allowlist_scope_by_surface_and_tool():
    policy = allow(surfaces=["tool_args"], tools=["send_email"])
    assert policy.scan(EMAIL, "output").blocked
    pii_block = {"categories": {"pii": {"tool_args": "block"}}}
    entry = {
        "id": "s",
        "reason": "r",
        "owner": "o",
        "expires": date.today() + timedelta(days=1),
        "kinds": ["email"],
        "tools": ["send_email"],
        "match": {"email_domain": "corp-mail.com"},
    }
    policy = DlpPolicy.from_dict({**pii_block, "allow": [entry]})
    assert not policy.scan_args({"to": EMAIL}, "send_email").blocked
    assert policy.scan_args({"to": EMAIL}, "http_post").blocked


def test_allowlist_by_hash_for_secrets_never_by_pattern():
    digest = hmac.new(KEY.encode(), AWS_KEY.encode(), hashlib.sha256).hexdigest()
    policy = allow(kinds=["aws_access_key_id"], match={"hmac_sha256": digest})
    assert policy.scan(AWS_KEY, "output").action is None
    # Unkeyed: a password or SSN in the bundle would be reversed by guessing.
    with pytest.raises(DlpConfigError, match="sha256 is not accepted"):
        allow(kinds=["aws_access_key_id"], match={"sha256": hashlib.sha256(b"x").hexdigest()})
    with pytest.raises(DlpConfigError, match="needs dlp.fingerprint_key"):
        DlpPolicy.from_dict({"allow": [{"id": "a", "reason": "r", "owner": "o",
                             "expires": (date.today() + timedelta(days=1)).isoformat(),
                             "kinds": ["aws_access_key_id"], "match": {"hmac_sha256": digest}}]})  # fmt: skip
    with pytest.raises(DlpConfigError, match="pii kinds only"):
        allow(kinds=["aws_access_key_id"], match={"pattern": "AKIA.*"})
    assert (
        allow(kinds=["us_ssn"], match={"pattern": r"219-09-\d{4}"})
        .scan(SSN, "output")
        .matches[0]
        .allowed_by
        == "support"
    )


def test_allowlist_entries_must_expire_and_stop_matching_when_they_do():
    with pytest.raises(DlpConfigError, match="180 days"):
        allow(expires=(date.today() + timedelta(days=181)).isoformat())
    for missing in ("owner", "reason", "expires", "kinds", "match"):
        with pytest.raises(DlpConfigError):
            allow(**{missing: None})
    policy = allow()
    later = dataclass_replace_clock(policy, datetime.now(UTC) + timedelta(days=31))
    assert later.scan(EMAIL, "output").blocked


def dataclass_replace_clock(policy, when):
    import dataclasses

    return dataclasses.replace(policy, clock=lambda: when)


def test_published_example_values_are_allowed_but_recorded():
    example = "AKIA" + "IOSFODNN7EXAMPLE"
    result = DlpPolicy().scan(f"{example} and 4242 4242 4242 4242", "output")
    assert result.action is None
    assert {m.allowed_by for m in result.matches} == {"builtin"}


# ------------------------------------------------------------------- fingerprints


def test_fingerprints_are_keyed_stable_and_optional(monkeypatch):
    monkeypatch.setenv("DLP_KEY", KEY)
    keyed = DlpPolicy.from_dict({"fingerprint_key": "env:DLP_KEY"})
    a = keyed.scan(AWS_KEY, "output").matches[0].fingerprint
    assert a == keyed.scan(f"again {AWS_KEY}", "output").matches[0].fingerprint
    assert a.startswith("hmac-sha256:") and len(a) == len("hmac-sha256:") + 16
    monkeypatch.setenv("DLP_KEY", "j" * 32)
    other = DlpPolicy.from_dict({"fingerprint_key": "env:DLP_KEY"})
    assert other.scan(AWS_KEY, "output").matches[0].fingerprint != a
    assert DlpPolicy().scan(AWS_KEY, "output").matches[0].fingerprint is None
    monkeypatch.setenv("DLP_KEY", "short")
    with pytest.raises(DlpConfigError, match="32 bytes"):
        DlpPolicy.from_dict({"fingerprint_key": "env:DLP_KEY"})
    with pytest.raises(DlpConfigError):
        DlpPolicy.from_dict({"fingerprint_key": KEY})  # a literal, not a reference


# --------------------------------------------------------------------- tool guard

POLICY = Policy.from_dict(
    {
        "tools": {
            "send_email": {"args": {"to": {}, "body": {}}},
            "search": {"args": {"q": {}}},
        }
    }
)


def test_library_tool_guard_denies_secrets_in_arguments():
    sink = MemorySink()
    guard = ToolGuard(POLICY, audit=AuditLogger(sink))
    decision = guard.authorize(
        ToolCall("send_email", {"to": "a@example.com", "body": f"key {AWS_KEY}"})
    )
    assert not decision.allowed
    assert "sensitive data in arguments (aws_access_key_id)" in decision.message()
    dlp = [r["data"] for r in sink.records if r["event"] == "dlp_match"]
    assert [(d["kind"], d["action"], d["location"], d["tool"]) for d in dlp] == [
        ("email", "allowed", "arguments.to", "send_email"),
        ("aws_access_key_id", "block", "arguments.body", "send_email"),
    ]


def test_pii_in_arguments_is_monitored_by_default_and_blockable():
    sink = MemorySink()
    guard = ToolGuard(POLICY, audit=AuditLogger(sink))
    assert guard.authorize(ToolCall("send_email", {"to": EMAIL, "body": f"ssn {SSN}"})).allowed
    actions = [r["data"]["action"] for r in sink.records if r["event"] == "dlp_match"]
    assert actions == ["monitor", "monitor"]
    strict = DlpPolicy.from_dict({"categories": {"pii": {"tool_args": "block"}}})
    assert not ToolGuard(POLICY, dlp=strict).authorize(ToolCall("search", {"q": SSN})).allowed


def test_secrets_hidden_in_keys_and_nesting_are_found():
    guard = ToolGuard(Policy.from_dict({"tools": {"t": {"allow_extra_args": True}}}))
    assert not guard.evaluate(ToolCall("t", {"meta": {"x": [{"y": GH_TOKEN}]}})).allowed
    assert not guard.evaluate(ToolCall("t", {f"api_key={GH_TOKEN}": 1})).allowed


def test_dlp_none_turns_the_argument_check_off():
    assert ToolGuard(POLICY, dlp=None).evaluate(ToolCall("search", {"q": AWS_KEY})).allowed


# ------------------------------------------------------------------ audit hygiene


def test_no_sensitive_value_reaches_the_audit_log(monkeypatch):
    monkeypatch.setenv("DLP_KEY", KEY)
    policy = DlpPolicy.from_dict(
        {
            "fingerprint_key": "env:DLP_KEY",
            "categories": {"pii": {"output": "redact", "tool_args": "block"}},
            "allow": [
                {
                    "id": "a",
                    "reason": "r",
                    "owner": "o",
                    "expires": date.today() + timedelta(days=1),
                    "kinds": ["email"],
                    "match": {"pattern": r"nobody@corp-mail\.com"},
                }
            ],
        }
    )
    sink = MemorySink()
    log = AuditLogger(sink)
    guard = ToolGuard(POLICY, audit=log, dlp=policy)
    mw = AgentMiddleware(guard=guard, output_guard=OutputGuard.default(dlp=policy), audit=log)
    values = [AWS_KEY, GH_TOKEN, SSN, CARD, EMAIL]
    mw.screen_output(" ".join(values))
    for v in values:
        guard.authorize(ToolCall("search", {"q": v}))
    raw = json.dumps(sink.records)
    assert raw.count('"dlp_match"') == 2 * len(values)
    for v in values:
        for form in (v, base64.b64encode(v.encode()).decode(), v.encode().hex(), KEY):
            assert form not in raw


def test_the_audit_log_hides_addresses_in_content_but_keeps_the_actor():
    sink = MemorySink()
    AuditLogger(sink, actor=EMAIL).log("tool_request", arguments={"to": EMAIL})
    record = sink.records[0]
    assert record["actor"] == EMAIL
    # No key: a fixed marker, never an unkeyed hash that a guess could confirm.
    assert record["data"]["arguments"]["to"] == "[REDACTED:email]"


def test_with_a_key_addresses_get_the_same_hmac_as_their_dlp_fingerprint():
    sink = MemorySink()
    AuditLogger(sink, email_key=KEY.encode()).log("x", a=f"to {EMAIL}")
    logged = sink.records[0]["data"]["a"]
    policy = DlpPolicy(fingerprint_key=KEY.encode())
    fingerprint = policy.scan(EMAIL, "output").matches[0].fingerprint
    assert logged == f"to [EMAIL:{fingerprint}]" and EMAIL not in logged
    other = MemorySink()
    AuditLogger(other, email_key=b"j" * 32).log("x", a=f"to {EMAIL}")
    assert other.records[0]["data"]["a"] != logged


def test_dlp_matches_rank_by_action_in_cef():
    assert severity("dlp_match", {"action": "block"}) == 7
    assert severity("dlp_match", {"action": "redact"}) == 5
    assert severity("dlp_match", {"action": "monitor"}) == 3


def test_output_guard_keeps_its_validator_names():
    result = OutputGuard.default().process(f"{AWS_KEY} {SSN}")
    assert [v.validator for v in result.violations] == ["secret_leak", "pii"]
    assert all(v.detail and "fingerprint" not in v.detail for v in result.violations)
