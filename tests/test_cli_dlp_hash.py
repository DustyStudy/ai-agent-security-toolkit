"""``agentsec dlp hash``: the keyed hash for a dlp.allow entry, without echoing the value."""

from __future__ import annotations

import io
import sys
from datetime import UTC, datetime, timedelta

from agentsec.cli import main
from agentsec.middleware.dlp import DlpPolicy, allow_digest
from tests.conftest import fake_aws_key

KEY = "f" * 40


class _Stdin(io.TextIOWrapper):
    def __init__(self, data: bytes, tty: bool = False):
        super().__init__(io.BytesIO(data), encoding="utf-8")
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def run(monkeypatch, capsys, data: bytes, tty: bool = False, key: str = "env:DLP_KEY"):
    monkeypatch.setenv("DLP_KEY", KEY)
    monkeypatch.setattr(sys, "stdin", _Stdin(data, tty))
    code = main(["dlp", "hash", "--key", key])
    out, err = capsys.readouterr()
    return code, out, err


def test_the_hash_is_what_the_allowlist_matches(monkeypatch, capsys):
    secret = fake_aws_key()
    code, out, err = run(monkeypatch, capsys, (secret + "\n").encode())
    assert code == 0 and out.strip() == allow_digest(KEY.encode(), secret)
    assert secret not in out + err and KEY not in out + err and "aws_access_key_id" in err
    expires = (datetime.now(UTC).date() + timedelta(days=30)).isoformat()
    entry = {"id": "fixture", "reason": "ci fixture", "owner": "sec", "expires": expires,
             "kinds": ["aws_access_key_id"], "match": {"hmac_sha256": out.strip()}}  # fmt: skip
    p = DlpPolicy.from_dict({"allow": [entry], "fingerprint_key": "env:DLP_KEY"})
    (m,) = p.scan(f"key {secret}", "output").matches
    assert m.allowed_by == "fixture"


def test_only_one_trailing_newline_is_dropped_and_utf8_is_used(monkeypatch, capsys):
    _, out, _ = run(monkeypatch, capsys, "pässword\r\n".encode())
    assert out.strip() == allow_digest(KEY.encode(), "pässword")
    _, out, _ = run(monkeypatch, capsys, b"x\n\n")
    assert out.strip() == allow_digest(KEY.encode(), "x\n")


def test_a_value_no_detector_matches_whole_gets_a_warning(monkeypatch, capsys):
    code, _, err = run(monkeypatch, capsys, b"4242 4242 4242 4242 and more")
    assert code == 0 and "warning: no built-in detector matches the whole value" in err


def test_an_empty_value_or_a_bad_key_is_an_error(monkeypatch, capsys):
    code, out, err = run(monkeypatch, capsys, b"\n")
    assert code == 2 and out == "" and "no value" in err
    monkeypatch.setenv("SHORT", "x" * 31)
    code, out, err = run(monkeypatch, capsys, b"v", key="env:SHORT")
    assert code == 2 and out == "" and "at least 32 bytes" in err


def test_a_terminal_reads_without_echo(monkeypatch, capsys):
    secret = fake_aws_key()
    monkeypatch.setattr("getpass.getpass", lambda prompt: secret)
    code, out, err = run(monkeypatch, capsys, b"", tty=True)
    assert code == 0 and out.strip() == allow_digest(KEY.encode(), secret)
    assert secret not in out + err
