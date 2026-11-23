"""``agentsec dlp hash``: the sha256 for a dlp.allow entry, without echoing the value."""

from __future__ import annotations

import hashlib
import io
import sys
from datetime import UTC, datetime, timedelta

from agentsec.cli import main
from agentsec.middleware.dlp import DlpPolicy
from tests.conftest import fake_aws_key


class _Stdin(io.TextIOWrapper):
    def __init__(self, data: bytes, tty: bool = False):
        super().__init__(io.BytesIO(data), encoding="utf-8")
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def run(monkeypatch, capsys, data: bytes, tty: bool = False):
    monkeypatch.setattr(sys, "stdin", _Stdin(data, tty))
    code = main(["dlp", "hash"])
    out, err = capsys.readouterr()
    return code, out, err


def test_the_hash_is_what_the_allowlist_matches(monkeypatch, capsys):
    key = fake_aws_key()
    code, out, err = run(monkeypatch, capsys, (key + "\n").encode())
    assert code == 0 and out.strip() == hashlib.sha256(key.encode()).hexdigest()
    assert key not in out + err and "aws_access_key_id" in err
    expires = (datetime.now(UTC).date() + timedelta(days=30)).isoformat()
    entry = {"id": "fixture", "reason": "ci fixture", "owner": "sec", "expires": expires,
             "kinds": ["aws_access_key_id"], "match": {"sha256": out.strip()}}  # fmt: skip
    (m,) = DlpPolicy.from_dict({"allow": [entry]}).scan(f"key {key}", "output").matches
    assert m.allowed_by == "fixture"


def test_only_one_trailing_newline_is_dropped_and_utf8_is_used(monkeypatch, capsys):
    _, out, _ = run(monkeypatch, capsys, "pässword\r\n".encode())
    assert out.strip() == hashlib.sha256("pässword".encode()).hexdigest()
    _, out, _ = run(monkeypatch, capsys, b"x\n\n")
    assert out.strip() == hashlib.sha256(b"x\n").hexdigest()


def test_a_value_no_detector_matches_whole_gets_a_warning(monkeypatch, capsys):
    code, _, err = run(monkeypatch, capsys, b"4242 4242 4242 4242 and more")
    assert code == 0 and "warning: no built-in detector matches the whole value" in err


def test_an_empty_value_is_an_error(monkeypatch, capsys):
    code, out, err = run(monkeypatch, capsys, b"\n")
    assert code == 2 and out == "" and "no value" in err


def test_a_terminal_reads_without_echo(monkeypatch, capsys):
    secret = fake_aws_key()
    monkeypatch.setattr("getpass.getpass", lambda prompt: secret)
    code, out, err = run(monkeypatch, capsys, b"", tty=True)
    assert code == 0 and out.strip() == hashlib.sha256(secret.encode()).hexdigest()
    assert secret not in out + err
