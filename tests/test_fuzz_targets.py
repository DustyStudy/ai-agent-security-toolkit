"""The fuzz targets, run as ordinary tests.

Coverage-guided fuzzing (``fuzz/run_fuzzer.py``) needs Atheris and time, so it runs in its own CI
job. Here every target runs on its checked-in seed corpus plus a deterministic batch of random
inputs, so the invariants are enforced on every change even without a fuzzing engine.
"""

from __future__ import annotations

import random
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentsec.sandbox import Decision, Verdict
from fuzz import targets
from fuzz.targets import TARGETS, Reader

CORPUS = Path(__file__).resolve().parents[1] / "fuzz" / "corpus"
RANDOM_INPUTS = 400


def _random_inputs(name: str, count: int = RANDOM_INPUTS) -> list[bytes]:
    rng = random.Random(f"agentsec-{name}")
    return [bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200))) for _ in range(count)]


@pytest.mark.parametrize("name", sorted(TARGETS))
def test_target_holds_on_its_seed_corpus_and_random_inputs(name):
    seeds = sorted((CORPUS / name).glob("*"))
    assert seeds, f"fuzz/corpus/{name} has no seed inputs"
    for data in [p.read_bytes() for p in seeds] + _random_inputs(name):
        TARGETS[name](data)


def test_the_runner_lists_every_target_and_compiles():
    source = (Path(__file__).resolve().parents[1] / "fuzz" / "run_fuzzer.py").read_text(
        encoding="utf-8"
    )
    compile(source, "run_fuzzer.py", "exec")
    assert "import atheris" in source
    assert set(TARGETS) == {
        "cef", "url", "url_private", "path", "redact", "scan", "policy", "guard", "audit",
    }  # fmt: skip


def test_reader_never_raises_on_any_input():
    for data in [b"", b"\x00", b"\xff" * 5, bytes(range(256))]:
        r = Reader(data)
        r.text(), r.json_value(), r.int32(), r.flag(), r.below(0), r.choice([1, 2, 3])


# ---------------------------------------------- the targets can actually fail
# A fuzz target that cannot fail proves nothing, so break the code under test in the way the
# invariant guards against and confirm the target notices.


def _fails_within(name: str, exc=AssertionError, budget: int = 3000) -> None:
    for data in _random_inputs(name, budget):
        try:
            TARGETS[name](data)
        except exc:
            return
    pytest.fail(f"target {name!r} did not detect the injected bug in {budget} inputs")


def test_cef_target_detects_a_multi_line_or_forging_formatter(monkeypatch):
    monkeypatch.setattr(targets, "format_cef", lambda *a, **k: "CEF:0|a|b|c|d|e|1|act=x\nact=y")
    _fails_within("cef")


def test_url_target_detects_a_guard_that_accepts_everything(monkeypatch):
    monkeypatch.setattr(targets, "check_url", lambda *a, **k: [])
    _fails_within("url")
    _fails_within("url_private")


def test_path_target_detects_a_guard_that_accepts_escapes(monkeypatch):
    monkeypatch.setattr(targets, "path_within_roots", lambda value, roots: (True, "/etc/passwd"))
    _fails_within("path")


def test_redact_target_detects_a_redactor_that_leaks(monkeypatch):
    monkeypatch.setattr(targets, "redact_text", lambda text, **k: (text, []))
    _fails_within("redact")


def test_scan_target_detects_an_out_of_range_score(monkeypatch):
    monkeypatch.setattr(
        targets._SCANNER, "scan", lambda text: SimpleNamespace(score=2.0, signals=[], flagged=True)
    )
    _fails_within("scan")


def test_policy_target_detects_a_loader_that_crashes(monkeypatch):
    def crash(raw):
        raise TypeError("unhashable")

    monkeypatch.setattr(targets.Policy, "from_dict", crash)
    _fails_within("policy", exc=TypeError)


def test_guard_target_detects_a_guard_that_allows_everything(monkeypatch):
    monkeypatch.setattr(
        targets._GUARD, "evaluate", lambda call, session: Decision(Verdict.ALLOW, call.name)
    )
    _fails_within("guard")


def test_audit_target_detects_a_verifier_that_misses_tampering(monkeypatch):
    monkeypatch.setattr(targets, "verify_records", lambda records: SimpleNamespace(ok=True))
    _fails_within("audit")
