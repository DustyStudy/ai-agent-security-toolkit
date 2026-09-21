# Contributing

Lightweight process; this is a solo-maintained project.

## Setup

```bash
git clone https://github.com/DustyStudy/ai-agent-security-toolkit.git
cd ai-agent-security-toolkit
python -m pip install -e ".[dev]"
```

## Before opening a PR

```bash
ruff check src tests fuzz scripts
ruff format src tests fuzz scripts
mypy src
pytest --cov=agentsec
```

All four also run in CI. Tests run on Linux, Windows and macOS, on Python 3.11 to 3.13, with a 90% coverage floor. Add a line to `CHANGELOG.md` under "Unreleased" for user-visible changes.

## Pinned CI dependencies

CI installs from hash-pinned files in `requirements/` (`pip install --require-hashes -r ...`), so a compromised package on the index cannot change what runs. If you add or change a dependency in `pyproject.toml` (or an `.in` file), regenerate them and commit the result; a CI job fails if they are stale:

```bash
pip install --require-hashes -r requirements/requirements-lock-tools.txt   # pinned uv
python scripts/lock.py             # re-resolve what changed, keep other pins
python scripts/lock.py --upgrade   # move every pin forward
```

## Fuzz targets

`fuzz/targets.py` holds functions that must keep an invariant for *any* input (an accepted URL really points at an allowed host, a planted secret never survives redaction, tampering with an audit chain is always detected, and so on). They run as ordinary tests on a seed corpus and random inputs. For coverage-guided fuzzing:

```bash
pip install atheris                       # Linux and macOS, Python 3.11 to 3.13
python fuzz/run_fuzzer.py url fuzz/corpus/url -max_total_time=60
```

When you change a validator, parser or the policy loader, add or extend a target for the property you are relying on. When a fuzz run finds a crash, add the input as a seed under `fuzz/corpus/<target>/` and a regression test.

## Guidelines

- **Security controls need adversarial tests.** A new validator or policy rule should come with the bypass attempts it is meant to stop (traversal, encodings, look-alike hosts) and, where a bypass is a *known limitation*, a test that documents it.
- **No secret-shaped literals** in source or tests. Build fake credentials at runtime (see `tests/conftest.py`) so secret scanners stay quiet.
- **Regenerate the example threat model** when the catalog or renderer changes:
  `agentsec threatmodel render examples/support-copilot.system.yaml -o docs/threat-model/EXAMPLE-support-copilot.md`
  (a test and a CI step both fail if it is stale).
- **New fuzz payloads** must be inert: ask for something the detectors can see (canary, forbidden tool name, attacker-domain link) and nothing that would be harmful if a target obeyed it.
- Keep the README's claims aligned with what the tests demonstrate.
