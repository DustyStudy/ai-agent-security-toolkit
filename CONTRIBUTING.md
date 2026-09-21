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
ruff check src tests
ruff format src tests
mypy src
pytest --cov=agentsec
```

All four also run in CI. Tests run on Linux, Windows and macOS, on Python 3.11 to 3.13, with a 90% coverage floor. Add a line to `CHANGELOG.md` under "Unreleased" for user-visible changes.

## Guidelines

- **Security controls need adversarial tests.** A new validator or policy rule should come with the bypass attempts it is meant to stop (traversal, encodings, look-alike hosts) and, where a bypass is a *known limitation*, a test that documents it.
- **No secret-shaped literals** in source or tests. Build fake credentials at runtime (see `tests/conftest.py`) so secret scanners stay quiet.
- **Regenerate the example threat model** when the catalog or renderer changes:
  `agentsec threatmodel render examples/support-copilot.system.yaml -o docs/threat-model/EXAMPLE-support-copilot.md`
  (a test and a CI step both fail if it is stale).
- **New fuzz payloads** must be inert: ask for something the detectors can see (canary, forbidden tool name, attacker-domain link) and nothing that would be harmful if a target obeyed it.
- Keep the README's claims aligned with what the tests demonstrate.
