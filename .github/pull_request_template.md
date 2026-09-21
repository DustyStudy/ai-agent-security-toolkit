## What and why

## Checklist
- [ ] `ruff check src tests`, `ruff format --check src tests`, `mypy src` and `pytest` pass
- [ ] New or changed security controls come with adversarial tests (bypass attempts), and known limitations are documented by a test
- [ ] No secret-shaped literals in source or tests
- [ ] README and `SECURITY.md` claims still match what the tests demonstrate
- [ ] `CHANGELOG.md` updated under "Unreleased"
