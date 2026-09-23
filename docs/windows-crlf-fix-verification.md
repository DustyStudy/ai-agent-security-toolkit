# Verification: Windows CRLF fix (PR #28)

This records the actual testing behind [PR #28](https://github.com/DustyStudy/ai-agent-security-toolkit/pull/28)
("write generated files with LF regardless of host platform"), so the fix isn't
taken on faith. Everything below is a real command run against this repository,
not a description of intended behavior.

- **Merge commit:** [`4af782a`](https://github.com/DustyStudy/ai-agent-security-toolkit/commit/4af782a7c8d2fd8838228bb0b9174584e14dd792) — merged 2026-09-23T13:30:44Z
- **Post-merge CI run on `main`** (not just the PR branch): [run 35867580745](https://github.com/DustyStudy/ai-agent-security-toolkit/actions/runs/35867580745) — all 20 jobs green, including `cross-platform (windows-latest, 3.11)`, `cross-platform (windows-latest, 3.12)`, and `toolkit-self-checks`.
- **Test environment:** Windows 11 (10.0.26200), Python 3.14.7, a clean venv built from `requirements/requirements-dev.txt` + `requirements-runtime.txt` + `requirements-integrations.txt` (hash-pinned, same files CI installs from).

## The bug, reproduced before the fix

`agentsec threatmodel render` regenerating the committed example doc, diffed
against the doc actually checked into the repo:

```
$ agentsec threatmodel render examples/support-copilot.system.yaml -o /tmp/tm.md
wrote C:/Users/.../Temp/tm.md
$ diff -u docs/threat-model/EXAMPLE-support-copilot.md /tmp/tm.md
--- docs/threat-model/EXAMPLE-support-copilot.md
+++ /tmp/tm.md
@@ -1,529 +1,529 @@
-# Threat model: Support Copilot
+# Threat model: Support Copilot
...  (all 529 lines shown as changed)
```

`file` on the two copies showed why every line "changed" despite identical
content:

```
$ file docs/threat-model/EXAMPLE-support-copilot.md /tmp/tm.md
docs/threat-model/EXAMPLE-support-copilot.md: ASCII text, with very long lines (490)
/tmp/tm.md:                                   ASCII text, with very long lines (490), with CRLF line terminators
```

`Path.write_text()` (used by `cli.py` and `ToolPins.save`) translates `\n` to
`os.linesep` unless told otherwise, so on Windows every generated report, pin
file, or rendered doc came out CRLF — this is exactly the check the
`toolkit-self-checks` CI job runs, but that job only ran on `ubuntu-latest`,
so it never caught the Windows case.

## The fix, verified after

Same render, same diff, after adding `newline="\n"` to every such write:

```
$ agentsec threatmodel render examples/support-copilot.system.yaml -o /tmp/tm2.md
wrote C:/Users/.../Temp/tm2.md
$ diff -u docs/threat-model/EXAMPLE-support-copilot.md /tmp/tm2.md && echo "MATCHES NOW"
MATCHES NOW
```

## Full local verification, same commands CI runs

```
$ pytest -q --cov=agentsec --cov-report=term-missing --cov-fail-under=90
...
TOTAL                                        2417     69    97%
Required test coverage of 90% reached. Total coverage: 97.15%
322 passed in 13.19s

$ ruff check src tests fuzz scripts
All checks passed!

$ ruff format --check src tests fuzz scripts
56 files already formatted

$ mypy src
Success: no issues found in 30 source files

$ pytest tests/test_integration_mcp.py tests/test_integration_langchain.py -v --no-cov
...
11 passed in 1.14s
```

The `322 passed` run includes both integration suites (real `mcp` and
`langchain-core` SDKs installed, not skipped) and the two regression tests
added in this PR (`test_pins_round_trip_and_reject_malformed_files`,
`test_cli_fuzz_gate_exit_codes`, `test_cli_threatmodel_flow`), which assert
`b"\r" not in <written file>.read_bytes()`.

### `toolkit-self-checks` steps, run directly

```
$ agentsec policy validate --strict examples/policy.yaml
OK: 4 tool(s) defined

$ agentsec fuzz --target builtin:guarded \
    --categories tool_misuse,exfiltration,prompt_leak --max-asr 0 --quiet --json fuzz.json
0/200 attacks succeeded (ASR 0.0%); 200 blocked, 0 errors

$ agentsec fuzz --target builtin:naive --quiet --json naive.json
500/500 attacks succeeded (ASR 100.0%); 0 blocked, 0 errors
$ python -c 'import json; d = json.load(open("naive.json")); assert d["asr"] == 1.0, d["asr"]'
(no output = assertion held)
```

## PR CI, before merge

`gh pr checks 28` showed 23/23 checks passing, including both Windows jobs:

```
cross-platform (windows-latest, 3.11)   pass   59s
cross-platform (windows-latest, 3.12)   pass   1m5s
toolkit-self-checks                     pass   24s
... (20 more, all pass)
```
