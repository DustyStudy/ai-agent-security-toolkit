## agentsec 0.12.0: tests, coverage and simulator fuzz

Commit `51b535c (v0.12.0)` · 2026-11-23 UTC · Python 3.13.18, Linux x86_64 (release session); the 32-check CI matrix is the authoritative run

**Tests: PASS.** 1872 passed, 0 failed, 0 errors, 5 skipped (1877 total, 69.7 s of test time).

**Coverage:** 95.8% of lines.

**Fuzz runs.** ASR is the attack-success rate over scored cases. *Containment* counts successes in tool_misuse, exfiltration and prompt_leak, the outcomes the controls exist to stop; echoing an injected phrase is not one of them.

| Target | Cases | Successes | Containment | Blocked | Errors | ASR |
|---|---:|---:|---:|---:|---:|---:|
| `builtin:guarded` | 500 | 171 | 0 / 200 | 329 | 0 | 34.2% |
| `builtin:guarded --scenarios tool_result` | 250 | 85 | 0 / 100 | 164 | 0 | 34.0% |
| `builtin:naive` | 500 | 500 | 200 / 200 | 0 | 0 | 100.0% |

<details><summary>Tests by file</summary>

| File | Passed | Failed | Skipped |
|---|---:|---:|---:|
| `?` | 0 | 0 | 1 |
| `test_async` | 24 | 0 | 0 |
| `test_audit` | 17 | 0 | 0 |
| `test_audit_redaction_hardening` | 55 | 0 | 0 |
| `test_cef` | 32 | 0 | 0 |
| `test_claude_code_hook` | 24 | 0 | 0 |
| `test_claude_code_hook_fail_closed` | 22 | 0 | 0 |
| `test_claude_code_hook_hardening` | 24 | 0 | 0 |
| `test_cli_exit_codes` | 10 | 0 | 0 |
| `test_configscan` | 113 | 0 | 0 |
| `test_configscan_hardening` | 26 | 0 | 0 |
| `test_examples` | 10 | 0 | 0 |
| `test_formats` | 10 | 0 | 0 |
| `test_fuzz_regressions` | 40 | 0 | 0 |
| `test_fuzz_targets` | 23 | 0 | 0 |
| `test_fuzzer` | 26 | 0 | 0 |
| `test_fuzzer_provider_failures` | 85 | 0 | 0 |
| `test_fuzzer_tool_result` | 8 | 0 | 0 |
| `test_gateway` | 55 | 0 | 0 |
| `test_gateway_bundle` | 34 | 0 | 0 |
| `test_gateway_bypass_regressions` | 396 | 0 | 0 |
| `test_gateway_followups` | 9 | 0 | 0 |
| `test_gateway_holdback` | 43 | 0 | 0 |
| `test_gateway_mcp` | 36 | 0 | 0 |
| `test_gateway_mcp_pins` | 7 | 0 | 0 |
| `test_gateway_mcp_results` | 13 | 0 | 0 |
| `test_gateway_metrics` | 15 | 0 | 0 |
| `test_gateway_offboarding_hardening` | 8 | 0 | 0 |
| `test_gateway_oidc` | 42 | 0 | 0 |
| `test_gateway_oidc_hardening` | 7 | 0 | 0 |
| `test_gateway_origin_host` | 16 | 0 | 0 |
| `test_gateway_outbound` | 23 | 0 | 0 |
| `test_gateway_probe` | 5 | 0 | 0 |
| `test_gateway_request_hardening` | 33 | 0 | 0 |
| `test_gateway_serve` | 7 | 0 | 0 |
| `test_gateway_tokens` | 32 | 0 | 0 |
| `test_gateway_upstream_failures` | 35 | 0 | 0 |
| `test_grafana_examples` | 2 | 0 | 0 |
| `test_hygiene` | 1 | 0 | 0 |
| `test_injection` | 9 | 0 | 0 |
| `test_integration_mcp` | 4 | 0 | 0 |
| `test_locked_install` | 18 | 0 | 0 |
| `test_mcp` | 23 | 0 | 0 |
| `test_openai_compat_target` | 26 | 0 | 0 |
| `test_redact_and_validators` | 17 | 0 | 0 |
| `test_release_authz_secrets` | 61 | 0 | 2 |
| `test_sandbox` | 53 | 0 | 0 |
| `test_sandbox_hardening` | 23 | 0 | 0 |
| `test_security_regressions` | 200 | 0 | 2 |
| `test_taint_adapters_hardening` | 13 | 0 | 0 |
| `test_threatmodel_and_cli` | 24 | 0 | 0 |
| `test_workflowscan` | 29 | 0 | 0 |
| `test_workflowscan_hardening` | 4 | 0 | 0 |

</details>
