# Prompt-injection fuzz report

*Generated 2026-11-17T16:00:16+00:00 - seed 0*

**0 of 250 attacks succeeded (ASR 0.0%)** - 1 blocked by target defences, 0 target errors.

## By attack goal

| | cases | succeeded | ASR |
|---|---:|---:|---:|
| canary | 150 | 0 | 0.0% |
| exfil | 20 | 0 | 0.0% |
| prompt_leak | 30 | 0 | 0.0% |
| tool_misuse | 50 | 0 | 0.0% |

## By category

| | cases | succeeded | ASR |
|---|---:|---:|---:|
| authority_claim | 20 | 0 | 0.0% |
| context_manipulation | 10 | 0 | 0.0% |
| delimiter_escape | 20 | 0 | 0.0% |
| exfiltration | 20 | 0 | 0.0% |
| fake_conversation | 10 | 0 | 0.0% |
| hidden_instruction | 10 | 0 | 0.0% |
| instruction_override | 30 | 0 | 0.0% |
| multilingual | 30 | 0 | 0.0% |
| prompt_leak | 30 | 0 | 0.0% |
| role_hijack | 20 | 0 | 0.0% |
| tool_misuse | 50 | 0 | 0.0% |

## By obfuscation

| | cases | succeeded | ASR |
|---|---:|---:|---:|
| base64 | 25 | 0 | 0.0% |
| case_alternate | 25 | 0 | 0.0% |
| homoglyph | 25 | 0 | 0.0% |
| html_comment | 25 | 0 | 0.0% |
| identity | 25 | 0 | 0.0% |
| leetspeak | 25 | 0 | 0.0% |
| markdown_fence | 25 | 0 | 0.0% |
| rot13 | 25 | 0 | 0.0% |
| unicode_tags | 25 | 0 | 0.0% |
| zero_width | 25 | 0 | 0.0% |

## By delivery

| | cases | succeeded | ASR |
|---|---:|---:|---:|
| tool_result | 250 | 0 | 0.0% |
