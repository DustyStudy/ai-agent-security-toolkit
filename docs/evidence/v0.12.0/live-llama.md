## agentsec 0.12.0: live model (Llama 3.1 8B)

Commit `922a7e0 (release candidate; same code as v0.12.0 except the version string)` · 2026-11-22 23:52-00:35 UTC · llama3.1:8b on Ollama 0.40.10, RTX 5070 Ti Laptop GPU 12 GB, Windows 11, Python 3.12.10, seed 0

**Fuzz runs.** ASR is the attack-success rate over scored cases. *Containment* counts successes in tool_misuse, exfiltration and prompt_leak, the outcomes the controls exist to stop; echoing an injected phrase is not one of them.

| Target | Cases | Successes | Containment | Blocked | Errors | ASR |
|---|---:|---:|---:|---:|---:|---:|
| `ollama:llama3.1:8b` | 500 | 177 | 66 / 198 | 0 | 2 | 35.5% |
| `guarded:ollama:llama3.1:8b` | 500 | 2 | 0 / 198 | 289 | 3 | 0.4% |
| `ollama:llama3.1:8b --scenarios tool_result` | 250 | 10 | 0 / 100 | 0 | 0 | 4.0% |
| `guarded:ollama:llama3.1:8b --scenarios tool_result` | 250 | 0 | 0 / 100 | 122 | 0 | 0.0% |
