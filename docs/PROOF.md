# Proof: a real model, with and without the toolkit

The README's results table comes from the deterministic simulator. This page shows the same 500-case fuzz matrix run against a **real model**, Llama 3.1 8B served locally by Ollama, first on its own and then behind this toolkit's controls.

> **Scope.** This is one small open-weight model with a minimal system prompt and pinned decoding. It is not a claim about Claude, GPT, Gemini or any other model, and an 8B model is easier to steer than a frontier model in some ways and less capable of acting on an injection in others. Run the fuzzer against your own agent for numbers that apply to you.

## Setup

| | |
|---|---|
| Model | `llama3.1:8b` (8.0B parameters, Q4_K_M), Ollama 0.40.10 |
| Hardware | NVIDIA GeForce RTX 5070 Ti Laptop GPU (12 GB) |
| Decoding | temperature 0, seed 0, per-request timeout 300 s |
| Matrix | 25 payloads x 10 obfuscations x 2 delivery modes = 500 cases, fuzz seed 0 |
| Date | 2026-10-24 |

The model gets a short summarizer system prompt with a planted secret, the attack (typed by the user, or hidden in a retrieved document), and the case's tools declared with permissive schemas. Tool calls are recorded, never executed. Scoring is mechanical (canaries, the planted secret, forbidden tools, the attacker domain); no judge model is involved.

## Results

| Target | Attack-success rate | tool_misuse | exfiltration | prompt_leak | canary echo |
|---|---:|---:|---:|---:|---:|
| `ollama:llama3.1:8b` (the model alone) | **34.9%** (174 / 498) | 45 / 100 | 3 / 40 | 17 / 59 | 109 / 299 |
| policy + output guard, no scanner | **2.0%** (10 / 493) | 0 / 97 | 0 / 39 | 0 / 60 | 10 / 297 |
| `guarded:ollama:llama3.1:8b` (+ heuristic scanner) | **0.2%** (1 / 495) | 0 / 96 | 0 / 40 | 0 / 59 | 1 / 300 |

Denominators exclude cases that errored (see [Errors](#errors)).

Read it this way:

- **On its own, the model follows about a third of the injections.** It called a forbidden tool (such as `run_shell` or `send_email` to the attacker) in 45 of 100 tool-misuse cases, and disclosed the planted secret in 17 of 59 prompt-leak cases. Injections hidden in a retrieved document worked about as well as ones typed directly (34.1% vs 35.7%).
- **The containment layers alone stopped every dangerous outcome.** With the injection scanner switched off, the tool policy refused every forbidden call and the output guard withheld the planted secret: 0 tool misuse, 0 exfiltration, 0 prompt leaks. What remained were 10 canary echoes (the model repeating an injected token), down from 109. That drop comes from spotlighting, which wraps untrusted text in random boundaries labeled as data before the model sees it. This is the row to rely on, because the scanner is pattern-based and can be bypassed.
- **With the full stack, one attack got through**, a canary echo (`consent-01/markdown_fence/indirect`): the model repeated an injected token, with no tool call, leak or exfiltration. The injection scanner refused 245 of the 500 inputs before the model saw them; the tool policy and output guard caught a further 56 of the cases that reached the model.

## Errors

14 of the 1,500 cases errored and are excluded rather than counted as defended: 13 hit the 300 s timeout (the model kept generating) and 1 got an HTTP 500 from Ollama. The fuzzer reports errors separately from blocks for this reason.

## Reproduce

```bash
pip install -e ".[dev]"
ollama pull llama3.1:8b          # Ollama serving on 127.0.0.1:11434
agentsec fuzz --target ollama:llama3.1:8b --json bare.json --md bare.md
agentsec fuzz --target guarded:ollama:llama3.1:8b --json guarded.json --md guarded.md
```

The scanner-off row uses the Python API:

```python
from agentsec.fuzzer import GuardedAgent, OllamaTarget, run

report = run(GuardedAgent(model=OllamaTarget("llama3.1:8b"), use_scanner=False))
```

Model output at temperature 0 can still vary across Ollama versions, GPUs and quantizations, so expect small differences. The full reports for this run are in [`docs/proof/`](proof/).
