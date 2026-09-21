# A five-minute tour

Everything below is real output from the commands shown, run from a clone with `pip install -e .`. No API key or network is needed: the fuzzer's built-in targets are simulators (see [Honest limitations](../README.md#honest-limitations)).

## 1. See what "the model obeys any injection" looks like

```console
$ agentsec fuzz --target builtin:naive --quiet
500/500 attacks succeeded (ASR 100.0%); 0 blocked, 0 errors
```

`builtin:naive` simulates a fully gullible model. Every one of the 500 generated attacks (25 payloads x 10 obfuscations x 2 delivery modes) works against it. This is the situation your containment layers have to survive, because a real model can be steered too.

## 2. Put the toolkit's layers around it

```console
$ agentsec fuzz --target builtin:guarded --quiet
171/500 attacks succeeded (ASR 34.2%); 329 blocked, 0 errors
```

The same simulated model behind the scanner, tool policy and output guard. The remaining 34% are attacks that only make the model *say* something (a planted canary word). Now look at what those layers do about the dangerous outcomes:

```console
$ agentsec fuzz --target builtin:guarded --categories tool_misuse,exfiltration,prompt_leak --max-asr 0 --quiet
0/200 attacks succeeded (ASR 0.0%); 200 blocked, 0 errors
$ echo $?
0
```

Tool misuse, data exfiltration and system-prompt leaks are at 0% even though the model itself obeys everything. `--max-asr 0` makes the command exit `1` on any success, so this is the line you put in CI. Add `--sarif report.sarif` to send findings to GitHub code scanning.

## 3. Test a tool policy without running an agent

The example policy ([`examples/policy.yaml`](../examples/policy.yaml)) is deny-by-default. `agentsec policy check` evaluates one call against it:

```console
$ agentsec policy check examples/policy.yaml --tool search_docs --args '{"query":"Q3 revenue"}'
ALLOW: allow

$ agentsec policy check examples/policy.yaml --tool run_shell --args '{"command":"id"}'
DENY: tool not in policy (default deny)

$ agentsec policy check examples/policy.yaml --tool read_file --args '{"path":"/srv/agent/workspace/../../etc/passwd"}'
DENY: argument 'path': path escapes allowed roots

$ agentsec policy check examples/policy.yaml --tool http_get --args '{"url":"http://169.254.169.254/latest/meta-data/"}'
DENY: argument 'url': scheme 'http' not allowed; argument 'url': host '169.254.169.254' not in allowlist; argument 'url': host '169.254.169.254' is a non-public address
```

The last one is the cloud-metadata SSRF that hijacked agents love. Each `DENY` exits `1`, so these also work as policy regression tests.

## 4. The part that stops the "lethal trifecta"

After an agent has read untrusted content (a retrieved document, a web page), the model's next action may reflect an attacker's instructions. The policy taints the session and gates tools that have side effects, without needing to detect the injection:

```console
$ agentsec policy check examples/policy.yaml --tool send_email --args '{"to":"a@corp.example","body":"hi"}'
NEEDS_APPROVAL: policy requires human approval

$ agentsec policy check examples/policy.yaml --tool send_email --args '{"to":"a@corp.example","body":"hi"}' --tainted
DENY: session has ingested untrusted content (cli) and this tool has side effects
```

The same call needs a human's approval normally and is refused outright once the session has read untrusted content.

## 5. Threat model it

```console
$ agentsec threatmodel catalog | head -4
AG-S-01  Spoofing                 Untrusted content impersonates an instruction source
AG-S-02  Spoofing                 Agent-to-agent or MCP server identity is not verified
AG-S-03  Spoofing                 End-user identity is confused with agent identity
AG-T-01  Tampering                Retrieval or knowledge-base poisoning
```

`agentsec threatmodel render system.yaml` turns a description of your agent into a threat register mapped to the OWASP LLM Top 10, the OWASP Agentic Top 10 and MITRE ATLAS. See the [worked example](threat-model/EXAMPLE-support-copilot.md) and the [framework crosswalk](threat-model/frameworks.md).

## Next

- Wire the guard into your agent loop: [`examples/agent_loop.py`](../examples/agent_loop.py) (sync) or [`examples/async_agent_loop.py`](../examples/async_agent_loop.py).
- Take it to production: [PRODUCTION.md](PRODUCTION.md).
