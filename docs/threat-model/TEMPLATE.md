# Threat model: <system name>

- **Owner:**
- **Data classification:** public / internal / confidential / regulated
- **Model(s) and versions:**
- **Review date / next review:**
- **Participants:**

## 1. What the agent does

One paragraph: users, tasks, what it can read, what it can change, and what it can send outside.

## 2. Architecture and trust boundaries

Paste a data-flow diagram (Mermaid is fine). Mark:

- every place **untrusted content** enters (user upload, e-mail, web fetch, RAG corpus, tool output, other agents, MCP servers);
- every **side effect** leaving the system (send, write, delete, spend, HTTP egress, rendered links/images);
- each **trust boundary** and what authenticates the crossing.

| ID | Component | Type | Trust zone | Untrusted input? | Side effects? | Credentials / privileges |
|---|---|---|---|---|---|---|
| | | | | | | |

## 3. Lethal-trifecta check

| Question | Answer | Evidence |
|---|---|---|
| Can a session access private / sensitive data? | | |
| Can a session ingest attacker-influenceable content? | | |
| Can a session communicate externally? | | |
| If all three: which leg is removed, or how is taint enforced? | | |

## 4. Threat register

Work through each STRIDE category against every component. Add a row per threat.

| ID | Component | STRIDE | Threat / abuse case | L | I | Existing controls | Planned mitigation | Owner | Decision | Test |
|---|---|---|---|---|---|---|---|---|---|---|
| | | S | | | | | | | mitigate / accept / transfer / n-a | |
| | | T | | | | | | | | |
| | | R | | | | | | | | |
| | | I | | | | | | | | |
| | | D | | | | | | | | |
| | | E | | | | | | | | |

**Prompts per category**

- **S**: Can text from data masquerade as an instruction? Are peer agents / tool servers / tool descriptions authenticated and pinned? Whose identity do tool calls run as?
- **T**: Can retrieval or memory be poisoned? Are tool arguments validated semantically (paths, URLs, SQL)? Is model output ever executed or rendered without encoding? Are model files and prompts integrity-checked?
- **R**: Could you reconstruct prompt, retrieved content, model version, tool calls, approvals and outputs for one incident? Is the log tamper-evident and stored off-host?
- **I**: Can output carry data out (markdown images, links, tool arguments)? Can the system prompt be extracted, and does it contain anything sensitive? Is retrieval authorised per end user? What reaches logs, traces and third-party APIs?
- **D**: What caps steps, tokens, time and spend? Can a tool exhaust CPU, memory, disk or downstream quota? Can approvals be flooded?
- **E**: Does the agent hold more tools or permissions than the task needs? Can an injection reach a privileged tool? What isolates code execution? What secrets can the runtime read?

## 5. Verification

| Control | How verified | Result | Date |
|---|---|---|---|
| Prompt-injection resistance | `agentsec fuzz ... --max-asr <n>` | | |
| Tool policy | `agentsec policy validate --strict` + tests | | |
| Audit integrity | `agentsec audit verify` | | |
| Output validation | | | |

## 6. Residual risk

| Threat | Decision | Rationale | Approver | Date |
|---|---|---|---|---|
| | | | | |
