"""Generate a STRIDE-for-agents threat model document from a system description."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

COMPONENT_TYPES = (
    "user_interface",
    "orchestrator",
    "llm",
    "tool",
    "retrieval_store",
    "memory",
    "external_agent",
    "code_executor",
    "secrets_store",
    "model_artifact",
)
STRIDE_ORDER = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information disclosure",
    "Denial of service",
    "Elevation of privilege",
)


class SystemSpecError(ValueError):
    pass


@dataclass
class Threat:
    id: str
    stride: str
    title: str
    applies_to: list[str]
    description: str
    example: str
    owasp_llm: list[str]
    mitigations: list[str]
    owasp_agentic: list[str] = field(default_factory=list)
    mitre_atlas: list[str] = field(default_factory=list)
    toolkit: list[str] = field(default_factory=list)
    fuzz: list[str] = field(default_factory=list)


@lru_cache(maxsize=1)
def load_frameworks() -> dict[str, Any]:
    """Names and sources for the external framework ids used by the catalog."""
    text = (
        resources.files("agentsec.threatmodel")
        .joinpath("data/frameworks.yaml")
        .read_text(encoding="utf-8")
    )
    return yaml.safe_load(text)


def load_catalog(path: str | Path | None = None) -> list[Threat]:
    if path is None:
        text = (
            resources.files("agentsec.threatmodel")
            .joinpath("data/threats.yaml")
            .read_text(encoding="utf-8")
        )
    else:
        text = Path(path).read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    threats = [Threat(**t) for t in raw["threats"]]
    for t in threats:
        if t.stride not in STRIDE_ORDER:
            raise SystemSpecError(f"{t.id}: unknown STRIDE category {t.stride!r}")
        bad = [c for c in t.applies_to if c not in COMPONENT_TYPES]
        if bad:
            raise SystemSpecError(f"{t.id}: unknown component type(s) {bad}")
        frameworks = load_frameworks()
        for key, ids in (("owasp_agentic", t.owasp_agentic), ("mitre_atlas", t.mitre_atlas)):
            unknown = [i for i in ids if i not in frameworks[key]["items"]]
            if unknown:
                raise SystemSpecError(f"{t.id}: unknown {key} id(s) {unknown}")
    return threats


def load_system(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as fh:
        spec = yaml.safe_load(fh)
    return validate_system(spec)


def validate_system(spec: Any) -> dict[str, Any]:
    if not isinstance(spec, dict):
        raise SystemSpecError("system description must be a mapping")
    for key in ("name", "components"):
        if key not in spec:
            raise SystemSpecError(f"missing required key {key!r}")
    ids: set[str] = set()
    for comp in spec["components"]:
        for key in ("id", "type", "name"):
            if key not in comp:
                raise SystemSpecError(f"component missing {key!r}: {comp}")
        if comp["type"] not in COMPONENT_TYPES:
            raise SystemSpecError(
                f"component {comp['id']!r}: unknown type {comp['type']!r}; "
                f"choose from {list(COMPONENT_TYPES)}"
            )
        if comp["id"] in ids:
            raise SystemSpecError(f"duplicate component id {comp['id']!r}")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", comp["id"]):
            raise SystemSpecError(f"component id {comp['id']!r} must be alphanumeric/underscore")
        ids.add(comp["id"])
    for flow in spec.get("data_flows", []):
        for end in ("from", "to"):
            if flow.get(end) not in ids:
                raise SystemSpecError(f"data flow references unknown component {flow.get(end)!r}")
    return spec


def _framework_lines(t: Threat) -> list[str]:
    """Optional lines naming the OWASP Agentic and MITRE ATLAS entries a threat maps to."""
    items = load_frameworks()
    lines: list[str] = []
    for label, key, ids in (
        ("OWASP Agentic Applications Top 10 (2026)", "owasp_agentic", t.owasp_agentic),
        ("MITRE ATLAS", "mitre_atlas", t.mitre_atlas),
    ):
        if ids:
            named = "; ".join(f"{i} {items[key]['items'][i]}" for i in ids)
            lines += [f"*{label}: {_esc(named)}*", ""]
    return lines


def _priority(comp: dict[str, Any], threat: Threat) -> str:
    """Rough triage hint: a starting point for the team's own likelihood/impact rating."""
    score = 0
    if comp.get("ingests_untrusted"):
        score += 1
    if comp.get("side_effects"):
        score += 1
    if comp.get("holds_sensitive_data") or comp.get("privileges"):
        score += 1
    if threat.stride in {"Elevation of privilege", "Information disclosure"}:
        score += 1
    return "High" if score >= 3 else "Medium" if score == 2 else "Low"


def _esc(text: str) -> str:
    """Make spec/catalog text safe to place in one inline markdown or table-cell position.

    The system description is an input file (often from a repo or a pull request) and the
    result is published as a document, so it must not be able to end a cell, start a heading
    or row, or smuggle in raw HTML.
    """
    return (
        text.replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .strip()
    )


def _mm(text: str) -> str:
    """Escape text for a double-quoted mermaid label: a bare quote would end the label."""
    return _esc(text).replace('"', "#quot;")


def _mermaid(spec: dict[str, Any]) -> str:
    lines = ["```mermaid", "flowchart LR"]
    zones: dict[str, list[dict[str, Any]]] = {}
    for c in spec["components"]:
        zones.setdefault(c.get("trust_zone", "default"), []).append(c)
    for zone, comps in zones.items():
        lines.append(
            f'  subgraph zone_{re.sub(r"[^A-Za-z0-9]", "_", str(zone))}["{_mm(str(zone))}"]'
        )
        for c in comps:
            lines.append(f'    {c["id"]}["{_mm(str(c["name"]))}<br/><i>{c["type"]}</i>"]')
        lines.append("  end")
    zone_of = {c["id"]: c.get("trust_zone", "default") for c in spec["components"]}
    for f in spec.get("data_flows", []):
        arrow = "-.->" if zone_of[f["from"]] != zone_of[f["to"]] else "-->"
        label = _mm(str(f.get("data", "")))
        lines.append(f'  {f["from"]} {arrow}|"{label}"| {f["to"]}')
    lines.append("```")
    return "\n".join(lines)


def render_markdown(spec: dict[str, Any], catalog: list[Threat] | None = None) -> str:
    catalog = catalog if catalog is not None else load_catalog()
    comps = spec["components"]
    lines = [f"# Threat model: {_esc(str(spec['name']))}", ""]
    if spec.get("description"):
        # Multi-line markdown is intended here, so keep newlines but never raw HTML.
        lines += [str(spec["description"]).strip().replace("<", "&lt;"), ""]
    meta = [
        ("Owner", spec.get("owner")),
        ("Data classification", spec.get("data_classification")),
        ("Model(s)", spec.get("models")),
        ("Review date", spec.get("review_date")),
    ]
    lines += [
        f"- **{k}:** {_esc(', '.join(map(str, v)) if isinstance(v, list) else str(v))}"
        for k, v in meta
        if v
    ]
    lines += [
        "",
        "> Generated by `agentsec threatmodel render`. Threats below are *candidates* from the",
        "> STRIDE-for-agents catalog. Confirm or dismiss each one, set likelihood and impact,",
        "> and record the decision. The priority column is a triage hint only.",
        "",
    ]

    lines += [
        "## 1. Architecture",
        "",
        _mermaid(spec),
        "",
        "Dashed arrows cross a trust boundary.",
        "",
    ]

    lines += [
        "## 2. Components",
        "",
        "| ID | Name | Type | Trust zone | Untrusted input | Side effects | Notes |",
        "|---|---|---|---|---|---|---|",
    ]
    for c in comps:
        lines.append(
            f"| {c['id']} | {_esc(str(c['name']))} | {c['type']} | {_esc(str(c.get('trust_zone', 'default')))} | "
            f"{'yes' if c.get('ingests_untrusted') else 'no'} | "
            f"{'yes' if c.get('side_effects') else 'no'} | {_esc(str(c.get('notes', c.get('privileges', ''))))} |"
        )
    lines.append("")

    rows: list[tuple[dict[str, Any], Threat]] = []
    for c in comps:
        for t in catalog:
            if c["type"] in t.applies_to:
                rows.append((c, t))

    lines += [
        "## 3. Threat register",
        "",
        "| Threat | Component | STRIDE | Threat | Priority hint | Suggested mitigations | Toolkit control | Status | Owner | L | I |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    order = {s: i for i, s in enumerate(STRIDE_ORDER)}
    for c, t in sorted(rows, key=lambda r: (order[r[1].stride], r[1].id, r[0]["id"])):
        lines.append(
            f"| {t.id} | {c['id']} | {t.stride} | {_esc(t.title)} | {_priority(c, t)} | "
            f"{_esc('; '.join(t.mitigations))} | {_esc(', '.join(t.toolkit) or '-')} | Open | | | |"
        )
    lines.append("")

    lines += ["## 4. Threat details", ""]
    seen: set[str] = set()
    for _, t in sorted(rows, key=lambda r: (order[r[1].stride], r[1].id)):
        if t.id in seen:
            continue
        seen.add(t.id)
        lines += [
            f"### {t.id} - {t.title}",
            "",
            f"*{t.stride}. OWASP LLM Top 10 (2025): {', '.join(t.owasp_llm) or 'n/a'}*",
            "",
            *_framework_lines(t),
            t.description.strip(),
            "",
            f"**Example:** {t.example.strip()}",
            "",
            "**Mitigations:**",
            *[f"- {m}" for m in t.mitigations],
            "",
        ]

    flows = spec.get("data_flows", [])
    crossing = [
        f
        for f in flows
        if {c["id"]: c.get("trust_zone", "default") for c in comps}[f["from"]]
        != {c["id"]: c.get("trust_zone", "default") for c in comps}[f["to"]]
    ]
    lines += ["## 5. Trust-boundary crossings", ""]
    if crossing:
        lines += ["| From | To | Data | Review focus |", "|---|---|---|---|"]
        for f in crossing:
            lines.append(
                f"| {f['from']} | {f['to']} | {_esc(str(f.get('data', '')))} | "
                "Authenticate, validate, log; treat inbound content as untrusted |"
            )
    else:
        lines.append("No boundary-crossing flows declared. Check that `trust_zone` values are set.")
    lines.append("")

    fuzz_cats = sorted({cat for _, t in rows for cat in t.fuzz})
    lines += [
        "## 6. Verification plan",
        "",
        "Run the fuzzer against the deployed agent and gate releases on attack-success rate:",
        "",
        "```bash",
        "agentsec fuzz --target <your-target> --max-asr 0.05 --json fuzz.json --md fuzz.md",
        "```",
        "",
    ]
    if fuzz_cats:
        lines += [
            "Categories relevant to this system: " + ", ".join(f"`{c}`" for c in fuzz_cats),
            "",
        ]
    lines += [
        "## 7. Residual risk and decisions",
        "",
        "| Threat | Decision (mitigate / accept / transfer) | Rationale | Approver | Date |",
        "|---|---|---|---|---|",
        "| | | | | |",
        "",
    ]
    return "\n".join(lines)


SYSTEM_TEMPLATE = """\
# Describe your agent system. Fields marked (optional) can be dropped.
name: My Agent
description: >
  One paragraph: what the agent does, for whom, and what it can touch.
owner: team-or-person          # (optional)
data_classification: internal  # (optional) public | internal | confidential | regulated
models: [model-name]           # (optional)
review_date: 2026-01-01        # (optional)

components:
  - {id: ui,   name: Chat UI,          type: user_interface, trust_zone: internet}
  - {id: orch, name: Agent runtime,    type: orchestrator,   trust_zone: app}
  - {id: llm,  name: Model API,        type: llm,            trust_zone: vendor}
  - id: kb
    name: Knowledge base
    type: retrieval_store
    trust_zone: app
    ingests_untrusted: true      # anything an outsider can write into
  - id: mail
    name: E-mail tool
    type: tool
    trust_zone: app
    side_effects: true           # sends, writes, deletes, spends, or egresses data
    privileges: send mail as the user

data_flows:
  - {from: ui,   to: orch, data: user prompt}
  - {from: orch, to: llm,  data: prompt + context}
  - {from: kb,   to: orch, data: retrieved chunks}
  - {from: orch, to: mail, data: message body}
"""
