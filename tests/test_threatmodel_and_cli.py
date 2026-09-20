from __future__ import annotations

import json

import pytest
import yaml

from agentsec.cli import main
from agentsec.middleware import AuditLogger, FileSink
from agentsec.threatmodel import (
    COMPONENT_TYPES,
    SYSTEM_TEMPLATE,
    SystemSpecError,
    load_catalog,
    render_markdown,
    validate_system,
)
from agentsec.threatmodel.render import STRIDE_ORDER

# ----------------------------------------------------------------- threat model


def test_catalog_is_well_formed_and_covers_all_stride_categories():
    catalog = load_catalog()
    ids = [t.id for t in catalog]
    assert len(ids) == len(set(ids))
    assert {t.stride for t in catalog} == set(STRIDE_ORDER)
    for t in catalog:
        assert t.mitigations and t.description and t.owasp_llm
        assert all(c in COMPONENT_TYPES for c in t.applies_to)
        assert t.id.startswith("AG-" + t.stride[0])


def test_catalog_toolkit_references_resolve():
    import importlib

    for t in load_catalog():
        for ref in t.toolkit:
            parts = ref.split(".")
            for i in range(len(parts), 1, -1):
                try:
                    obj = importlib.import_module(".".join(parts[:i]))
                except ImportError:
                    continue
                for attr in parts[i:]:
                    obj = getattr(obj, attr)
                break
            else:
                pytest.fail(f"{t.id}: cannot resolve {ref}")


def test_every_fuzz_category_in_catalog_exists_in_corpus():
    from agentsec.fuzzer import CORPUS

    known = {p.category for p in CORPUS}
    for t in load_catalog():
        assert set(t.fuzz) <= known, t.id


def test_template_renders_and_selects_threats_by_component_type():
    spec = validate_system(yaml.safe_load(SYSTEM_TEMPLATE))
    doc = render_markdown(spec)
    assert doc.startswith("# Threat model: My Agent")
    assert "```mermaid" in doc and "AG-S-01" in doc and "AG-E-02" in doc
    assert "-.->" in doc  # trust boundary crossing
    # no memory component -> memory-only threat must not appear in the register
    assert "AG-T-02" not in doc.split("## 4.")[0]


def test_priority_hint_rises_with_untrusted_input_and_side_effects():
    spec = validate_system(yaml.safe_load(SYSTEM_TEMPLATE))
    doc = render_markdown(spec)
    row = next(line for line in doc.splitlines() if line.startswith("| AG-E-02 | mail"))
    assert "| High |" in row


@pytest.mark.parametrize(
    "bad,msg",
    [
        ({}, "missing required key"),
        ({"name": "x", "components": [{"id": "a", "type": "wizard", "name": "A"}]}, "unknown type"),
        ({"name": "x", "components": [{"id": "a", "name": "A"}]}, "missing 'type'"),
        (
            {"name": "x", "components": [{"id": "a", "type": "llm", "name": "A"}] * 2},
            "duplicate",
        ),
        ({"name": "x", "components": [{"id": "a b", "type": "llm", "name": "A"}]}, "alphanumeric"),
        (
            {
                "name": "x",
                "components": [{"id": "a", "type": "llm", "name": "A"}],
                "data_flows": [{"from": "a", "to": "ghost"}],
            },
            "unknown component",
        ),
    ],
)
def test_invalid_system_descriptions_rejected(bad, msg):
    with pytest.raises(SystemSpecError, match=msg):
        validate_system(bad)


# -------------------------------------------------------------------------- CLI


def test_cli_fuzz_gate_exit_codes(capsys, tmp_path):
    out_json, out_md = tmp_path / "r.json", tmp_path / "r.md"
    assert (
        main(
            [
                "fuzz",
                "--target",
                "builtin:naive",
                "--max-cases",
                "20",
                "--quiet",
                "--json",
                str(out_json),
                "--md",
                str(out_md),
                "--max-asr",
                "0.5",
            ]
        )
        == 1
    )
    assert json.loads(out_json.read_text())["total"] == 20 and out_md.read_text().startswith("#")
    assert (
        main(
            [
                "fuzz",
                "--target",
                "builtin:guarded",
                "--categories",
                "tool_misuse",
                "--quiet",
                "--max-asr",
                "0",
            ]
        )
        == 0
    )
    assert main(["fuzz", "--target", "nonsense"]) == 2
    assert "attacks succeeded" in capsys.readouterr().out


def test_cli_fuzz_list(capsys):
    assert main(["fuzz", "--list"]) == 0
    assert "selected: 500 cases" in capsys.readouterr().out


def test_cli_policy_validate_and_check(tmp_path, capsys):
    f = tmp_path / "policy.yaml"
    f.write_text(
        "tools:\n"
        "  http_get:\n"
        "    side_effects: true\n"
        "    args:\n"
        "      url: {type: url, hosts: [api.example.com]}\n"
    )
    assert main(["policy", "validate", str(f)]) == 0
    assert (
        main(
            [
                "policy",
                "check",
                str(f),
                "--tool",
                "http_get",
                "--args",
                '{"url": "https://api.example.com/x"}',
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "policy",
                "check",
                str(f),
                "--tool",
                "http_get",
                "--args",
                '{"url": "https://evil.example/x"}',
            ]
        )
        == 1
    )
    assert (
        main(
            [
                "policy",
                "check",
                str(f),
                "--tool",
                "http_get",
                "--tainted",
                "--args",
                '{"url": "https://api.example.com/x"}',
            ]
        )
        == 1
    )
    assert main(["policy", "check", str(f), "--tool", "x", "--args", "{bad"]) == 2
    bad = tmp_path / "bad.yaml"
    bad.write_text("tools: {t: {typo: 1}}\n")
    assert main(["policy", "validate", str(bad)]) == 2
    assert "DENY" in capsys.readouterr().out


def test_cli_policy_validate_strict_fails_on_lint(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("tools:\n  fetch:\n    side_effects: true\n    args:\n      url: {type: url}\n")
    assert main(["policy", "validate", str(f)]) == 0
    assert main(["policy", "validate", str(f), "--strict"]) == 1


def test_cli_audit_verify(tmp_path):
    path = tmp_path / "a.jsonl"
    log = AuditLogger(FileSink(path))
    log.log("a", v=1)
    log.log("b", v=2)
    assert main(["audit", "verify", str(path)]) == 0
    path.write_text(path.read_text().replace('"v":1', '"v":9'))
    assert main(["audit", "verify", str(path)]) == 1
    assert main(["audit", "verify", str(tmp_path / "missing.jsonl")]) == 2


def test_cli_threatmodel_flow(tmp_path, capsys):
    spec, doc = tmp_path / "system.yaml", tmp_path / "TM.md"
    assert main(["threatmodel", "init", "-o", str(spec)]) == 0
    assert main(["threatmodel", "render", str(spec), "-o", str(doc)]) == 0
    assert "## 3. Threat register" in doc.read_text()
    assert main(["threatmodel", "catalog"]) == 0
    assert "AG-E-02" in capsys.readouterr().out
    spec.write_text("name: x\ncomponents: [{id: a, type: nope, name: A}]\n")
    assert main(["threatmodel", "render", str(spec)]) == 2
