"""The example dashboard and alert rules use only metrics and events the gateway emits."""

from __future__ import annotations

import dataclasses
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

import agentsec.gateway
from tests.test_gateway import gateway
from tests.test_gateway_metrics import admin

GRAFANA = Path(__file__).parent.parent / "examples" / "grafana"


def dashboard_exprs() -> list[str]:
    dashboard = json.loads((GRAFANA / "agentsec-gateway.json").read_text(encoding="utf-8"))
    assert all(p["datasource"]["uid"] == "${datasource}" for p in dashboard["panels"])
    return [t["expr"] for p in dashboard["panels"] for t in p["targets"]]


def alert_exprs() -> list[str]:
    rules = yaml.safe_load((GRAFANA / "alerts.yaml").read_text(encoding="utf-8"))
    return [r["expr"] for g in rules["groups"] for r in g["rules"]]


@pytest.mark.parametrize("exprs", [dashboard_exprs, alert_exprs])
def test_examples_reference_only_what_the_gateway_emits(tmp_path, exprs):
    app, _ = gateway(tmp_path)
    app._policies = dataclasses.replace(app._policies, expires=datetime.now(UTC))  # optional gauge
    emitted = set(re.findall(r"^# TYPE (\S+)", admin(app, "/metrics")[1], re.M))
    source = "".join(
        p.read_text(encoding="utf-8") for p in Path(agentsec.gateway.__file__).parent.glob("*.py")
    )
    audited = set(re.findall(r'\.log\(\s*"(\w+)"', source))  # first argument of each audit call
    text = "\n".join(exprs())
    events = {e for m in re.findall(r'event=~?"([^"]*)"', text) for e in m.split("|")}
    # What is left once selectors, ranges and groupings are gone is metric names and PromQL words.
    bare = re.sub(r"\{[^}]*\}|\[[^\]]*\]|by \([^)]*\)", "", text)
    names = set(re.findall(r"(?<![\w$])[a-zA-Z_]\w*", bare))
    promql = {"sum", "min", "max", "rate", "increase", "absent", "time", "vector"}
    promql |= {"group", "and", "or", "unless", "offset"}
    assert events and events <= audited
    assert names - promql and names - promql <= emitted
