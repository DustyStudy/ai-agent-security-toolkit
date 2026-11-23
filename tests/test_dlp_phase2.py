"""DLP phase 2: MCP tool results, requests sent to model providers, metrics, per-group email keys.

Secret-shaped values are built at run time so no scanner trips on this file.
"""

from __future__ import annotations

import contextlib
import copy
import json
from types import SimpleNamespace

import pytest

from agentsec.gateway import Gateway, load_config
from agentsec.gateway.policyset import group_policy
from agentsec.middleware.audit import MemorySink
from agentsec.middleware.dlp import DlpPolicy
from tests.conftest import fake_aws_key
from tests.test_gateway import FakeUpstream, call, write_config

SSN = "219-09-" + "9999"
EMAIL = "jane.doe" + "@corp-mail.com"
KEY = "k" * 32


def dlp_records(sink, surface=None):
    return [
        r["data"]
        for r in sink.records
        if r["event"] == "dlp_match" and surface in (None, r["data"].get("surface"))
    ]


# ------------------------------------------------------------------- MCP tool results

mcp = pytest.importorskip("mcp")
from mcp import types as t  # noqa: E402

from agentsec.gateway import mcp as gwmcp  # noqa: E402
from tests.test_gateway_mcp import run  # noqa: E402
from tests.test_gateway_mcp import write_config as mcp_config  # noqa: E402


class ToolUpstream:
    def __init__(self, result):
        self.result = result

    async def list_tools(self, **kwargs):
        tool = t.Tool(name="search", description="Search the docs", input_schema={"type": "object"})
        return t.ListToolsResult(tools=[tool])

    async def call_tool(self, name, arguments, **kwargs):
        return self.result


def tool_result(tmp_path, text, dlp=None, mode="enforce"):
    """Call docs__search through the MCP handlers; returns (what the client got, sink)."""
    cfg = mcp_config(tmp_path)
    sink = MemorySink()

    @contextlib.asynccontextmanager
    async def connect(upstream, timeout, max_bytes):
        yield ToolUpstream(t.CallToolResult(content=[t.TextContent(type="text", text=text)]))

    gw = gwmcp.McpGateway(cfg, gwmcp.AuditLogger(sink), gwmcp.InjectionScanner(), connector=connect)
    base = cfg.policies.groups[0]
    gp = group_policy("*", base.policy, mode=mode, mcp=None, dlp=dlp or DlpPolicy())
    caller = gwmcp.Caller("alice", ("eng",), cfg.policies, gp, "req")
    ctx = SimpleNamespace(request=SimpleNamespace(scope={gwmcp.SCOPE_KEY: caller, "headers": []}))

    async def main():
        await gw._list_tools(ctx, None)
        return await gw._call_tool(ctx, SimpleNamespace(name="docs__search", arguments={"q": "x"}))

    return run(main()), sink


def text(result):
    return "".join(b.text for b in result.content if hasattr(b, "text"))


def test_tool_results_redact_secrets_and_record_pii_by_default(tmp_path):
    key = fake_aws_key()
    out, sink = tool_result(tmp_path, f"key {key}, ssn {SSN}")
    assert not out.is_error
    assert key not in text(out) and "[REDACTED:aws_access_key_id]" in text(out)
    assert SSN in text(out)  # PII in results is only recorded by default
    found = {(d["kind"], d["action"], d["tool"]) for d in dlp_records(sink, "tool_results")}
    assert found == {
        ("aws_access_key_id", "redact", "docs__search"),
        ("us_ssn", "monitor", "docs__search"),
    }
    assert key not in json.dumps(sink.records) and SSN not in json.dumps(sink.records)


def test_tool_results_can_block_pii(tmp_path):
    policy = DlpPolicy.from_dict({"categories": {"pii": {"tool_results": "block"}}})
    out, sink = tool_result(tmp_path, f"ssn {SSN}", policy)
    assert out.is_error and "withheld" in text(out)
    (rec,) = [r["data"] for r in sink.records if r["event"] == "gateway_mcp_result"]
    assert rec["withheld"] and "output policy" in rec["reasons"]
    assert SSN not in json.dumps(sink.records)


def test_tool_results_in_monitor_mode_are_delivered_and_recorded(tmp_path):
    policy = DlpPolicy.from_dict({"categories": {"pii": {"tool_results": "block"}}})
    out, sink = tool_result(tmp_path, f"ssn {SSN}", policy, mode="monitor")
    assert not out.is_error and SSN in text(out)
    assert [d["enforced"] for d in dlp_records(sink, "tool_results")] == [False]


def test_a_result_with_only_monitored_findings_is_not_withheld(tmp_path):
    # Regression: a monitored email used to count as "could not be fully redacted".
    out, _ = tool_result(tmp_path, f"contact {EMAIL}")
    assert not out.is_error and EMAIL in text(out)


# ------------------------------------------------------------- requests to providers


def app_with(tmp_path, extra="", outbound=None):
    write_config(tmp_path, extra)
    path = tmp_path / "gateway.yaml"
    if outbound:
        text_ = path.read_text().replace(
            "model: llama3.1:8b", f"model: llama3.1:8b\n    outbound: {outbound}"
        )
        path.write_text(text_)
    up, sink = FakeUpstream(), MemorySink()
    return Gateway(load_config(path), transport=up, sink=sink), up, sink


def chat_with(content):
    return {"model": "local", "messages": [{"role": "user", "content": content}]}


def test_provider_requests_are_recorded_by_default_and_sent_unchanged(tmp_path):
    app, up, sink = app_with(tmp_path)
    status, _ = call(app, body=chat_with(f"my ssn is {SSN}"))
    assert status == 200 and SSN in json.dumps(up.requests)
    (rec,) = dlp_records(sink, "upstream")
    assert rec["kind"] == "us_ssn" and rec["action"] == "monitor"
    assert rec["location"] == "request.messages[0].content" and rec["upstream"] == "local"
    assert SSN not in json.dumps(sink.records)


def test_group_dlp_can_redact_pii_before_the_provider(tmp_path):
    extra = "dlp: {categories: {pii: {upstream: redact}}}\n"
    app, up, sink = app_with(tmp_path, extra)
    status, _ = call(app, body=chat_with(f"my ssn is {SSN}"))
    assert status == 200
    assert SSN not in json.dumps(up.requests)
    assert "[REDACTED:us_ssn]" in json.dumps(up.requests)
    assert "gateway_outbound_redacted" in [r["event"] for r in sink.records]


def test_on_pii_overrides_the_group_for_one_upstream(tmp_path):
    app, up, sink = app_with(tmp_path, outbound="{on_pii: block}")
    status, _ = call(app, body=chat_with(f"write to {EMAIL}"))
    assert status == 400 and up.requests == []
    blocked = [r["data"] for r in sink.records if r["event"] == "gateway_outbound_blocked"]
    assert blocked[0]["kinds"] == ["email"]
    assert EMAIL not in json.dumps(sink.records)


def test_on_pii_is_validated(tmp_path):
    from agentsec.gateway import ConfigError

    with pytest.raises(ConfigError, match="on_pii"):
        app_with(tmp_path, outbound="{on_pii: maybe}")


def test_a_secret_to_the_provider_is_recorded_even_with_on_secret_off(tmp_path):
    secret = fake_aws_key()
    app, up, sink = app_with(tmp_path)
    status, _ = call(app, body=chat_with(f"key {secret}"))
    assert status == 200  # default: monitor, so the request still goes
    assert [d["kind"] for d in dlp_records(sink, "upstream")] == ["aws_access_key_id"]
    assert secret not in json.dumps(sink.records)


# --------------------------------------------------------------------------- metrics


def test_dlp_matches_are_counted_in_metrics(tmp_path):
    app, _, _ = app_with(tmp_path)
    call(app, body=chat_with(f"my ssn is {SSN}"))
    text_ = app.metrics.render(app._policies)
    assert (
        'agentsec_gateway_dlp_matches_total{category="pii",surface="upstream",action="monitor"} 1'
        in text_
    )
    assert SSN not in text_


def test_metrics_ignore_labels_outside_the_fixed_sets():
    from agentsec.gateway.metrics import Metrics

    m = Metrics()
    m.dlp({"category": "pii", "surface": 'x"} 1\nevil', "action": "block"})
    m.dlp("not a dict")
    assert m.snapshot()["dlp"] == {}


# ------------------------------------------------------------ per-group email keys


def test_each_request_hashes_addresses_with_its_groups_key(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_FP_KEY", KEY)
    extra = "dlp: {fingerprint_key: env:DLP_FP_KEY}\n"
    message = {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "c",
                "type": "function",
                "function": {"name": "search", "arguments": json.dumps({"q": EMAIL})},
            }
        ],
    }
    write_config(tmp_path, extra)
    sink = MemorySink()
    app = Gateway(
        load_config(tmp_path / "gateway.yaml"), transport=FakeUpstream(message), sink=sink
    )
    from tests.test_gateway import tool

    body = {
        "model": "local",
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [tool("search")],
    }
    call(app, body=copy.deepcopy(body))
    request = next(r for r in sink.records if r["event"] == "tool_request")
    fingerprint = (
        DlpPolicy(fingerprint_key=KEY.encode()).scan(EMAIL, "output").matches[0].fingerprint
    )
    assert request["data"]["arguments"]["q"] == f"[EMAIL:{fingerprint}]"
    assert EMAIL not in json.dumps(sink.records)


def test_records_outside_a_group_mark_addresses_without_a_key(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_FP_KEY", KEY)
    app, _, _ = app_with(tmp_path, "dlp: {fingerprint_key: env:DLP_FP_KEY}\n")
    assert app._audit.email_key is None  # the shared logger: no group, so no key
