"""Per-upstream outbound policy: secrets never reach the model upstream (block or redact)."""

from __future__ import annotations

import copy
import json

import pytest

from agentsec.gateway import ConfigError, Gateway, load_config
from agentsec.middleware.audit import MemorySink

from .test_gateway import FakeUpstream, call, write_config

SECRET = "AKIA" + "ABCDEFGHIJKLMNOP"  # obviously fake, AWS-key shaped


def app_for(tmp_path, mode):
    write_config(tmp_path)
    path = tmp_path / "gateway.yaml"
    if mode:
        text = path.read_text().replace(
            "model: llama3.1:8b", f"model: llama3.1:8b\n    outbound: {{on_secret: {mode}}}"
        )
        path.write_text(text)
    up, sink = FakeUpstream(), MemorySink()
    return Gateway(load_config(path), transport=up, sink=sink), up, sink


def _tool_call(args):
    return {"id": "c1", "type": "function", "function": {"name": "search", "arguments": args}}


# Every input path a credential can travel; each request carries SECRET in exactly one place.
def _bodies():
    base = [{"role": "user", "content": "hi"}]
    cases = {
        "system": [{"role": "system", "content": f"key {SECRET}"}, *base],
        "developer": [{"role": "developer", "content": f"key {SECRET}"}, *base],
        "user": [{"role": "user", "content": f"key {SECRET}"}],
        "user_text_part": [{"role": "user", "content": [{"type": "text", "text": SECRET}]}],
        "assistant_history": [
            {"role": "user", "content": "a"},
            {"role": "assistant", "content": f"key {SECRET}"},
            {"role": "user", "content": "b"},
        ],
        "assistant_tool_call_args": [
            {"role": "user", "content": "a"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [_tool_call(f'{{"q": "{SECRET}"}}')],
            },
            {"role": "tool", "tool_call_id": "c1", "content": "ok"},
            {"role": "user", "content": "b"},
        ],
        "tool_result": [
            {"role": "user", "content": "a"},
            {"role": "assistant", "content": None, "tool_calls": [_tool_call('{"q": "x"}')]},
            {"role": "tool", "tool_call_id": "c1", "content": f"found {SECRET}"},
        ],
    }
    return {k: {"model": "local", "messages": v} for k, v in cases.items()}


BODIES = _bodies()


@pytest.mark.parametrize("path", BODIES)
def test_block_sends_nothing_upstream(tmp_path, path):
    app, up, sink = app_for(tmp_path, "block")
    status, _ = call(app, body=copy.deepcopy(BODIES[path]))
    assert status == 400 and up.requests == []
    rec = [r for r in sink.records if r["event"] == "gateway_outbound_blocked"]
    assert rec and SECRET not in json.dumps(sink.records)


@pytest.mark.parametrize("path", BODIES)
def test_redact_removes_the_secret_before_the_upstream(tmp_path, path):
    app, up, sink = app_for(tmp_path, "redact")
    status, _ = call(app, body=copy.deepcopy(BODIES[path]))
    assert status == 200 and len(up.requests) == 1
    assert SECRET not in json.dumps(up.requests[0])
    assert "gateway_outbound_redacted" in [r["event"] for r in sink.records]
    assert SECRET not in json.dumps(sink.records)


@pytest.mark.parametrize("mode", ["block", "redact"])
@pytest.mark.parametrize(
    "part",
    [
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
        {"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}},
        {"type": "file", "file": {"file_data": "data:text/plain;base64,AAAA"}},
    ],
)
def test_attachments_are_refused_when_the_policy_is_on(tmp_path, mode, part):
    app, up, sink = app_for(tmp_path, mode)
    body = {"model": "local", "messages": [{"role": "user", "content": [part]}]}
    assert call(app, body=body)[0] == 400 and up.requests == []
    assert "gateway_outbound_blocked" in [r["event"] for r in sink.records]


def test_off_is_the_default_and_changes_nothing(tmp_path):
    app, up, _ = app_for(tmp_path, None)
    img = {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}
    body = {"model": "local", "messages": [{"role": "user", "content": [img]}]}
    assert call(app, body=body)[0] == 200
    assert call(app, body=BODIES["user"])[0] == 200
    assert SECRET in json.dumps(up.requests[1])


def test_clean_requests_pass_untouched(tmp_path):
    app, up, sink = app_for(tmp_path, "block")
    assert (
        call(app, body={"model": "local", "messages": [{"role": "user", "content": "hi"}]})[0]
        == 200
    )
    assert up.requests[0]["messages"] == [{"role": "user", "content": "hi"}]
    assert not [r for r in sink.records if "outbound" in r["event"]]


def test_invalid_mode_is_a_config_error(tmp_path):
    write_config(tmp_path)
    path = tmp_path / "gateway.yaml"
    path.write_text(
        path.read_text().replace("model: llama3.1:8b", "model: m\n    outbound: {on_secret: nope}")
    )
    with pytest.raises(ConfigError, match="on_secret"):
        load_config(path)
