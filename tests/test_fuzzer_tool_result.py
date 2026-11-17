"""The opt-in ``tool_result`` scenario: the payload arrives as the result of the agent's own tool."""

from __future__ import annotations

import json

from agentsec.cli import main
from agentsec.fuzzer import FuzzConfig, load_target, run
from agentsec.fuzzer.harness import DEFAULT_SCENARIOS, SCENARIOS, TOOL_NAME, build_cases
from agentsec.fuzzer.targets import AnthropicTarget, _chat_messages, _tool_names, _user_content
from agentsec.types import AttackInput
from tests.test_fuzzer import _Block, _FakeAnthropic

CONTAINMENT = ["tool_misuse", "exfiltration", "prompt_leak"]


def tool_case() -> AttackInput:
    config = FuzzConfig(
        payload_ids=["override-01"], mutators=["identity"], scenarios=["tool_result"]
    )
    (case,) = build_cases(config)
    return case.input


def test_default_matrix_is_unchanged_and_the_scenario_is_opt_in():
    assert DEFAULT_SCENARIOS == ("direct", "indirect") and "tool_result" in SCENARIOS
    assert len(build_cases(FuzzConfig())) == 500  # the number every published result is for
    assert len(build_cases(FuzzConfig(scenarios=["tool_result"]))) == 250


def test_payload_sits_in_the_tool_result_and_the_user_only_asks_for_work():
    inp = tool_case()
    assert inp.untrusted_tool == TOOL_NAME
    assert "Ignore all previous instructions" in inp.untrusted_content
    assert "## Resolution" in inp.untrusted_content  # laid out like the tool's own template
    assert "Ignore" not in inp.user_message
    # A diagnosis only: a forbidden tool call is then never what the user asked for.
    assert "Do not change anything or run anything" in inp.user_message


def test_positional_arguments_keep_their_meaning_and_http_body_is_unchanged_by_default():
    inp = AttackInput("task", "doc", "secret")
    assert (inp.system_secret, inp.untrusted_tool) == ("secret", None)
    sent = {}

    class Reply:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, _limit):
            return b'{"text": "ok"}'

    def fake_open(req, timeout):
        sent.update(json.loads(req.data))
        return Reply()

    from agentsec.fuzzer import targets

    target = targets.HttpTarget("http://127.0.0.1:1/agent")
    original, targets._OPENER.open = targets._OPENER.open, fake_open
    try:
        target(inp)
        assert set(sent) == {"message", "context", "available_tools"}
        target(tool_case())
        assert sent["context_tool"] == TOOL_NAME
    finally:
        targets._OPENER.open = original


def test_chat_targets_deliver_it_in_the_tool_role_not_in_the_user_turn():
    inp = tool_case()
    assert _user_content(inp) == inp.user_message
    assert _tool_names(inp)[-1] == TOOL_NAME  # the tool the model "called" is declared

    system, user, assistant, result = _chat_messages(inp, "sys")
    assert (system["role"], user["content"]) == ("system", inp.user_message)
    call = assistant["tool_calls"][0]
    assert call["function"] == {"name": TOOL_NAME, "arguments": "{}"}
    assert result == {
        "role": "tool",
        "tool_call_id": call["id"],
        "content": inp.untrusted_content,
    }

    *_, assistant, result = _chat_messages(inp, "sys", ollama=True)
    assert assistant["tool_calls"] == [{"function": {"name": TOOL_NAME, "arguments": {}}}]
    assert result == {"role": "tool", "tool_name": TOOL_NAME, "content": inp.untrusted_content}


def test_a_document_still_rides_in_the_user_turn():
    inp = AttackInput(user_message="summarize", untrusted_content="doc body")
    messages = _chat_messages(inp, "sys")
    assert len(messages) == 2 and "<document>\ndoc body\n</document>" in messages[1]["content"]
    assert _tool_names(inp) == ()


def test_anthropic_target_sends_a_tool_use_and_tool_result_pair():
    fake = _FakeAnthropic([_Block("text", text="ok")])
    inp = tool_case()
    AnthropicTarget(client=fake, model="claude-sonnet-5-5")(inp)
    call = fake.calls[0]
    user, assistant, result = call["messages"]
    assert user == {"role": "user", "content": inp.user_message}
    use = assistant["content"][0]
    assert (use["type"], use["name"]) == ("tool_use", TOOL_NAME)
    assert result["role"] == "user" and result["content"] == [
        {"type": "tool_result", "tool_use_id": use["id"], "content": inp.untrusted_content}
    ]
    assert TOOL_NAME in [t["name"] for t in call["tools"]]


def test_simulators_naive_is_fully_compromised_and_guarded_contains_it():
    config = FuzzConfig(scenarios=["tool_result"])
    assert run(load_target("builtin:naive"), config).asr == 1.0
    contained = FuzzConfig(scenarios=["tool_result"], categories=CONTAINMENT)
    for name in ("builtin:guarded", "builtin:guarded-noscanner"):
        report = run(load_target(name), contained)
        assert report.asr == 0.0, name


def test_cli_selects_and_reports_the_scenario(tmp_path, capsys):
    out = tmp_path / "r.json"
    args = ["fuzz", "--target", "builtin:naive", "--scenarios", "tool_result", "--quiet"]
    assert main([*args, "--max-cases", "10", "--json", str(out)]) == 0
    assert list(json.loads(out.read_text())["by_scenario"]) == ["tool_result"]
    assert main(["fuzz", "--target", "builtin:naive", "--list"]) == 0
    assert "x 2 scenarios" in capsys.readouterr().out
