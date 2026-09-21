"""Prompt-injection test harness / fuzzer."""

from agentsec.fuzzer.harness import (
    Case,
    CaseResult,
    FuzzConfig,
    build_cases,
    detect,
    run,
)
from agentsec.fuzzer.mock_agents import GuardedAgent, NaiveAgent, demo_policy
from agentsec.fuzzer.mutators import MUTATORS
from agentsec.fuzzer.payloads import CORPUS, Payload
from agentsec.fuzzer.report import FuzzReport
from agentsec.fuzzer.targets import (
    AnthropicTarget,
    HttpTarget,
    load_target,
    sync_target,
    text_target,
)

__all__ = [
    "CORPUS",
    "MUTATORS",
    "AnthropicTarget",
    "Case",
    "CaseResult",
    "FuzzConfig",
    "FuzzReport",
    "GuardedAgent",
    "HttpTarget",
    "NaiveAgent",
    "Payload",
    "build_cases",
    "demo_policy",
    "detect",
    "load_target",
    "run",
    "sync_target",
    "text_target",
]
