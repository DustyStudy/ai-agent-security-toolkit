"""Declarative, deny-by-default tool policy.

A policy is data (YAML/JSON/dict) so it can be code-reviewed, diffed and
validated in CI separately from the agent code. Loading is strict: unknown keys
are errors, because a typo in a security policy that silently disables a rule
is worse than a crash.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ARG_TYPES = {"string", "integer", "number", "boolean", "path", "url", "any"}


class PolicyError(ValueError):
    """Raised when a policy document is malformed."""


@dataclass
class ArgRule:
    type: str = "string"
    required: bool = False
    enum: list[Any] | None = None
    pattern: str | None = None  # must fully match (strings)
    deny_patterns: list[str] = field(default_factory=list)  # must not match (search)
    max_length: int | None = None
    minimum: float | None = None
    maximum: float | None = None
    # path
    roots: list[str] = field(default_factory=list)
    # url
    schemes: list[str] = field(default_factory=lambda: ["https"])
    hosts: list[str] = field(default_factory=list)
    block_private: bool = True
    resolve_dns: bool = False


@dataclass
class ToolRule:
    name: str = ""
    allow: bool = True
    description: str = ""
    side_effects: bool = False  # writes, sends, deletes, spends money, egresses data
    returns_untrusted: bool = False  # output contains attacker-influenceable text
    require_approval: bool = False
    max_calls: int | None = None  # per session
    allow_extra_args: bool = False
    args: dict[str, ArgRule] = field(default_factory=dict)


@dataclass
class TaintPolicy:
    enabled: bool = True
    # What to do with a side-effecting tool once the session has touched untrusted content.
    action: str = "deny"  # "deny" | "approve"


@dataclass
class Policy:
    tools: dict[str, ToolRule] = field(default_factory=dict)
    taint: TaintPolicy = field(default_factory=TaintPolicy)
    max_total_calls: int | None = None
    version: int = 1

    # ------------------------------------------------------------------ loading
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        if not isinstance(data, dict):
            raise PolicyError("policy must be a mapping")
        data = dict(data)
        _reject_unknown(data, {"version", "tools", "taint", "max_total_calls"}, "policy")
        tools_raw = data.get("tools") or {}
        if not isinstance(tools_raw, dict):
            raise PolicyError("'tools' must be a mapping of tool name -> rule")
        tools = {name: _build_tool(name, raw) for name, raw in tools_raw.items()}
        taint = _build(TaintPolicy, data.get("taint") or {}, "taint")
        if taint.action not in {"deny", "approve"}:
            raise PolicyError("taint.action must be 'deny' or 'approve'")
        return cls(
            tools=tools,
            taint=taint,
            max_total_calls=data.get("max_total_calls"),
            version=int(data.get("version", 1)),
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> Policy:
        with Path(path).open(encoding="utf-8") as fh:
            return cls.from_dict(yaml.safe_load(fh) or {})

    # --------------------------------------------------------------- inspection
    def lint(self) -> list[str]:
        """Non-fatal advice about risky-looking rules."""
        notes: list[str] = []
        for name, rule in self.tools.items():
            if not rule.allow:
                continue
            if rule.side_effects and not rule.args and not rule.allow_extra_args:
                notes.append(f"{name}: side-effecting tool with no argument constraints")
            if rule.side_effects and not rule.require_approval and not self.taint.enabled:
                notes.append(f"{name}: side-effecting, no approval, and taint tracking is off")
            for arg_name, arg in rule.args.items():
                if arg.type == "url" and not arg.hosts:
                    notes.append(f"{name}.{arg_name}: url argument without a host allowlist")
                if arg.type == "path" and not arg.roots:
                    notes.append(f"{name}.{arg_name}: path argument without roots")
                if arg.type == "string" and arg.max_length is None and arg.pattern is None:
                    notes.append(f"{name}.{arg_name}: unbounded string argument")
        return notes


def _reject_unknown(data: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = set(data) - allowed
    if unknown:
        raise PolicyError(f"{where}: unknown key(s) {sorted(unknown)}")


def _build(cls: type, raw: Any, where: str) -> Any:
    if not isinstance(raw, dict):
        raise PolicyError(f"{where} must be a mapping")
    names = {f.name for f in dataclasses.fields(cls)}
    _reject_unknown(raw, names, where)
    return cls(**raw)


def _build_tool(name: str, raw: Any) -> ToolRule:
    if not isinstance(raw, dict):
        raise PolicyError(f"tools.{name} must be a mapping")
    raw = dict(raw)
    args_raw = raw.pop("args", None) or {}
    if not isinstance(args_raw, dict):
        raise PolicyError(f"tools.{name}.args must be a mapping")
    raw.setdefault("name", name)
    rule: ToolRule = _build(ToolRule, {**raw, "args": {}}, f"tools.{name}")
    for arg_name, arg_raw in args_raw.items():
        arg: ArgRule = _build(ArgRule, arg_raw or {}, f"tools.{name}.args.{arg_name}")
        if arg.type not in ARG_TYPES:
            raise PolicyError(f"tools.{name}.args.{arg_name}: unknown type {arg.type!r}")
        for pat in [arg.pattern, *arg.deny_patterns]:
            if pat is not None:
                try:
                    re.compile(pat)
                except re.error as exc:
                    raise PolicyError(
                        f"tools.{name}.args.{arg_name}: bad regex {pat!r}: {exc}"
                    ) from exc
        rule.args[arg_name] = arg
    return rule
