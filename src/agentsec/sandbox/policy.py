"""Declarative, deny-by-default tool policy.

A policy is data (YAML/JSON/dict) so it can be code-reviewed, diffed and
validated in CI separately from the agent code. Loading is strict: unknown keys
are errors, because a typo in a security policy that silently disables a rule
is worse than a crash.
"""

from __future__ import annotations

import dataclasses
import math
import re
from collections.abc import Callable
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
        if not all(isinstance(name, str) for name in tools_raw):
            raise PolicyError("tool names must be strings")
        tools = {name: _build_tool(name, raw) for name, raw in tools_raw.items()}
        taint = _build(TaintPolicy, data.get("taint") or {}, "taint")
        if taint.action not in ("deny", "approve"):
            raise PolicyError("taint.action must be 'deny' or 'approve'")
        max_total = data.get("max_total_calls")
        if max_total is not None and not (_is_int(max_total) and max_total >= 0):
            raise PolicyError("max_total_calls must be a non-negative integer")
        version = data.get("version", 1)
        if not _is_int(version):
            raise PolicyError("version must be an integer")
        return cls(tools=tools, taint=taint, max_total_calls=max_total, version=version)

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


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# kind -> (predicate, description). A quoted "false" is a truthy string, so a wrongly typed
# flag such as `allow: "false"` would otherwise *enable* a tool; reject it instead.
_KINDS: dict[str, tuple[Callable[[Any], bool], str]] = {
    "bool": (lambda v: isinstance(v, bool), "true or false"),
    "str": (lambda v: isinstance(v, str), "a string"),
    "str?": (lambda v: v is None or isinstance(v, str), "a string"),
    "int?": (lambda v: v is None or (_is_int(v) and v >= 0), "a non-negative integer"),
    "num?": (
        lambda v: (
            v is None
            or (isinstance(v, int | float) and not isinstance(v, bool) and math.isfinite(v))
        ),
        "a finite number",
    ),
    "list?": (lambda v: v is None or isinstance(v, list), "a list"),
    "strs": (
        lambda v: isinstance(v, list) and all(isinstance(x, str) for x in v),
        "a list of strings",
    ),
}
_FIELD_KINDS: dict[str, dict[str, str]] = {
    "TaintPolicy": {"enabled": "bool", "action": "str"},
    "ToolRule": {
        "name": "str",
        "allow": "bool",
        "description": "str",
        "side_effects": "bool",
        "returns_untrusted": "bool",
        "require_approval": "bool",
        "max_calls": "int?",
        "allow_extra_args": "bool",
    },
    "ArgRule": {
        "type": "str",
        "required": "bool",
        "enum": "list?",
        "pattern": "str?",
        "deny_patterns": "strs",
        "max_length": "int?",
        "minimum": "num?",
        "maximum": "num?",
        "roots": "strs",
        "schemes": "strs",
        "hosts": "strs",
        "block_private": "bool",
        "resolve_dns": "bool",
    },
}


def _build(cls: type, raw: Any, where: str) -> Any:
    if not isinstance(raw, dict):
        raise PolicyError(f"{where} must be a mapping")
    names = {f.name for f in dataclasses.fields(cls)}
    _reject_unknown(raw, names, where)
    for key, kind in _FIELD_KINDS.get(cls.__name__, {}).items():
        if key in raw and not _KINDS[kind][0](raw[key]):
            raise PolicyError(f"{where}.{key} must be {_KINDS[kind][1]}")
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
