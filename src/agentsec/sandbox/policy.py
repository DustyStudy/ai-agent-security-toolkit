"""Declarative, deny-by-default tool policy.

A policy is data (YAML/JSON/dict) so it can be code-reviewed, diffed and
validated in CI separately from the agent code. Loading is strict: unknown keys
are errors, because a typo in a security policy that silently disables a rule
is worse than a crash.
"""

from __future__ import annotations

import dataclasses
import math
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

import yaml

ARG_TYPES = {"string", "integer", "number", "boolean", "path", "url", "any"}


class PolicyError(ValueError):
    """Raised when a policy document is malformed."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML that refuses duplicate mapping keys (same check as configscan._YamlLoader)."""

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        # PyYAML keeps the last duplicate, so a second `Bash:` block would silently replace
        # the first and drop its approval and taint gating. Keys are taken before super()
        # folds `<<` merges into node.value: overriding a merged key is not a duplicate.
        key_nodes = [key for key, _ in node.value if key.tag != "tag:yaml.org,2002:merge"]
        mapping = super().construct_mapping(node, deep)
        keys = [self.construct_object(key, deep=True) for key in key_nodes]
        if len(set(keys)) != len(keys):
            line = node.start_mark.line + 1
            raise PolicyError(f"duplicate key in the mapping that starts on line {line}")
        return mapping


def load_yaml_strict(text: str | bytes | IO[str]) -> Any:
    """``yaml.safe_load`` that raises PolicyError on a duplicate mapping key."""
    return yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 - a SafeLoader subclass


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
    # None = automatic: resolve when block_private is on and there is no host allowlist, since
    # then any name (e.g. 127.0.0.1.nip.io) could point at a private address.
    resolve_dns: bool | None = None


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
class FilesPolicy:
    """Folders the agent may touch, for every ``type: path`` argument of every tool.

    A path argument of a ``side_effects`` tool is a write and gets ``write_roots`` (or, when
    that is empty, ``read_roots``); any other path argument is a read and gets ``read_roots``.
    An argument without its own ``roots`` inherits them; one with its own must sit inside
    them. ``deny_patterns`` are added to every path argument.
    """

    read_roots: list[str] = field(default_factory=list)
    write_roots: list[str] = field(default_factory=list)
    deny_patterns: list[str] = field(default_factory=list)


@dataclass
class Policy:
    tools: dict[str, ToolRule] = field(default_factory=dict)
    taint: TaintPolicy = field(default_factory=TaintPolicy)
    max_total_calls: int | None = None
    version: int = 1
    files: FilesPolicy = field(default_factory=FilesPolicy)

    # ------------------------------------------------------------------ loading
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        if not isinstance(data, dict):
            raise PolicyError("policy must be a mapping")
        data = dict(data)
        _reject_unknown(data, {"version", "tools", "taint", "max_total_calls", "files"}, "policy")
        tools_raw = data.get("tools") or {}
        if not isinstance(tools_raw, dict):
            raise PolicyError("'tools' must be a mapping of tool name -> rule")
        if not all(isinstance(name, str) for name in tools_raw):
            raise PolicyError("tool names must be strings")
        tools = {name: _build_tool(name, raw) for name, raw in tools_raw.items()}
        files = _build(FilesPolicy, data.get("files") or {}, "files")
        _apply_files(files, tools)
        taint = _build(TaintPolicy, data.get("taint") or {}, "taint")
        if taint.action not in ("deny", "approve"):
            raise PolicyError("taint.action must be 'deny' or 'approve'")
        max_total = data.get("max_total_calls")
        if max_total is not None and not (_is_int(max_total) and max_total >= 0):
            raise PolicyError("max_total_calls must be a non-negative integer")
        version = data.get("version", 1)
        if not _is_int(version):
            raise PolicyError("version must be an integer")
        return cls(
            tools=tools, taint=taint, max_total_calls=max_total, version=version, files=files
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> Policy:
        with Path(path).open(encoding="utf-8") as fh:
            data = load_yaml_strict(fh)
        return cls.from_dict(data or {})

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
            if rule.allow_extra_args:
                notes.append(f"{name}: allow_extra_args passes unchecked arguments to the tool")
            for arg_name, arg in rule.args.items():
                if arg.type == "any":
                    notes.append(f"{name}.{arg_name}: type 'any' is not validated")
                if arg.type == "url" and not arg.hosts:
                    notes.append(f"{name}.{arg_name}: url argument without a host allowlist")
                    if arg.resolve_dns is False and arg.block_private:
                        notes.append(
                            f"{name}.{arg_name}: resolve_dns is off, so hostnames that resolve "
                            "to private addresses are allowed"
                        )
                if arg.type == "url" and not arg.block_private:
                    notes.append(f"{name}.{arg_name}: block_private is off (SSRF exposure)")
                if arg.type == "path" and not arg.roots:
                    notes.append(f"{name}.{arg_name}: path argument without roots")
                if arg.type == "string" and arg.max_length is None and arg.pattern is None:
                    notes.append(f"{name}.{arg_name}: unbounded string argument")
        return notes


def dns_check_enabled(rule: ArgRule) -> bool:
    """Whether a URL rule resolves hostnames to check for private addresses."""
    if rule.resolve_dns is not None:
        return rule.resolve_dns
    return rule.block_private and not rule.hosts


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
    "bool?": (lambda v: v is None or isinstance(v, bool), "true or false"),
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
    "FilesPolicy": {"read_roots": "strs", "write_roots": "strs", "deny_patterns": "strs"},
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
        "resolve_dns": "bool?",
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


def _inside(path: str, roots: list[str]) -> bool:
    real = os.path.normcase(os.path.realpath(path))
    for root in roots:
        top = os.path.normcase(os.path.realpath(root))
        try:
            if os.path.commonpath([real, top]) == top:
                return True
        except ValueError:  # different drives on Windows
            continue
    return False


def _apply_files(files: FilesPolicy, tools: dict[str, ToolRule]) -> None:
    for root in (*files.read_roots, *files.write_roots):
        if not os.path.isabs(root):
            raise PolicyError(f"files: root {root!r} must be an absolute path")
    for pat in files.deny_patterns:
        try:
            re.compile(pat)
        except re.error as exc:
            raise PolicyError(f"files.deny_patterns: bad regex {pat!r}: {exc}") from exc
    for name, rule in tools.items():
        ceiling = (files.write_roots or files.read_roots) if rule.side_effects else files.read_roots
        for arg_name, arg in rule.args.items():
            if arg.type != "path":
                continue
            where = f"tools.{name}.args.{arg_name}"
            if ceiling:
                if not arg.roots:
                    arg.roots = list(ceiling)
                for root in arg.roots:
                    if not _inside(root, ceiling):
                        kind = "write" if rule.side_effects and files.write_roots else "read"
                        raise PolicyError(f"{where}: root {root!r} is outside files.{kind}_roots")
            arg.deny_patterns = list(dict.fromkeys([*arg.deny_patterns, *files.deny_patterns]))


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
