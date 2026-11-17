"""Inventory, scan and pin the files that steer a coding agent.

A coding agent takes instructions and runs commands from files in the working tree: MCP server
lists, hooks and settings, and instruction files such as ``AGENTS.md``. Whoever can write one
of them (a malicious package's install script, a cloned repository, a pull request) controls
the agent. :func:`scan_config` finds those files, runs the injection and secret scanners over
them, and fingerprints every entry so :func:`check_pins` can report what was added, changed or
removed since a human last reviewed it.

The content scan is the same heuristic tripwire as everywhere else in the toolkit: a hook that
runs ``curl ... | sh`` contains no injection phrase and no secret. The pins are the control.
Keep the pin file where the agent cannot write and require review for changes to it.
"""

from __future__ import annotations

import hashlib
import json
import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentsec.integrations.mcp import _strings
from agentsec.middleware.injection import InjectionScanner
from agentsec.middleware.redact import find_sensitive, redact_text

PIN_FILE_VERSION = 1
# A file or entry longer than this is reported instead of trusted: padding could push an
# injection or a secret past the prefix the scanners read.
MAX_SCANNED_CHARS = 200_000
MAX_FILE_BYTES = 5_000_000

AGENT_DIRS = frozenset(
    {
        ".agents",
        ".amazonq",
        ".claude",
        ".claude-plugin",
        ".clinerules",
        ".codex",
        ".continue",
        ".cursor",
        ".gemini",
        ".kiro",
        ".opencode",
        ".roo",
        ".windsurf",
    }
)
# Names are compared casefolded: on Windows and macOS an agent opens agents.md as AGENTS.md.
_INSTRUCTION_NAMES = frozenset(
    {
        "agents.md",
        "agents.override.md",
        "claude.md",
        "claude.local.md",
        "gemini.md",
        "skill.md",
        ".cursorrules",
        ".windsurfrules",
        ".clinerules",
        "copilot-instructions.md",
    }
)
_INSTRUCTION_SUFFIXES = (".instructions.md", ".prompt.md", ".chatmode.md", ".agent.md")
_CONFIG_ANYWHERE = frozenset({".mcp.json", ".claude.json", "opencode.json"})
_CONFIG_IN_AGENT_DIR = frozenset(
    {
        "mcp.json",
        "mcp_config.json",
        "settings.json",
        "settings.local.json",
        "hooks.json",
        "config.toml",
    }
)
# Top-level keys whose members are listed one by one, so a diff names the server or hook event.
_EXPANDED = {
    "mcpservers": "mcp_server",
    "mcp_servers": "mcp_server",
    "servers": "mcp_server",
    "hooks": "hook",
}


@dataclass(frozen=True)
class ConfigItem:
    """One reviewable entry: an MCP server, a hook event, a setting or a file."""

    id: str  # "<relative path>" or "<relative path>#<key>[.<member>]"
    kind: str  # mcp_server | hook | setting | instructions | file | symlink
    fingerprint: str
    summary: str  # redacted, escaped and bounded: safe to print


@dataclass(frozen=True)
class ConfigFinding:
    item: str
    # injection | secret | oversized | unparsed | ambiguous | new | changed | removed
    kind: str
    detail: str


@dataclass
class ConfigScan:
    items: dict[str, ConfigItem] = field(default_factory=dict)
    findings: list[ConfigFinding] = field(default_factory=list)

    @property
    def fingerprints(self) -> dict[str, str]:
        """What to pin. Only pin a scan that has no findings: a finding means an entry was
        flagged, or that part of the tree could not be read."""
        return {i.id: i.fingerprint for i in self.items.values()}

    def _add(self, item: ConfigItem) -> None:
        if item.id in self.items:
            # Two entries with one id (a key named "mcpServers.docs" beside the server "docs")
            # would let a decoy carry the pinned fingerprint for a changed entry.
            self.findings.append(ConfigFinding(item.id, "ambiguous", "two entries share this id"))
        else:
            self.items[item.id] = item


def show(text: str, limit: int = 160) -> str:
    """Redact, escape and bound attacker-controlled text before it reaches a terminal or log."""
    redacted, _ = redact_text(text, include_pii=False)
    # json.dumps escapes control characters and non-ASCII, so no ANSI or bidi sequence survives.
    return json.dumps(redacted[:limit])[1:-1]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _classify(parts: tuple[str, ...]) -> str | None:
    name = parts[-1].casefold()
    in_agent_dir = bool({p.casefold() for p in parts[:-1]} & AGENT_DIRS)
    if (
        name in _INSTRUCTION_NAMES
        or name.endswith(_INSTRUCTION_SUFFIXES)
        or (in_agent_dir and name.endswith((".md", ".mdc")))
    ):
        return "instructions"
    if (
        name in _CONFIG_ANYWHERE
        or (in_agent_dir and name in _CONFIG_IN_AGENT_DIR)
        or (name == "mcp.json" and len(parts) > 1 and parts[-2].casefold() == ".vscode")
    ):
        return "config"
    # Everything else under an agent directory is pinned whole: a hook script, a YAML config.
    return "file" if in_agent_dir else None


def _context(directory: Path) -> tuple[str, ...]:
    """The directory names that count as a file's ancestors: the path as it was given plus the
    directory's own name. So scanning ``.claude/rules`` or ``~/.claude`` keeps its meaning, while
    a checkout that merely lives under ``.claude/worktrees`` is not all agent configuration.
    Nothing is resolved, so a symlink keeps the name the agent sees.
    """
    return (*directory.parts, Path(os.path.abspath(directory)).name)


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out = dict(pairs)
    if len(out) != len(pairs):
        # Parsers disagree on which duplicate wins, so the scan could read one and the agent
        # the other.
        raise ValueError("duplicate key")
    return out


def _entries(rel: str, data: Any) -> list[tuple[str, str, Any]]:
    """(id, kind, value keyed by its name) for each entry of a parsed config file.

    Every top-level key is an entry, not only the keys known to run code: agents keep adding
    settings that do (helpers, status lines, environment overrides), and a list of the dangerous
    ones would go stale.
    """
    if not isinstance(data, Mapping):
        return [(rel, "setting", data)]
    out: list[tuple[str, str, Any]] = []
    for key, value in data.items():
        kind = _EXPANDED.get(str(key).casefold())
        if kind and isinstance(value, Mapping):
            out += [(f"{rel}#{key}.{name}", kind, {key: {name: v}}) for name, v in value.items()]
        else:
            out.append((f"{rel}#{key}", "setting", {key: value}))
    return out


def _scan_text(
    scan: ConfigScan, item: str, text: str, scanner: InjectionScanner, *, injection: bool = True
) -> None:
    limit = min(MAX_SCANNED_CHARS, scanner.max_scan_chars)
    if len(text) > limit:
        scan.findings.append(
            ConfigFinding(item, "oversized", f"{len(text)} chars (max {limit}); not fully scanned")
        )
    if injection:
        result = scanner.scan(text)
        if result.flagged:
            detail = f"score {result.score:.2f}: {', '.join(result.signals)}"
            scan.findings.append(ConfigFinding(item, "injection", detail))
    kinds = sorted({f.kind for f in find_sensitive(text, include_pii=False)})
    if kinds:
        scan.findings.append(ConfigFinding(item, "secret", f"plaintext {', '.join(kinds)}"))


def _scan_file(
    scan: ConfigScan, path: Path, rel: str, kind: str, scanner: InjectionScanner
) -> None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            scan.findings.append(ConfigFinding(rel, "oversized", f"over {MAX_FILE_BYTES} bytes"))
            return
        raw = path.read_bytes()
    except OSError as exc:
        scan.findings.append(ConfigFinding(rel, "unparsed", f"cannot read: {type(exc).__name__}"))
        return
    # Newlines are normalised so a pin made on Linux matches a Windows checkout. Files are
    # fingerprinted as bytes: two invalid UTF-8 sequences decode to the same replacement.
    whole = _sha256(raw.replace(b"\r\n", b"\n"))
    if kind == "file":
        scan._add(ConfigItem(rel, kind, whole, f"{len(raw)} bytes"))
        return
    text = raw.decode("utf-8-sig", errors="replace").replace("\r\n", "\n")
    if kind == "instructions":
        scan._add(ConfigItem(rel, kind, whole, show(text.strip().partition("\n")[0])))
        _scan_text(scan, rel, text, scanner)
        return
    # The raw text is checked for size and for secrets the parsed entries do not hold, such as
    # one in a TOML comment.
    _scan_text(scan, rel, text, scanner, injection=False)
    try:
        strict = raw.decode("utf-8-sig")
        if path.suffix.lower() == ".toml":
            data = tomllib.loads(strict)
        else:
            data = json.loads(strict, object_pairs_hook=_no_duplicates)
        for item_id, item_kind, keyed in _entries(rel, data):
            # repr, not str, for TOML dates: the date 1979-05-27 and the string "1979-05-27"
            # must not share a fingerprint.
            encoded = json.dumps(keyed, sort_keys=True, ensure_ascii=False, default=repr)
            fingerprint = _sha256(encoded.encode("utf-8"))
            scan._add(ConfigItem(item_id, item_kind, fingerprint, show(encoded)))
            # The entry is scanned decoded and with its names: "ghp_..." is a token only
            # after decoding, and a server can be named "ignore all previous instructions".
            _scan_text(scan, item_id, encoded + "\n" + "\n".join(_strings(keyed)), scanner)
    except (ValueError, RecursionError) as exc:
        # Fails closed: a file the scanner cannot read is one nobody reviewed. That includes
        # JSON with comments, duplicate keys, invalid UTF-8 and nesting too deep to walk.
        scan.findings.append(ConfigFinding(rel, "unparsed", f"not valid: {type(exc).__name__}"))


def scan_config(root: str | Path, scanner: InjectionScanner | None = None) -> ConfigScan:
    """Find and scan agent configuration under ``root`` (a directory, or one file).

    Item ids use paths relative to ``root`` with forward slashes, so a pin file made on one
    machine checks out on another. Only ``.git`` is skipped: an ``AGENTS.md`` inside
    ``node_modules`` steers an agent that works there. Symlinked directories are not followed;
    each is listed as an item, fingerprinted by its target.
    """
    scanner = scanner or InjectionScanner()
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"no such file or directory: {root}")
    scan = ConfigScan()
    if root.is_file():
        kind = _classify((*_context(root.parent), root.name))
        if kind:
            _scan_file(scan, root, root.name, kind, scanner)
        return scan

    def unreadable(exc: OSError) -> None:
        rel = Path(os.path.relpath(exc.filename or root, root)).as_posix()
        scan.findings.append(ConfigFinding(rel, "unparsed", "cannot list directory"))

    context = _context(root)
    for directory, subdirs, names in os.walk(root, onerror=unreadable):
        subdirs[:] = sorted(d for d in subdirs if d != ".git")
        for name in subdirs:
            link = Path(directory, name)
            if link.is_symlink():
                rel = link.relative_to(root).as_posix()
                target = os.readlink(link)
                scan._add(ConfigItem(rel, "symlink", _sha256(target.encode()), show(target)))
        for name in sorted(names):
            path = Path(directory, name)
            rel = path.relative_to(root).as_posix()
            kind = _classify((*context, *rel.split("/")))
            if kind:
                _scan_file(scan, path, rel, kind, scanner)
    return scan


def check_pins(scan: ConfigScan, pins: Mapping[str, str]) -> list[ConfigFinding]:
    """Compare a scan against reviewed pins: what is new, changed or gone."""
    findings: list[ConfigFinding] = []
    for item in scan.items.values():
        pinned = pins.get(item.id)
        if pinned is None:
            findings.append(ConfigFinding(item.id, "new", f"{item.kind}, no pin: {item.summary}"))
        elif pinned != item.fingerprint:
            detail = f"{item.kind} differs from its pin: {item.summary}"
            findings.append(ConfigFinding(item.id, "changed", detail))
    # A removed entry matters too: the hook that is gone may have been a guard.
    findings += [
        ConfigFinding(i, "removed", "pinned entry is gone") for i in pins if i not in scan.items
    ]
    return findings


def save_pins(path: str | Path, pins: Mapping[str, str]) -> None:
    payload = {"version": PIN_FILE_VERSION, "items": dict(pins)}
    Path(path).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )


def load_pins(path: str | Path) -> dict[str, str]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("version") != PIN_FILE_VERSION:
        raise ValueError(f"unsupported config pin file (expected version {PIN_FILE_VERSION})")
    items = raw.get("items")
    if not isinstance(items, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in items.items()
    ):
        raise ValueError("config pin file must map item ids to fingerprint strings")
    return items
