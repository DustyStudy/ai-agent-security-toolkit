"""Signed policy bundles: per-group policy, verified with Ed25519 before anything is parsed.

A bundle is a directory::

    manifest.yaml      revision, expiry and the group_policies list
    manifest.sig       written by ``agentsec bundle sign``
    policies/*.yaml    ToolGuard policies the manifest references

``manifest.sig`` is JSON: the SHA-256 of the manifest and of every referenced file, and an
Ed25519 signature over that list. Verification checks the signature first, then every hash,
and only then parses YAML, from the exact bytes that were hashed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from agentsec.gateway.policyset import ANY_GROUP, PolicySet, group_policy, stream_settings
from agentsec.sandbox.policy import Policy, PolicyError

MANIFEST = "manifest.yaml"
SIGNATURE = "manifest.sig"
FORMAT = "agentsec-bundle-v1"
MAX_FILE_BYTES = 1024 * 1024

_ENTRY_KEYS = {"group", "tools", "mode", "models", "output", "input", "mcp"}
_OUTPUT_KEYS = {"allowed_hosts", "protected", "stream_mode", "holdback_chars"}
_MANIFEST_KEYS = {"revision", "created", "expires", "group_policies", "mcp_pins"}


class BundleError(ValueError):
    pass


def _payload(manifest_sha256: str, files: dict[str, str]) -> bytes:
    doc = {"format": FORMAT, "manifest_sha256": manifest_sha256, "files": files}
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def _read(root: Path, rel: str) -> bytes:
    """Read a bundle file by a manifest-relative path that must stay inside the bundle."""
    p = PurePosixPath(rel)
    if not rel or "\\" in rel or p.is_absolute() or ".." in p.parts or ":" in rel:
        raise BundleError(f"bundle path {rel!r} must be relative and inside the bundle")
    path = (root / p).resolve()
    if not path.is_relative_to(root.resolve()):
        raise BundleError(f"bundle path {rel!r} escapes the bundle")
    try:
        with path.open("rb") as fh:
            data = fh.read(MAX_FILE_BYTES + 1)  # bounded: a huge file is refused, not read
    except OSError as e:
        raise BundleError(f"cannot read bundle file {rel!r}: {type(e).__name__}") from None
    if len(data) > MAX_FILE_BYTES:
        raise BundleError(f"bundle file {rel!r} is over {MAX_FILE_BYTES} bytes")
    return data


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _referenced_files(manifest: dict[str, Any]) -> list[str]:
    entries = manifest.get("group_policies")
    if not isinstance(entries, list):
        raise BundleError("group_policies must be a list")
    files = {e["tools"] for e in entries if isinstance(e, dict) and isinstance(e.get("tools"), str)}
    pins = manifest.get("mcp_pins") or {}
    if isinstance(pins, dict):
        files |= {v for v in pins.values() if isinstance(v, str)}  # signed like the policies
    return sorted(files)


# ----------------------------------------------------------------------------- signing


def sign_bundle(root: str | Path, private_key_pem: bytes) -> Path:
    """Write ``manifest.sig`` for the bundle in ``root``. Run it where the signing key lives."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    root = Path(root)
    key = load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise BundleError("the signing key must be an Ed25519 private key")
    manifest_bytes = _read(root, MANIFEST)
    manifest = yaml.safe_load(manifest_bytes)
    if not isinstance(manifest, dict):
        raise BundleError("manifest must be a mapping")
    files = {rel: _sha(_read(root, rel)) for rel in _referenced_files(manifest)}
    payload = _payload(_sha(manifest_bytes), files)
    sig = {
        "format": FORMAT,
        "manifest_sha256": _sha(manifest_bytes),
        "files": files,
        "signature": base64.b64encode(key.sign(payload)).decode(),
    }
    out = root / SIGNATURE
    out.write_text(json.dumps(sig, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


# ------------------------------------------------------------------ rollback state


def read_state(path: str | Path) -> tuple[int, str] | None:
    """The highest accepted ``(revision, policy_rev)``, or None before the first bundle."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        raise BundleError("bundle state file is unreadable; refusing to guess") from None
    if not isinstance(doc, dict):
        raise BundleError("bundle state file is malformed; refusing to guess")
    revision, rev_id = doc.get("revision"), doc.get("policy_rev")
    if not isinstance(revision, int) or isinstance(revision, bool) or not isinstance(rev_id, str):
        raise BundleError("bundle state file is malformed; refusing to guess")
    return revision, rev_id


def check_state(policies: PolicySet, state: tuple[int, str] | None) -> None:
    """Refuse an older bundle, or another bundle with the same revision number."""
    if state is None or policies.numeric_revision is None:
        return
    revision, rev_id = state
    if policies.numeric_revision < revision or (
        policies.numeric_revision == revision and policies.revision != rev_id
    ):
        raise BundleError(
            f"bundle revision {policies.numeric_revision} does not follow the last accepted "
            f"{rev_id} (rollback refused)"
        )


def write_state(path: str | Path, policies: PolicySet) -> None:
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    doc = {"revision": policies.numeric_revision, "policy_rev": policies.revision}
    tmp.write_text(json.dumps(doc) + "\n", encoding="utf-8")
    os.replace(tmp, path)  # atomic: a crash leaves the old state or the new, never half


# ------------------------------------------------------------------------ verification


def load_public_key(pem: bytes) -> Any:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    key = load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise BundleError("the bundle public key must be an Ed25519 public key")
    return key


def verify_bundle(root: str | Path, public_key: Any) -> tuple[bytes, dict[str, bytes]]:
    """Check the signature and every hash. Returns the manifest and file bytes that were checked."""
    from cryptography.exceptions import InvalidSignature

    root = Path(root)
    manifest_bytes = _read(root, MANIFEST)
    try:
        sig = json.loads(_read(root, SIGNATURE))
        files = sig["files"]
        signature = base64.b64decode(sig["signature"], validate=True)
    except (ValueError, KeyError, TypeError, binascii.Error):
        raise BundleError("manifest.sig is missing or malformed") from None
    if (
        not isinstance(files, dict)
        or not all(isinstance(k, str) and isinstance(v, str) for k, v in files.items())
        or sig.get("format") != FORMAT
    ):
        raise BundleError("manifest.sig is missing or malformed")
    try:
        # Rebuilt from the manifest bytes on disk, so the signed hash is the one checked.
        public_key.verify(signature, _payload(_sha(manifest_bytes), files))
    except InvalidSignature:
        raise BundleError("bundle signature does not verify") from None
    contents = {}
    for rel, expected in files.items():
        data = _read(root, rel)
        if _sha(data) != expected:
            raise BundleError(f"bundle file {rel!r} does not match its signed hash")
        contents[rel] = data
    return manifest_bytes, contents


def _expiry(value: Any) -> datetime:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            raise BundleError("expires must be an ISO 8601 timestamp") from None
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise BundleError("expires must be a timestamp with a time zone (for example ...Z)")
    return value


def _pins(data: bytes, rel: str) -> dict[str, str]:
    """A ToolPins file (``agentsec mcp pin`` format) from the checked bytes."""
    from agentsec.integrations.mcp import PIN_FILE_VERSION

    try:
        doc = json.loads(data)
    except ValueError:
        raise BundleError(f"{rel}: not JSON") from None
    if not isinstance(doc, dict):
        raise BundleError(f"{rel}: not a tool pin file (version {PIN_FILE_VERSION})")
    tools = doc.get("tools")
    if (
        doc.get("version") != PIN_FILE_VERSION
        or not isinstance(tools, dict)
        or not all(isinstance(k, str) and isinstance(v, str) for k, v in tools.items())
    ):
        raise BundleError(f"{rel}: not a tool pin file (version {PIN_FILE_VERSION})")
    return dict(tools)


def _strs(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise BundleError(f"{where} must be a list of strings")
    return value


def load_bundle(
    root: str | Path,
    public_key: Any,
    *,
    upstreams: set[str] | None = None,
    mcp_upstreams: set[str] | None = None,
    now: datetime | None = None,
) -> PolicySet:
    """Verify and parse a bundle. ``upstreams`` checks each group's ``models`` against config."""
    manifest_bytes, contents = verify_bundle(root, public_key)
    manifest = yaml.safe_load(manifest_bytes)
    if not isinstance(manifest, dict):
        raise BundleError("manifest must be a mapping")
    unknown = set(manifest) - _MANIFEST_KEYS
    if unknown:
        raise BundleError(f"unknown manifest keys: {sorted(unknown)}")
    revision = manifest.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise BundleError("revision must be a non-negative integer")
    expires = _expiry(manifest.get("expires"))
    if expires <= (now or datetime.now(UTC)):
        raise BundleError("bundle has expired")

    entries = manifest.get("group_policies")
    if not isinstance(entries, list) or not entries:
        raise BundleError("group_policies must be a non-empty list")
    groups, parsed = [], {}
    for i, e in enumerate(entries):
        where = f"group_policies[{i}]"
        if not isinstance(e, dict) or set(e) - _ENTRY_KEYS:
            raise BundleError(f"{where}: unknown keys or not a mapping")
        group, tools = e.get("group"), e.get("tools")
        if not isinstance(group, str) or not group:
            raise BundleError(f"{where}.group must be a group name or '{ANY_GROUP}'")
        if not isinstance(tools, str) or tools not in contents:
            raise BundleError(f"{where}.tools must name a signed policy file")
        if tools not in parsed:
            try:
                parsed[tools] = Policy.from_dict(yaml.safe_load(contents[tools]))
            except (PolicyError, yaml.YAMLError) as err:
                raise BundleError(f"{tools}: {err}") from None
        mode = e.get("mode", "enforce")
        if not isinstance(mode, str) or mode not in {"enforce", "monitor"}:
            raise BundleError(f"{where}.mode must be 'enforce' or 'monitor'")
        models = None if e.get("models") is None else _strs(e["models"], f"{where}.models")
        mcp = _strs(e.get("mcp", []), f"{where}.mcp")
        if mcp_upstreams is not None and set(mcp) - mcp_upstreams:
            raise BundleError(
                f"{where}.mcp names unknown mcp_upstreams: {sorted(set(mcp) - mcp_upstreams)}"
            )
        if models is not None and upstreams is not None and set(models) - upstreams:
            raise BundleError(
                f"{where}.models names unknown upstreams: {sorted(set(models) - upstreams)}"
            )
        output, inp = e.get("output") or {}, e.get("input") or {}
        if not isinstance(output, dict) or set(output) - _OUTPUT_KEYS:
            raise BundleError(f"{where}.output takes {', '.join(sorted(_OUTPUT_KEYS))}")
        try:
            stream_mode, holdback_chars = stream_settings(output, f"{where}.output")
        except ValueError as err:
            raise BundleError(str(err)) from None
        if not isinstance(inp, dict) or set(inp) - {"block_on_injection", "spotlight_tool_results"}:
            raise BundleError(f"{where}.input takes block_on_injection and spotlight_tool_results")
        flags = {
            k: inp.get(k, d)
            for k, d in (("block_on_injection", True), ("spotlight_tool_results", False))
        }
        if not all(isinstance(v, bool) for v in flags.values()):
            raise BundleError(f"{where}.input values must be booleans")
        groups.append(
            group_policy(
                group,
                parsed[tools],
                mode=mode,
                models=models,
                allowed_hosts=_strs(
                    output.get("allowed_hosts", []), f"{where}.output.allowed_hosts"
                ),
                protected=_strs(output.get("protected", []), f"{where}.output.protected"),
                stream_mode=stream_mode,
                holdback_chars=holdback_chars,
                mcp=mcp,
                **flags,
            )
        )
    pins_raw = manifest.get("mcp_pins") or {}
    if not isinstance(pins_raw, dict):
        raise BundleError("mcp_pins must map MCP upstream names to pin files")
    mcp_pins = {}
    for name, rel in pins_raw.items():
        if mcp_upstreams is not None and name not in mcp_upstreams:
            raise BundleError(f"mcp_pins names an unknown mcp_upstream: {name!r}")
        if not isinstance(rel, str) or rel not in contents:
            raise BundleError(f"mcp_pins.{name} must name a signed pin file")
        mcp_pins[str(name)] = _pins(contents[rel], rel)
    return PolicySet(
        # Short enough to stay readable in the audit log with log_content off.
        revision=f"bundle:{revision}:{_sha(manifest_bytes)[:16]}",
        groups=tuple(groups),
        expires=expires,
        numeric_revision=revision,
        mcp_pins=mcp_pins,
    )
