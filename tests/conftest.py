"""Shared fixtures. Fake credentials are assembled at runtime so no literal
secret-shaped string ever appears in the repository (keeps secret scanners quiet)."""

from __future__ import annotations

import pytest

from agentsec.sandbox import Policy


def fake_aws_key() -> str:
    return "AK" + "IA" + "IOSFODNN7EXAMPLE"


def fake_github_token() -> str:
    return "gh" + "p_" + "a1B2c3D4e5" * 4  # 40 chars after prefix


def fake_slack_token() -> str:
    return "xo" + "xb-" + "1234567890-abcdefghij"


def fake_anthropic_key() -> str:
    return "sk-" + "ant-" + "api03-" + "x" * 30


def fake_jwt() -> str:
    return ".".join(
        ["ey" + "JhbGciOiJIUzI1NiJ9", "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0", "abcdefghijk1234"]
    )


def fake_private_key_header() -> str:
    return "-----BEGIN " + "RSA PRIVATE KEY-----"


@pytest.fixture
def sample_policy(tmp_path) -> Policy:
    root = tmp_path / "workspace"
    root.mkdir()
    return Policy.from_dict(
        {
            "tools": {
                "search_docs": {
                    "returns_untrusted": True,
                    "args": {"query": {"type": "string", "required": True, "max_length": 100}},
                },
                "read_file": {
                    "args": {"path": {"type": "path", "required": True, "roots": [str(root)]}},
                },
                "http_get": {
                    "side_effects": True,
                    "args": {
                        "url": {
                            "type": "url",
                            "required": True,
                            "hosts": ["api.example.com", "*.corp.example"],
                        }
                    },
                },
                "send_email": {
                    "side_effects": True,
                    "require_approval": True,
                    "args": {"to": {"type": "string", "pattern": r"[^@]+@corp\.example"}},
                },
                "limited": {
                    "max_calls": 2,
                    "args": {"n": {"type": "integer", "minimum": 0, "maximum": 10}},
                },
                "disabled": {"allow": False},
            },
            "max_total_calls": 50,
        }
    )
