"""Gateway hardening: JWKS fetches ignore proxy env, fixed alg reason, strict trusted_proxies."""

from __future__ import annotations

import urllib.request

import pytest

pytest.importorskip("jwt")

from agentsec.gateway import ConfigError  # noqa: E402
from agentsec.gateway.oidc import TokenRejected, fetch_jwks  # noqa: E402
from tests.test_gateway import write_config  # noqa: E402
from tests.test_gateway_oidc import b64, verifier  # noqa: E402


def test_jwks_fetch_ignores_proxy_environment(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    seen = []

    def fake_open(self, req, timeout=None):
        seen.append(self)
        raise OSError("stop before the network")

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", fake_open)
    with pytest.raises(OSError, match="stop before"):
        fetch_jwks("https://idp.example/jwks")
    proxies = [h for h in seen[0].handlers if isinstance(h, urllib.request.ProxyHandler)]
    # A ProxyHandler with a route grows a <scheme>_open method for it.
    assert not any(hasattr(h, "https_open") or hasattr(h, "http_open") for h in proxies)


def test_alg_header_value_is_not_echoed_in_the_reason():
    marker = "EVIL" * 500
    forged = b64({"alg": marker, "kid": "rsa1"}) + "." + b64({"sub": "x"}) + ".sig"
    with pytest.raises(TokenRejected) as e:
        verifier().verify(forged)
    assert str(e.value) == "token algorithm not allowed"


@pytest.mark.parametrize(
    ("proxies", "match"),
    [
        ("172.28.0.10/16", "host bits"),
        ("10.0.0.0/8", "too broad"),
        ("10.0.0.0/15", "too broad"),
        ("'fd00::/47'", "too broad"),
    ],
)
def test_trusted_proxies_refuses_host_bits_and_broad_prefixes(tmp_path, proxies, match):
    with pytest.raises(ConfigError, match=match):
        write_config(tmp_path, extra=f"identity:\n  trusted_proxies: [{proxies}]\n")


def test_trusted_proxies_accepts_the_broadest_allowed_prefixes(tmp_path):
    config = write_config(
        tmp_path, extra="identity:\n  trusted_proxies: [172.28.0.0/16, 'fd00::/48', 127.0.0.1]\n"
    )
    assert len(config.trusted_proxies) == 3
