"""Ask an external DLP or policy service about each tool call before it runs.

``ToolGuard(policy_hook=HttpPolicyHook(url))`` posts every call the local policy does not deny
and runs it only on an explicit allow. Errors, timeouts, redirects, oversized or malformed
answers all deny (the guard fails closed).

Request body (JSON)::

    {"tool": "send_email", "arguments": {...}, "verdict": "allow", "reasons": [], "actor": "a@x"}

The arguments are sent as the model wrote them, unredacted, because a DLP service has to see
them: send them only to a service you trust with that data, over HTTPS.

Answer: ``{"allow": true}`` runs the call; anything else (``{"allow": false}``, a missing key,
``"true"`` as a string) refuses it.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.request
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from agentsec.types import ToolCall

MAX_ANSWER_BYTES = 65536


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # A redirect would replay the arguments (and the auth header) to another host.
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        raise OSError("policy service answered with a redirect; refused")


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class HttpPolicyHook:
    """A ``policy_hook`` that asks an HTTP service. Plain ``http`` only to a loopback host."""

    def __init__(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        actor: str | None = None,
        timeout_s: float = 5.0,
    ) -> None:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if parts.scheme != "https" and not (parts.scheme == "http" and _is_loopback(host)):
            raise ValueError("policy hook URL must be https (http only to a loopback host)")
        if parts.username or parts.password:
            raise ValueError("put credentials in headers, not in the policy hook URL")
        self.url = url
        self.actor = actor
        self.timeout_s = timeout_s
        self._headers = {"Content-Type": "application/json", **(headers or {})}
        self._opener = urllib.request.build_opener(_NoRedirect)

    def __call__(self, call: ToolCall, decision: Any) -> bool:
        body = {
            "tool": call.name,
            "arguments": call.arguments,
            "verdict": getattr(getattr(decision, "verdict", None), "value", None),
            "reasons": list(getattr(decision, "reasons", ())),
            "actor": self.actor,
        }
        request = urllib.request.Request(  # noqa: S310 - scheme checked in __init__
            self.url, data=json.dumps(body, default=str).encode(), headers=self._headers
        )
        with self._opener.open(request, timeout=self.timeout_s) as response:
            if response.status != 200:
                return False
            raw = response.read(MAX_ANSWER_BYTES + 1)
        if len(raw) > MAX_ANSWER_BYTES:
            return False
        try:
            answer = json.loads(raw)
        except ValueError:
            return False
        return isinstance(answer, dict) and answer.get("allow") is True
