"""Prometheus text metrics for the gateway, without a client library.

Counters come from two places, so they cannot drift from what the gateway did:

- every audit record written (``agentsec_gateway_events_total{event=...}``): each decision the
  gateway takes is an audit event, and a record is counted only once it was written;
- every HTTP response sent (``agentsec_gateway_responses_total{status=...}``).

Label values are event names and status codes from the code, never request content, so the
label set stays small and nothing a client sends reaches the metrics.
"""

from __future__ import annotations

import threading
from collections import Counter
from typing import Any

from agentsec.gateway.policyset import PolicySet
from agentsec.middleware.audit import AuditSink, RetrySink
from agentsec.middleware.dlp import CATEGORIES, SURFACES

_DLP_ACTIONS = ("monitor", "redact", "block", "allowed")


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: Counter[str] = Counter()
        self._responses: Counter[int] = Counter()
        self._dlp: Counter[tuple[str, str, str]] = Counter()
        self._write_failures = 0
        self.delivery: RetrySink | None = None  # the secondary (SIEM) feed, when configured

    def event(self, name: str) -> None:
        with self._lock:
            self._events[name] += 1

    def dlp(self, data: Any) -> None:
        """Count a dlp_match record by category, surface and action (fixed sets: no content)."""
        if not isinstance(data, dict):
            return
        key = (str(data.get("category")), str(data.get("surface")), str(data.get("action")))
        if key[0] in (*CATEGORIES, "unscanned") and key[1] in SURFACES and key[2] in _DLP_ACTIONS:
            with self._lock:
                self._dlp[key] += 1

    def response(self, status: int) -> None:
        with self._lock:
            self._responses[status] += 1

    def flush(self) -> None:
        if self.delivery:
            self.delivery.flush()

    def write_failed(self) -> None:
        with self._lock:
            self._write_failures += 1

    def snapshot(self) -> dict[str, Any]:
        """One consistent read of every counter (for /metrics and /dashboard)."""
        with self._lock:
            events, responses = dict(self._events), dict(self._responses)
            dlp = dict(self._dlp)
            failures = self._write_failures
        backlog = self.delivery.backlog if self.delivery else 0
        age = self.delivery.last_delivery_age if self.delivery and backlog else 0.0
        return {
            "events": events,
            "responses": responses,
            "dlp": dlp,
            "write_failures": failures,
            "siem_backlog": backlog,
            "siem_age": age,
        }

    def render(self, policies: PolicySet, blocklist_ages: dict[str, float] | None = None) -> str:
        snap = self.snapshot()
        events, responses = snap["events"], snap["responses"]
        failures, backlog, age = snap["write_failures"], snap["siem_backlog"], snap["siem_age"]
        lines = [
            "# HELP agentsec_gateway_events_total Audit events written, by event name.",
            "# TYPE agentsec_gateway_events_total counter",
            *(
                f'agentsec_gateway_events_total{{event="{_label(k)}"}} {v}'
                for k, v in sorted(events.items())
            ),
            "# HELP agentsec_gateway_responses_total HTTP responses sent, by status code.",
            "# TYPE agentsec_gateway_responses_total counter",
            *(
                f'agentsec_gateway_responses_total{{status="{k}"}} {v}'
                for k, v in sorted(responses.items())
            ),
            "# HELP agentsec_gateway_dlp_matches_total Sensitive-data findings, by category, surface and action.",
            "# TYPE agentsec_gateway_dlp_matches_total counter",
            *(
                f'agentsec_gateway_dlp_matches_total{{category="{c}",surface="{s}",action="{a}"}} {v}'
                for (c, s, a), v in sorted(snap["dlp"].items())
            ),
            "# HELP agentsec_gateway_audit_write_failures_total Records the local audit file refused.",
            "# TYPE agentsec_gateway_audit_write_failures_total counter",
            f"agentsec_gateway_audit_write_failures_total {failures}",
            "# HELP agentsec_gateway_siem_backlog_records Written locally, not yet delivered to the SIEM sink.",
            "# TYPE agentsec_gateway_siem_backlog_records gauge",
            f"agentsec_gateway_siem_backlog_records {backlog}",
            "# HELP agentsec_gateway_siem_last_delivery_age_seconds Seconds since the last SIEM delivery; 0 with no backlog.",
            "# TYPE agentsec_gateway_siem_last_delivery_age_seconds gauge",
            f"agentsec_gateway_siem_last_delivery_age_seconds {age:.3f}",
            "# HELP agentsec_gateway_policy_info The policy revision in force.",
            "# TYPE agentsec_gateway_policy_info gauge",
            f'agentsec_gateway_policy_info{{policy_rev="{_label(policies.revision)}"}} 1',
            "# HELP agentsec_gateway_monitor_groups Policy groups in monitor mode (not enforcing).",
            "# TYPE agentsec_gateway_monitor_groups gauge",
            f"agentsec_gateway_monitor_groups {sum(g.mode == 'monitor' for g in policies.groups)}",
        ]
        if policies.expires is not None:
            lines += [
                "# HELP agentsec_gateway_policy_expiry_timestamp_seconds When the policy expires.",
                "# TYPE agentsec_gateway_policy_expiry_timestamp_seconds gauge",
                f"agentsec_gateway_policy_expiry_timestamp_seconds {policies.expires.timestamp()}",
            ]
        if blocklist_ages:
            lines += [
                "# HELP agentsec_gateway_blocklist_age_seconds Age of each egress feed, from its signed issued_at.",
                "# TYPE agentsec_gateway_blocklist_age_seconds gauge",
                *(
                    f'agentsec_gateway_blocklist_age_seconds{{list="{_label(k)}"}} {v:.0f}'
                    for k, v in sorted(blocklist_ages.items())
                ),
            ]
        return "\n".join(lines) + "\n"


class CountingSink:
    """Counts each record after the wrapped sink wrote it; everything else is delegated."""

    def __init__(self, sink: AuditSink, metrics: Metrics) -> None:
        self._sink = sink
        self._metrics = metrics

    def write(self, record: dict[str, Any]) -> None:
        try:
            self._sink.write(record)
        except Exception:
            self._metrics.write_failed()
            raise
        self._metrics.event(str(record.get("event")))
        if record.get("event") == "dlp_match":
            self._metrics.dlp(record.get("data"))

    def __getattr__(self, name: str) -> Any:  # chain_key, last_record, ...
        if name.startswith("_"):  # also stops recursion while copy builds a bare instance
            raise AttributeError(name)
        return getattr(self._sink, name)


def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
