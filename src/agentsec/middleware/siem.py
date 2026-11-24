"""Send audit records to a SIEM over syslog (UDP, TCP or TLS) or HTTP(S).

Nothing here is SIEM-specific: syslog is RFC 5424 (octet-counted framing on TCP and TLS, RFC
6587/5425) and HTTP is one ``POST`` per record, so any collector that takes syslog or an HTTP
event endpoint works (Splunk, Sentinel, QRadar, Elastic, Graylog, a Vector or Fluent Bit relay).
Each record goes as a CEF line (:func:`~agentsec.middleware.cef.format_cef`) or as the JSON
record itself.

Wrap a network sink in :class:`BackgroundSink` and put that behind the hash-chained file with
:class:`~agentsec.middleware.audit.TeeSink`: the file stays the record, delivery happens off the
request path, and a SIEM that is down only grows the backlog, which is retried oldest first
with backoff.
"""

from __future__ import annotations

import json
import logging
import socket
import ssl
import threading
import time
import urllib.request
from collections import deque
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from agentsec.middleware.cef import format_cef, severity
from agentsec.sandbox.policy_hook import _is_loopback

_LOG = logging.getLogger("agentsec.audit")

FORMATS = ("cef", "json")
MAX_UDP_BYTES = 8192  # larger datagrams are cut; use TCP or TLS for big records
_FACILITY = 13 * 8  # "log audit"


def _render(record: dict[str, Any], fmt: str) -> str:
    if fmt == "cef":
        return format_cef(record)
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _token(value: Any, limit: int = 32) -> str:
    # RFC 5424 header fields: printable ASCII, no spaces, bounded; "-" when empty.
    text = "".join(c for c in str(value or "") if "!" <= c <= "~")[:limit]
    return text or "-"


def _syslog_severity(record: dict[str, Any]) -> int:
    # CEF 0-10 to syslog 7 (debug) .. 2 (critical).
    cef = severity(str(record.get("event", "")), record.get("data") or {})
    return 2 if cef >= 9 else 3 if cef >= 7 else 4 if cef >= 4 else 6


def tls_context(
    ca_file: str | None = None, cert_file: str | None = None, key_file: str | None = None
) -> ssl.SSLContext:
    """A verifying client context: system CAs (or *ca_file*), optional client cert for mTLS."""
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if cert_file:
        ctx.load_cert_chain(cert_file, key_file)
    return ctx


class SyslogSink:
    """Writes each record as one RFC 5424 syslog message.

    ``address`` is ``udp://host:514``, ``tcp://host:601`` or ``tls://host:6514``. Plain UDP and
    TCP are only allowed to a loopback host (a local relay); anything crossing the network must
    use TLS. A failed send closes the connection and raises, so a retrying wrapper resends.
    """

    def __init__(
        self,
        address: str,
        *,
        format: str = "cef",
        timeout_s: float = 5.0,
        ssl_context: ssl.SSLContext | None = None,
        app_name: str = "agentsec",
        hostname: str | None = None,
    ) -> None:
        parts = urlsplit(address)
        if parts.scheme not in ("udp", "tcp", "tls") or not parts.hostname or not parts.port:
            raise ValueError("syslog address must be udp://, tcp:// or tls://host:port")
        if parts.scheme != "tls" and not _is_loopback(parts.hostname):
            raise ValueError("plain udp/tcp syslog only to a loopback relay; use tls:// otherwise")
        if format not in FORMATS:
            raise ValueError(f"format must be one of {FORMATS}")
        self.scheme, self.host, self.port = parts.scheme, parts.hostname, parts.port
        self._format = format
        self._timeout = timeout_s
        self._ctx = ssl_context or (tls_context() if self.scheme == "tls" else None)
        self._app = app_name
        self._hostname = _token(hostname or socket.gethostname(), 255)
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()

    def message(self, record: dict[str, Any]) -> bytes:
        stamp = _token(record.get("ts") or datetime.now(UTC).isoformat(), 64)
        pri = _FACILITY + _syslog_severity(record)
        head = f"<{pri}>1 {stamp} {self._hostname} {self._app} - {_token(record.get('event'))} - "
        return (head + _render(record, self._format)).encode("utf-8")

    def _connect(self) -> socket.socket:
        if self.scheme == "udp":
            sock = socket.socket(
                socket.AF_INET6 if ":" in self.host else socket.AF_INET, socket.SOCK_DGRAM
            )
            sock.connect((self.host, self.port))
            return sock
        sock = socket.create_connection((self.host, self.port), timeout=self._timeout)
        if self._ctx is not None:
            sock = self._ctx.wrap_socket(sock, server_hostname=self.host)
        return sock

    def write(self, record: dict[str, Any]) -> None:
        msg = self.message(record)
        with self._lock:
            try:
                if self._sock is None:
                    self._sock = self._connect()
                if self.scheme == "udp":
                    self._sock.send(msg[:MAX_UDP_BYTES])
                else:
                    self._sock.sendall(b"%d %s" % (len(msg), msg))
            except OSError:
                self.close_locked()
                raise

    def close_locked(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def close(self) -> None:
        with self._lock:
            self.close_locked()

    def last_record(self) -> dict[str, Any] | None:
        return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        raise OSError("SIEM endpoint answered with a redirect; refused")


class HttpSink:
    """POSTs each record to an HTTP event endpoint; any 2xx answer is a delivery.

    https only (plain http only to a loopback host), no redirects, credentials in *headers*.
    shortcut: one request per record; add batching if a SIEM rate-limits requests.
    """

    def __init__(
        self,
        url: str,
        *,
        format: str = "json",
        headers: Mapping[str, str] | None = None,
        timeout_s: float = 5.0,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https" and not (
            parts.scheme == "http" and _is_loopback(parts.hostname or "")
        ):
            raise ValueError("SIEM URL must be https (http only to a loopback host)")
        if parts.username or parts.password:
            raise ValueError("put credentials in headers, not in the SIEM URL")
        if format not in FORMATS:
            raise ValueError(f"format must be one of {FORMATS}")
        self.url = url
        self._format = format
        kind = "application/json" if format == "json" else "text/plain; charset=utf-8"
        self._headers = {"Content-Type": kind, **(headers or {})}
        self._timeout = timeout_s
        handlers: list[Any] = [_NoRedirect]
        if ssl_context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
        self._opener = urllib.request.build_opener(*handlers)

    def write(self, record: dict[str, Any]) -> None:
        body = _render(record, self._format).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - scheme checked in __init__
            self.url, data=body, headers=self._headers, method="POST"
        )
        with self._opener.open(request, timeout=self._timeout) as response:
            if not 200 <= response.status < 300:
                raise OSError(f"SIEM endpoint answered {response.status}")

    def last_record(self) -> dict[str, Any] | None:
        return None


class BackgroundSink:
    """Delivers records to *sink* from a worker thread, in order, retrying with backoff.

    ``write`` only queues, so a slow or unreachable SIEM never delays a request. A failed
    delivery is retried after 1, 2, 4 ... up to *max_backoff_s* seconds. Past *max_backlog*
    queued records the oldest are dropped and counted in ``dropped`` (the audit file still has
    them). The backlog is in memory, so a restart loses it too.
    """

    def __init__(
        self,
        sink: Any,
        *,
        max_backlog: int = 100_000,
        max_backoff_s: float = 60.0,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], Any] | None = None,
    ) -> None:
        self._sink = sink
        self._max = max_backlog
        self._max_backoff = max_backoff_s
        self._clock = clock
        self._pending: deque[dict[str, Any]] = deque()
        self._cond = threading.Condition()
        self._stop = threading.Event()
        self._wait = sleep or self._stop.wait
        self._last_ok = clock()
        self._closed = False
        self.dropped = 0
        self._thread = threading.Thread(target=self._run, name="agentsec-siem", daemon=True)
        self._thread.start()

    def write(self, record: dict[str, Any]) -> None:
        with self._cond:
            if len(self._pending) >= self._max:
                self._pending.popleft()
                self.dropped += 1
            self._pending.append(record)
            self._cond.notify()

    def flush(self) -> None:
        with self._cond:
            self._cond.notify()

    def _run(self) -> None:
        backoff = 1.0
        while True:
            with self._cond:
                while not self._pending and not self._closed:
                    self._cond.wait()
                if not self._pending:
                    return
                record = self._pending[0]
            try:
                self._sink.write(record)
            except Exception:  # noqa: BLE001 - keep the record, back off and retry
                _LOG.exception("SIEM delivery via %s failed", type(self._sink).__name__)
                if self._closed:
                    return
                self._wait(backoff)  # new records do not cut the backoff short
                backoff = min(backoff * 2, self._max_backoff)
                continue
            backoff = 1.0
            with self._cond:
                if self._pending and self._pending[0] is record:
                    self._pending.popleft()
                self._last_ok = self._clock()
                self._cond.notify_all()

    def drain(self, timeout_s: float) -> bool:
        """Wait up to *timeout_s* for the backlog to empty; True if it did."""
        deadline = time.monotonic() + timeout_s
        with self._cond:
            while self._pending:
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                self._cond.wait(min(left, 0.05))
        return True

    def close(self, timeout_s: float = 2.0) -> None:
        self.drain(timeout_s)
        with self._cond:
            self._closed = True
            self._cond.notify_all()
        self._stop.set()
        self._thread.join(timeout_s)
        getattr(self._sink, "close", lambda: None)()

    @property
    def backlog(self) -> int:
        return len(self._pending)

    @property
    def last_delivery_age(self) -> float:
        return self._clock() - self._last_ok

    def last_record(self) -> dict[str, Any] | None:
        return None


__all__ = ["BackgroundSink", "HttpSink", "SyslogSink", "tls_context"]
