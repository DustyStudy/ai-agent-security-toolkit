"""SIEM export: syslog over UDP/TCP/TLS, HTTP(S), background delivery with retry."""

from __future__ import annotations

import datetime
import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from agentsec.gateway import ConfigError, Gateway
from agentsec.middleware.siem import BackgroundSink, HttpSink, SyslogSink, tls_context
from tests.test_gateway import call, chat, write_config

REC = {"seq": 1, "ts": "2026-11-24T05:00:00+00:00", "event": "tool_decision", "actor": "alice",
       "data": {"tool": "rm", "verdict": "deny"}, "hash": "h1", "prev_hash": "h0"}  # fmt: skip


def _frames(conn: socket.socket, n: int) -> list[bytes]:
    """Read *n* octet-counted syslog frames (RFC 6587)."""
    buf, out = b"", []
    while len(out) < n:
        while b" " not in buf:
            buf += conn.recv(65536)
        size, _, rest = buf.partition(b" ")
        while len(rest) < int(size):
            rest += conn.recv(65536)
        out.append(rest[: int(size)])
        buf = rest[int(size) :]
    return out


class _Listener:
    """A one-connection TCP (optionally TLS) syslog receiver."""

    def __init__(self, n: int, ctx: ssl.SSLContext | None = None) -> None:
        self.server = socket.create_server(("127.0.0.1", 0))
        self.port = self.server.getsockname()[1]
        self.frames: list[bytes] = []
        self._t = threading.Thread(target=self._serve, args=(n, ctx), daemon=True)
        self._t.start()

    def _serve(self, n: int, ctx: ssl.SSLContext | None) -> None:
        conn, _ = self.server.accept()
        if ctx is not None:
            conn = ctx.wrap_socket(conn, server_side=True)
        self.frames = _frames(conn, n)
        conn.close()

    def join(self) -> list[bytes]:
        self._t.join(5)
        self.server.close()
        return self.frames


def test_tcp_syslog_frames_and_header():
    rx = _Listener(2)
    sink = SyslogSink(f"tcp://127.0.0.1:{rx.port}", hostname="gw 1")
    sink.write(REC)
    sink.write({**REC, "event": "x y\nz"})
    first, second = rx.join()
    # <facility 13 (log audit) * 8 + severity> 1 TIMESTAMP HOST APP PROCID MSGID SD MSG
    assert first.startswith(
        b"<108>1 2026-11-24T05:00:00+00:00 gw1 agentsec - tool_decision - CEF:0|"
    )
    assert b"\n" not in second and b" xyz - " in second  # header fields cannot be forged


def test_json_format_over_udp():
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(5)
    SyslogSink(f"udp://127.0.0.1:{rx.getsockname()[1]}", format="json").write(REC)
    msg = rx.recv(65536)
    rx.close()
    assert json.loads(msg.split(b" - ", 2)[2]) == REC


def test_plain_syslog_and_http_only_to_loopback_and_urls_are_checked():
    for bad in ("tcp://siem.example.com:601", "udp://10.0.0.5:514", "tls://host", "ftp://h:1"):
        with pytest.raises(ValueError):
            SyslogSink(bad)
    SyslogSink("tls://siem.example.com:6514")  # no I/O until the first write
    for bad in ("http://siem.example.com/x", "https://u:p@siem.example.com/x"):
        with pytest.raises(ValueError):
            HttpSink(bad)
    with pytest.raises(ValueError):
        HttpSink("https://siem.example.com/x", format="xml")


def _certs(tmp_path):
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(tmp_path / "c.pem"), str(tmp_path / "k.pem")


def test_tls_syslog_verifies_the_server(tmp_path):
    cert, key = _certs(tmp_path)
    server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_ctx.load_cert_chain(cert, key)
    rx = _Listener(1, server_ctx)
    SyslogSink(f"tls://localhost:{rx.port}", ssl_context=tls_context(cert)).write(REC)
    assert b"CEF:0|" in rx.join()[0]
    # Without trusting that CA the handshake fails and the record is not sent.
    rx2 = socket.create_server(("127.0.0.1", 0))
    t = threading.Thread(target=lambda: _accept_tls(rx2, server_ctx), daemon=True)
    t.start()
    with pytest.raises(ssl.SSLError):
        SyslogSink(f"tls://localhost:{rx2.getsockname()[1]}").write(REC)
    t.join(5)
    rx2.close()


def _accept_tls(server, ctx):
    conn, _ = server.accept()
    try:
        ctx.wrap_socket(conn, server_side=True)
    except (ssl.SSLError, OSError):
        pass
    finally:
        conn.close()


class _Http:
    def __init__(self, statuses):
        self.bodies: list[tuple[dict, bytes]] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.bodies.append((dict(self.headers), body))
                code = statuses.pop(0) if statuses else 200
                self.send_response(code)
                if code == 302:
                    self.send_header("Location", "http://127.0.0.1:1/elsewhere")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}/events"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def test_http_posts_each_record_and_errors_raise():
    rx = _Http([200, 500, 302])
    sink = HttpSink(rx.url, headers={"Authorization": "Splunk t0k"})
    sink.write(REC)
    with pytest.raises(OSError):
        sink.write(REC)  # 500
    with pytest.raises(OSError):
        sink.write(REC)  # a redirect is refused, not followed
    rx.close()
    headers, body = rx.bodies[0]
    assert json.loads(body) == REC and headers["Authorization"] == "Splunk t0k"
    assert headers["Content-Type"] == "application/json" and len(rx.bodies) == 3


class _Flaky:
    def __init__(self, fails: int) -> None:
        self.fails, self.got = fails, []

    def write(self, record):
        if self.fails:
            self.fails -= 1
            raise OSError("down")
        self.got.append(record["seq"])


def test_background_delivery_retries_in_order_with_backoff():
    waits: list[float] = []
    target = _Flaky(fails=3)
    bg = BackgroundSink(target, sleep=waits.append)
    for i in range(5):
        bg.write({"seq": i})
    assert bg.drain(5)
    assert target.got == [0, 1, 2, 3, 4]  # nothing lost, nothing reordered
    assert waits == [1.0, 2.0, 4.0]
    bg.close()


def test_background_write_never_blocks_and_the_backlog_is_bounded():
    gate = threading.Event()

    class Stuck:
        def write(self, record):
            gate.wait(5)

    bg = BackgroundSink(Stuck(), max_backlog=3)
    start = time.monotonic()
    for i in range(10):
        bg.write({"seq": i})
    assert time.monotonic() - start < 0.5
    assert bg.backlog <= 3 and bg.dropped >= 6
    gate.set()
    bg.close()


def test_gateway_ships_every_audit_record_to_the_siem(tmp_path, monkeypatch):
    rx = _Http([500])  # the first delivery fails and is retried
    monkeypatch.setenv("SIEM_TOKEN", "s3cret")
    cfg = write_config(
        tmp_path,
        "audit:\n  file: audit.jsonl\n  siem:\n"
        f"    - url: {rx.url}\n      format: json\n      auth: env:SIEM_TOKEN\n"
        "      auth_scheme: Splunk\n",
    )
    from tests.test_gateway import FakeUpstream

    app = Gateway(cfg, transport=FakeUpstream())
    app.metrics.delivery[0]._wait = lambda s: None  # no real backoff sleep in the test
    assert call(app, body=chat())[0] == 200
    assert app.metrics.delivery[0].drain(5)
    rx.close()
    local = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    shipped = [json.loads(b) for _, b in rx.bodies[1:]]
    assert shipped == local and rx.bodies[1][0]["Authorization"] == "Splunk s3cret"


def test_config_checks_siem_entries(tmp_path):
    def cfg(entry: str):
        return write_config(tmp_path, "audit:\n  file: audit.jsonl\n  siem:\n" + entry)

    ok = cfg("    - url: tls://siem.example.com:6514\n")
    assert ok.siem[0].format == "cef"
    for bad in (
        "    - url: tcp://siem.example.com:601\n",  # plain syslog over the network
        "    - url: https://siem.example.com\n      format: xml\n",
        "    - url: https://siem.example.com\n      auth: s3cret\n",  # not a reference
        "    - url: tls://siem.example.com:6514\n      auth: env:X\n",  # auth is HTTP-only
        "    - url: tls://siem.example.com:6514\n      ca_file: missing.pem\n",
        "    - url: https://siem.example.com\n      bogus: 1\n",
        "    - url: https://siem.example.com\n      timeout_s: 0\n",
    ):
        with pytest.raises(ConfigError):
            cfg(bad)
