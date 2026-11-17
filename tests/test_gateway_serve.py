"""The gateway's HTTP server settings, against a real uvicorn: the request-head deadline."""

from __future__ import annotations

import asyncio
import socket
import threading
import time

import pytest

from agentsec.gateway import header_timeout_protocol

uvicorn = pytest.importorskip("uvicorn")

TIMEOUT = 0.5


async def app(scope, receive, send):
    if scope["type"] != "http":
        return
    if scope["path"] == "/slow":
        await asyncio.sleep(3 * TIMEOUT)  # longer than the head deadline
    await send(
        {"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"2")]}
    )
    await send({"type": "http.response.body", "body": b"ok"})


@pytest.fixture(scope="module")
def port():
    # Bound here and handed to uvicorn, so no other process can take the port in between.
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            http=header_timeout_protocol(TIMEOUT),
            ws="none",  # as serve() runs it
            lifespan="off",
            log_level="error",
            timeout_keep_alive=30,  # so only the head deadline can close a connection here
        )
    )
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started
    yield port
    server.should_exit = True
    thread.join(timeout=10)


def connect(port):
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.settimeout(10)
    return sock


def closed_within(sock, seconds):
    """True if the server closes the connection (EOF) within ``seconds``."""
    sock.settimeout(seconds)
    try:
        return sock.recv(1) == b""
    except TimeoutError:
        return False
    except ConnectionError:
        return True


def response(sock):
    data = b""
    while not data.endswith(b"ok"):
        chunk = sock.recv(4096)
        assert chunk, f"connection closed after {data!r}"
        data += chunk
    return data


GET = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"


def test_a_connection_that_sends_nothing_is_closed(port):
    with connect(port) as sock:
        start = time.monotonic()
        assert closed_within(sock, 10 * TIMEOUT)
        assert time.monotonic() - start >= TIMEOUT * 0.8


def test_a_request_head_sent_a_byte_at_a_time_is_closed_at_the_deadline(port):
    with connect(port) as sock:
        start = time.monotonic()
        closed = False
        for byte in b"GET / HTTP/1.1\r\nHost: x\r\nX-Pad: " + b"a" * 200:
            try:
                sock.sendall(bytes([byte]))
            except ConnectionError:
                closed = True
                break
            time.sleep(TIMEOUT / 10)  # every byte arrives well inside the deadline
            if time.monotonic() - start > 3 * TIMEOUT:
                break
        assert closed or closed_within(sock, TIMEOUT)
        assert time.monotonic() - start < 4 * TIMEOUT


def test_requests_are_served_and_a_kept_alive_connection_can_wait(port):
    with connect(port) as sock:
        sock.sendall(GET)
        assert response(sock).startswith(b"HTTP/1.1 200")
        time.sleep(2 * TIMEOUT)  # idle between requests: the keep-alive timer's job, not ours
        sock.sendall(GET)
        assert response(sock).startswith(b"HTTP/1.1 200")


def test_a_slow_response_is_not_cut_off(port):
    with connect(port) as sock:
        sock.sendall(b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
        assert response(sock).startswith(b"HTTP/1.1 200")


def test_a_stalled_second_head_on_a_kept_alive_connection_is_closed(port):
    with connect(port) as sock:
        sock.sendall(GET)
        assert response(sock).startswith(b"HTTP/1.1 200")
        sock.sendall(b"GET / HTTP/1.1\r\nHost")  # and then nothing
        assert closed_within(sock, 10 * TIMEOUT)


def test_an_upgrade_request_is_answered_as_plain_http(port):
    with connect(port) as sock:
        sock.sendall(
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        assert response(sock).startswith(b"HTTP/1.1 200")  # not a 101: no protocol handoff


def test_a_partial_head_pipelined_behind_a_request_is_closed(port):
    with connect(port) as sock:
        sock.sendall(GET + b"GET / HTTP/1.1\r\nHost")
        assert response(sock).startswith(b"HTTP/1.1 200")
        assert closed_within(sock, 10 * TIMEOUT)
