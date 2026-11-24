"""Model-upstream failure paths: timeouts, bad statuses, broken bodies and cut streams.

Most tests run the real transports against a local socket server that misbehaves on purpose,
so what is checked is what a deployed gateway does, not what a fake transport claims.
"""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
from collections.abc import Callable, Iterator

import pytest

from agentsec.gateway import Gateway, UpstreamError
from agentsec.gateway.app import http_stream_transport, http_transport
from agentsec.gateway.config import Upstream
from agentsec.middleware.audit import MemorySink
from tests.test_gateway import FakeUpstream, call, chat, write_config
from tests.test_gateway_holdback import HOLDBACK, FakeStream, content, sse, words

KEY = "test-upstream-key-" + "q7" * 6  # not secret-shaped: only its absence is checked
INTERNAL = "http://10.9.8.7:9999/internal/billing"  # what an upstream error body may name

Handler = Callable[[socket.socket, bytes], None]


def _read_request(conn: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        got = conn.recv(65536)
        if not got:
            return data
        data += got
    head, _, rest = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n"):
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value)
    while len(rest) < length:
        rest += conn.recv(65536)
    return head + b"\r\n\r\n" + rest


class StubUpstream:
    """A raw-socket model server; ``handler`` writes whatever bytes the test wants."""

    def __init__(self) -> None:
        self.handler: Handler = lambda conn, req: None
        self.requests: list[bytes] = []
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.url = f"http://127.0.0.1:{self._sock.getsockname()[1]}/v1"
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn: socket.socket) -> None:
        with conn:
            try:
                req = _read_request(conn)
                self.requests.append(req)
                self.handler(conn, req)
            except OSError:
                pass  # the gateway hung up, as it should on a timeout

    def close(self) -> None:
        self._stop.set()
        self._sock.close()


@pytest.fixture
def stub() -> Iterator[StubUpstream]:
    server = StubUpstream()
    yield server
    server.close()


def respond(status: str, body: bytes, ctype: str = "application/json", extra: bytes = b""):
    def handler(conn: socket.socket, req: bytes) -> None:
        conn.sendall(
            f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n".encode()
            + extra
            + b"Connection: close\r\n\r\n"
            + body
        )

    return handler


def sse_body(*events: object, done: bool = True) -> bytes:
    out = b"".join(b"data: " + json.dumps(e).encode() + b"\n\n" for e in events)
    return out + (b"data: [DONE]\n\n" if done else b"")


def text_event(text: str) -> dict:
    return {"choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}]}


def completion(text: str = "hello") -> bytes:
    msg = {"role": "assistant", "content": text}
    return json.dumps({"choices": [{"index": 0, "message": msg, "finish_reason": "stop"}]}).encode()


def real_gateway(tmp_path, monkeypatch, stub, *, holdback=False, timeout=0.5, key=KEY):
    monkeypatch.setenv("AGENTSEC_TEST_UPSTREAM_KEY", key)
    extra = (
        "upstreams:\n"
        "  local:\n"
        f"    url: {stub.url}\n"
        "    model: m\n"
        "    api_key: env:AGENTSEC_TEST_UPSTREAM_KEY\n"
        f"limits:\n  upstream_timeout_s: {timeout}\n"
    )
    if holdback:
        extra += HOLDBACK
    sink = MemorySink()
    return Gateway(write_config(tmp_path, extra), sink=sink), sink


def upstream_errors(sink) -> list[dict]:
    return [r["data"] for r in sink.records if r["event"] == "gateway_upstream_error"]


def audit_text(sink) -> str:
    return json.dumps(sink.records)


# ------------------------------------------------------------------ timeouts are bounded


def drip_headers(conn: socket.socket, req: bytes) -> None:
    """A status line, then a header byte now and then: each read is quick, the call is not."""
    conn.sendall(b"HTTP/1.1 200 OK\r\n")
    for _ in range(400):
        conn.sendall(b"X")
        time.sleep(0.05)


def stall_mid_stream(conn: socket.socket, req: bytes) -> None:
    head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
    conn.sendall(head + sse_body(text_event("partial "), done=False))
    time.sleep(10)


def test_an_upstream_dripping_its_headers_is_cut_at_the_deadline(stub):
    stub.handler = drip_headers
    up = Upstream("local", stub.url, "m")
    for transport in (http_transport, lambda *a: list(http_stream_transport(*a))):
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            transport(up, b"{}", 0.4, 10_000)
        assert time.monotonic() - started < 3  # was unbounded: about 20 s here, forever in life


def test_a_dripping_upstream_is_a_504_through_the_gateway(tmp_path, monkeypatch, stub):
    stub.handler = drip_headers
    app, sink = real_gateway(tmp_path, monkeypatch, stub, timeout=0.4)
    started = time.monotonic()
    status, body = call(app, body=chat())
    assert status == 504 and body["error"]["code"] == "upstream_timeout"
    assert time.monotonic() - started < 3
    assert upstream_errors(sink)[-1]["error"] == "timeout"


def test_a_connect_timeout_is_a_timeout_not_an_unreachable_upstream(monkeypatch):
    import http.client

    def slow_connect(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(http.client.socket, "create_connection", slow_connect)
    up = Upstream("local", "http://127.0.0.1:9/v1", "m")
    with pytest.raises(TimeoutError):
        http_transport(up, b"{}", 0.5, 1000)
    with pytest.raises(TimeoutError):
        list(http_stream_transport(up, b"{}", 0.5, 1000))


def test_a_refused_connection_names_the_cause_not_just_urlerror():
    # Windows retries a refused SYN for about 2 s before reporting it; a shorter deadline
    # would turn the refusal into a (correctly reported) connect timeout.
    with pytest.raises(UpstreamError, match="unreachable: ConnectionRefusedError"):
        http_transport(Upstream("local", "http://127.0.0.1:1/v1", "m"), b"{}", 10, 1000)


def test_a_stream_that_stalls_after_release_ends_with_a_timeout_event(tmp_path, monkeypatch, stub):
    def handler(conn: socket.socket, req: bytes) -> None:
        head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
        conn.sendall(head + sse_body(*(text_event(w) for w in words(40)), done=False))
        time.sleep(10)

    stub.handler = handler
    app, sink = real_gateway(tmp_path, monkeypatch, stub, holdback=True, timeout=0.5)
    started = time.monotonic()
    status, text = call(app, body=chat(stream=True))
    events, done = sse(text)
    assert time.monotonic() - started < 4
    assert status == 200 and not done and content(events)
    assert events[-1]["error"]["code"] == "upstream_timeout"
    (error,) = upstream_errors(sink)
    assert error["error"] == "timeout" and error["released_chars"] == len(content(events))


def test_a_stream_that_stalls_before_release_is_a_plain_504(tmp_path, monkeypatch, stub):
    stub.handler = stall_mid_stream
    app, _ = real_gateway(tmp_path, monkeypatch, stub, holdback=True, timeout=0.4)
    status, body = call(app, body=chat(stream=True))
    assert status == 504 and body["error"]["code"] == "upstream_timeout"


# ---------------------------------------------------- bad statuses never leak upstream text


@pytest.mark.parametrize("status", ["429 Too Many Requests", "500 Internal Server Error"])
@pytest.mark.parametrize("holdback", [False, True])
def test_upstream_error_statuses_are_502_without_upstream_text(
    tmp_path, monkeypatch, stub, status, holdback, caplog
):
    error = {"error": {"message": f"quota for key {KEY} exceeded, see {INTERNAL}"}}
    stub.handler = respond(status, json.dumps(error).encode(), extra=b"Retry-After: 30\r\n")
    app, sink = real_gateway(tmp_path, monkeypatch, stub, holdback=holdback)
    with caplog.at_level(logging.DEBUG):
        code, body = call(app, body=chat(stream=holdback))
    assert code == 502 and body["error"]["code"] == "upstream_error"
    assert upstream_errors(sink)[-1]["error"] == f"upstream returned HTTP {status[:3]}"
    # The key went to the upstream, and nowhere else: not the client, the audit or the logs.
    assert f"Bearer {KEY}".encode() in stub.requests[0]
    for where in (json.dumps(body), audit_text(sink), caplog.text):
        assert KEY not in where and "10.9.8.7" not in where and "quota" not in where


# ------------------------------------------------------------ broken bodies are 502, not 500


def truncated_chunked(conn: socket.socket, req: bytes) -> None:
    head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n"
    conn.sendall(head + b'\r\n40\r\n{"choices": [')  # the connection closes mid-chunk


def bad_status_line(conn: socket.socket, req: bytes) -> None:
    conn.sendall(b"this is not http\r\n\r\n")


@pytest.mark.parametrize(
    ("handler", "error"),
    [
        (truncated_chunked, "upstream protocol error: IncompleteRead"),
        (bad_status_line, "upstream protocol error: BadStatusLine"),
        (respond("200 OK", b"[" * 50_000), "upstream response is not JSON"),
        (respond("200 OK", b"<html>proxy error</html>", "text/html"), "not JSON"),
        (respond("200 OK", b'{"choices": {"0": {"message": {}}}}'), "response has no message"),
        (respond("200 OK", b'{"choices": "abc"}'), "response has no message"),
        (respond("200 OK", b'{"error": {"message": "overloaded"}}'), "response has no message"),
        (respond("200 OK", completion("x" * 70_000)), "upstream response too large"),
    ],
)
def test_malformed_upstream_answers_are_502(tmp_path, monkeypatch, stub, handler, error):
    stub.handler = handler
    monkeypatch.setenv("AGENTSEC_TEST_UPSTREAM_KEY", KEY)
    extra = (
        f"upstreams:\n  local:\n    url: {stub.url}\n    model: m\n"
        "limits:\n  upstream_timeout_s: 2\n  max_response_bytes: 65536\n"
    )
    sink = MemorySink()
    app = Gateway(write_config(tmp_path, extra), sink=sink)
    code, body = call(app, body=chat())
    assert code == 502 and body["error"]["code"] == "upstream_error"
    assert error in upstream_errors(sink)[-1]["error"]
    assert "gateway_error" not in [r["event"] for r in sink.records]


def test_a_truncated_chunked_stream_is_an_upstream_error(stub):
    def handler(conn: socket.socket, req: bytes) -> None:
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
            b'Content-Type: text/event-stream\r\n\r\n80\r\ndata: {"choices"'
        )

    stub.handler = handler
    with pytest.raises(UpstreamError, match="IncompleteRead"):
        list(http_stream_transport(Upstream("local", stub.url, "m"), b"{}", 2, 10_000))


# --------------------------------------------------------- the upstream key stays out of logs


def test_a_key_that_is_not_a_header_value_never_reaches_the_logs(
    tmp_path, monkeypatch, stub, caplog
):
    """An env secret with a trailing newline made http.client raise a ValueError quoting the
    Authorization header, and the gateway logged that traceback: the key, in the log."""
    stub.handler = respond("200 OK", completion())
    app, sink = real_gateway(tmp_path, monkeypatch, stub, key=KEY + "\n")
    with caplog.at_level(logging.DEBUG):
        code, body = call(app, body=chat())
    assert code == 502 and body["error"]["code"] == "upstream_error"
    assert upstream_errors(sink)[-1]["error"] == "upstream api key is not a valid header value"
    assert stub.requests == []  # refused before anything was sent
    for where in (json.dumps(body), audit_text(sink), caplog.text):
        assert KEY not in where


def test_an_unreadable_key_file_is_an_upstream_error_not_an_audit_outage(tmp_path, stub):
    extra = (
        f"upstreams:\n  local:\n    url: {stub.url}\n    model: m\n"
        f"    api_key: file:{tmp_path / 'missing-key'}\n"
    )
    sink = MemorySink()
    app = Gateway(write_config(tmp_path, extra), sink=sink)
    code, _ = call(app, body=chat())
    assert code == 502
    assert upstream_errors(sink)[-1]["error"] == ("upstream api key unavailable: FileNotFoundError")


# -------------------------------------------------------------- cut and broken SSE streams


def test_an_error_event_followed_by_done_is_not_a_finished_answer(tmp_path, monkeypatch, stub):
    """vLLM and LiteLLM report a failure mid-stream as an error event, then send [DONE]. That
    was taken for a whole answer: the cut-off text went out with finish_reason "stop"."""
    pieces = [text_event(w) for w in words(40)]
    err = {"error": {"message": f"CUDA out of memory at {INTERNAL}", "code": 500}}
    stub.handler = respond("200 OK", sse_body(*pieces, err), "text/event-stream")
    app, sink = real_gateway(tmp_path, monkeypatch, stub, holdback=True)
    status, text = call(app, body=chat(stream=True))
    events, done = sse(text)
    assert status == 200 and not done
    assert events[-1]["error"]["code"] == "upstream_error"
    assert not any(e["choices"][0].get("finish_reason") for e in events if e.get("choices"))
    assert upstream_errors(sink)[-1]["error"] == "upstream stream reported an error"
    assert "CUDA" not in text and "CUDA" not in audit_text(sink)
    assert "gateway_response" not in [r["event"] for r in sink.records]


def test_an_error_event_before_any_text_is_a_502(tmp_path, monkeypatch, stub):
    err = {"error": {"message": "overloaded"}}
    stub.handler = respond("200 OK", sse_body(err), "text/event-stream")
    app, _ = real_gateway(tmp_path, monkeypatch, stub, holdback=True)
    status, body = call(app, body=chat(stream=True))
    assert status == 502 and body["error"]["code"] == "upstream_error"


@pytest.mark.parametrize(
    ("tail", "error"),
    [
        (b"", "without [DONE]"),
        (b'data: {"choices": [{"delta": {"content": "tru', "without [DONE]"),
        (b"data: {not json}\n\n", "not JSON"),
    ],
)
def test_a_cut_stream_after_release_is_audited_with_what_was_delivered(
    tmp_path, monkeypatch, stub, tail, error
):
    pieces = [text_event(w) for w in words(40)]
    stub.handler = respond("200 OK", sse_body(*pieces, done=False) + tail, "text/event-stream")
    app, sink = real_gateway(tmp_path, monkeypatch, stub, holdback=True)
    status, text = call(app, body=chat(stream=True))
    events, done = sse(text)
    delivered = content(events)
    assert status == 200 and not done and delivered
    assert events[-1]["error"]["code"] == "upstream_error"
    (record,) = upstream_errors(sink)
    assert error in record["error"] and record["released_chars"] == len(delivered)
    # The delivered text is in the audit trail, as a finished answer's would be.
    outputs = [r["data"] for r in sink.records if r["event"] == "model_output"]
    assert len(outputs) == 1 and outputs[0]["text"]["length"] == len(delivered)


def test_a_violation_in_text_delivered_before_a_cut_is_flagged(tmp_path):
    """The final check never ran on a cut stream, so a protected string longer than the
    window, already sent, left no trace of the leak."""
    protected = "P" * 120
    extra = HOLDBACK + f"  protected: [{protected}]\n"
    pieces = (
        ["intro " * 10]
        + [protected[i : i + 4] for i in range(0, 120, 4)]
        + words(20)
        + ["never sent"]
    )
    stream = FakeStream(pieces=pieces, fail_at=len(pieces) - 1)
    sink = MemorySink()
    cfg = write_config(tmp_path, extra)
    app = Gateway(cfg, transport=FakeUpstream(), stream_transport=stream, sink=sink)
    status, text = call(app, body=chat(stream=True))
    events, done = sse(text)
    assert status == 200 and not done and protected in content(events)
    assert events[-1]["error"]["code"] == "upstream_error"
    record = next(
        r["data"] for r in sink.records if r["event"] == "gateway_output_violation_after_delivery"
    )
    assert record["severity"] == "high" and record["interrupted"] is True


def test_an_unexpected_failure_mid_stream_is_audited(tmp_path):
    """Only UpstreamError and timeouts were audited; anything else after the first chunk was
    an error event for the client and a log line, with no audit record of the request's end."""

    def broken(upstream, body, timeout, max_bytes):
        def events():
            for w in words(40):
                yield text_event(w)
            raise RuntimeError("bug in a transport")

        return events()

    sink = MemorySink()
    cfg = write_config(tmp_path, HOLDBACK)
    app = Gateway(cfg, transport=FakeUpstream(), stream_transport=broken, sink=sink)
    status, text = call(app, body=chat(stream=True))
    events, done = sse(text)
    assert status == 200 and not done
    assert events[-1]["error"]["code"] == "internal_error"
    assert "bug in a transport" not in text
    error = next(r["data"] for r in sink.records if r["event"] == "gateway_error")
    assert error["error"] == "RuntimeError"
    assert error["released_chars"] == len(content(events))


def test_a_client_disconnect_records_the_delivered_text(tmp_path):
    import asyncio

    from tests.test_gateway import USER

    sink = MemorySink()
    cfg = write_config(tmp_path, HOLDBACK)
    app = Gateway(
        cfg, transport=FakeUpstream(), stream_transport=FakeStream(pieces=words(80)), sink=sink
    )
    scope = {"type": "http", "method": "POST", "path": "/v1/chat/completions"}
    scope |= {"headers": USER, "client": ("127.0.0.1", 1)}
    body = json.dumps(chat(stream=True)).encode()
    sent = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        if message["type"] == "http.response.body" and len(sent) > 2:
            raise OSError("client went away")
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    names = [r["event"] for r in sink.records]
    assert "gateway_client_disconnected" in names and "model_output" in names


# ------------------------------------------------- tool calls with broken arguments fail closed


@pytest.mark.parametrize("arguments", ['{"q": "ca', "[1, 2]", '"just a string"', "{" * 5000])
def test_tool_calls_with_invalid_arguments_are_withheld_in_both_stream_modes(tmp_path, arguments):
    tc = {"id": "u1", "type": "function", "function": {"name": "search", "arguments": arguments}}
    message = {"role": "assistant", "content": None, "tool_calls": [tc]}
    sink = MemorySink()
    stream = FakeStream(tool_calls=[{"index": 0, **tc}], finish="tool_calls")
    app = Gateway(
        write_config(tmp_path, HOLDBACK),
        transport=FakeUpstream(message=message),
        stream_transport=stream,
        sink=sink,
    )
    status, body = call(app, body=chat())
    assert status == 200
    assert "tool_calls" not in body["choices"][0]["message"]
    assert body["choices"][0]["finish_reason"] == "stop"
    status, text = call(app, body=chat(stream=True))
    events, done = sse(text)
    assert status == 200 and done and "tool_calls" not in text
    names = [r["event"] for r in sink.records]
    assert names.count("gateway_tool_call_malformed") == 2


# -------------------------------------------------------- limits hold on failures and streams


def test_failed_upstream_calls_still_count_against_the_rate_limit(tmp_path, monkeypatch, stub):
    stub.handler = respond("503 Service Unavailable", b"busy")
    monkeypatch.setenv("AGENTSEC_TEST_UPSTREAM_KEY", KEY)
    extra = (
        f"upstreams:\n  local:\n    url: {stub.url}\n    model: m\n"
        "limits:\n  upstream_timeout_s: 2\n  requests_per_min: 2\n"
    )
    app = Gateway(write_config(tmp_path, extra), sink=MemorySink())
    assert [call(app, body=chat())[0] for _ in range(3)] == [502, 502, 429]
    assert len(stub.requests) == 2


def test_max_tokens_is_capped_on_streamed_requests(tmp_path):
    stream = FakeStream(pieces=["ok"])
    sink = MemorySink()
    cfg = write_config(tmp_path, HOLDBACK + "limits:\n  max_tokens_cap: 50\n")
    app = Gateway(cfg, transport=FakeUpstream(), stream_transport=stream, sink=sink)
    status, _ = call(app, body=chat(stream=True, max_tokens=100_000, max_completion_tokens=9999))
    assert status == 200
    assert stream.requests[0]["max_tokens"] == 50
    assert "max_completion_tokens" not in stream.requests[0]


def test_a_hung_name_lookup_ends_at_the_call_deadline(monkeypatch):
    real = socket.getaddrinfo
    release = threading.Event()

    def hung(host, *args, **kwargs):
        if host == "hung.invalid":
            release.wait(10)  # a resolver that is not answering
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", hung)
    up = Upstream("local", "http://hung.invalid:9/v1", "m")
    try:
        for call_it in (
            lambda: http_transport(up, b"{}", 0.5, 1000),
            lambda: list(http_stream_transport(up, b"{}", 0.5, 1000)),
        ):
            started = time.monotonic()
            with pytest.raises(TimeoutError):
                call_it()
            assert time.monotonic() - started < 2
    finally:
        release.set()
