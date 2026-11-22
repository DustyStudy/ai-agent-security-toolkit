"""Holdback streaming: text released once checked and behind; tool calls only at the end."""

from __future__ import annotations

import asyncio
import json

import pytest

from agentsec.gateway import ConfigError, Gateway, UpstreamError
from agentsec.gateway.holdback import Holdback, unclosed
from agentsec.middleware.audit import MemorySink
from agentsec.middleware.validators import OutputGuard
from tests.test_gateway import USER, FakeUpstream, call, chat, write_config

HOLDBACK = "output:\n  stream_mode: holdback\n  holdback_chars: 32\n"
SECRET = "AKIA" + "ABCDEFGHIJKLMNOP"


class FakeStream:
    def __init__(self, pieces=(), tool_calls=(), finish="stop", usage=None, fail_at=None):
        self.pieces, self.tool_calls, self.finish, self.usage = pieces, tool_calls, finish, usage
        self.fail_at = fail_at
        self.requests, self.closed = [], False

    def __call__(self, upstream, body, timeout, max_bytes):
        self.requests.append(json.loads(body))
        return self._events()

    def _events(self):
        try:
            for i, piece in enumerate(self.pieces):
                if i == self.fail_at:
                    raise UpstreamError("connection reset")
                yield {
                    "choices": [{"index": 0, "delta": {"content": piece}, "finish_reason": None}]
                }
            for tc in self.tool_calls:
                yield {"choices": [{"index": 0, "delta": {"tool_calls": [tc]}}]}
            yield {"choices": [{"index": 0, "delta": {}, "finish_reason": self.finish}]}
            if self.usage:
                yield {"choices": [], "usage": self.usage}
        finally:
            self.closed = True


def app_for(tmp_path, stream, extra=HOLDBACK, mode="enforce"):
    sink = MemorySink()
    cfg = write_config(tmp_path, extra, mode=mode)
    return Gateway(cfg, transport=FakeUpstream(), stream_transport=stream, sink=sink), sink


def sse(text):
    frames = [f[len("data: ") :] for f in text.split("\n\n") if f.startswith("data: ")]
    done = bool(frames) and frames[-1] == "[DONE]"
    return [json.loads(f) for f in frames if f != "[DONE]"], done


def content(events):
    return "".join(
        e["choices"][0]["delta"].get("content") or "" for e in events if e.get("choices")
    )


def words(n):
    return [f"word{i} " for i in range(n)]


# ------------------------------------------------------------------------ the buffer


def test_text_is_released_only_once_it_is_behind_the_head():
    held = Holdback(OutputGuard.default(), 32)
    out = []
    for piece in words(30):
        out.append(held.feed(piece))
        assert len(held.text) - len(held.released) >= min(32, len(held.text))  # behind the head
    assert out[0] == ""
    assert sum(1 for o in out if o) > 5  # released in steps, not all at the end
    assert held.text == "".join(words(30))
    assert held.text.startswith(held.released)


def test_a_secret_split_across_chunks_is_never_released():
    held = Holdback(OutputGuard.default(), 32)
    pieces = ["intro " * 8, SECRET[:6], SECRET[6:], " and more text" * 8]
    released = "".join(held.feed(p) for p in pieces)
    assert SECRET[:4] not in released
    assert held.buffering


@pytest.mark.parametrize(
    ("text", "cut"),
    [
        ("see ![a](http://x.example/?q=", 4),
        ("see [a](http://x", 4),
        ("ok [1] and <b", 11),
        ("a ```\ncode", 2),
        ("a ```x``` b", 11),
        ("done [a](b) ok", 14),
        ("tail [", 5),
    ],
)
def test_unclosed_constructs_hold_everything_after_them(text, cut):
    assert unclosed(text, fence_open=False) == cut


def test_a_fence_opened_in_released_text_holds_until_closed():
    assert unclosed("more code", fence_open=True) == 0
    assert unclosed("end```after", fence_open=True) == len("end```after")


def test_the_held_text_is_bounded():
    held = Holdback(OutputGuard.default(), 32)
    held.feed("[" + "x" * 300)  # an unclosed link that never closes
    assert held.buffering
    held.feed("y" * 10)
    assert held.text.endswith("y" * 10)


# --------------------------------------------------------------------- the gateway


def test_holdback_streams_checked_text_before_the_answer_ends(tmp_path):
    stream = FakeStream(pieces=words(40), usage={"prompt_tokens": 1, "completion_tokens": 40})
    app, sink = app_for(tmp_path, stream)
    status, text = call(app, body=chat(stream=True, stream_options={"include_usage": True}))
    events, done = sse(text)
    assert status == 200 and done
    assert content(events) == "".join(words(40))
    assert len([e for e in events if e.get("choices")]) > 5
    assert events[0]["choices"][0]["delta"]["role"] == "assistant"
    assert events[-1]["usage"]["completion_tokens"] == 40
    assert stream.requests[0]["stream"] is True
    assert stream.requests[0]["stream_options"] == {"include_usage": True}
    start = next(r for r in sink.records if r["event"] == "gateway_start")
    assert start["data"]["holdback_groups"] == ["*"]
    response = next(r for r in sink.records if r["event"] == "gateway_response")
    assert response["data"]["released_early"] > 0


def test_a_streamed_secret_is_redacted_and_never_sent(tmp_path):
    pieces = ["here it is: ", SECRET[:8], SECRET[8:], " done" * 20]
    app, _ = app_for(tmp_path, FakeStream(pieces=pieces))
    status, text = call(app, body=chat(stream=True))
    events, done = sse(text)
    assert status == 200 and done
    assert SECRET not in text and SECRET[:8] not in text
    assert "here it is" in content(events)


def test_a_violation_found_after_release_ends_the_stream_without_done(tmp_path):
    protected = "P" * 120  # longer than the window, so only the final check sees it whole
    extra = HOLDBACK + f"  protected: [{protected}]\n"
    pieces = ["intro " * 10] + [protected[i : i + 4] for i in range(0, 120, 4)] + [" tail"]
    app, sink = app_for(tmp_path, FakeStream(pieces=pieces), extra=extra)
    status, text = call(app, body=chat(stream=True))
    events, done = sse(text)
    assert status == 200 and not done
    assert events[-1]["error"]["code"] == "output_violation"
    record = next(
        r for r in sink.records if r["event"] == "gateway_output_violation_after_delivery"
    )
    assert record["data"]["severity"] == "high"


def test_streamed_tool_calls_are_assembled_and_checked_at_the_end(tmp_path):
    calls = [
        {"index": 0, "id": "up1", "function": {"name": "search", "arguments": '{"q": "ca'}},
        {"index": 0, "function": {"arguments": 'ts"}'}},
        {"index": 1, "id": "up2", "function": {"name": "delete_repo", "arguments": "{}"}},
    ]
    app, sink = app_for(tmp_path, FakeStream(pieces=["Looking."], tool_calls=calls))
    status, text = call(app, body=chat(stream=True))
    events, done = sse(text)
    assert status == 200 and done
    sent = [tc for e in events for tc in e["choices"][0]["delta"].get("tool_calls", [])]
    assert [tc["function"]["name"] for tc in sent] == ["search"]
    assert json.loads(sent[0]["function"]["arguments"]) == {"q": "cats"}
    assert sent[0]["id"].startswith("call_") and sent[0]["id"] != "up1"
    assert events[-1]["choices"][0]["finish_reason"] == "tool_calls"
    assert any(r["event"] == "gateway_tool_calls_withheld" for r in sink.records)


def test_an_upstream_failure_before_release_is_a_plain_http_error(tmp_path):
    app, _ = app_for(tmp_path, FakeStream(pieces=words(5), fail_at=2))
    status, payload = call(app, body=chat(stream=True))
    assert status == 502 and payload["error"]["code"] == "upstream_error"


def test_an_upstream_failure_after_release_ends_with_an_error_event(tmp_path):
    stream = FakeStream(pieces=words(40), fail_at=30)
    app, sink = app_for(tmp_path, stream)
    status, text = call(app, body=chat(stream=True))
    events, done = sse(text)
    assert status == 200 and not done and content(events)
    assert events[-1]["error"]["code"] == "upstream_error"
    assert stream.closed
    assert any(r["event"] == "gateway_upstream_error" for r in sink.records)


@pytest.mark.parametrize(
    "bad",
    [{"index": 99, "function": {"name": "x"}}, {"index": True}, "not a call"],
)
def test_malformed_streamed_tool_calls_are_upstream_errors(tmp_path, bad):
    app, _ = app_for(tmp_path, FakeStream(tool_calls=[bad]))
    assert call(app, body=chat(stream=True))[0] == 502


def test_a_client_disconnect_stops_the_upstream(tmp_path):
    stream = FakeStream(pieces=words(80))
    app, sink = app_for(tmp_path, stream)
    scope = {"type": "http", "method": "POST", "path": "/v1/chat/completions"}
    scope |= {"headers": USER, "client": ("127.0.0.1", 1)}
    body = json.dumps(chat(stream=True)).encode()
    sent = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        if message["type"] == "http.response.body" and sent:
            raise OSError("client went away")
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    assert stream.closed
    assert any(r["event"] == "gateway_client_disconnected" for r in sink.records)


def test_monitor_mode_delivers_the_original_text(tmp_path):
    pieces = ["key: ", SECRET, " end" * 20]
    app, _ = app_for(tmp_path, FakeStream(pieces=pieces), mode="monitor")
    events, done = sse(call(app, body=chat(stream=True))[1])
    assert done and SECRET in content(events)


def test_buffer_stays_the_default(tmp_path):
    stream = FakeStream(pieces=["never used"])
    app, _ = app_for(tmp_path, stream, extra="")
    status, text = call(app, body=chat(stream=True))
    assert status == 200 and "hello" in text and not stream.requests


def test_non_streaming_requests_ignore_holdback(tmp_path):
    stream = FakeStream(pieces=["never used"])
    app, _ = app_for(tmp_path, stream)
    status, payload = call(app, body=chat())
    assert status == 200 and payload["choices"][0]["message"]["content"] == "hello"
    assert not stream.requests


@pytest.mark.parametrize(
    "extra",
    [
        "output:\n  stream_mode: passthrough\n",
        "output:\n  stream_mode: holdback\n  holdback_chars: 8\n",
        "output:\n  stream_mode: holdback\n  holdback_chars: true\n",
        "output:\n  stream_mode: [holdback]\n",
    ],
)
def test_stream_settings_are_validated(tmp_path, extra):
    with pytest.raises(ConfigError, match="stream_mode|holdback_chars"):
        write_config(tmp_path, extra)


# ------------------------------------------------------------------- the transport


@pytest.fixture
def sse_server():
    import http.server
    import threading

    replies = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - http.server API
            self.rfile.read(int(self.headers["Content-Length"]))
            status, body = replies["next"]
            self.send_response(status)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield replies, f"http://127.0.0.1:{server.server_address[1]}/v1"
    server.shutdown()


def _upstream(url):
    from agentsec.gateway.config import Upstream

    return Upstream(name="local", url=url, model="m")


def test_stream_transport_parses_sse(sse_server):
    from agentsec.gateway.app import http_stream_transport

    replies, url = sse_server
    replies["next"] = (
        200,
        b': keep-alive\n\nevent: x\ndata: {"a": 1}\n\ndata: {"a": 2}\r\n\r\ndata: [DONE]\n\n'
        b'data: {"after": "done"}\n\n',
    )
    assert list(http_stream_transport(_upstream(url), b"{}", 5, 10_000)) == [{"a": 1}, {"a": 2}]


@pytest.mark.parametrize(
    ("status", "body", "limit", "error"),
    [
        (200, b"data: not json\n\n", 10_000, "not JSON"),
        (200, b'data: {"a": "' + b"x" * 500 + b'"}\n\n', 100, "too large"),
        (500, b"", 10_000, "HTTP 500"),
    ],
)
def test_stream_transport_fails_closed(sse_server, status, body, limit, error):
    from agentsec.gateway.app import http_stream_transport

    replies, url = sse_server
    replies["next"] = (status, body)
    with pytest.raises(UpstreamError, match=error):
        list(http_stream_transport(_upstream(url), b"{}", 5, limit))


def test_stream_transport_unreachable():
    from agentsec.gateway.app import http_stream_transport

    # Windows retries a refused SYN for about 2 s before reporting it; a shorter deadline
    # would turn the refusal into a (correctly reported) connect timeout.
    with pytest.raises(UpstreamError, match="unreachable"):
        list(http_stream_transport(_upstream("http://127.0.0.1:1/v1"), b"{}", 10, 1000))


# ------------------------------------------------------- review regressions (Codex)


def chunks(text, size=4):
    return [text[i : i + size] for i in range(0, len(text), size)]


def released_by(guard, text, hold=32):
    held = Holdback(guard, hold)
    return "".join(held.feed(p) for p in chunks(text))


def test_a_quoted_angle_bracket_does_not_close_a_tag():
    text = '<img title=">' + "x" * 100 + '" src="//evil.example/x">' + " " * 100
    assert "evil.example" not in released_by(OutputGuard.default(), text)
    assert unclosed('<a title="x>y" href=z', fence_open=False) == 0


@pytest.mark.parametrize(
    "text",
    [
        "![a]\n\n" + "x " * 80 + "\n\n[a]: //evil.example/x\n" + " " * 100,
        "[a]: //evil.example/x\n\n" + "x " * 80 + "\n\n![a]\n" + " " * 100,
        "![a][b]\n\n" + "x " * 80 + "\n\n[b]: //evil.example/x\n" + " " * 100,
    ],
)
def test_a_reference_image_is_held_to_the_final_check(text):
    released = released_by(OutputGuard.default(), text)
    assert "![" not in released


def test_whitespace_cannot_split_a_protected_string_out_of_the_window():
    guard = OutputGuard.default(protected=("AB",))
    # Spaces do not count toward the window, so "A" is still held when "B" arrives.
    assert released_by(guard, "A" + " " * 100 + "B" + " " * 100) == ""
    released = released_by(guard, "A" + " " * 100 + "B" + " x" * 100)
    assert "A" not in released


def test_a_stream_cut_before_done_is_an_upstream_error(sse_server):
    from agentsec.gateway.app import http_stream_transport

    replies, url = sse_server
    replies["next"] = (200, b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n')
    with pytest.raises(UpstreamError, match=r"without \[DONE\]"):
        list(http_stream_transport(_upstream(url), b"{}", 5, 10_000))


@pytest.mark.parametrize(
    "body",
    [
        b'data: {"a": 1}\r\rdata: [DONE]\r\r',
        b'data: {"a":\ndata: 1}\n\ndata: [DONE]\n\n',
        b'data:{"a": 1}\r\n\r\ndata:[DONE]\r\n\r\n',
    ],
)
def test_stream_transport_handles_sse_line_endings_and_multiline_data(sse_server, body):
    from agentsec.gateway.app import http_stream_transport

    replies, url = sse_server
    replies["next"] = (200, body)
    assert list(http_stream_transport(_upstream(url), b"{}", 5, 10_000)) == [{"a": 1}]


def test_a_stream_exactly_at_the_size_cap_is_accepted(sse_server):
    from agentsec.gateway.app import http_stream_transport

    replies, url = sse_server
    body = b'data: {"a": 1}\r\rdata: [DONE]\r\r'
    replies["next"] = (200, body)
    assert list(http_stream_transport(_upstream(url), b"{}", 5, len(body))) == [{"a": 1}]
