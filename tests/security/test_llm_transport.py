# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Through the shipped transport, every failure a local model server can cause is a ValidationError.

That is the type ``incident_report_agent._build_narrative`` degrades on. Measured
before the fix, seven server-controlled failures escaped ``generate()`` as their
raw types and crashed the report build. Raw loopback TCP listeners only, so the
HTTP framing itself can be hostile.
"""

from __future__ import annotations

import socketserver
import threading
from collections.abc import Callable, Iterator

import pytest

from agents.incident_report_agent import _build_narrative
from agents.tools.llm import MAX_RESPONSE_BYTES, OllamaGenerator
from agents.tools.validation import ValidationError


def _http(body: bytes, declared: int | None = None) -> bytes:
    """A 200 response carrying ``body`` — with a lying ``Content-Length`` when asked."""
    length = len(body) if declared is None else declared
    return b"HTTP/1.1 200 OK\r\nContent-Length: " + str(length).encode() + b"\r\n\r\n" + body


class _QuietServer(socketserver.TCPServer):
    def handle_error(self, *_: object) -> None:  # the client may hang up on an oversized reply
        pass


@pytest.fixture
def raw_serve() -> Iterator[Callable[[bytes], str]]:
    """Loopback TCP listeners that answer every connection with ``reply`` verbatim, then hang up."""
    servers: list[socketserver.TCPServer] = []

    def start(reply: bytes) -> str:
        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.recv(65536)
                if reply:
                    self.request.sendall(reply)

        server = _QuietServer(("127.0.0.1", 0), Handler)
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def _assert_fails_closed(gen: OllamaGenerator) -> None:
    with pytest.raises(ValidationError):
        gen.generate("x")
    narrative = _build_narrative({"event_type": "t"}, {"technique_id": "T1"}, gen)
    assert narrative.startswith("_AI narrative unavailable")  # degraded, not crashed


@pytest.mark.security
@pytest.mark.parametrize(
    "reply",
    [
        pytest.param(
            _http(b"9" * 4301), id="4301-digit integer: plain ValueError, not JSONDecodeError"
        ),
        pytest.param(
            _http(b'{"response": "ok", "n": ' + b"9" * 5000 + b"}"), id="over-long int field"
        ),
        pytest.param(_http(b"\xff\xfe"), id="invalid UTF-8"),
        pytest.param(
            _http(b"[" * 100_000 + b"]" * 100_000), id="100000-deep array: RecursionError"
        ),
        pytest.param(_http(b"12345", declared=100), id="short body under Content-Length 100"),
        pytest.param(
            _http(b'"' + b"A" * (MAX_RESPONSE_BYTES + 1) + b'"'), id="body over the bound"
        ),
        pytest.param(_http(b"[]"), id="non-object payload"),
        pytest.param(b"NOT-HTTP garbage\r\n\r\n", id="garbage status line: BadStatusLine"),
        pytest.param(b"", id="closed without a response: RemoteDisconnected"),
        pytest.param(b"HTTP/1.1 200 OK\r\nX: " + b"a" * 70_000 + b"\r\n\r\n{}", id="LineTooLong"),
    ],
)
def test_hostile_reply_from_the_model_server_is_a_validation_error(
    reply: bytes, raw_serve: Callable[[bytes], str]
) -> None:
    _assert_fails_closed(OllamaGenerator(host=raw_serve(reply)))


@pytest.mark.security
def test_a_response_inside_the_bound_still_parses(raw_serve: Callable[[bytes], str]) -> None:
    text = "A" * 1000
    gen = OllamaGenerator(host=raw_serve(_http(f'{{"response": "{text}"}}'.encode())))
    assert gen.generate("x") == text
