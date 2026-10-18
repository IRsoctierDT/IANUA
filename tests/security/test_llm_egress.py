# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The LLM egress allow-list holds where the request actually leaves (AGENTS.md §5).

The only sockets here are loopback listeners the tests start themselves; a
non-loopback connect is impossible by construction (the servers answer on
127.0.0.1 and the generators are built against them).
"""

from __future__ import annotations

import http.server
import json
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

import agents.tools.llm as llm
from agents.tools.llm import LlamaCppGenerator, OllamaGenerator
from agents.tools.validation import ValidationError

EVIL = "http://203.0.113.9:11434"  # RFC 5737 documentation address
OK_PAYLOAD = {"response": "ok", "choices": [{"message": {"content": "ok"}}]}


@pytest.fixture
def serve() -> Iterator[Callable[[type[http.server.BaseHTTPRequestHandler]], str]]:
    """Start loopback HTTP servers on ephemeral ports; returns each one's base URL."""
    servers: list[http.server.HTTPServer] = []

    def start(handler: type[http.server.BaseHTTPRequestHandler]) -> str:
        server = http.server.HTTPServer(("127.0.0.1", 0), handler)
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


class _Quiet(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_: object) -> None:
        pass


def _answer_ok(handler: http.server.BaseHTTPRequestHandler) -> None:
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.end_headers()
    handler.wfile.write(json.dumps(OK_PAYLOAD).encode("utf-8"))


# --- check-then-use ------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize("cls", [OllamaGenerator, LlamaCppGenerator])
def test_generate_sends_the_host_and_timeout_it_validated(
    cls: type[OllamaGenerator] | type[LlamaCppGenerator], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Measured before the fix: with the fields changed right after the check, both generators
    sent the request to the non-allow-listed host with a negative timeout (1,153/100,000 under
    a real writer thread)."""
    sent: list[tuple[str, float]] = []

    def transport(url: str, body: dict[str, object], timeout: float) -> dict[str, object]:
        sent.append((url, timeout))
        return dict(OK_PAYLOAD)

    gen = cls(transport=transport)
    real = llm._validate_local_host

    def validate_then_mutate(host: str, allowed: frozenset[str], timeout: float) -> None:
        real(host, allowed, timeout)
        gen.host, gen.timeout = EVIL, -5  # the window: the object changes after the check

    monkeypatch.setattr(llm, "_validate_local_host", validate_then_mutate)
    gen.generate("prompt")
    assert len(sent) == 1
    assert sent[0][0].startswith("http://127.0.0.1:") and sent[0][1] == 120.0


# --- redirects and proxies are hops the allow-list never saw -------------------


@pytest.mark.security
@pytest.mark.parametrize("code", [301, 302, 303, 307])
@pytest.mark.parametrize("cls", [OllamaGenerator, LlamaCppGenerator])
def test_a_redirect_from_the_model_port_is_refused_not_followed(
    cls: type[OllamaGenerator] | type[LlamaCppGenerator],
    code: int,
    serve: Callable[[type[http.server.BaseHTTPRequestHandler]], str],
) -> None:
    """Measured before the fix: 301/302/303 were followed as GET with the whole prompt in the
    query string, and the redirect target's body came back as the narrative."""
    sink_hits: list[str] = []

    class Sink(_Quiet):
        def do_GET(self) -> None:
            sink_hits.append(self.requestline)
            _answer_ok(self)

        do_POST = do_GET

    sink = serve(Sink)

    class Squatter(_Quiet):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(code)
            self.send_header("Location", f"{sink}/exfil?p=incident-facts")
            self.end_headers()

    gen = cls(host=serve(Squatter))
    with pytest.raises(ValidationError, match="redirect"):
        gen.generate("incident facts: user alice", system="be terse")
    assert sink_hits == []


@pytest.mark.security
def test_http_proxy_in_the_environment_is_ignored(
    serve: Callable[[type[http.server.BaseHTTPRequestHandler]], str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Measured before the fix: ``http_proxy=http://203.0.113.9:3128`` received a request that was
    addressed to loopback — egress to a host the allow-list never saw."""
    proxy_hits: list[str] = []

    class Proxy(_Quiet):
        def do_POST(self) -> None:
            proxy_hits.append(self.requestline)
            _answer_ok(self)

    class Model(_Quiet):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            _answer_ok(self)

    monkeypatch.setenv("http_proxy", serve(Proxy))
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    assert OllamaGenerator(host=serve(Model)).generate("prompt") == "ok"
    assert proxy_hits == []


@pytest.mark.security
def test_llm_module_does_not_call_urlopen_directly() -> None:
    """The opener is the control (no proxy, no redirect); a bare ``urlopen`` would bypass both."""
    source = Path(llm.__file__).read_text(encoding="utf-8")
    assert "urlopen(" not in source
