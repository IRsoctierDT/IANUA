# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The HA peer-health listener's connection-level bounds (AGENTS.md §5 stage 7).

The stage 7 amendment licenses an inbound listener built from `http.server`,
and those mandated primitives default to a listener **one connection can
stall**. The amendment's audit-write bound covers request *floods* — the path
that needs a key. This file covers the opposite attack, which needs no key, no
valid MAC and triggers no audit write at all, so it is invisible to exactly the
logging that was added to make probing detectable.

Measured on CPython 3.13.17, and identically on 3.11.17 and 3.12.3:
``HTTPServer`` is not threading, ``BaseHTTPRequestHandler.timeout`` is ``None``
and ``TCPServer.request_queue_size`` is ``5``. So ``handle_one_request`` blocks
in ``rfile.readline()`` with no deadline, and one connection that opens and
sends nothing denies service for as long as the attacker holds the socket.

Three kinds of check, because each covers what the others cannot:

1. **Default pins.** The charter quotes these figures. If a future CPython
   changes one, this file goes red and the charter needs re-measuring rather
   than silently resting on a stale number.
2. **A behavioural pair.** The hostile default is shown denying service, and
   the bounded form is shown surviving the identical probe — paired, because
   "served" on its own proves nothing about the probe being real.
3. **A forward AST guard** over the packages a listener could land in. It
   passes trivially today, since no listener exists yet — a guard over zero
   files is vacuous, so each of its rules is also driven against planted
   hostile source to show it can fail.

What this file deliberately does **not** claim to check: the concurrent-worker
cap. ``ThreadingMixIn`` spawns one thread per connection with no ceiling —
measured, 500 silent connections parked 500 threads and ~7.9 MiB of RSS — so
threading without a cap trades the outage for an unbounded leak. A cap is a
runtime quantity, not a structural property an AST walk can read, and the
implementation PR owes its own measured figure for it. Nor does it check a
*request* deadline: the handler ``timeout`` is a per-read deadline, and
measured, 23 one-byte writes at 0.8 s intervals held a worker 18.4 s against a
1.0 s timeout and were answered ``200 OK``.
"""

from __future__ import annotations

import ast
import contextlib
import http.client
import http.server
import socket
import socketserver
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]

#: The packages §7 type-checks, minus ``tests`` — a listener would live in one
#: of these. ``tests`` is excluded on purpose: the behavioural pair below has to
#: be able to build the hostile form in order to demonstrate it.
_SCANNED_PACKAGES = (
    "agents",
    "attack",
    "intel",
    "ingest",
    "store",
    "correlation",
    "pipeline",
    "collect",
    "scripts",
    "dashboard",
    "mcp",
    "rag",
    "compliance",
    "sli",
)

#: Server classes that handle one request at a time. Naming
#: ``socketserver.TCPServer`` as well as ``http.server.HTTPServer`` matters:
#: the serial behaviour comes from ``TCPServer``, and subclassing it directly
#: is the same defect one import away.
_SERIAL_SERVERS = {"HTTPServer", "TCPServer"}

#: Mixins that free the accept loop.
_THREADING_BASES = {"ThreadingMixIn", "ThreadingHTTPServer", "ForkingMixIn"}

#: Handler bases whose ``timeout`` defaults to ``None``.
_HANDLER_BASES = {
    "BaseHTTPRequestHandler",
    "SimpleHTTPRequestHandler",
    "CGIHTTPRequestHandler",
    "StreamRequestHandler",
    "BaseRequestHandler",
}


def _stdlib_limit(name: str) -> int:
    """Read one of ``http.client``'s private per-request size limits.

    ``_MAXLINE`` and ``_MAXHEADERS`` are the real enforcement points — the
    handler reads through ``http.client.parse_headers`` — and typeshed does not
    declare either, so they are read by name rather than as attributes. The
    ``isinstance`` check is the point rather than a formality: an upstream
    rename fails loudly here instead of quietly skipping the pin.
    """
    value = getattr(http.client, name)
    assert isinstance(value, int), f"http.client.{name} is {type(value).__name__}"
    return value


def _base_names(node: ast.ClassDef) -> set[str]:
    """Last name component of every base, so ``http.server.X`` reads as ``X``."""
    names: set[str] = set()
    for base in node.bases:
        if isinstance(base, ast.Name):
            names.add(base.id)
        elif isinstance(base, ast.Attribute):
            names.add(base.attr)
    return names


def _class_level_assignment(node: ast.ClassDef, name: str) -> ast.expr | None:
    """Return the value assigned to ``name`` in the class body, if any."""
    for stmt in node.body:
        targets: list[ast.expr] = []
        if isinstance(stmt, ast.Assign):
            targets = list(stmt.targets)
        elif isinstance(stmt, ast.AnnAssign):
            targets = [stmt.target]
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id == name:
                return stmt.value
    return None


def _module_constants(tree: ast.Module) -> dict[str, float]:
    """Module-level names bound once to a numeric literal.

    Resolved so that ``timeout = _READ_DEADLINE_SECONDS`` passes, which is how
    a real implementation would write it. A guard that rejects the idiomatic
    form is a guard the implementer deletes rather than satisfies. A name bound
    more than once is dropped, since the value at class-definition time is then
    not a single literal.
    """
    # Every name stored anywhere in the module, at any depth. Counting stores
    # over the whole tree rather than over ``tree.body`` is deliberate: a first
    # version counted module-level numeric assignments only, so ``DEADLINE =
    # 5.0`` followed by ``DEADLINE = None`` kept the 5.0 — the second binding
    # was skipped for not being numeric — and the guard passed a listener whose
    # timeout was ``None``. A ``global`` rebinding inside a function is the same
    # hole one scope down. Found by this file's own bypass case, not by review.
    stores: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            stores[node.id] = stores.get(node.id, 0) + 1

    literals: dict[str, float] = {}
    for stmt in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(stmt, ast.Assign):
            targets, value = list(stmt.targets), stmt.value
        elif isinstance(stmt, ast.AnnAssign):
            targets, value = [stmt.target], stmt.value
        if not isinstance(value, ast.Constant):
            continue
        if isinstance(value.value, bool) or not isinstance(value.value, (int, float)):
            continue
        for target in targets:
            if isinstance(target, ast.Name) and stores.get(target.id) == 1:
                literals[target.id] = value.value
    return literals


def _is_positive_number(value: ast.expr | None, constants: dict[str, float]) -> bool:
    """A finite, positive number — a literal, or a module constant that is one.

    ``None``, ``0``, a negative, a ``bool`` and an expression this cannot
    account for are all rejected: ``timeout = 0`` is not a deadline, and an
    unresolvable value is treated as absent rather than assumed benign.
    """
    if isinstance(value, ast.Name):
        resolved = constants.get(value.id)
        return resolved is not None and resolved > 0
    if not isinstance(value, ast.Constant):
        return False
    if isinstance(value.value, bool) or not isinstance(value.value, (int, float)):
        return False
    return value.value > 0


def listener_violations(source: str, filename: str = "<planted>") -> list[str]:
    """Report every connection-level bound a candidate listener module omits.

    A pure function over source text so that the rules can be driven against
    planted hostile source: a guard that has never been shown to fail is a
    guard nobody can trust.
    """
    tree = ast.parse(source, filename=filename)
    constants = _module_constants(tree)
    found: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            called = (
                func.id
                if isinstance(func, ast.Name)
                else func.attr
                if isinstance(func, ast.Attribute)
                else None
            )
            if called in {"HTTPServer", "TCPServer"}:
                found.append(
                    f"{filename}: instantiates {called} directly, which handles one "
                    "request at a time; one silent connection stalls it"
                )
            continue

        if not isinstance(node, ast.ClassDef):
            continue
        bases = _base_names(node)

        if bases & _SERIAL_SERVERS and not bases & _THREADING_BASES:
            found.append(
                f"{filename}:{node.name}: subclasses a serial server "
                f"({sorted(bases & _SERIAL_SERVERS)}) without a threading mixin"
            )

        if bases & (_SERIAL_SERVERS | _THREADING_BASES):
            queue = _class_level_assignment(node, "request_queue_size")
            if not _is_positive_number(queue, constants):
                found.append(
                    f"{filename}:{node.name}: does not set request_queue_size to a "
                    "positive literal; TCPServer's inherited default is 5"
                )

        if bases & _HANDLER_BASES:
            timeout = _class_level_assignment(node, "timeout")
            if not _is_positive_number(timeout, constants):
                found.append(
                    f"{filename}:{node.name}: does not set timeout to a positive "
                    "literal; BaseHTTPRequestHandler's default is None, so a stalled "
                    "read is parked rather than closed"
                )

    return found


def _scanned_modules() -> Iterator[Path]:
    for package in _SCANNED_PACKAGES:
        yield from sorted((_REPO_ROOT / package).rglob("*.py"))


# --------------------------------------------------------------------------
# 1. Default pins — the figures AGENTS.md §5 quotes
# --------------------------------------------------------------------------


@pytest.mark.security
def test_stdlib_http_server_defaults_are_the_ones_the_charter_measured() -> None:
    """Red here means the charter's figures are stale, not that CPython is wrong."""
    assert not issubclass(http.server.HTTPServer, socketserver.ThreadingMixIn), (
        "HTTPServer became threading; AGENTS.md §5 stage 7 reasons from it being serial"
    )
    assert http.server.BaseHTTPRequestHandler.timeout is None
    assert socketserver.TCPServer.request_queue_size == 5
    assert http.server.BaseHTTPRequestHandler.protocol_version == "HTTP/1.0"
    assert _stdlib_limit("_MAXLINE") == 65536
    assert _stdlib_limit("_MAXHEADERS") == 100


@pytest.mark.security
def test_stdlib_bounds_one_request_at_6_25_mib_before_any_body_is_read() -> None:
    """The ceiling an unauthenticated caller can make the node read per connection.

    Measured: 99 header lines pass and 100 answers ``431 Too many headers`` (the
    blank terminator counts toward ``_MAXHEADERS``); a request line of 65,536
    bytes passes and 65,537 answers ``414 URI Too Long``. So the stdlib's own
    pre-dispatch ceiling is the request line plus 99 header lines — 6.25 MiB,
    four orders of magnitude above a health request, which is why the listener
    owes an explicit bound of its own rather than inheriting this one.
    """
    max_line = _stdlib_limit("_MAXLINE")
    request_line = max_line
    header_lines = (_stdlib_limit("_MAXHEADERS") - 1) * max_line
    assert request_line + header_lines == 6_553_600
    assert (request_line + header_lines) / 1024 / 1024 == pytest.approx(6.25)


# --------------------------------------------------------------------------
# 2. The behavioural pair — the hostile default, and the bounded form
# --------------------------------------------------------------------------


class _Handler(http.server.BaseHTTPRequestHandler):
    """Answers the one route a health listener would expose."""

    protocol_version = "HTTP/1.0"

    def do_GET(self) -> None:  # stdlib dispatch name, not our naming choice
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args: object) -> None:
        """Silence the handler; the suite's output is not a web log."""


class _BoundedHandler(_Handler):
    timeout = 0.5


@contextlib.contextmanager
def _listener(
    server_cls: type[socketserver.TCPServer],
    handler_cls: type[http.server.BaseHTTPRequestHandler],
) -> Iterator[tuple[str, int]]:
    """Serve on an ephemeral loopback port for the duration of the block.

    Teardown closes held client sockets *first*, deliberately: ``shutdown()``
    on a stalled serial server never returns, because the flag it sets is only
    read between requests. Measured — the first harness written to time this
    defect deadlocked on exactly that call.
    """
    server = server_cls(("127.0.0.1", 0), handler_cls)
    host, port = server.server_address[0], server.server_address[1]
    assert isinstance(host, str)
    assert isinstance(port, int)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield host, port
    finally:
        with contextlib.suppress(OSError):
            server.shutdown()
        server.server_close()


@contextlib.contextmanager
def _silent_connection(host: str, port: int) -> Iterator[None]:
    """Connect and send nothing, ever. No key, no MAC, no audit write."""
    sock = socket.socket()
    sock.settimeout(2.0)
    sock.connect((host, port))
    try:
        yield
    finally:
        sock.close()
        time.sleep(0.1)  # let the handler observe EOF before teardown


def _health_request(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        client = socket.socket()
        client.settimeout(timeout)
        client.connect((host, port))
        client.sendall(b"GET /health HTTP/1.0\r\n\r\n")
        try:
            return "served" if client.recv(32).startswith(b"HTTP/1.0 200") else "odd"
        finally:
            client.close()
    except OSError as exc:
        return f"denied:{type(exc).__name__}"


@pytest.mark.security
def test_one_silent_connection_denies_service_on_the_stdlib_default() -> None:
    """Not six connections — one. The backlog never enters into it.

    The amendment's audit-write bound cannot see this: the connection never
    reaches HMAC verification, so it is not a rejected request either.
    """
    with _listener(http.server.HTTPServer, _Handler) as (host, port):
        assert _health_request(host, port) == "served", (
            "control: the listener must answer before the probe, or the probe below proves nothing"
        )
        with _silent_connection(host, port):
            assert _health_request(host, port).startswith("denied:")


@pytest.mark.security
def test_threading_plus_a_finite_handler_timeout_survives_the_same_probe() -> None:
    """The bound, measured against the identical probe that denies the default."""
    assert _BoundedHandler.timeout is not None
    with _listener(http.server.ThreadingHTTPServer, _BoundedHandler) as (host, port):
        with _silent_connection(host, port):
            assert _health_request(host, port) == "served"
        assert _health_request(host, port) == "served"


# --------------------------------------------------------------------------
# 3. The forward guard — and proof it can fail
# --------------------------------------------------------------------------


@pytest.mark.security
def test_no_shipped_module_builds_an_unbounded_http_listener() -> None:
    """Passes trivially until a listener lands, and is red the moment one lands
    as a bare ``HTTPServer`` or without a finite timeout and an explicit queue."""
    findings: list[str] = []
    for path in _scanned_modules():
        findings.extend(
            listener_violations(path.read_text(encoding="utf-8"), str(path.relative_to(_REPO_ROOT)))
        )
    assert findings == [], "unbounded listener construction:\n" + "\n".join(findings)


@pytest.mark.parametrize(
    ("planted", "expected"),
    [
        pytest.param(
            "import http.server\nsrv = http.server.HTTPServer(('127.0.0.1', 9), None)\n",
            "instantiates HTTPServer directly",
            id="bare-serial-instantiation",
        ),
        pytest.param(
            "from http.server import HTTPServer\n"
            "class Listener(HTTPServer):\n"
            "    request_queue_size = 16\n",
            "without a threading mixin",
            id="serial-subclass",
        ),
        pytest.param(
            "from socketserver import ThreadingMixIn\n"
            "from http.server import HTTPServer\n"
            "class Listener(ThreadingMixIn, HTTPServer):\n"
            "    pass\n",
            "does not set request_queue_size",
            id="inherited-queue-size",
        ),
        pytest.param(
            "from http.server import BaseHTTPRequestHandler\n"
            "class Handler(BaseHTTPRequestHandler):\n"
            "    timeout = None\n",
            "does not set timeout",
            id="timeout-left-none",
        ),
        pytest.param(
            "from http.server import BaseHTTPRequestHandler\n"
            "class Handler(BaseHTTPRequestHandler):\n"
            "    timeout = 0\n",
            "does not set timeout",
            id="zero-timeout-is-not-a-deadline",
        ),
    ],
)
@pytest.mark.security
def test_the_guard_fires_on_planted_hostile_source(planted: str, expected: str) -> None:
    """A guard that has never been shown to fail is a guard nobody can trust."""
    findings = listener_violations(planted)
    assert any(expected in finding for finding in findings), (
        f"guard missed {expected!r}; it reported {findings}"
    )


@pytest.mark.security
def test_the_guard_accepts_the_bounded_form() -> None:
    """The paired control: the rules must pass what the charter actually licenses."""
    bounded = (
        "from socketserver import ThreadingMixIn\n"
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        "class Listener(ThreadingMixIn, HTTPServer):\n"
        "    request_queue_size = 16\n"
        "    daemon_threads = True\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        "    timeout = 5.0\n"
    )
    assert listener_violations(bounded) == []


@pytest.mark.security
def test_the_guard_resolves_a_named_constant_rather_than_demanding_a_literal() -> None:
    """A guard that rejects the idiomatic form is one the implementer deletes."""
    named = (
        "from socketserver import ThreadingMixIn\n"
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        "READ_DEADLINE_SECONDS = 5.0\n"
        "BACKLOG = 16\n"
        "class Listener(ThreadingMixIn, HTTPServer):\n"
        "    request_queue_size = BACKLOG\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        "    timeout = READ_DEADLINE_SECONDS\n"
    )
    assert listener_violations(named) == []


@pytest.mark.parametrize(
    ("planted", "why"),
    [
        pytest.param(
            "from http.server import BaseHTTPRequestHandler\n"
            "DEADLINE = 0\n"
            "class Handler(BaseHTTPRequestHandler):\n"
            "    timeout = DEADLINE\n",
            "a constant resolving to zero is not a deadline",
            id="constant-resolves-to-zero",
        ),
        pytest.param(
            "from http.server import BaseHTTPRequestHandler\n"
            "DEADLINE = 5.0\n"
            "DEADLINE = None\n"
            "class Handler(BaseHTTPRequestHandler):\n"
            "    timeout = DEADLINE\n",
            "a rebound name has no single value at class-definition time",
            id="constant-rebound",
        ),
        pytest.param(
            "import os\n"
            "from http.server import BaseHTTPRequestHandler\n"
            "class Handler(BaseHTTPRequestHandler):\n"
            "    timeout = float(os.environ['T'])\n",
            "an unresolvable expression is treated as absent, not assumed benign",
            id="constant-from-the-environment",
        ),
        pytest.param(
            "from http.server import BaseHTTPRequestHandler\n"
            "DEADLINE = 5.0\n"
            "def disable() -> None:\n"
            "    global DEADLINE\n"
            "    DEADLINE = 0\n"
            "class Handler(BaseHTTPRequestHandler):\n"
            "    timeout = DEADLINE\n",
            "a global rebinding inside a function is the same hole one scope down",
            id="constant-rebound-via-global",
        ),
    ],
)
@pytest.mark.security
def test_constant_resolution_does_not_become_a_bypass(planted: str, why: str) -> None:
    """Resolving names must not let a non-deadline through under a name."""
    assert any("does not set timeout" in finding for finding in listener_violations(planted)), why
