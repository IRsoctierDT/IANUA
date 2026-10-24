# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Line-delimited JSON-RPC 2.0 transport over stdio for the MCP server stub.

This wires `ToolRegistry` (mcp/server.py) to a concrete transport so an agent
host can speak to it. It implements the three calls a host needs to bootstrap
and use tools:

    * ``initialize``  -> server/capability handshake
    * ``tools/list``  -> advertise the allow-listed tool surface
    * ``tools/call``  -> dispatch one tool (arguments are validated by the tool)

Protocol note: this is a minimal, dependency-free framing (one JSON object per
line) so the gates run offline. For production, swap this module for the
official ``mcp`` Python SDK's stdio server while keeping the same registry --
the security model (allow-list + self-validating tools) is unchanged.

Security (AGENTS.md §3, §5): unknown methods/tools fail closed with a JSON-RPC
error; malformed input never crashes the loop or escapes the registry root.
Every line is untrusted (DESIGN.md §5 boundary 2), so its shape is checked
before anything reads it, and a malformed line gets one error response:

    * not UTF-8, not JSON (``NaN`` and ``Infinity`` included), or past a
      decoder limit (nesting depth, integer length)    -> PARSE_ERROR
    * not an object, or an ``id`` that is not a string,
      number or null                                   -> INVALID_REQUEST
    * a ``tools/call`` whose ``params`` is not an object -> INVALID_PARAMS

The first two carry ``id: null``, because no id can be read from them. Batches
are not supported, so a top-level array is an invalid request like any other
non-object.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, NoReturn, TextIO

from agents.tools.validation import ValidationError
from mcp.server import ToolRegistry, build_default_registry

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "ai-operator-mcp-stub", "version": "0.1.0"}

# JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def _result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _is_valid_id(value: object) -> bool:
    """Whether ``value`` is a JSON-RPC 2.0 id (a string, a number or null).

    Only a valid id is ever echoed. ``bool`` is refused explicitly because it
    subclasses ``int``. A float must be finite: ``1e400`` decodes to ``inf``,
    and echoing it would write ``Infinity``, which is not JSON.
    """
    if isinstance(value, bool):
        return False
    if isinstance(value, float):
        return math.isfinite(value)
    return value is None or isinstance(value, (str, int))


def _reject_constant(token: str) -> NoReturn:
    """Refuse ``NaN``, ``Infinity`` and ``-Infinity``: ``json.loads`` accepts them, JSON does not."""
    raise ValueError(f"not a JSON value: {token}")


def handle_request(registry: ToolRegistry, request: object) -> dict[str, Any] | None:
    """Process one decoded JSON-RPC message; return a response (or None for notifications).

    ``request`` is whatever the line decoded to, so its shape is checked rather
    than assumed: a non-object, or an ``id`` that is not a string, number or
    null, is ``INVALID_REQUEST`` with ``id: null``.
    """
    if not isinstance(request, dict):
        return _error(None, INVALID_REQUEST, "invalid JSON-RPC request")
    req_id = request.get("id")
    if not _is_valid_id(req_id):
        return _error(None, INVALID_REQUEST, "invalid JSON-RPC request")
    method = request.get("method")

    if request.get("jsonrpc") != "2.0" or not isinstance(method, str):
        return _error(req_id, INVALID_REQUEST, "invalid JSON-RPC request")

    # Notifications (no id) get no response.
    is_notification = "id" not in request

    if method == "initialize":
        return _result(
            req_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "serverInfo": SERVER_INFO,
                "capabilities": {"tools": {}},
            },
        )

    if method == "tools/list":
        tools = [
            {"name": t["name"], "description": t["description"], "inputSchema": {"type": "object"}}
            for t in registry.list_tools()
        ]
        return _result(req_id, {"tools": tools})

    if method == "tools/call":
        params = request.get("params", {})
        if not isinstance(params, dict):
            return _error(req_id, INVALID_PARAMS, "'params' must be an object")
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str):
            return _error(req_id, INVALID_PARAMS, "'name' must be a string")
        try:
            output = registry.dispatch(name, arguments)
        except ValidationError as exc:
            # Tool/allow-list violation -> structured tool error, not a crash.
            return _result(
                req_id, {"isError": True, "content": [{"type": "text", "text": str(exc)}]}
            )
        except Exception:
            return _error(req_id, INTERNAL_ERROR, "internal error")
        return _result(req_id, {"isError": False, "content": [{"type": "json", "json": output}]})

    if is_notification:
        return None
    return _error(req_id, METHOD_NOT_FOUND, f"unknown method: {method}")


def serve(registry: ToolRegistry, lines: Iterator[str], out: TextIO) -> None:
    """Run the read-eval-respond loop over an iterator of input lines.

    No input line ends the loop: each non-blank one gets the response
    ``handle_request`` returns, or none when that is ``None`` (a notification).
    ``lines`` must not raise either, so give a byte stream to ``utf8_lines``
    rather than iterating a strict text stream. Two failures are not caught: a
    failed write, since once the host stops reading there is nobody left to
    answer, and tool output ``json.dumps`` cannot encode, which the default
    registry's one tool never returns.
    """
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            # A lone surrogate is an input byte that was not UTF-8 (see utf8_lines).
            raw.encode("utf-8")
            request = json.loads(raw, parse_constant=_reject_constant)
        except (ValueError, RecursionError):
            # ValueError covers JSONDecodeError, UnicodeEncodeError and the
            # int-digit limit; RecursionError is nesting deeper than the
            # decoder's stack. None of them leaves an id to echo.
            out.write(json.dumps(_error(None, PARSE_ERROR, "parse error")) + "\n")
            out.flush()
            continue
        response = handle_request(registry, request)
        if response is not None:
            out.write(json.dumps(response) + "\n")
            out.flush()


def utf8_lines(stream: Iterable[bytes]) -> Iterator[str]:
    """Decode each line of a byte stream for ``serve``, never raising on a bad byte.

    ``surrogateescape`` carries an invalid byte through as a lone surrogate, and
    ``serve`` answers that one line PARSE_ERROR. Iterating ``sys.stdin`` instead
    decodes whole reads with the locale's error handler, which is ``strict``
    under an ordinary UTF-8 locale such as macOS's: one invalid byte raised
    ``UnicodeDecodeError`` out of the loop, and the valid lines read with it
    were never answered.
    """
    for line in stream:
        yield line.decode("utf-8", "surrogateescape")


def main() -> None:  # pragma: no cover - process entrypoint
    """Stdio entrypoint. Root defaults to ./data; override with MCP_ROOT."""
    import os
    import sys

    root = Path(os.environ.get("MCP_ROOT", "./data"))
    registry = build_default_registry(root)
    serve(registry, utf8_lines(sys.stdin.buffer), sys.stdout)


if __name__ == "__main__":  # pragma: no cover
    main()
