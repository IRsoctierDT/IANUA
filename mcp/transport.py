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
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, TextIO

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


def handle_request(registry: ToolRegistry, request: dict[str, Any]) -> dict[str, Any] | None:
    """Process a single JSON-RPC request object; return a response (or None for notifications)."""
    req_id = request.get("id")
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
        params = request.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str):
            return _error(req_id, INVALID_PARAMS, "'name' must be a string")
        try:
            output = registry.dispatch(name, arguments)
        except ValidationError as exc:
            # Tool/allow-list violation -> structured tool error, not a crash.
            return _result(req_id, {"isError": True, "content": [{"type": "text", "text": str(exc)}]})
        except Exception:
            return _error(req_id, INTERNAL_ERROR, "internal error")
        return _result(req_id, {"isError": False, "content": [{"type": "json", "json": output}]})

    if is_notification:
        return None
    return _error(req_id, METHOD_NOT_FOUND, f"unknown method: {method}")


def serve(registry: ToolRegistry, lines: Iterator[str], out: TextIO) -> None:
    """Run the read-eval-respond loop over an iterator of input lines."""
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            request = json.loads(raw)
        except json.JSONDecodeError:
            out.write(json.dumps(_error(None, PARSE_ERROR, "parse error")) + "\n")
            out.flush()
            continue
        response = handle_request(registry, request)
        if response is not None:
            out.write(json.dumps(response) + "\n")
            out.flush()


def main() -> None:  # pragma: no cover - process entrypoint
    """Stdio entrypoint. Root defaults to ./data; override with MCP_ROOT."""
    import os
    import sys

    root = Path(os.environ.get("MCP_ROOT", "./data"))
    registry = build_default_registry(root)
    serve(registry, iter(sys.stdin), sys.stdout)


if __name__ == "__main__":  # pragma: no cover
    main()
