"""Unit + security tests for the stdio JSON-RPC transport."""

import io
import json
from pathlib import Path

import pytest

from mcp.server import build_default_registry
from mcp.transport import handle_request, serve


def _registry(tmp_path: Path):
    (tmp_path / "note.txt").write_text("hello", encoding="utf-8")
    return build_default_registry(tmp_path)


@pytest.mark.unit
def test_initialize_handshake(tmp_path: Path) -> None:
    resp = handle_request(_registry(tmp_path), {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert resp["result"]["protocolVersion"]
    assert resp["result"]["serverInfo"]["name"] == "ai-operator-mcp-stub"


@pytest.mark.unit
def test_tools_list_advertises_allowlist(tmp_path: Path) -> None:
    resp = handle_request(_registry(tmp_path), {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "read_text_file" in names


@pytest.mark.unit
def test_tools_call_returns_content(tmp_path: Path) -> None:
    req = {
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "read_text_file", "arguments": {"path": "note.txt"}},
    }
    resp = handle_request(_registry(tmp_path), req)
    assert resp["result"]["isError"] is False
    assert resp["result"]["content"][0]["json"]["content"] == "hello"


@pytest.mark.security
def test_unknown_method_fails_closed(tmp_path: Path) -> None:
    resp = handle_request(_registry(tmp_path), {"jsonrpc": "2.0", "id": 4, "method": "danger/exec"})
    assert resp["error"]["code"] == -32601


@pytest.mark.security
def test_traversal_returns_tool_error_not_crash(tmp_path: Path) -> None:
    req = {
        "jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": "read_text_file", "arguments": {"path": "../../etc/passwd"}},
    }
    resp = handle_request(_registry(tmp_path), req)
    assert resp["result"]["isError"] is True


@pytest.mark.security
def test_serve_handles_malformed_line(tmp_path: Path) -> None:
    out = io.StringIO()
    serve(_registry(tmp_path), iter(["not json\n", ""]), out)
    parsed = json.loads(out.getvalue().strip())
    assert parsed["error"]["code"] == -32700  # parse error, loop survived
