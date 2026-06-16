"""Unit tests for the MCP server stub: allow-list + confinement behavior."""

from pathlib import Path

import pytest
from agents.tools.validation import ValidationError
from mcp.server import build_default_registry


@pytest.mark.unit
def test_lists_registered_tools(tmp_path: Path) -> None:
    reg = build_default_registry(tmp_path)
    names = {t["name"] for t in reg.list_tools()}
    assert "read_text_file" in names


@pytest.mark.unit
def test_reads_file_within_root(tmp_path: Path) -> None:
    (tmp_path / "note.txt").write_text("hello", encoding="utf-8")
    reg = build_default_registry(tmp_path)
    result = reg.dispatch("read_text_file", {"path": "note.txt"})
    assert result["content"] == "hello"


@pytest.mark.security
def test_unknown_tool_is_rejected(tmp_path: Path) -> None:
    reg = build_default_registry(tmp_path)
    with pytest.raises(ValidationError):
        reg.dispatch("definitely_not_registered", {})


@pytest.mark.security
def test_traversal_outside_root_is_blocked(tmp_path: Path) -> None:
    reg = build_default_registry(tmp_path)
    with pytest.raises(ValidationError):
        reg.dispatch("read_text_file", {"path": "../../etc/passwd"})


@pytest.mark.security
def test_missing_path_arg_is_rejected(tmp_path: Path) -> None:
    reg = build_default_registry(tmp_path)
    with pytest.raises(ValidationError):
        reg.dispatch("read_text_file", {})
