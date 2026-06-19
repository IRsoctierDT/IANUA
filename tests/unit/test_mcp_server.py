"""Unit tests for the MCP server stub: allow-list + confinement + policy gating."""

from pathlib import Path

import pytest
from agents.policies import AuditLogger, PolicyEngine
from agents.tools.validation import ValidationError
from mcp.server import Tool, ToolRegistry, build_default_registry


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


@pytest.mark.security
def test_non_readonly_tool_is_blocked_by_policy(tmp_path: Path) -> None:
    """A destructive tool must not run autonomously — policy fails closed (§5.1)."""
    reg = ToolRegistry(root=tmp_path)
    reg.register(Tool("wipe", "danger", lambda a: {"ok": True}, action_class="destructive"))
    with pytest.raises(ValidationError):
        reg.dispatch("wipe", {})


@pytest.mark.security
def test_boundary_crossing_tool_is_denied(tmp_path: Path) -> None:
    reg = ToolRegistry(root=tmp_path)
    reg.register(Tool("attack", "bad", lambda a: {}, action_class="boundary_crossing"))
    with pytest.raises(ValidationError):
        reg.dispatch("attack", {})


@pytest.mark.security
def test_allow_listed_tool_runs(tmp_path: Path) -> None:
    """An operator allow-list entry lets a gated tool run."""
    reg = ToolRegistry(root=tmp_path, policy=PolicyEngine(allow=["sync"]))
    reg.register(Tool("sync", "deploy thing", lambda a: {"ran": True}, action_class="deployment"))
    assert reg.dispatch("sync", {}) == {"ran": True}


@pytest.mark.security
def test_dispatch_is_audited(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "audit.log")
    (tmp_path / "n.txt").write_text("hi", encoding="utf-8")
    reg = build_default_registry(tmp_path, audit=audit)
    reg.dispatch("read_text_file", {"path": "n.txt"})
    assert audit.verify() is True
    assert "tool:read_text_file" in audit.path.read_text(encoding="utf-8")


@pytest.mark.security
def test_blocked_tool_is_audited(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "audit.log")
    reg = ToolRegistry(root=tmp_path, audit=audit)
    reg.register(Tool("wipe", "danger", lambda a: {}, action_class="destructive"))
    with pytest.raises(ValidationError):
        reg.dispatch("wipe", {})
    # The blocked attempt is still recorded.
    assert "require_approval" in audit.path.read_text(encoding="utf-8")
    assert audit.verify() is True
