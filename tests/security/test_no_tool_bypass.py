"""Security tests proving no MCP tool dispatch bypasses the policy choke point.

Every ``ToolRegistry.dispatch`` must route through ``enforce()`` (AGENTS.md §5.1).
These tests exercise the dispatch path directly so a future refactor that drops the
enforcement call fails CI.
"""

from pathlib import Path

import pytest
from agents.policies import AuditLogger, PolicyEngine
from agents.tools.guarded import ToolBlockedError
from agents.tools.validation import ValidationError
from mcp.server import Tool, ToolRegistry, build_default_registry


@pytest.mark.security
def test_read_only_tool_dispatches(tmp_path: Path) -> None:
    (tmp_path / "note.txt").write_text("hello", encoding="utf-8")
    registry = build_default_registry(tmp_path)
    result = registry.dispatch("read_text_file", {"path": "note.txt"})
    assert result["content"] == "hello"


@pytest.mark.security
def test_destructive_tool_is_blocked_and_never_runs(tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []

    def _wipe(args: dict[str, object]) -> dict[str, object]:
        calls.append(args)
        return args

    registry = ToolRegistry(root=tmp_path)
    registry.register(
        Tool(name="wipe", description="danger", handler=_wipe, action_class="destructive")
    )
    with pytest.raises(ToolBlockedError):
        registry.dispatch("wipe", {})
    assert calls == []  # the handler never executed — enforcement ran first


@pytest.mark.security
def test_allow_list_lets_a_gated_tool_dispatch(tmp_path: Path) -> None:
    def _sync(args: dict[str, object]) -> dict[str, object]:
        return {"ok": True}

    registry = ToolRegistry(root=tmp_path, policy=PolicyEngine(allow=["sync"]))
    registry.register(
        Tool(name="sync", description="deploy", handler=_sync, action_class="deployment")
    )
    assert registry.dispatch("sync", {})["ok"] is True


@pytest.mark.security
def test_unknown_tool_fails_closed(tmp_path: Path) -> None:
    registry = build_default_registry(tmp_path)
    with pytest.raises(ValidationError):
        registry.dispatch("not_registered", {})


@pytest.mark.security
def test_blocked_dispatch_is_audited(tmp_path: Path) -> None:
    audit = AuditLogger(tmp_path / "audit.log")
    registry = ToolRegistry(root=tmp_path, audit=audit)
    registry.register(
        Tool(name="wipe", description="danger", handler=lambda a: a, action_class="destructive")
    )
    with pytest.raises(ToolBlockedError):
        registry.dispatch("wipe", {})
    assert "tool:wipe" in audit.path.read_text(encoding="utf-8")
    assert audit.verify() is True
