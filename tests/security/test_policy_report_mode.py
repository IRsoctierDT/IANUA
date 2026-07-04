"""Security tests for staged-rollout report-only mode on enforce()."""

from pathlib import Path

import pytest
from agents.policies import AuditLogger, PolicyEngine
from agents.tools.guarded import ToolBlockedError, enforce


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine()


@pytest.mark.security
def test_report_only_does_not_raise_on_gated(engine: PolicyEngine) -> None:
    decision = enforce(action_class="destructive", name="wipe", engine=engine, report_only=True)
    assert decision.decision == "require_approval"


@pytest.mark.security
def test_report_only_still_audits_with_marker(tmp_path: Path, engine: PolicyEngine) -> None:
    audit = AuditLogger(tmp_path / "audit.log")
    enforce(
        action_class="destructive",
        name="wipe",
        engine=engine,
        audit=audit,
        actor="mcp",
        report_only=True,
    )
    content = audit.path.read_text(encoding="utf-8")
    assert "tool:wipe" in content
    assert "report-only" in content
    assert audit.verify() is True


@pytest.mark.security
def test_report_only_off_still_fails_closed(engine: PolicyEngine) -> None:
    with pytest.raises(ToolBlockedError):
        enforce(action_class="destructive", name="wipe", engine=engine, report_only=False)


@pytest.mark.security
def test_report_only_leaves_allow_unchanged(engine: PolicyEngine) -> None:
    decision = enforce(action_class="read_only", name="read_x", engine=engine, report_only=True)
    assert decision.decision == "allow"
