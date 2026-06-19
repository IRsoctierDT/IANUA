"""Security tests for the shared policy-guarded capability primitive."""

from pathlib import Path

import pytest
from agents.policies import AuditLogger, PolicyEngine
from agents.tools.guarded import GuardedCapability, ToolBlockedError, enforce


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine()


@pytest.mark.security
def test_enforce_allows_read_only(engine: PolicyEngine) -> None:
    decision = enforce(action_class="read_only", name="read_x", engine=engine)
    assert decision.decision == "allow"


@pytest.mark.security
def test_enforce_blocks_destructive(engine: PolicyEngine) -> None:
    with pytest.raises(ToolBlockedError):
        enforce(action_class="destructive", name="wipe", engine=engine)


@pytest.mark.security
def test_enforce_denies_boundary_crossing(engine: PolicyEngine) -> None:
    with pytest.raises(ToolBlockedError):
        enforce(action_class="boundary_crossing", name="attack", engine=engine)


@pytest.mark.security
def test_enforce_allow_list_lets_gated_run() -> None:
    eng = PolicyEngine(allow=["sync"])
    assert enforce(action_class="deployment", name="sync", engine=eng).decision == "allow"


@pytest.mark.security
def test_enforce_audits_allow_and_block(tmp_path: Path, engine: PolicyEngine) -> None:
    audit = AuditLogger(tmp_path / "audit.log")
    enforce(action_class="read_only", name="read_x", engine=engine, audit=audit, actor="t")
    with pytest.raises(ToolBlockedError):
        enforce(action_class="destructive", name="wipe", engine=engine, audit=audit, actor="t")
    content = audit.path.read_text(encoding="utf-8")
    assert "tool:read_x" in content
    assert "tool:wipe" in content  # blocked attempt still recorded
    assert audit.verify() is True


@pytest.mark.security
def test_guarded_capability_runs_when_allowed(engine: PolicyEngine) -> None:
    cap = GuardedCapability(lambda x: x + 1, name="inc", action_class="read_only", engine=engine)
    assert cap(41) == 42


@pytest.mark.security
def test_guarded_capability_blocks_and_does_not_run(engine: PolicyEngine) -> None:
    calls: list[int] = []

    def _danger(x: int) -> int:
        calls.append(x)
        return x

    cap = GuardedCapability(_danger, name="wipe", action_class="destructive", engine=engine)
    with pytest.raises(ToolBlockedError):
        cap(1)
    assert calls == []  # the wrapped capability never executed


@pytest.mark.security
def test_tool_blocked_error_is_validation_error() -> None:
    from agents.tools.validation import ValidationError

    assert issubclass(ToolBlockedError, ValidationError)
