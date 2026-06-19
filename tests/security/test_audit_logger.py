"""Security tests for the tamper-evident audit logger (AGENTS.md §3)."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from agents.policies import AuditLogger, PolicyEngine, guard


def _fixed_clock() -> Iterator[str]:
    n = 0
    while True:
        yield f"2026-06-19T00:00:{n:02d}+00:00"
        n += 1


@pytest.fixture
def logger(tmp_path: Path) -> AuditLogger:
    gen = _fixed_clock()
    return AuditLogger(tmp_path / "audit.log", clock=lambda: next(gen))


@pytest.mark.security
def test_record_returns_chained_events(logger: AuditLogger) -> None:
    e0 = logger.record(
        actor="a", action="x", action_class="read_only", decision="allow", reason="r"
    )
    e1 = logger.record(
        actor="a", action="y", action_class="destructive", decision="deny", reason="r"
    )
    assert e0.seq == 0 and e1.seq == 1
    assert e1.prev_hash == e0.entry_hash  # chained
    assert e0.prev_hash == "0" * 64  # genesis


@pytest.mark.security
def test_verify_intact_chain(logger: AuditLogger) -> None:
    for i in range(3):
        logger.record(
            actor="a", action=f"x{i}", action_class="read_only", decision="allow", reason="r"
        )
    assert logger.verify() is True


@pytest.mark.security
def test_verify_detects_edit(logger: AuditLogger) -> None:
    logger.record(actor="a", action="orig", action_class="destructive", decision="deny", reason="r")
    logger.record(actor="a", action="next", action_class="read_only", decision="allow", reason="r")
    tampered = logger.path.read_text(encoding="utf-8").replace("orig", "edited")
    logger.path.write_text(tampered, encoding="utf-8")
    assert logger.verify() is False


@pytest.mark.security
def test_verify_detects_deletion(logger: AuditLogger) -> None:
    for i in range(3):
        logger.record(
            actor="a", action=f"x{i}", action_class="read_only", decision="allow", reason="r"
        )
    lines = logger.path.read_text(encoding="utf-8").splitlines()
    del lines[1]  # remove the middle entry
    logger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert logger.verify() is False


@pytest.mark.security
def test_empty_log_verifies(tmp_path: Path) -> None:
    assert AuditLogger(tmp_path / "none.log").verify() is True


@pytest.mark.security
def test_guard_evaluates_and_records(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path / "audit.log")
    engine = PolicyEngine()
    decision = guard("Delete the database", engine=engine, logger=logger, actor="orchestrator")
    assert decision.decision == "require_approval"
    assert logger.verify() is True
    content = logger.path.read_text(encoding="utf-8")
    assert "orchestrator" in content
    assert "require_approval" in content
