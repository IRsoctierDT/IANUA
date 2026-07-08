"""Security tests for audit-log rotation & retention (Hardening Roadmap #2).

The tamper-evident hash chain must remain unbroken *across* rotation and
retention pruning, and any dropped/edited segment — or a removed checkpoint —
must be caught by ``verify()``.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from agents.policies import AuditLogger


def _counter_clock() -> Iterator[str]:
    n = 0
    while True:
        yield f"2026-01-01T00:00:{n:02d}Z"
        n += 1


def _logger(path: Path, **kw: object) -> AuditLogger:
    gen = _counter_clock()
    return AuditLogger(path, clock=lambda: next(gen), **kw)  # type: ignore[arg-type]


def _emit(logger: AuditLogger, n: int) -> None:
    for i in range(n):
        logger.record(
            actor="mcp", action=f"act{i}", action_class="read_only", decision="allow", reason="ok"
        )


# ---------------------------------------------------------------- config guards
@pytest.mark.security
@pytest.mark.parametrize("bad", [{"max_bytes": 0}, {"max_bytes": -1}, {"retain_segments": -1}])
def test_rejects_invalid_retention_config(tmp_path: Path, bad: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        AuditLogger(tmp_path / "audit.log", **bad)  # type: ignore[arg-type]


# ------------------------------------------------------------- back-compat
@pytest.mark.security
def test_unrotated_log_behaves_as_before(tmp_path: Path) -> None:
    log = _logger(tmp_path / "audit.log")  # no rotation configured
    _emit(log, 5)
    assert log.verify() is True
    assert not list(tmp_path.glob("audit.log.*"))  # no archives
    assert log._read_checkpoint() is None


# ------------------------------------------------------------- rotation
@pytest.mark.security
def test_rotation_creates_archives_and_chain_is_continuous(tmp_path: Path) -> None:
    log = _logger(tmp_path / "audit.log", max_bytes=1)  # rotate every append
    _emit(log, 4)
    archives = sorted(p.name for p in tmp_path.glob("audit.log.[0-9]*"))
    assert archives  # rotation happened
    assert log.verify() is True  # chain intact across all segments

    # seq is continuous (never resets to 0 in a later segment).
    seqs: list[int] = []
    for seg in [
        *sorted(tmp_path.glob("audit.log.[0-9]"), key=lambda p: int(p.suffix[1:])),
        tmp_path / "audit.log",
    ]:
        for line in seg.read_text(encoding="utf-8").splitlines():
            if line.strip():
                seqs.append(json.loads(line)["seq"])
    assert seqs == list(range(len(seqs)))  # 0,1,2,3 unbroken


# ------------------------------------------------------------- retention
@pytest.mark.security
def test_retention_prunes_old_segments_but_stays_verifiable(tmp_path: Path) -> None:
    log = _logger(tmp_path / "audit.log", max_bytes=1, retain_segments=2)
    _emit(log, 6)
    archives = list(tmp_path.glob("audit.log.[0-9]*"))
    assert len(archives) <= 2  # older segments pruned
    assert log._read_checkpoint() is not None  # pruning recorded a checkpoint
    assert log.verify() is True  # retained window still verifies via checkpoint


# ------------------------------------------------------------- tamper detection
@pytest.mark.security
def test_editing_an_archived_entry_is_detected(tmp_path: Path) -> None:
    log = _logger(tmp_path / "audit.log", max_bytes=1)
    _emit(log, 4)
    archive = sorted(tmp_path.glob("audit.log.[0-9]"), key=lambda p: int(p.suffix[1:]))[0]
    rec = json.loads(archive.read_text(encoding="utf-8").splitlines()[0])
    rec["reason"] = "tampered"  # edit content, leave hashes
    archive.write_text(json.dumps(rec) + "\n", encoding="utf-8")
    assert log.verify() is False


@pytest.mark.security
def test_dropping_a_whole_segment_is_detected(tmp_path: Path) -> None:
    log = _logger(tmp_path / "audit.log", max_bytes=1)
    _emit(log, 5)
    archives = sorted(tmp_path.glob("audit.log.[0-9]"), key=lambda p: int(p.suffix[1:]))
    archives[1].unlink()  # remove a middle segment -> gap in the chain
    assert log.verify() is False


@pytest.mark.security
def test_removing_the_checkpoint_after_pruning_is_detected(tmp_path: Path) -> None:
    log = _logger(tmp_path / "audit.log", max_bytes=1, retain_segments=2)
    _emit(log, 6)
    assert log.verify() is True
    log._checkpoint_path.unlink()  # attacker drops the anchor
    # Oldest retained entry no longer starts at genesis and has no checkpoint.
    assert log.verify() is False
