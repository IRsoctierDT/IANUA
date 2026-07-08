"""Tests for on-demand audit retention and the scheduled maintenance CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from agents.policies import AuditLogger
from scripts import audit_maintenance


def _emit(logger: AuditLogger, n: int) -> None:
    for i in range(n):
        logger.record(
            actor="mcp", action=f"a{i}", action_class="read_only", decision="allow", reason="ok"
        )


# ---------------------------------------------------------------- apply_retention
def test_apply_retention_rotates_and_prunes(tmp_path: Path) -> None:
    log = AuditLogger(tmp_path / "audit.log", max_bytes=1, retain_segments=2)
    _emit(log, 3)  # each record rotates (max_bytes=1)
    # Fill the active log, then apply on demand.
    summary = log.apply_retention()
    assert summary["rotated"] is True
    assert isinstance(summary["archives"], int)
    assert len(list(tmp_path.glob("audit.log.[0-9]*"))) <= 2  # retention enforced
    assert log.verify() is True  # chain intact across rotation


def test_apply_retention_is_idempotent(tmp_path: Path) -> None:
    log = AuditLogger(tmp_path / "audit.log", max_bytes=10_000, retain_segments=5)
    _emit(log, 2)
    first = log.apply_retention()
    second = log.apply_retention()
    assert first["rotated"] is False and second["rotated"] is False
    assert log.verify() is True


def test_apply_retention_does_not_change_the_head_signature(tmp_path: Path) -> None:
    key = b"maint-test-key"
    log = AuditLogger(tmp_path / "audit.log", max_bytes=1, retain_segments=3, signing_key=key)
    _emit(log, 3)
    assert log.verify() is True
    log.apply_retention()  # rotates; head (and its signature) unchanged
    assert log.verify() is True
    assert log.verify_signature() is True


# ---------------------------------------------------------------- CLI
def test_cli_verifies_then_applies(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "audit.log"
    _emit(AuditLogger(path, max_bytes=1), 3)
    code = audit_maintenance.main(
        ["--log", str(path), "--max-bytes", "1", "--retain-segments", "2"]
    )
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["verified"] is True
    assert "archives" in out


def test_cli_fails_closed_on_tampered_log(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "audit.log"
    _emit(AuditLogger(path), 3)
    # Tamper: flip a character in the middle entry.
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace("allow", "DENY!", 1)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    before = path.read_bytes()

    code = audit_maintenance.main(
        ["--log", str(path), "--max-bytes", "1", "--retain-segments", "2"]
    )
    assert code == 2  # fail closed
    assert path.read_bytes() == before  # log left untouched (not rotated)
    assert '"verified": false' in capsys.readouterr().err


def test_cli_no_verify_skips_the_check(tmp_path: Path) -> None:
    path = tmp_path / "audit.log"
    _emit(AuditLogger(path), 2)
    assert audit_maintenance.main(["--log", str(path), "--no-verify"]) == 0


def test_cli_rejects_bad_config(tmp_path: Path) -> None:
    assert audit_maintenance.main(["--log", str(tmp_path / "a.log"), "--max-bytes", "0"]) == 3
