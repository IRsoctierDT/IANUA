"""Security tests: audit artifacts are created owner-only (0o600 / 0o700).

Audit logs are sensitive by default (AGENTS.md §5). Every artifact the logger
creates — active log, rotated segments, ``.checkpoint`` sidecar, head
signature, and the parent directory — must be readable and writable by the
owner alone at creation time. POSIX-only assertions (mode bits are not
meaningful on Windows).
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest
from agents.policies.audit import AuditLogger

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits required")

_KEY = b"perm-test-key"


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.mark.security
def test_active_log_checkpoint_signature_and_dir_are_owner_only(tmp_path: Path) -> None:
    old_umask = os.umask(0o000)  # permissive umask must not widen the artifacts
    try:
        logger = AuditLogger(
            tmp_path / "audit" / "audit.log",
            signing_key=_KEY,
            max_bytes=1,
            retain_segments=1,
        )
        for i in range(4):  # force rotation + checkpoint + signature
            logger.record(
                actor="tester",
                action=f"a{i}",
                action_class="read_only",
                decision="allow",
                reason="perm test",
            )
    finally:
        os.umask(old_umask)

    assert _mode(logger.path.parent) == 0o700
    assert _mode(logger.path) == 0o600
    assert _mode(logger._sig_path) == 0o600
    assert _mode(logger._checkpoint_path) == 0o600
    for segment in logger.path.parent.glob("audit.log.*"):
        if segment.suffix not in {".sig", ".checkpoint"}:
            assert _mode(segment) == 0o600, segment


@pytest.mark.security
def test_existing_file_permissions_are_not_rewritten(tmp_path: Path) -> None:
    # An operator-chosen scheme (e.g. group-readable) is respected: creation
    # sets 0o600, but appends to an existing file never re-chmod it.
    logger = AuditLogger(tmp_path / "audit.log")
    logger.record(actor="t", action="a", action_class="read_only", decision="allow", reason="r")
    logger.path.chmod(0o640)
    logger.record(actor="t", action="b", action_class="read_only", decision="allow", reason="r")
    assert _mode(logger.path) == 0o640
    assert logger.verify() is True
