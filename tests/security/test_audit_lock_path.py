# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The audit chain lock is opened by descriptor and refuses anything but a file (#69).

``AuditLogger._exclusive`` used to open the lock with ``open(path, "a")`` and then
take a *blocking* ``LOCK_EX``. Measured before the fix: a FIFO at
``audit.log.lock`` made ``record()`` hang indefinitely — and since every guarded
action records, every guarded action hung with it; a symlink at the lock path was
followed and its target created ``0o600`` wherever it pointed. The CLI locks got
the descriptor-based open in #58; this is the same shape on the chain's own lock.

The FIFO case runs in a subprocess with a timeout, because the failure mode under
test is a hang, and a hung test process reports nothing.
"""

from __future__ import annotations

import fcntl
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agents.policies.audit import AuditLogger

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RECORD = {
    "actor": "t",
    "action": "a",
    "action_class": "read_only",
    "decision": "allow",
    "reason": "r",
}


def _record_in_subprocess(
    log_path: Path, timeout: float = 15.0
) -> subprocess.CompletedProcess[str]:
    code = (
        "from agents.policies.audit import AuditLogger\n"
        f"AuditLogger({str(log_path)!r}).record(**{_RECORD!r})\n"
    )
    try:
        return subprocess.run(  # noqa: S603 - fixed interpreter, literal code, no user input
            [sys.executable, "-c", code],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"record() hung for {timeout}s on a hostile lock path instead of refusing")


@pytest.mark.security
def test_a_fifo_at_the_lock_path_is_refused_not_blocked_on(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "audit.log.lock")
    result = _record_in_subprocess(tmp_path / "audit.log")
    assert result.returncode != 0, result.stdout
    assert "not a regular file" in result.stderr, result.stderr[-400:]
    assert not (tmp_path / "audit.log").exists(), "an entry was appended without the lock"


@pytest.mark.security
def test_a_symlink_at_the_lock_path_is_refused_and_its_target_untouched(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere" / "victim.lock"
    target.parent.mkdir()
    (tmp_path / "audit.log.lock").symlink_to(target)
    with pytest.raises(OSError):
        AuditLogger(tmp_path / "audit.log").record(**_RECORD)
    assert not target.exists(), "the symlink was followed and its target created"
    assert not (tmp_path / "audit.log").exists(), "an entry was appended without the lock"


@pytest.mark.security
def test_a_directory_at_the_lock_path_is_refused(tmp_path: Path) -> None:
    (tmp_path / "audit.log.lock").mkdir()
    with pytest.raises(OSError):
        AuditLogger(tmp_path / "audit.log").record(**_RECORD)
    assert not (tmp_path / "audit.log").exists()


@pytest.mark.security
def test_a_reader_neither_follows_a_symlinked_lock_nor_creates_one(tmp_path: Path) -> None:
    """A reader takes a shared lock only on a path the writer could lock."""
    log = AuditLogger(tmp_path / "audit.log")
    log.record(**_RECORD)
    lock = tmp_path / "audit.log.lock"
    lock.unlink()
    target = tmp_path / "other.lock"
    target.write_text("", encoding="utf-8")
    lock.symlink_to(target)
    assert log.verify_report().intact is True
    assert lock.is_symlink(), "the reader replaced the planted object"
    lock.unlink()
    os.mkfifo(lock)
    assert log.verify_report().intact is True
    assert not lock.is_file(), "the reader materialised a lock file"


@pytest.mark.security
def test_a_regular_lock_still_serialises_and_is_created_owner_only(tmp_path: Path) -> None:
    """The guard changed how the lock is opened, not what it does once open."""
    log = AuditLogger(tmp_path / "audit.log")
    log.record(**_RECORD)
    lock = tmp_path / "audit.log.lock"
    assert lock.is_file() and lock.stat().st_mode & 0o777 == 0o600
    with (
        lock.open(encoding="utf-8") as handle,
        log._exclusive(),
        pytest.raises(BlockingIOError),
    ):
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
