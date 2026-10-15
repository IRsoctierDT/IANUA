# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Security tests: the event store is owner-only, like every other state file.

AGENTS.md §5 treats logs and anything under ``data/`` as sensitive by default,
and `pipeline/cursor.py`, `collect/offsets.py` and the audit log all create
their state 0o600 inside 0o700. The event database — the one file that holds
*every collected event* — was the only writer under the lab-data root created
at the process umask and never narrowed: measured at 0o644 inside 0o755, so a
byte offset was protected while the evidence it pointed at was readable by
every local account. Found by review.

POSIX-only: mode bits are not meaningful on Windows.
"""

from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest

from ingest import normalize
from store import EventStore

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits required")

_RECORD = "type=SYSCALL msg=audit(1760000001.200:2): node=web-01 auid=svc comm=bash"


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.mark.security
def test_the_event_database_and_its_directory_are_owner_only(tmp_path: Path) -> None:
    """The database, both WAL sidecars, and the enclosing directory."""
    with EventStore.open(tmp_path) as store:
        store.append(normalize(_RECORD), ingested_at=1_000.0)
        database = store.path
        assert _mode(database.parent) == 0o700, "the events directory is not owner-only"
        assert _mode(database) == 0o600, "the event database is not owner-only"
        for suffix in ("-wal", "-shm"):
            sidecar = database.with_name(database.name + suffix)
            if sidecar.exists():
                assert _mode(sidecar) == 0o600, f"{sidecar.name} is not owner-only"


@pytest.mark.security
def test_an_existing_wide_store_is_narrowed_when_reopened(tmp_path: Path) -> None:
    """The upgrade path matters more than the creation path.

    Every store written before this change is 0o644 in a 0o755 directory, and
    an operator will not know to chmod it. Reopening narrows both, so a
    deployed store corrects itself on the next pass rather than staying wide
    until someone reads a release note.
    """
    with EventStore.open(tmp_path) as store:
        store.append(normalize(_RECORD), ingested_at=1_000.0)
        database = store.path

    database.chmod(0o644)
    database.parent.chmod(0o755)
    assert _mode(database) == 0o644

    with EventStore.open(tmp_path) as store:
        assert _mode(database) == 0o600, "reopening did not narrow the database"
        assert _mode(database.parent) == 0o700, "reopening did not narrow the directory"
        # And it is still usable, which is the point of narrowing rather than refusing.
        assert store.count() == 1


@pytest.mark.security
def test_the_directory_mode_is_what_protects_the_contents(tmp_path: Path) -> None:
    """Stated as the code states it, so the weaker claim is the tested one.

    SQLite creates the database and its sidecars at the umask default and may
    recreate a sidecar on any later write, so the file modes cannot be
    guaranteed for the whole lifetime. The 0o700 directory is the control; the
    file modes are defence in depth. This pins the control.
    """
    with EventStore.open(tmp_path) as store:
        store.append(normalize(_RECORD), ingested_at=1_000.0)
        events_dir = store.path.parent
    assert not _mode(events_dir) & stat.S_IRGRP
    assert not _mode(events_dir) & stat.S_IROTH
    assert not _mode(events_dir) & stat.S_IXGRP
    assert not _mode(events_dir) & stat.S_IXOTH
