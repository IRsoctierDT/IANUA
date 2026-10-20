# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""A restore made with hard links is refused; a copied restore from a farmed backup is not.

``docs/RESTORE.md`` step 4 is a copy. Done instead with ``cp -al``, ``rsync
--link-dest`` or ``ln``, every live file *is* the backup's file. Measured on main:
``--verify-restore`` exited 0 "restore verified" while its own gate and pass
records appended through the shared inode into the backup's ``audit.log``, which
then failed ``--verify`` for good; and the first re-collected event would have
landed in the backup's store.

This check compares identity with the argued backup. Since #259 the store's own
check refuses any store file with a second name, so ``--verify`` of a backup in a
hard-link snapshot farm of ``data/backups`` now fails on its store; what the last test
here pins is that a copied restore from such a backup still passes the promotion
gate, because no live file is linked.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import time
from pathlib import Path

import pytest

from ingest import normalize
from store import EventStore
from tests._backup_cli import backup_main

_RECORD = 'type=USER_AUTH msg=audit(1760000000.1:1): acct="svc-%d" addr=203.0.113.9 res=failed'
_CHAIN = Path("data") / "events" / "audit.log"
_STORE = Path("data") / "events" / "events.sqlite3"
_REPORT = Path("data") / "reports" / "r.md"


def _fingerprint(path: Path) -> tuple[int, str]:
    return path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest()


def _source_with_backup(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "source"
    source.mkdir()
    now = time.time()
    with EventStore.open(source) as store:
        for index in range(12):
            store.append(normalize(_RECORD % index), ingested_at=store.next_stamp(now + index))
    (source / _REPORT).parent.mkdir(parents=True)
    (source / _REPORT).write_text("# incident\n", encoding="utf-8")
    assert backup_main(["--root", str(source), "--name", "probe", "--caller", "test"]) == 0
    return source, source / "data" / "backups" / "probe"


def _copy_restore(backup: Path, live: Path) -> None:
    (live / "data").mkdir(parents=True)
    shutil.copytree(backup / "data", live / "data", dirs_exist_ok=True)


def _link_tree(source: Path, target: Path) -> None:
    """``cp -al``: the same directories, every file a hard link."""
    for directory, _subdirs, files in os.walk(source):
        here = target / Path(directory).relative_to(source)
        here.mkdir(parents=True, exist_ok=True)
        for name in files:
            os.link(Path(directory) / name, here / name)


def _verify_restore(live: Path, backup: Path) -> int:
    return backup_main(["--root", str(live), "--caller", "test", "--verify-restore", str(backup)])


@pytest.mark.security
def test_a_hard_link_restore_is_refused_before_the_gate_writes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _source, backup = _source_with_backup(tmp_path)
    live = tmp_path / "live"
    _link_tree(backup / "data", live / "data")
    chain = _fingerprint(backup / _CHAIN)
    clean = tmp_path / "clean"
    clean.mkdir()
    capsys.readouterr()

    assert _verify_restore(live, backup) == 1
    err = capsys.readouterr().err
    assert "is the backup's own file (a hard link)" in err, err
    assert _fingerprint(backup / _CHAIN) == chain, "the gate record was written into the backup"
    # And the backup is still a backup once the linked tree is gone. While it exists
    # the backup's store has a second name, which --verify refuses (#259).
    assert backup_main(["--root", str(clean), "--caller", "test", "--verify", str(backup)]) == 1
    shutil.rmtree(live)
    assert backup_main(["--root", str(clean), "--caller", "test", "--verify", str(backup)]) == 0


@pytest.mark.security
@pytest.mark.parametrize("linked", [_STORE, _REPORT])
def test_a_hard_linked_file_in_a_copied_restore_is_a_finding(
    tmp_path: Path, linked: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The chain is copied, so the pass may write; any other file that is the backup's
    own is named, because the next pass or step 5 would write through it."""
    _source, backup = _source_with_backup(tmp_path)
    live = tmp_path / "live"
    _copy_restore(backup, live)
    (live / linked).unlink()
    os.link(backup / linked, live / linked)
    before = _fingerprint(backup / linked)
    capsys.readouterr()

    assert _verify_restore(live, backup) == 1
    out = capsys.readouterr().out
    assert f"LINKED: {linked} in the live root is the backup's own file" in out, out
    assert _fingerprint(backup / linked) == before


@pytest.mark.security
def test_a_hard_link_snapshot_farm_of_the_backups_restores_by_copy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """rsnapshot-style snapshots hard-link every backup file into a second tree. Under
    #259 a store file with a second name is refused wherever it is opened, so --verify
    of either copy names the store's link; the identity check here adds nothing to that.
    What must still hold is the acceptance side of this change: a correct copied restore
    from such a backup passes the promotion gate, because no live file is linked."""
    source, backup = _source_with_backup(tmp_path)
    snapshot = source / "data" / "backups" / "probe-snapshot"
    _link_tree(backup, snapshot)
    assert (backup / _STORE).stat().st_nlink == 2, "the premise: every file has two names"
    live = tmp_path / "live"
    _copy_restore(backup, live)
    capsys.readouterr()

    assert backup_main(["--root", str(source), "--caller", "test", "--verify", str(snapshot)]) == 1
    assert "has 2 hard links" in capsys.readouterr().out
    assert _verify_restore(live, backup) == 0, capsys.readouterr().out
