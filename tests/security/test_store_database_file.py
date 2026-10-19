# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The event database itself must not be a hard link or a FIFO when the store opens it.

#257 refused an unsafe ``-journal``, ``-wal`` or ``-shm`` and left the database file to
``store.paths.confine``, which refuses a symlink and nothing else. Measured through every
CLI that opens the live store, on the tree before ``EventStore.open`` stated the file:

* a ``cp -al``-style second name for the store, outside ``data/``, grew by 4 KiB with a
  new digest when the collector ran, at exit 0;
* a 0-byte file outside ``data/`` linked in at the store path was initialised in place,
  0 -> 61440 bytes and 0o644 -> 0o600, by the collector, the pipeline and retention (all
  at exit 0) and by the SLI reporter;
* the backup take and both verifiers exited 0 over a hard-linked store;
* a FIFO read-only to the running account hung the collector, the pipeline and retention
  inside SQLite's open (it retries ``O_RDONLY`` after ``EACCES``), each holding its lock,
  so a second pass printed "skipped" at exit 0; a FIFO it could write gave a bare "disk
  I/O error", and the backup CLI read either as "missing".

Refusal is paired with acceptance: a normal store still opens, and a root with no
database still gets one. The FIFO cases run in a subprocess with a timeout, as in
``test_store_sidecars.py``, because the failure under test is a hang. Run as root, the
read-only FIFO does not hang (root is not refused the ``O_RDWR`` open) and fails the old
code with the "disk I/O error" instead; either way the assertions below are the refusal.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ingest import normalize
from scripts.run_backup import _database_problem
from scripts.run_backup import main as backup_main
from store import (
    EventStore,
    StoreError,
    StoreFileError,
    StorePathError,
    StoreSidecarError,
    refuse_unsafe_database,
)
from tests.security.test_store_sidecars import (
    _CLIS,
    _RECORD,
    _REPO_ROOT,
    _STORE,
    _cli_argv,
    _seeded,
)

_TIMEOUT = 60.0


def _state(path: Path) -> tuple[object, ...]:
    """Type, inode, links, size, mode and (for a regular file) sha256, without following."""
    found = os.lstat(path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest() if stat.S_ISREG(found.st_mode) else ""
    return (
        stat.S_IFMT(found.st_mode),
        found.st_ino,
        found.st_nlink,
        found.st_size,
        stat.S_IMODE(found.st_mode),
        digest,
    )


def _plant(db: Path, case: str, outside: Path) -> Path | None:
    """Put ``case`` at the store path ``db``. Returns the other name a link reaches."""
    victim = outside / "victim.sqlite3"
    if case == "snapshot":
        # A hard-link snapshot: the store keeps its content and gains a name outside.
        os.link(db, victim)
        return victim
    if case == "empty-link":
        # A file outside data/ linked in at the store path, which used to become a store.
        db.unlink()
        victim.write_bytes(b"")
        victim.chmod(0o644)
        os.link(victim, db)
        return victim
    if case == "directory":
        db.unlink()
        db.mkdir()
        return None
    if case == "fifo":
        # Read-only to its owner: the mode that hung a non-root account.
        db.unlink()
        os.mkfifo(db, 0o400)
        db.chmod(0o400)
        return None
    raise AssertionError(case)  # pragma: no cover - a typo in a parametrization


def _sidecars(db: Path) -> list[str]:
    return sorted(path.name for path in db.parent.iterdir() if path.name.startswith(db.name + "-"))


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(  # noqa: S603 - fixed interpreter, literal argv, test paths
            [sys.executable, *argv],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"{argv[0]} blocked on the database file instead of refusing it")


# -- the store ------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("snapshot", "has 2 hard links"),
        ("empty-link", "has 2 hard links"),
        ("directory", "is not a regular file (a directory)"),
    ],
)
def test_open_refuses_a_database_that_is_not_one_regular_file(
    tmp_path: Path, case: str, expected: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refused before ``sqlite3.connect``, with neither name of a link touched."""
    root = _seeded(tmp_path)
    db = root / _STORE
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = _plant(db, case, outside)
    db.parent.chmod(0o750)  # a refusal must not even narrow the directory
    victim_before = _state(victim) if victim is not None else None
    db_before = _state(db)
    connected: list[object] = []
    real_connect = sqlite3.connect

    def recording_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        connected.append(args)
        return real_connect(*args, **kwargs)  # type: ignore[call-overload,no-any-return]

    monkeypatch.setattr(sqlite3, "connect", recording_connect)

    with pytest.raises(StoreFileError) as caught:
        EventStore.open(root)

    refusal = caught.value
    assert isinstance(refusal, StorePathError) and isinstance(refusal, StoreError)
    assert not isinstance(refusal, StoreSidecarError), "the database was blamed on a sidecar"
    assert refusal.problem == expected
    assert f"{db} {expected};" in str(refusal) and "the store was not opened" in str(refusal)
    assert connected == [], "the check ran after SQLite had already opened the store"
    assert _state(db) == db_before
    if victim_before is not None:
        assert victim is not None and _state(victim) == victim_before
    assert stat.S_IMODE(db.parent.stat().st_mode) == 0o750
    assert _sidecars(db) == []


@pytest.mark.security
@pytest.mark.parametrize("mode", [0o400, 0o600], ids=["read-only", "writable"])
def test_open_refuses_a_fifo_database_without_blocking(tmp_path: Path, mode: int) -> None:
    """Measured before the check, as a non-root account: read-only hung inside SQLite's
    open, writable raised a bare ``disk I/O error``. Both are now the same refusal."""
    root = _seeded(tmp_path)
    db = root / _STORE
    db.unlink()
    os.mkfifo(db, mode)
    db.chmod(mode)
    # The root goes on the child's sys.path by name: `-c` adds the working directory
    # only when PYTHONSAFEPATH is unset (as `_run_isolated` records for the backup tests).
    code = (
        f"import sys\nsys.path.insert(0, {str(_REPO_ROOT)!r})\n"
        "from pathlib import Path\n"
        "from store import EventStore, StoreFileError, StoreSidecarError\n"
        "try:\n"
        "    EventStore.open(Path(sys.argv[1])).close()\n"
        "except StoreSidecarError as exc:\n"
        "    print('SIDECAR', exc.suffix, exc.problem)\n"
        "    sys.exit(4)\n"
        "except StoreFileError as exc:\n"
        "    print('REFUSED', exc.problem)\n"
        "    sys.exit(3)\n"
    )

    result = _run(["-c", code, str(root)])

    assert result.returncode == 3, result.stdout[-400:] + result.stderr[-400:]
    assert "REFUSED is not a regular file (a FIFO)" in result.stdout, result.stdout
    assert db.is_fifo() and stat.S_IMODE(db.lstat().st_mode) == mode, "the FIFO was changed"
    assert _sidecars(db) == []


@pytest.mark.security
def test_only_absence_reads_as_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``ENOENT`` and ``ENOTDIR`` mean there is no file, so ``open`` may create one; any
    other ``stat`` failure fails closed rather than being read as "no database yet".

    Called directly: ``confine``'s symlink walk stats the same path first, and on 3.11
    ``Path.is_symlink`` does so through the ``Path.lstat`` patched here.
    """
    refuse_unsafe_database(tmp_path / "absent.sqlite3")
    (tmp_path / "file").write_bytes(b"")
    refuse_unsafe_database(tmp_path / "file" / "events.sqlite3")

    db = tmp_path / "events.sqlite3"
    db.write_bytes(b"")
    real_lstat = Path.lstat

    def denying_lstat(self: Path) -> os.stat_result:
        if self == db:
            raise PermissionError(13, "Permission denied", str(self))
        return real_lstat(self)

    monkeypatch.setattr(Path, "lstat", denying_lstat)

    with pytest.raises(StoreFileError, match="cannot be stated") as caught:
        refuse_unsafe_database(db)
    assert caught.value.problem == "cannot be stated (Permission denied)"


@pytest.mark.security
def test_a_normal_store_opens_and_a_fresh_root_is_still_created(tmp_path: Path) -> None:
    """The acceptance half: the check is a type and link-count check on a file that
    exists, so neither the common case nor the first run may change."""
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    with EventStore.open(fresh) as store:
        assert store.count() == 0
    created = (fresh / _STORE).lstat()
    assert stat.S_ISREG(created.st_mode) and created.st_nlink == 1
    assert stat.S_IMODE(created.st_mode) == 0o600

    root = _seeded(tmp_path)
    with EventStore.open(root) as store:
        assert store.count() == 12


@pytest.mark.security
def test_the_documented_remedies_for_a_hard_link_reopen_the_store(tmp_path: Path) -> None:
    """``store/README.md`` gives two ways out, and both must work: delete the other name,
    or give the store a new inode of its own, which leaves the other name as it was."""
    root = _seeded(tmp_path)
    db = root / _STORE
    snapshot = tmp_path / "snapshot.sqlite3"

    os.link(db, snapshot)
    with pytest.raises(StoreFileError):
        EventStore.open(root)
    snapshot.unlink()
    with EventStore.open(root) as store:
        assert store.count() == 12

    os.link(db, snapshot)
    frozen = _state(snapshot)
    copy = db.with_name(db.name + ".unlinked")
    shutil.copy2(db, copy)
    copy.replace(db)
    with EventStore.open(root) as store:
        store.append(normalize(_RECORD % 77), ingested_at=store.next_stamp(time.time()))
        assert store.count() == 13
    kept = snapshot.lstat()
    assert (kept.st_ino, kept.st_nlink) == (frozen[1], 1), "the snapshot lost its inode"
    assert hashlib.sha256(snapshot.read_bytes()).hexdigest() == frozen[5], "it was written"


@pytest.mark.security
@pytest.mark.parametrize("case", ["snapshot", "empty-link", "directory", "fifo"])
def test_the_backup_cli_reports_the_stores_own_verdict(tmp_path: Path, case: str) -> None:
    """One rule, two phrasings: ``run_backup`` asks ``store`` rather than keeping a copy
    (unlike its ``_sidecar_problem``, which predates the store's check), so the finding
    must carry the store's ``problem`` word for word, and absent must be absent in both.
    Neither opens the file, so a FIFO is safe to state here in-process."""
    root = _seeded(tmp_path)
    db = root / _STORE
    outside = tmp_path / "outside"
    outside.mkdir()
    _plant(db, case, outside)

    with pytest.raises(StoreFileError) as caught:
        refuse_unsafe_database(db)
    finding = _database_problem(db, what="the live store")

    assert finding is not None
    assert finding.startswith(f"the live store cannot be opened safely: it {caught.value.problem}.")
    assert finding.endswith("the store was not opened")
    assert _database_problem(tmp_path / "absent.sqlite3", what="x") is None


# -- every CLI that opens the live store ----------------------------------------


@pytest.mark.security
@pytest.mark.parametrize("cli", _CLIS)
@pytest.mark.parametrize("case", ["fifo", "snapshot", "empty-link"])
def test_every_cli_refuses_the_database_instead_of_hanging_or_writing_through(
    tmp_path: Path, cli: str, case: str
) -> None:
    """The measured failures, through each entry point as a scheduler runs it.

    Exit 1 is the "damage, page someone" code these CLIs already use for a store that
    will not open, and it is what the hang used to turn into "skipped" at exit 0. Every
    one except the SLI reporter names the problem and says the store was not opened.
    The SLI reporter checks ``is_file()`` before it opens anything, so a FIFO never
    reaches the store there: it reports "no event store", which is unmeasured and exit 1
    by its contract, and that cell pins behaviour that was already fail-closed. A hard
    link does reach ``EventStore.open`` and is reported as ``StoreFileError``.
    """
    root = _seeded(tmp_path)
    log = root / "logs" / "auth.log"
    log.parent.mkdir()
    log.write_text(_RECORD % 500 + "\n", encoding="utf-8")
    backup = None
    if cli.startswith("backup-verify"):
        assert backup_main(["--root", str(root), "--name", "probe", "--caller", "test"]) == 0
        backup = root / "data" / "backups" / "probe"
    db = (backup if cli == "backup-verify" and backup is not None else root) / _STORE
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = _plant(db, case, outside)
    victim_before = _state(victim) if victim is not None else None
    db_before = _state(db)

    result = _run(_cli_argv(cli, root, backup))

    out = result.stdout + result.stderr
    assert result.returncode == 1, out[-600:]
    if cli == "sli" and case == "fifo":
        # Named, not read as absent: the SLI guard is an lstat now, so a FIFO reaches
        # EventStore.open's refusal like the other CLIs' (it used to say "no event store").
        assert "StoreFileError" in out and "is not a regular file (a FIFO)" in out, out[-600:]
    elif cli == "sli":
        assert "StoreFileError" in out and "has 2 hard links" in out, out[-600:]
    else:
        problem = "is not a regular file (a FIFO)" if case == "fifo" else "has 2 hard links"
        assert problem in out and "the store was not opened" in out, out[-600:]
    assert _state(db) == db_before, "the store path changed"
    if victim_before is not None:
        assert victim is not None and _state(victim) == victim_before, "a link was written"
    assert _sidecars(db) == [], "a sidecar was created beside a refused store"
    if cli == "backup-take":
        assert not (root / "data" / "backups" / "after").exists(), "a partial backup was left"
