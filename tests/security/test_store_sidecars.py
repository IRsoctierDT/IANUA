# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""A sidecar SQLite opens by name must not hang the store's open or be written through.

SQLite opens ``-journal``, ``-wal`` and ``-shm`` beside the database by name. Measured
through every CLI that opens the live store before ``EventStore.open`` checked them:

* a FIFO ``-journal`` hung the collector, the pipeline, retention, the backup take and
  the SLI reporter inside SQLite's open; the four with a single-instance lock held it
  while blocked, so a second pass printed "skipped" at exit 0;
* a 64 KiB file hard-linked as ``-shm`` came back as 32 KiB of WAL index, at exit 0,
  from all of them and from the read-only ``--verify``; a hard-linked ``-wal`` had its
  other name overwritten with WAL frames by the collector and the take;
* a FIFO ``-wal`` was deleted at exit 0, and a symlinked, FIFO or directory ``-shm``
  replaced the output with a bare SQLite error.

Refusal is paired with acceptance: a live writer's non-empty ``-wal`` and ``-shm`` must
still open, because the check is a type and link-count check and nothing more.

The FIFO cases run in a subprocess with a timeout, as in
``test_backup_manifest_shape.py``: the failure under test is a hang, and ``SIGALRM``
does not interrupt SQLite's open.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ingest import normalize
from scripts.run_backup import _SIDECARS
from scripts.run_backup import main as backup_main
from store import (
    SIDECAR_SUFFIXES,
    EventStore,
    StoreError,
    StorePathError,
    StoreSidecarError,
)

_RECORD = 'type=USER_AUTH msg=audit(1760000000.1:1): acct="svc-%d" addr=203.0.113.9 res=failed'
_REPO_ROOT = Path(__file__).resolve().parents[2]
_STORE = Path("data") / "events" / "events.sqlite3"
#: 64 KiB with no zero run, so the measured 32 KiB ``-shm`` rewrite cannot leave it equal.
_VICTIM = bytes(range(1, 256)) * 257
_TIMEOUT = 60.0


def _seeded(tmp_path: Path) -> Path:
    """A lab root holding a closed store of 12 events, so no sidecar is left behind."""
    root = tmp_path / "lab"
    root.mkdir()
    now = time.time() - 3600
    with EventStore.open(root) as store:
        for index in range(12):
            store.append(normalize(_RECORD % index), ingested_at=store.next_stamp(now + index))
    db = root / _STORE
    for suffix in SIDECAR_SUFFIXES:
        assert not os.path.lexists(db.with_name(db.name + suffix)), suffix
    return root


def _fingerprint(path: Path) -> tuple[int, int, str]:
    """Size, inode and sha256: a rewrite in place keeps the inode and changes the rest."""
    found = path.stat()
    return found.st_size, found.st_ino, hashlib.sha256(path.read_bytes()).hexdigest()


def _plant(db: Path, suffix: str, kind: str, victim: Path) -> Path:
    """Create ``db + suffix`` as ``kind``; ``victim`` is the file a link would reach."""
    side = db.with_name(db.name + suffix)
    if kind == "fifo":
        os.mkfifo(side, 0o600)
    elif kind == "hardlink":
        victim.write_bytes(_VICTIM)
        os.link(victim, side)
    elif kind == "symlink":
        # The target is a regular file with ONE link, so only an lstat refuses it:
        # a check that followed the link would see exactly what it accepts.
        victim.write_bytes(_VICTIM)
        side.symlink_to(victim)
    elif kind == "directory":
        side.mkdir()
    else:  # pragma: no cover - a typo in a parametrization
        raise AssertionError(kind)
    return side


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
        pytest.fail(f"{argv[0]} blocked on a sidecar instead of refusing it")


# -- the store ------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize("suffix", SIDECAR_SUFFIXES)
@pytest.mark.parametrize("kind", ["hardlink", "symlink", "directory"])
def test_open_refuses_a_sidecar_that_is_not_one_regular_file(
    tmp_path: Path, suffix: str, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refused before ``sqlite3.connect``, with nothing on either side of a link touched."""
    root = _seeded(tmp_path)
    db = root / _STORE
    victim = tmp_path / "victim.bin"
    side = _plant(db, suffix, kind, victim)
    db.parent.chmod(0o750)  # a refusal must not even narrow the directory
    victim_before = _fingerprint(victim) if victim.exists() else None
    db_before = _fingerprint(db)
    connected: list[object] = []
    real_connect = sqlite3.connect

    def recording_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        connected.append(args)
        return real_connect(*args, **kwargs)  # type: ignore[call-overload,no-any-return]

    monkeypatch.setattr(sqlite3, "connect", recording_connect)

    with pytest.raises(StoreSidecarError) as caught:
        EventStore.open(root)

    refusal = caught.value
    assert isinstance(refusal, StorePathError) and isinstance(refusal, StoreError)
    assert refusal.suffix == suffix
    assert f"{db} has a {suffix} beside it that {refusal.problem}" in str(refusal)
    expected = "has 2 hard links" if kind == "hardlink" else f"(a {kind})"
    assert expected in refusal.problem, refusal.problem
    assert connected == [], "the check ran after SQLite had already opened the store"
    assert _fingerprint(db) == db_before
    assert stat.S_IMODE(db.parent.stat().st_mode) == 0o750
    if victim_before is not None:
        assert _fingerprint(victim) == victim_before
    assert os.path.lexists(side), "the refusal removed the sidecar it named"


@pytest.mark.security
@pytest.mark.parametrize("suffix", SIDECAR_SUFFIXES)
def test_open_refuses_a_fifo_sidecar_without_blocking(tmp_path: Path, suffix: str) -> None:
    """Measured before the check: ``-journal`` blocked, ``-wal`` was deleted, ``-shm``
    raised a bare ``disk I/O error``. All three must now be the same refusal."""
    root = _seeded(tmp_path)
    side = _plant(root / _STORE, suffix, "fifo", tmp_path / "unused")
    # The root goes on the child's sys.path by name: `-c` adds the working directory
    # only when PYTHONSAFEPATH is unset (as `_run_isolated` records for the backup tests).
    code = (
        f"import sys\nsys.path.insert(0, {str(_REPO_ROOT)!r})\n"
        "from pathlib import Path\n"
        "from store import EventStore, StoreSidecarError\n"
        "try:\n"
        "    EventStore.open(Path(sys.argv[1])).close()\n"
        "except StoreSidecarError as exc:\n"
        "    print('REFUSED', exc.suffix, exc.problem)\n"
        "    sys.exit(3)\n"
    )

    result = _run(["-c", code, str(root)])

    assert result.returncode == 3, result.stdout[-400:] + result.stderr[-400:]
    assert f"REFUSED {suffix} is not a regular file (a FIFO)" in result.stdout, result.stdout
    assert side.is_fifo(), "the FIFO was removed"


@pytest.mark.security
def test_a_sidecar_that_cannot_be_stated_is_refused_not_read_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only ``ENOENT`` means absent; anything else fails closed."""
    root = _seeded(tmp_path)
    real_lstat = Path.lstat

    def denying_lstat(self: Path) -> os.stat_result:
        if self.name.endswith("-wal"):
            raise PermissionError(13, "Permission denied", str(self))
        return real_lstat(self)

    monkeypatch.setattr(Path, "lstat", denying_lstat)

    with pytest.raises(StoreSidecarError, match="cannot be stated") as caught:
        EventStore.open(root)
    assert caught.value.suffix == "-wal"


@pytest.mark.security
def test_an_events_path_that_is_a_file_is_not_blamed_on_a_sidecar(tmp_path: Path) -> None:
    """``ENOTDIR`` means no sidecar can exist, so the pre-check reads it as absent and
    ``open`` keeps the error it raised before the check: ``mkdir`` refusing a file."""
    root = tmp_path / "lab"
    (root / "data").mkdir(parents=True)
    (root / "data" / "events").write_bytes(b"")

    with pytest.raises(FileExistsError):
        EventStore.open(root)


@pytest.mark.security
def test_a_live_writers_sidecars_are_accepted(tmp_path: Path) -> None:
    """The acceptance half: a held-open store leaves a non-empty ``-wal`` and a ``-shm``,
    and a second open beside it must succeed. Size and content are not the check."""
    root = _seeded(tmp_path)
    with EventStore.open(root) as writer:
        writer.append(normalize(_RECORD % 99), ingested_at=writer.next_stamp(time.time()))
        db = writer.path
        for suffix in ("-wal", "-shm"):
            side = db.with_name(db.name + suffix).lstat()
            assert stat.S_ISREG(side.st_mode) and side.st_nlink == 1, suffix
        assert db.with_name(db.name + "-wal").stat().st_size > 0
        with EventStore.open(root) as reader:
            assert reader.count() == 13


@pytest.mark.security
def test_the_backup_cli_and_the_store_check_the_same_sidecars() -> None:
    """Two implementations of one rule: the backup take reads the live store through
    ``sqlite3.connect``, not ``EventStore.open``, so it keeps its own check. They must
    not drift on which names they cover, which is how one copy stays fixed and the
    other does not."""
    assert set(_SIDECARS) == set(SIDECAR_SUFFIXES)


# -- every CLI that opens the live store ----------------------------------------

_CLIS = [
    "collector",
    "pipeline",
    "retention",
    "backup-take",
    "backup-verify",
    "backup-verify-restore",
    "sli",
]


def _cli_argv(cli: str, root: Path, backup: Path | None) -> list[str]:
    log = root / "logs" / "auth.log"
    caller = ["--caller", "test"]
    return {
        "collector": ["scripts/run_collector.py", "--root", str(root), "--source", str(log)],
        "pipeline": ["scripts/run_pipeline.py", "--root", str(root)],
        "retention": ["scripts/run_retention.py", "--root", str(root)],
        "backup-take": ["scripts/run_backup.py", "--root", str(root), "--name", "after"],
        "backup-verify": ["scripts/run_backup.py", "--root", str(root), "--verify", str(backup)],
        "backup-verify-restore": [
            "scripts/run_backup.py",
            "--root",
            str(root),
            "--verify-restore",
            str(backup),
        ],
        "sli": ["scripts/report_sli.py", "--root", str(root)],
    }[cli] + caller


@pytest.mark.security
@pytest.mark.parametrize("cli", _CLIS)
@pytest.mark.parametrize(
    ("suffix", "kind"), [("-journal", "fifo"), ("-shm", "hardlink")], ids=["fifo", "hardlink"]
)
def test_every_cli_refuses_the_sidecar_instead_of_hanging_or_writing_through(
    tmp_path: Path, cli: str, suffix: str, kind: str
) -> None:
    """The two measured headline failures, through each entry point as a scheduler runs it.

    Exit 1 is the "damage, page someone" code every one of these CLIs already uses for a
    store that will not open. It is what the hang used to turn into "skipped" at exit 0.
    The backup CLI refuses through its own ``_sidecar_problem`` (same rule, and it names
    every offending sidecar), the rest through ``EventStore.open``; both name the suffix
    and say the store was not opened, which is what is asserted.
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
    victim = tmp_path / "victim.bin"
    side = _plant(db, suffix, kind, victim)
    victim_before = _fingerprint(victim) if kind == "hardlink" else None
    db_before = _fingerprint(db)

    result = _run(_cli_argv(cli, root, backup))

    out = result.stdout + result.stderr
    assert result.returncode == 1, out[-600:]
    assert suffix in out and "the store was not opened" in out, out[-600:]
    if cli == "sli":
        assert "StoreSidecarError" in out, out[-600:]
    assert _fingerprint(db) == db_before
    if victim_before is not None:
        assert _fingerprint(victim) == victim_before, "a link beside the store was written"
        assert side.lstat().st_nlink == 2
    else:
        assert side.is_fifo()
    if cli == "backup-take":
        assert not (root / "data" / "backups" / "after").exists(), "a partial backup was left"
