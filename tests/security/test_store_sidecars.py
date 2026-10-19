# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The live store must not hand SQLite a sidecar it would block on or write through.

``scripts/run_backup.py`` learned this for its own paths (``test_backup_manifest_shape.py``)
while every other scheduled entry point that opens the live store went through
``EventStore.open`` with no check at all. Measured on the code before this file, through
``EventStore.open`` and through each CLI, with each object planted beside a seeded store:

- a FIFO ``-journal`` blocked the open in ``open(2)`` for good, and the collector, the
  pipeline and retention hold their single-instance lock across it, so every later pass
  printed "skipped" at exit 0; ``scripts/report_sli.py`` hung the same way;
- a ``-shm`` hard-linked to a file outside the root left that file 65536 -> 32768 bytes of
  WAL index and mode 0o644 -> 0o600 at exit 0, and the ``-shm`` name was unlinked on close,
  so nothing in the tree showed it; a hard-linked ``-wal`` was chmodded the same way;
- a symlinked, directory or FIFO sidecar raised a bare ``OperationalError``, or (a
  directory ``-shm``, a FIFO ``-wal``) opened without complaint;
- with the refusal in place and ``sli/`` unchanged, ``store-intact`` and
  ``store-readable`` graded the refusal BREACHED 0.0, "the store's database is damaged".

Refusal is paired with acceptance: a database with a second hard link (a snapshot farm),
and a live writer's legitimate ``-wal`` and ``-shm``, still open. Every FIFO case runs in a
child with a timeout, because the regression is a hang and ``SIGALRM`` does not interrupt
SQLite's open (measured in ``test_backup_manifest_shape.py``).
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

import store.events
import store.paths
from ingest import normalize
from scripts import run_pipeline, run_retention
from sli import measure
from store import EventStore, StorePathError, StoreSidecarError

_REPO_ROOT = Path(__file__).resolve().parents[2]
_STORE = Path("data") / "events" / "events.sqlite3"
_SUFFIXES = ("-wal", "-journal", "-shm")
_RECORD = 'type=USER_AUTH msg=audit(1760000000.1:1): acct="svc-%d" addr=203.0.113.9 res=failed'
_SEEDED = 12
#: Long enough for a child interpreter to import the platform under a loaded runner, and
#: short enough that a regression fails the suite instead of stalling it.
_TIMEOUT = 20.0

#: The store indicators: every objective whose measurer opens the event store.
_STORE_INDICATORS = (
    "ingest-freshness",
    "detection-lag",
    "detection-backlog",
    "store-intact",
    "store-readable",
)


def _seed(tmp_path: Path) -> tuple[Path, Path]:
    """A lab root holding a closed store of ``_SEEDED`` events, and that store's path."""
    root = tmp_path / "lab"
    root.mkdir()
    now = time.time() - 60
    with EventStore.open(root) as events:
        for index in range(_SEEDED):
            events.append(normalize(_RECORD % index), ingested_at=events.next_stamp(now + index))
    db = root / _STORE
    assert not any(db.with_name(db.name + s).exists() for s in _SUFFIXES), (
        "a closed store left a sidecar"
    )
    return root, db


def _victim(tmp_path: Path) -> Path:
    """A file outside the root that nothing here may write: the target of every link."""
    victim = tmp_path / "victim"
    victim.write_bytes(hashlib.sha256(b"not the store's to write").digest() * 2048)
    victim.chmod(0o644)
    return victim


def _fingerprint(path: Path) -> tuple[int, str, int, int]:
    """Size, sha256, mode and inode — a write, a chmod and a replacement all change it."""
    found = path.stat()
    return (
        found.st_size,
        hashlib.sha256(path.read_bytes()).hexdigest(),
        stat.S_IMODE(found.st_mode),
        found.st_ino,
    )


def _kind(path: Path) -> tuple[int, int]:
    """File type and inode, without following a link: what a planted object *is*."""
    found = os.lstat(path)
    return stat.S_IFMT(found.st_mode), found.st_ino


def _plant(side: Path, shape: str, victim: Path) -> None:
    """Put a ``shape`` at ``side``. ``victim`` is what a link points at."""
    if shape == "fifo":
        os.mkfifo(side, 0o600)
    elif shape == "socket":
        # Bound relatively: ``sun_path`` is ~108 bytes and a tmp_path can exceed it.
        here = Path.cwd()
        sock = socket.socket(socket.AF_UNIX)
        try:
            os.chdir(side.parent)
            sock.bind(side.name)
        finally:
            os.chdir(here)
            sock.close()
    elif shape == "directory":
        side.mkdir()
    elif shape == "dangling-symlink":
        side.symlink_to(victim.parent / "nowhere")
    elif shape == "symlink-to-file":
        side.symlink_to(victim)
    elif shape == "hard-link":
        os.link(victim, side)
    else:  # pragma: no cover - a typo in the parametrize list
        raise AssertionError(shape)


_SHAPES = ["fifo", "socket", "directory", "dangling-symlink", "symlink-to-file", "hard-link"]


def _named(suffix: str, shape: str, victim: Path) -> str:
    """The words the refusal must use for ``shape``: what is wrong, not only that it is."""
    kind = {
        "fifo": "a FIFO",
        "socket": "a socket",
        "directory": "a directory",
        "dangling-symlink": "a symlink",
        "symlink-to-file": "a symlink",
    }.get(shape)
    if kind is None:
        return f"its {suffix} ({victim.stat().st_size} bytes) has 2 links"
    return f"its {suffix} is {kind}, not a regular file"


def _child(code: str, what: str) -> subprocess.CompletedProcess[str]:
    """Run ``code`` in a child with the repository root on its ``sys.path`` by name.

    By name because ``-c`` adds the working directory only when ``PYTHONSAFEPATH`` is
    unset (found by review in ``test_backup_manifest_shape.py``).
    """
    program = f"import sys\nsys.path.insert(0, {str(_REPO_ROOT)!r})\n{code}"
    try:
        return subprocess.run(  # noqa: S603 - fixed interpreter, literal code, test paths
            [sys.executable, "-c", program],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"{what} blocked for {_TIMEOUT}s instead of refusing")


def _open_isolated(root: Path) -> tuple[str | None, str]:
    """``EventStore.open(root)`` in a child: what it raised, as (type name, message)."""
    code = (
        "import json\nfrom pathlib import Path\nfrom store import EventStore\n"
        "try:\n"
        f"    with EventStore.open(Path({str(root)!r})) as events:\n"
        "        events.count()\n"
        "except Exception as exc:\n"
        "    print(json.dumps([type(exc).__name__, str(exc)]))\n"
        "else:\n"
        "    print(json.dumps([None, '']))\n"
    )
    result = _child(code, f"EventStore.open({root})")
    assert result.returncode == 0, result.stderr[-800:]
    name, message = json.loads(result.stdout.strip().splitlines()[-1])
    return name, message


def _open(root: Path, shape: str) -> tuple[str | None, str]:
    """What ``EventStore.open(root)`` raised. A FIFO in a child: the regression is a hang."""
    if shape == "fifo":
        return _open_isolated(root)
    try:
        with EventStore.open(root) as events:
            events.count()
    except Exception as exc:
        return type(exc).__name__, str(exc)
    return None, ""


@pytest.mark.security
@pytest.mark.parametrize("suffix", _SUFFIXES)
@pytest.mark.parametrize("shape", _SHAPES)
def test_open_refuses_a_sidecar_sqlite_would_block_on_or_write_through(
    tmp_path: Path, suffix: str, shape: str
) -> None:
    """Every shape at every sidecar name, refused before the connection exists.

    Both symlink shapes are needed: a dangling one is caught only by not following it,
    and one to a regular file only because ``is_file()`` would follow it. The victim is
    fingerprinted by mode as well as content, because the hard-linked ``-wal`` measured
    before the fix kept its bytes and lost its mode through an open alone.
    """
    root, db = _seed(tmp_path)
    victim = _victim(tmp_path)
    side = db.with_name(db.name + suffix)
    _plant(side, shape, victim)
    others = [db.with_name(db.name + s) for s in _SUFFIXES if s != suffix]
    planted, store_before, victim_before = _kind(side), _fingerprint(db), _fingerprint(victim)

    raised, message = _open(root, shape)

    assert raised == "StoreSidecarError", f"{raised}: {message}"
    assert _named(suffix, shape, victim) in message, message
    assert message.startswith(f"the event store {db} cannot be opened safely"), message
    assert message.endswith("so the store was not opened"), message
    assert _kind(side) == planted, "the open replaced or removed the planted sidecar"
    assert _fingerprint(db) == store_before, "the store changed under a refused open"
    assert _fingerprint(victim) == victim_before, "the victim was written or chmodded"
    assert not (tmp_path / "nowhere").exists(), "the open created a dangling link's target"
    assert not any(other.exists() for other in others), "the refused open created a sidecar"


@pytest.mark.security
@pytest.mark.parametrize(("shape", "kind"), [("fifo", "a FIFO"), ("directory", "a directory")])
def test_a_special_file_at_the_database_path_is_refused_by_kind(
    tmp_path: Path, shape: str, kind: str
) -> None:
    """Measured before the fix: a FIFO at the database path raised a bare
    ``OperationalError`` ("disk I/O error") and a directory raised "unable to open database
    file", neither naming what was wrong. A :class:`StorePathError` rather than a
    :class:`StoreSidecarError`, because the remedy is the database path itself."""
    root = tmp_path / "lab"
    db = root / _STORE
    db.parent.mkdir(parents=True)
    victim = _victim(tmp_path)
    _plant(db, shape, victim)
    planted = _kind(db)

    raised, message = _open(root, shape)

    assert raised == "StorePathError", f"{raised}: {message}"
    assert f"the event store {db} is {kind}, not a regular file" in message, message
    assert _kind(db) == planted
    assert not any(db.with_name(db.name + s).exists() for s in _SUFFIXES)


@pytest.mark.security
def test_a_database_that_cannot_be_stated_is_refused_not_taken_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Absent is a fresh store, so any other ``lstat`` failure must not read as absent:
    SQLite would then create or open a file this check never saw."""
    root, db = _seed(tmp_path)
    real_lstat = os.lstat

    def refusing(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if os.fspath(path) == str(db):  # type: ignore[call-overload]
            raise PermissionError(13, "Permission denied", os.fspath(path))  # type: ignore[call-overload]
        return real_lstat(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(store.events.os, "lstat", refusing)
    with pytest.raises(StorePathError, match=r"cannot be checked \(PermissionError\)"):
        EventStore.open(root)


@pytest.mark.security
@pytest.mark.parametrize("suffix", _SUFFIXES)
@pytest.mark.parametrize("shape", _SHAPES)
def test_the_store_helper_says_exactly_what_run_backup_says(
    tmp_path: Path, suffix: str, shape: str
) -> None:
    """``store.paths.sidecar_problem`` is ``run_backup._sidecar_problem`` moved down a
    layer, and ``docs/RESTORE.md``'s findings table quotes its sentences. Until
    ``run_backup`` imports it, the two copies must agree word for word."""
    from scripts import run_backup

    db = tmp_path / "events.sqlite3"
    db.write_bytes(b"x")
    victim = _victim(tmp_path)
    _plant(db.with_name(db.name + suffix), shape, victim)
    what = f"the live store {db}"

    moved = store.paths.sidecar_problem(db, what=what)

    assert moved is not None and _named(suffix, shape, victim) in moved, moved
    assert moved == run_backup._sidecar_problem(db, what=what)


@pytest.mark.security
def test_every_offending_sidecar_is_named(tmp_path: Path) -> None:
    """The remedies differ by sidecar, so stopping at the first lets a FIFO hide behind a
    benign-looking link count (found by review of ``run_backup``'s first version)."""
    db = tmp_path / "events.sqlite3"
    db.write_bytes(b"x")
    victim = _victim(tmp_path)
    _plant(db.with_name(db.name + "-wal"), "fifo", victim)
    _plant(db.with_name(db.name + "-shm"), "hard-link", victim)

    reason = store.paths.sidecar_problem(db, what="the store")

    assert reason is not None
    assert "its -wal is a FIFO, not a regular file" in reason, reason
    assert f"its -shm ({victim.stat().st_size} bytes) has 2 links" in reason, reason
    assert store.paths.sidecar_problem(tmp_path / "absent.sqlite3", what="x") is None


@pytest.mark.security
@pytest.mark.parametrize("suffix", _SUFFIXES)
def test_a_sidecar_that_cannot_be_checked_is_refused_not_taken_as_absent(
    tmp_path: Path, suffix: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not walkable is not safe — the branch nothing pinned in ``run_backup`` until review."""
    db = tmp_path / "events.sqlite3"
    db.write_bytes(b"x")
    real_lstat = os.lstat

    def refusing(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if os.fspath(path).endswith(suffix):  # type: ignore[call-overload]
            raise PermissionError(13, "Permission denied", os.fspath(path))  # type: ignore[call-overload]
        return real_lstat(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(store.paths.os, "lstat", refusing)
    reason = store.paths.sidecar_problem(db, what="the store")
    assert reason is not None and f"its {suffix} cannot be checked (PermissionError)" in reason


@pytest.mark.security
def test_a_device_sidecar_is_named_as_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The device kinds cannot be created without CAP_MKNOD, so an existing node's
    ``lstat`` stands in, as ``test_backup_manifest_shape.py`` does for ``run_backup``."""
    db = tmp_path / "events.sqlite3"
    db.write_bytes(b"x")
    real_lstat = os.lstat
    device = real_lstat("/dev/null")

    def as_device(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if os.fspath(path).endswith("-wal"):  # type: ignore[call-overload]
            return device
        return real_lstat(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(store.paths.os, "lstat", as_device)
    reason = store.paths.sidecar_problem(db, what="the store")
    assert reason is not None and "its -wal is a character device, not a regular file" in reason


# -- acceptance: what must still open ----------------------------------------------------


@pytest.mark.security
def test_a_database_with_a_second_hard_link_is_still_opened(tmp_path: Path) -> None:
    """Deliberately not refused. A hard-link copy of the tree (``cp -al``, ``rsync
    --link-dest``, rsnapshot) gives the live database a second name for as long as the
    copy exists, and refusing it would fail every scheduled pass. A control, so it is
    green before and after the fix: what it pins is the absence of a false alarm."""
    root, db = _seed(tmp_path)
    snapshot = tmp_path / "snapshot.sqlite3"
    os.link(db, snapshot)
    assert db.stat().st_nlink == 2

    with EventStore.open(root) as events:
        assert events.count() == _SEEDED
    assert db.samefile(snapshot)


@pytest.mark.security
def test_a_live_writers_sidecars_do_not_trigger_the_refusal(tmp_path: Path) -> None:
    """A writer holding the store open has a non-empty ``-wal`` and a ``-shm``, each a
    regular file with one link, and a second opener — a cycle, a retention report — must
    open beside them. A control: green before and after the fix."""
    root, db = _seed(tmp_path)
    wal, shm = db.with_name(db.name + "-wal"), db.with_name(db.name + "-shm")
    with EventStore.open(root) as writer:
        writer.append(normalize(_RECORD % 99), ingested_at=writer.next_stamp(time.time()))
        assert wal.is_file() and wal.stat().st_size > 0, "the writer has no WAL to test against"
        assert shm.is_file() and wal.stat().st_nlink == 1 and shm.stat().st_nlink == 1

        with EventStore.open(root) as reader:
            assert reader.count() == _SEEDED + 1
        assert run_pipeline.main(["--root", str(root), "--caller", "test", "--json"]) == 0
        assert run_retention.main(["--root", str(root), "--caller", "test", "--json"]) == 0


# -- the four scheduled entry points that open the live store -----------------------------


_CLIS = ("run_collector", "run_pipeline", "run_retention", "report_sli")
_PLANTS = (("-journal", "fifo"), ("-shm", "hard-link"))


@pytest.mark.security
@pytest.mark.parametrize("cli", _CLIS)
@pytest.mark.parametrize(("suffix", "shape"), _PLANTS)
def test_every_cli_that_opens_the_live_store_refuses_at_exit_1(
    tmp_path: Path, cli: str, suffix: str, shape: str
) -> None:
    """Before the fix a FIFO ``-journal`` hung all four (three while holding their lock,
    so every later pass printed "skipped" at exit 0), and a hard-linked ``-shm`` had its
    victim overwritten under an exit 0. Each now fails closed at exit 1 within the timeout,
    with no CLI change: ``StorePathError`` already reached every handler.

    ``report_sli`` exits 1 whenever any objective is unmet, so for it the signal is the
    store indicators, which must read UNKNOWN — the store was not read — and never
    BREACHED, which would send an operator to the backups for an intact store.
    """
    root, db = _seed(tmp_path)
    victim = _victim(tmp_path)
    side = db.with_name(db.name + suffix)
    _plant(side, shape, victim)
    others = [db.with_name(db.name + s) for s in _SUFFIXES if s != suffix]
    planted, store_before, victim_before = _kind(side), _fingerprint(db), _fingerprint(victim)
    named = _named(suffix, shape, victim)
    source = tmp_path / "source.log"
    source.write_text((_RECORD % 1) + "\n" + (_RECORD % 2) + "\n", encoding="utf-8")
    argv = ["--root", str(root), "--caller", "test", "--json"]
    if cli == "run_collector":
        argv += ["--source", str(source)]

    result = _child(f"from scripts.{cli} import main\nsys.exit(main({argv!r}))\n", cli)

    assert result.returncode == 1, result.stdout[-400:] + result.stderr[-400:]
    assert "Traceback" not in result.stderr, result.stderr[-800:]
    if cli == "report_sli":
        indicators = {item["id"]: item for item in json.loads(result.stdout)["indicators"]}
        for objective in _STORE_INDICATORS:
            assert indicators[objective]["status"] == "unknown", indicators[objective]
            assert "StoreSidecarError" in indicators[objective]["detail"], indicators[objective]
        for objective in ("store-intact", "store-readable"):
            assert named in indicators[objective]["detail"], indicators[objective]
    else:
        assert f"error: the event store {db} cannot be opened safely" in result.stderr, (
            result.stderr[-800:]
        )
        assert named in result.stderr, result.stderr[-800:]
        # The collector used to report a sidecar fault against the log it was reading.
        assert str(source) not in result.stderr, result.stderr[-800:]
    assert _kind(side) == planted, "the CLI replaced or removed the planted sidecar"
    assert _fingerprint(db) == store_before, "the store changed under a refused open"
    assert _fingerprint(victim) == victim_before, "the victim was written or chmodded"
    assert not any(other.exists() for other in others), "the refused open created a sidecar"


@pytest.mark.security
@pytest.mark.parametrize("plant", ["hard-link-shm", "symlinked-events-directory"])
def test_a_store_open_refuses_is_unmeasurable_not_damaged(tmp_path: Path, plant: str) -> None:
    """``store-intact`` and ``store-readable`` reserve ``None`` for "a store that is not
    there or will not open", and graded a refused open BREACHED 0.0 regardless: measured
    with the sidecar refusal in place, "the store's database is damaged". A symlinked
    ``data/events``, which ``confine`` refused long before the sidecar check, read the same
    on the code before this file. A store whose pages are damaged still breaches:
    ``tests/unit/test_sli.py::test_store_intact_catches_the_damage_the_readability_sample_cannot``.
    """
    root, db = _seed(tmp_path)
    victim = _victim(tmp_path)
    before = _fingerprint(victim)
    if plant == "hard-link-shm":
        _plant(db.with_name(db.name + "-shm"), "hard-link", victim)
        reason = _named("-shm", "hard-link", victim)
    else:
        moved = tmp_path / "elsewhere"
        (root / "data" / "events").rename(moved)
        (root / "data" / "events").symlink_to(moved)
        reason = "is a symlink"

    indicators = {item.objective.id: item for item in measure(root, now=time.time()).indicators}

    for objective in ("store-intact", "store-readable"):
        indicator = indicators[objective]
        assert indicator.value is None, f"{objective}: {indicator.status.value} {indicator.detail}"
        assert indicator.status.value == "unknown"
        assert indicator.detail.startswith("the store could not be opened ("), indicator.detail
        assert reason in indicator.detail, indicator.detail
    assert _fingerprint(victim) == before
    assert issubclass(StoreSidecarError, StorePathError)
