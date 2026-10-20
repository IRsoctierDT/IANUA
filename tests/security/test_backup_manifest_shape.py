# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""A backup manifest is untrusted input; a verifier must not write the artifact it reads.

Measured before the fix: a ``store.path`` naming another existing file in the backup
sent ``--verify`` on to ``EventStore.open``, which **created** the store inside the
backup under inspection; four malformed shapes reached a traceback under both
verifiers. Refusal is paired with acceptance: the untampered backup verifies first.

Review then showed the write was route-specific and the invariant was not held: with
the manifest **untouched**, a 0-byte store at the canonical path went 0 -> 61440 bytes
on the same inode, a foreign database gained the schema, a 0-byte *live* store was
initialised by ``--verify-restore``, and a hot ``-wal`` planted beside an intact
backup store was checkpointed into it at exit 0. A tree comparison saw none of it, so
these tests fingerprint the store (size, inode, sha256) rather than list the tree.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ingest import normalize
from scripts.run_backup import MANIFEST_FORMAT
from tests._backup_cli import backup_main, with_audit_anchor
from store import EventStore, StoreFileError

_RECORD = 'type=USER_AUTH msg=audit(1760000000.1:1): acct="svc-%d" addr=203.0.113.9 res=failed'
# The current format, so each hostile manifest reaches the shape check it names
# rather than being refused one step earlier as superseded.
_FORMAT = MANIFEST_FORMAT


def _backup(tmp_path: Path, *, report: bool = False) -> tuple[Path, Path]:
    root = tmp_path / "lab"
    root.mkdir()
    now = time.time()
    with EventStore.open(root) as store:
        for index in range(12):
            store.append(normalize(_RECORD % index), ingested_at=store.next_stamp(now + index))
    if report:
        (root / _REPORT).parent.mkdir(parents=True)
        (root / _REPORT).write_text("# incident\n\nCorrelated 12 events.\n", encoding="utf-8")
    assert backup_main(["--root", str(root), "--name", "probe", "--caller", "test"]) == 0
    return root, root / "data" / "backups" / "probe"


def _tree(path: Path) -> set[str]:
    return {str(child.relative_to(path)) for child in path.rglob("*")}


def _verify(root: Path, backup: Path, mode: str) -> int:
    return backup_main(["--root", str(root), "--caller", "test", mode, str(backup)])


def _fingerprint(path: Path) -> tuple[int, int, str]:
    """Size, inode and sha256: what ``_tree()`` cannot see.

    Measured before the fix, a 0-byte store went 0 -> 61440 bytes on the SAME inode
    with ``_tree()`` unchanged, so the earlier test passed over the write.
    """
    stat = path.stat()
    return stat.st_size, stat.st_ino, hashlib.sha256(path.read_bytes()).hexdigest()


_REPO_ROOT = Path(__file__).resolve().parents[2]
_STORE = Path("data") / "events" / "events.sqlite3"
_CHAIN = "data/events/audit.log"
_REPORT = Path("data") / "reports" / "r.md"


def _run_isolated(
    argv: list[str], *, timeout: float = 30.0, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run the CLI in a child, for the cases whose failure is a hang.

    A subprocess with a timeout, as in ``test_audit_lock_path.py``: measured on the
    pre-fix verifier, a 30s ``SIGALRM`` never raised while the open blocked inside
    SQLite, so the suite hung rather than failed. The repository root goes on the
    child's ``sys.path`` by name, because ``-c`` adds the working directory only when
    ``PYTHONSAFEPATH`` is unset (found by review).
    """
    argv = with_audit_anchor(argv)
    code = (
        f"import sys\nsys.path.insert(0, {str(_REPO_ROOT)!r})\n"
        f"from scripts.run_backup import main\nsys.exit(main({argv!r}))\n"
    )
    try:
        return subprocess.run(  # noqa: S603 - fixed interpreter, literal code, test paths
            [sys.executable, "-c", code],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"the CLI blocked for {timeout}s instead of refusing: {argv}")


def _kind(path: Path) -> tuple[int, int]:
    """File type and inode, without following a link: what a planted object *is*."""
    found = os.lstat(path)
    return stat.S_IFMT(found.st_mode), found.st_ino


def _plant(side: Path, shape: str, victim: Path) -> None:
    """Put a ``shape`` at a sidecar name. ``victim`` is what a link points at."""
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
    """The words the finding must use for ``shape``: what is wrong, not only that it is."""
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


@pytest.mark.security
def test_verify_does_not_create_a_store_inside_the_backup(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, backup = _backup(tmp_path)
    assert _verify(root, backup, "--verify") == 0, "the untampered backup must verify"

    shutil.rmtree(backup / "data" / "events")
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["store"]["path"] = "manifest.json"  # another regular file inside the backup
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    before = _tree(backup)
    capsys.readouterr()

    assert _verify(root, backup, "--verify") == 1
    assert _tree(backup) == before, "a read-only verification wrote into the backup"
    # A finding beside the rest, not a refusal: #241 settled that for an escaping path.
    assert "only path a backup writes" in capsys.readouterr().out


@pytest.mark.security
@pytest.mark.parametrize("mode", ["--verify", "--verify-restore"])
def test_a_zero_byte_store_is_reported_and_not_initialised(
    tmp_path: Path, mode: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """The module docstring's own "truncated transfer", through an untouched manifest.

    SQLite treats an empty file as a new database, so ``EventStore.open`` initialised
    it: measured, 0 -> 61440 bytes with three tables, in the backup under ``--verify``
    and in the live root under ``--verify-restore`` alike, and a second ``--verify``
    then reported a different digest. A hard link to a 0-byte file outside the backup
    took the same path, which is why the check is on the bytes and not on the name.
    """
    root, backup = _backup(tmp_path)
    target = (backup if mode == "--verify" else root) / _STORE
    target.write_bytes(b"")
    before = _fingerprint(target)
    capsys.readouterr()

    assert _verify(root, backup, mode) == 1
    out = capsys.readouterr().out
    assert "is 0 bytes" in out and "was not opened" in out, out
    assert _fingerprint(target) == before, "the verifier initialised the empty store"


@pytest.mark.security
@pytest.mark.parametrize(
    ("journal", "expected"),
    [("delete", "not in WAL mode"), ("wal", "carries no event-store schema")],
)
def test_a_foreign_database_at_the_store_path_is_not_given_the_schema(
    tmp_path: Path, journal: str, expected: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Measured before the fix: one foreign table became four, 8192 -> 65536 bytes.

    Two refusals, because ``EventStore.open`` writes twice: ``journal_mode=WAL``
    rewrites the header of a rollback-journal file, and the schema is applied to any
    file without a ``meta`` table. A WAL-mode foreign file reaches the second.
    """
    root, backup = _backup(tmp_path)
    target = backup / _STORE
    target.unlink()
    with contextlib.closing(sqlite3.connect(target)) as conn:
        if journal == "wal":
            conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE foreign_table (x)")
        conn.commit()
    before = _fingerprint(target)
    capsys.readouterr()

    assert _verify(root, backup, "--verify") == 1
    out = capsys.readouterr().out
    assert expected in out and "was not opened" in out, out
    assert _fingerprint(target) == before, "the verifier wrote a foreign database"


@pytest.mark.security
def test_a_hot_wal_beside_the_store_is_refused_rather_than_checkpointed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The exit-0 instance. Measured before the fix: a ``-wal`` planted beside an intact
    backup store was checkpointed INTO it on close — "every file digest match the
    manifest", exit 0, sha256 changed, the planted row in the main file.
    """
    root, backup = _backup(tmp_path)
    target = backup / _STORE
    # A hot WAL from a copy of the same store: a holder keeps a read snapshot open so
    # the writer's close is not the last one and nothing checkpoints.
    copy = tmp_path / "copy.sqlite3"
    shutil.copy2(target, copy)
    with contextlib.closing(sqlite3.connect(copy)) as holder:
        holder.execute("BEGIN")
        holder.execute("SELECT count(*) FROM meta").fetchone()
        with contextlib.closing(sqlite3.connect(copy)) as writer:
            writer.execute("INSERT INTO meta (key, value) VALUES ('planted', 'x')")
            writer.commit()
        wal = copy.with_name(copy.name + "-wal")
        assert wal.stat().st_size > 0, "the probe did not produce a hot WAL"
        shutil.copy2(wal, target.with_name(target.name + "-wal"))
        holder.rollback()
    before = _fingerprint(target)
    capsys.readouterr()

    assert _verify(root, backup, "--verify") == 1
    out = capsys.readouterr().out
    assert "-wal beside it" in out and "was not opened" in out, out
    assert _fingerprint(target) == before, "the verifier checkpointed a planted WAL"


@pytest.mark.security
def test_removing_a_chains_record_cannot_hide_a_broken_chain(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Measured before the fix: flip one byte in the backup's ``audit.log``, drop its
    chains record and its files entry — exit 0, ``verified: true``, while the same
    payload's chain verdict read ``intact: false``. The one check made independently
    of the manifest was silenced by the manifest; ``chains: {}`` did the same.
    """
    root, backup = _backup(tmp_path)
    chain = backup / _CHAIN
    raw = bytearray(chain.read_bytes())
    raw[5] ^= 0x01
    chain.write_bytes(bytes(raw))
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["chains"].pop(_CHAIN)
    manifest["files"] = [entry for entry in manifest["files"] if entry["path"] != _CHAIN]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    capsys.readouterr()

    assert _verify(root, backup, "--verify") == 1
    assert f"chains[{_CHAIN!r}]" in capsys.readouterr().err


def _store(events: object) -> dict[str, object]:
    digest = "0" * 64
    return {
        "path": "data/events/events.sqlite3",
        "sha256": digest,
        "attestation": {"events": events, "digest": digest},
    }


# A null or mis-typed attestation is not here: it is a finding on stdout, not a
# refusal, and test_promotion_verify.py pins that for every attestation field.
_MALFORMED: dict[str, object] = {
    "array": [],
    "store-is-string": {"format": _FORMAT, "store": "x", "files": [], "chains": {}},
    "files-entry-string": {"format": _FORMAT, "store": _store(1), "files": ["x"], "chains": {}},
    "chains-is-list": {"format": _FORMAT, "store": _store(1), "files": [], "chains": []},
    "chains-empty": {"format": _FORMAT, "store": _store(1), "files": [], "chains": {}},
    "chains-record-string": {
        "format": _FORMAT,
        "store": _store(1),
        "files": [],
        "chains": {_CHAIN: "x"},
    },
    # Raw text, not JSON: measured, a RecursionError traceback under both verifiers.
    "deeply-nested": "[" * 100_000,
    # Measured, the uncapped repr of this was 2,000,032 bytes of stderr.
    "format-2mb": {"format": "A" * 2_000_000, "store": _store(1), "files": [], "chains": {}},
}


@pytest.mark.security
@pytest.mark.parametrize("mode", ["--verify", "--verify-restore"])
@pytest.mark.parametrize("shape", sorted(_MALFORMED))
def test_a_malformed_manifest_is_a_message_and_exit_1_not_a_traceback(
    tmp_path: Path, shape: str, mode: str, capsys: pytest.CaptureFixture[str]
) -> None:
    root, _real = _backup(tmp_path)
    hostile = tmp_path / shape
    (hostile / "data" / "events").mkdir(parents=True)
    value = _MALFORMED[shape]
    text = value if isinstance(value, str) else json.dumps(value)
    (hostile / "manifest.json").write_text(text, encoding="utf-8")
    capsys.readouterr()

    # An exception propagating out of main() fails this line on its own.
    assert _verify(root, hostile, mode) == 1
    err = capsys.readouterr().err
    assert "manifest.json" in err, err
    assert any(
        reason in err
        for reason in (
            "refusing to verify",
            "nothing in it can be compared",
            "unknown backup format",
        )
    ), err
    assert "Traceback" not in err, err
    assert len(err) < 2048, "the refusal echoed the manifest's content"


def _edit_attestation(backup: Path, key: str, value: object) -> None:
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["store"]["attestation"][key] = value
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


@pytest.mark.security
@pytest.mark.parametrize("mode", ["--verify", "--verify-restore"])
def test_a_hot_journal_beside_the_store_is_refused_rather_than_replayed(
    tmp_path: Path, mode: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """The ``-wal`` hazard spelled ``-journal``, found by review of the merge.

    Measured: a hot rollback journal beside an intact WAL-mode store was replayed into
    it by ``EventStore.open``, the sha256 changed, the journal was deleted and the run
    exited 0, so the next ``--verify`` failed against the manifest it had just passed.
    """
    root, backup = _backup(tmp_path)
    target = (backup if mode == "--verify" else root) / _STORE
    target.with_name(target.name + "-journal").write_bytes(b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7" * 64)
    before = _fingerprint(target)
    capsys.readouterr()

    assert _verify(root, backup, mode) == 1
    out = capsys.readouterr().out
    assert "-journal beside it" in out and "was not opened" in out, out
    assert _fingerprint(target) == before, "the verifier replayed a planted journal"


@pytest.mark.security
@pytest.mark.parametrize("mode", ["--verify", "--verify-restore"])
@pytest.mark.parametrize(
    "path",
    ["data/events/\x00x", "data/events/" + "x" * 300, "/" + "A" * 200_000],
    ids=["nul", "overlong-component", "huge-absolute"],
)
def test_an_unwalkable_store_path_is_a_bounded_finding_not_an_os_error(
    tmp_path: Path, mode: str, path: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Walking these paths raised ``embedded null byte`` or ``File name too long`` in
    place of the whole report; the absolute one echoed 2 MB. Found by review of the merge.
    """
    root, backup = _backup(tmp_path)
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["store"]["path"] = path
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    capsys.readouterr()

    assert _verify(root, backup, mode) == 1
    captured = capsys.readouterr()
    assert "only path a backup writes" in captured.out, captured
    assert captured.err == "", captured.err
    assert len(captured.out) < 8192, "the finding echoed the manifest's content"


@pytest.mark.security
@pytest.mark.parametrize("mode", ["--verify", "--verify-restore"])
@pytest.mark.parametrize("events", ["1|forged", "E" * 100_000], ids=["delimiter", "huge"])
def test_an_unchecked_event_count_never_reaches_the_audit_chain(
    tmp_path: Path, mode: str, events: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """The manifest's ``events`` went into the audit record's action unchecked.

    Measured on the merge: ``'1|forged'`` made the record refuse the delimiter, so the
    findings were never printed; 2,000,000 characters grew the live chain by 4 MB.
    """
    root, backup = _backup(tmp_path)
    _edit_attestation(backup, "events", events)
    chain = root / _CHAIN
    before = chain.stat().st_size
    capsys.readouterr()

    assert _verify(root, backup, mode) == 1
    captured = capsys.readouterr()
    assert "'events' is not an integer" in captured.out, captured
    assert captured.err == "", captured.err
    assert len(captured.out) < 8192, "the finding echoed the manifest's content"
    assert chain.stat().st_size - before < 4096, "the manifest's value reached the chain"


@pytest.mark.security
@pytest.mark.parametrize("mode", ["--verify", "--verify-restore"])
@pytest.mark.parametrize("field", ["events", "observables"])
def test_a_negative_count_is_a_damaged_manifest_not_re_collection(
    tmp_path: Path, mode: str, field: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Measured on the merge: ``events: -1`` read as ``ADDED`` under ``--verify-restore``,
    whose text names re-collection as the expected cause."""
    root, backup = _backup(tmp_path)
    _edit_attestation(backup, field, -1)
    capsys.readouterr()

    assert _verify(root, backup, mode) == 1
    out = capsys.readouterr().out
    assert f"{field!r} is negative" in out and "ADDED" not in out, out


@pytest.mark.security
@pytest.mark.parametrize("mode", ["--verify", "--verify-restore"])
def test_an_unknown_attestation_field_is_refused(
    tmp_path: Path, mode: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Measured on the merge: an added ``injected`` field verified at exit 0."""
    root, backup = _backup(tmp_path)
    _edit_attestation(backup, "injected", 1)
    capsys.readouterr()

    assert _verify(root, backup, mode) == 1
    out = capsys.readouterr().out
    assert "never does ('injected')" in out, out


@pytest.mark.security
@pytest.mark.parametrize("mode", ["--verify", "--verify-restore"])
@pytest.mark.parametrize("suffix", ["-wal", "-journal", "-shm"])
@pytest.mark.parametrize("shape", _SHAPES)
def test_a_sidecar_that_is_not_a_plain_file_is_refused_rather_than_opened(
    tmp_path: Path, mode: str, suffix: str, shape: str
) -> None:
    """SQLite opens all three sidecars with the store, so each must be a regular file
    with one link. Measured, found by review:

    - a FIFO ``-journal`` hung both verifiers inside ``EventStore.open`` while they held
      the backup lock, so a scheduled take skipped at exit 0;
    - a FIFO, socket, directory or symlink ``-shm`` replaced the report with a bare
      SQLite error and left a new ``-wal`` in the tree under inspection;
    - a ``-shm`` hard-linked to the backup's own manifest had the manifest overwritten
      with 32 KiB of WAL index under a run that exited 0 "verified".

    Every shape runs in a child, so a regression is a failure rather than a hung
    suite. Both symlink shapes are needed: a dangling one is caught only by not
    following it, and one to a regular file only because ``is_file()`` would follow it.
    """
    root, backup = _backup(tmp_path)
    target = (backup if mode == "--verify" else root) / _STORE
    side = target.with_name(target.name + suffix)
    victim = backup / "manifest.json"
    _plant(side, shape, victim)
    others = [
        target.with_name(target.name + s) for s in ("-wal", "-journal", "-shm") if s != suffix
    ]
    planted, store, manifest = _kind(side), _fingerprint(target), _fingerprint(victim)
    named = _named(suffix, shape, victim)

    result = _run_isolated(["--root", str(root), "--caller", "test", mode, str(backup)])

    assert result.returncode == 1, result.stdout[-400:] + result.stderr[-400:]
    assert named in result.stdout, result.stdout[-400:] + result.stderr[-400:]
    assert result.stderr == "", result.stderr[-400:]
    assert _kind(side) == planted, "the verifier replaced or removed the planted sidecar"
    assert _fingerprint(target) == store, "the store under inspection changed"
    assert _fingerprint(victim) == manifest, "the manifest was written through the sidecar"
    assert not any(other.exists() for other in others), "the verifier created a sidecar"


@pytest.mark.security
def test_a_backup_shm_hard_linked_to_the_live_store_cannot_destroy_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The worst case the review measured: a plain ``--verify`` of the backup exited 0
    "verified" and left the LIVE evidence store as 32 KiB of WAL index, which no
    longer opened ("file is not a database")."""
    root, backup = _backup(tmp_path)
    live = root / _STORE
    os.link(live, (backup / _STORE).with_name(_STORE.name + "-shm"))
    before = _fingerprint(live)
    capsys.readouterr()

    assert _verify(root, backup, "--verify") == 1
    assert f"its -shm ({before[0]} bytes) has 2 links" in capsys.readouterr().out
    assert _fingerprint(live) == before
    # While the backup's -shm is a second name for it, the live store is refused
    # too: every write would also land in that name. Remove it and the store opens.
    shm = (backup / _STORE).with_name(_STORE.name + "-shm")
    with pytest.raises(StoreFileError, match="has 2 hard links"):
        EventStore.open(root)
    shm.unlink()
    with EventStore.open(root) as store:
        assert store.count() == 12


@pytest.mark.security
@pytest.mark.parametrize("suffix", ["-wal", "-journal", "-shm"])
@pytest.mark.parametrize("shape", ["fifo", "hard-link"])
def test_a_take_refuses_a_sidecar_before_it_writes_anything(
    tmp_path: Path, suffix: str, shape: str
) -> None:
    """Found by review: the take had the hang the verifiers were fixed for. A FIFO
    ``-journal`` beside the live store blocked it inside the copy while it held the
    backup lock, so every later take and verify printed "skipped" at exit 0 for as long
    as the FIFO stayed. A hard link has its target written through the WAL index. The
    take now refuses either before it creates the backup directory."""
    root, _first = _backup(tmp_path)
    live = root / _STORE
    side = live.with_name(live.name + suffix)
    victim = tmp_path / "victim"
    victim.write_text("not the store's to write\n", encoding="utf-8")
    _plant(side, shape, victim)
    planted, store, untouched = _kind(side), _fingerprint(live), _fingerprint(victim)
    named = _named(suffix, shape, victim)

    result = _run_isolated(["--root", str(root), "--name", "second", "--caller", "test"])

    assert result.returncode == 1, result.stdout[-400:] + result.stderr[-400:]
    assert named in result.stderr, result.stderr
    assert "Traceback" not in result.stderr, result.stderr[-800:]
    assert not (root / "data" / "backups" / "second").exists(), "a refused take left a tree"
    assert _kind(side) == planted
    assert _fingerprint(live) == store
    assert _fingerprint(victim) == untouched


def _dac_enforced(tmp_path: Path) -> bool:
    """Does this process get EACCES from a directory it cannot search?

    Probed rather than read off ``geteuid()``: root with ``CAP_DAC_OVERRIDE`` dropped is
    refused like anyone else, and the CI runner is not root at all.
    """
    probe = tmp_path / "dac-probe"
    probe.mkdir()
    (probe / "f").write_text("x", encoding="utf-8")
    probe.chmod(0o600)
    try:
        (probe / "f").stat()
    except PermissionError:
        return True
    else:
        return False
    finally:
        probe.chmod(0o700)


@pytest.mark.security
def test_a_take_over_an_unsearchable_tree_fails_closed(tmp_path: Path) -> None:
    """Found by review of the round-2 fix: catching ``OSError`` in the walk the take
    shares turned an unsearchable ``data/reports`` into a "refused" entry, and the take
    exited 0 with the reports silently absent. The catch now lives only on the
    verifiers' side, and the take fails as it did before."""
    if not _dac_enforced(tmp_path):
        pytest.skip("this process bypasses DAC checks, so the result would be vacuous")
    root = tmp_path / "lab"
    root.mkdir()
    with EventStore.open(root) as store:
        store.append(normalize(_RECORD % 0), ingested_at=store.next_stamp(time.time()))
    reports = root / "data" / "reports"
    reports.mkdir(parents=True)
    (reports / "r.md").write_text("# incident\n", encoding="utf-8")
    reports.chmod(0o600)
    try:
        code = backup_main(["--root", str(root), "--name", "b", "--caller", "test"])
    finally:
        reports.chmod(0o700)
    assert code == 1
    assert not (root / "data" / "backups" / "b" / "manifest.json").exists()


@pytest.mark.security
@pytest.mark.parametrize("mode", ["--verify", "--verify-restore"])
@pytest.mark.parametrize(
    "path",
    [
        "data/reports/\x00x",
        "data/" + "z" * 200_000,
        "/" + "A" * 200_000,
        "data/reports/\ud800",
        "data/\ud800/x",
    ],
    ids=["nul", "overlong-component", "huge-absolute", "surrogate", "surrogate-directory"],
)
def test_an_unwalkable_file_path_is_a_finding_not_an_os_error(
    tmp_path: Path, mode: str, path: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """The store-path fix, for ``files[]``: these raised a bare error in place of the
    whole report, so a genuine mismatch beside them was never shown.

    The hostile entry goes first and a genuinely altered report after it, so the test
    shows the report survives the entry rather than ending at it, and the echo is
    bounded (found by review: two wrong fixes passed the first version of this test).
    """
    root, backup = _backup(tmp_path, report=True)
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].insert(0, {"path": path, "size": 1, "sha256": "0" * 64})
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    altered = (backup if mode == "--verify" else root) / _REPORT
    altered.write_text("# a different incident\n", encoding="utf-8")
    capsys.readouterr()

    assert _verify(root, backup, mode) == 1
    captured = capsys.readouterr()
    assert captured.err == "", captured.err[-400:]
    assert len(captured.out) < 8192, len(captured.out)
    reasons = ("cannot be checked", "contains a NUL byte", "is absolute")
    assert any(reason in captured.out for reason in reasons), captured.out
    assert str(_REPORT) in captured.out, "the genuine mismatch after the entry was lost"


@pytest.mark.security
@pytest.mark.parametrize("field", ["attestation-digest", "store-sha256", "file-sha256"])
def test_a_mismatched_digest_is_echoed_capped(
    tmp_path: Path, field: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Measured on the merge: a 2,000,000-character digest became 2 MB of output. Each
    of the three places ``--verify`` echoes one is pinned (found by review: uncapping
    the two sha256 sites passed the first version of this test)."""
    root, backup = _backup(tmp_path)
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    huge = "a" * 2_000_000
    if field == "attestation-digest":
        manifest["store"]["attestation"]["digest"] = huge
    elif field == "store-sha256":
        manifest["store"]["sha256"] = huge
    else:
        next(entry for entry in manifest["files"] if entry["path"] == _CHAIN)["sha256"] = huge
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    capsys.readouterr()

    assert _verify(root, backup, "--verify") == 1
    out = capsys.readouterr().out
    assert len(out) < 8192, len(out)
    assert "a" * 79 + "..." in out, out[-400:]


@pytest.mark.security
def test_an_unknown_attestation_key_cannot_write_control_sequences(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review of the merge: the unknown-field finding printed keys raw."""
    root, backup = _backup(tmp_path)
    _edit_attestation(backup, "\x1b[2J\x1b[Hrestore verified: OK\n", 1)
    capsys.readouterr()

    assert _verify(root, backup, "--verify") == 1
    out = capsys.readouterr().out
    assert "\x1b" not in out and "never does" in out, out


#: C0 (ESC, LF, CR, BEL), C1 (the single-character CSI, NEL), a bidi override and a
#: line separator: an escaper that knew only C0 passed the first version of the test
#: below (found by review).
_FORGED = "\x1b[2J\x1b[H\nrestore verified: OK\r\n\x9b2J\x07\u202e\u2028\x85"


def _all_printable(text: str) -> bool:
    """Every character shows as itself; a newline only ever ends a line."""
    return all(char.isprintable() or char == "\n" for char in text)


@pytest.mark.security
@pytest.mark.parametrize("mode", ["--verify", "--verify-restore"])
@pytest.mark.parametrize(
    "site",
    ["absolute-path", "missing-path", "surrogate-path", "store-sha256"],
)
def test_manifest_text_reaches_the_terminal_escaped(
    tmp_path: Path, mode: str, site: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: escaping only the attestation keys left every other echo raw.
    A ``files[]`` path of ``"/\\x1b[2J\\x1b[Hrestore verified: OK\\r\\n"`` cleared the
    operator's terminal and wrote a forged line, and a lone surrogate crashed the text
    report with a traceback partway through. Escaped once, where lines are printed."""
    if site == "store-sha256" and mode == "--verify-restore":
        pytest.skip("--verify-restore does not echo the store sha256")
    root, backup = _backup(tmp_path)
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    hostile = {
        "absolute-path": "/" + _FORGED,
        "missing-path": "data/reports/" + _FORGED,
        "surrogate-path": "/\ud800" + _FORGED,
        "store-sha256": _FORGED + "\ud800",
    }[site]
    if site == "store-sha256":
        manifest["store"]["sha256"] = hostile
    else:
        manifest["files"].insert(0, {"path": hostile, "size": 1, "sha256": "0" * 64})
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    capsys.readouterr()

    assert _verify(root, backup, mode) == 1
    captured = capsys.readouterr()
    assert captured.err == "", captured.err[-400:]
    assert _all_printable(captured.out), repr(captured.out[-400:])
    assert "restore verified: OK" not in captured.out.splitlines(), captured.out
    assert "\\x1b[2J" in captured.out, "the finding was dropped rather than escaped"


@pytest.mark.security
def test_a_symlinked_component_is_named_relative_to_the_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: capping the absolute path cut the finding to the backup's own
    prefix, so it named neither the symlinked component nor where it pointed."""
    root, backup = _backup(tmp_path, report=True)
    elsewhere = tmp_path / ("deep-" * 20) / "elsewhere"
    elsewhere.mkdir(parents=True)
    shutil.copy2(backup / _REPORT, elsewhere / _REPORT.name)
    shutil.rmtree(backup / _REPORT.parent)
    (backup / _REPORT.parent).symlink_to(elsewhere, target_is_directory=True)
    capsys.readouterr()

    assert _verify(root, backup, "--verify") == 1
    out = capsys.readouterr().out
    assert f"passes through the symlink {_REPORT.parent} (->" in out, out
    assert "deep-deep-/elsewhere); refusing" in out, out


def _lab(tmp_path: Path) -> Path:
    """A root holding one event and nothing else, for the take tests."""
    root = tmp_path / "lab"
    root.mkdir()
    with EventStore.open(root) as store:
        store.append(normalize(_RECORD % 0), ingested_at=store.next_stamp(time.time()))
    return root


@pytest.mark.security
@pytest.mark.parametrize(
    "name", [("x" + _FORGED).encode(), b"\x80evil.md"], ids=["control-sequences", "undecodable"]
)
def test_a_take_warning_reaches_the_terminal_escaped(
    tmp_path: Path, name: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: nothing pinned the escaping on the take's "sources NOT in this
    backup" warnings, where a planted link's name is printed: raw control sequences at
    exit 0, or, for a name that is not UTF-8, a traceback after the backup was written."""
    root = _lab(tmp_path)
    reports = root / "data" / "reports"
    reports.mkdir()
    Path(os.fsdecode(os.fsencode(reports) + b"/" + name)).symlink_to("/nowhere")
    capsys.readouterr()

    assert backup_main(["--root", str(root), "--name", "b", "--caller", "test"]) == 0
    captured = capsys.readouterr()
    assert captured.err == "", captured.err[-400:]
    assert "sources NOT in this backup" in captured.out, captured.out
    assert _all_printable(captured.out), repr(captured.out[-400:])
    assert ("\\x1b[2J" if b"\x1b" in name else "\\udc80evil.md") in captured.out
    assert (root / "data" / "backups" / "b" / "manifest.json").is_file()


@pytest.mark.security
def test_a_pass_error_reaches_the_terminal_escaped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: the pass's ``error:`` line was escaped in the code and pinned by
    nothing. A SchemaVersionError quotes the store's own ``meta`` value, which is the
    backup's content."""
    root, backup = _backup(tmp_path)
    db = backup / _STORE
    with contextlib.closing(sqlite3.connect(db)) as conn:
        conn.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'", ("9" + _FORGED,))
        conn.commit()
    for suffix in ("-wal", "-shm"):
        db.with_name(db.name + suffix).unlink(missing_ok=True)
    capsys.readouterr()

    assert _verify(root, backup, "--verify") == 1
    err = capsys.readouterr().err
    assert "schema version" in err and "\\x1b[2J" in err, err
    assert _all_printable(err), repr(err[-400:])


@pytest.mark.security
@pytest.mark.parametrize("mode", ["take", "--verify", "--verify-restore", "--verify-another"])
def test_the_gate_record_cannot_follow_a_symlinked_events_directory(
    tmp_path: Path, mode: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: the gate decision is every mode's first write, and AuditLogger
    refuses a symlink only at the leaf. With ``data/events`` linked into a backup the
    record landed in that backup's chain, which then failed ``--verify`` for good; a
    ``--verify`` of a *different* backup did it at exit 0."""
    root, backup = _backup(tmp_path)
    other = root / "data" / "backups" / "other"
    assert backup_main(["--root", str(root), "--name", "other", "--caller", "test"]) == 0
    events = root / "data" / "events"
    events.rename(events.with_name("events.real"))
    events.symlink_to(other / "data" / "events", target_is_directory=True)
    chain = other / _CHAIN
    before = _fingerprint(chain)
    tail = {
        "take": ["--name", "third"],
        "--verify": ["--verify", str(other)],
        "--verify-restore": ["--verify-restore", str(other)],
        "--verify-another": ["--verify", str(backup)],
    }[mode]
    capsys.readouterr()

    assert backup_main(["--root", str(root), "--caller", "test", *tail]) == 2
    assert "is a symlink" in capsys.readouterr().err
    assert _fingerprint(chain) == before, "the gate record was written into the backup's chain"
    assert not (root / "data" / "backups" / "third").exists()


@pytest.mark.security
def test_the_gate_record_cannot_be_written_outside_the_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The same hole pointed outside: measured, a ``--verify`` exited 0 "verified" and
    created ``audit.log`` in a directory outside the lab root. The refusal quotes the
    link target, so its name is escaped too."""
    root, backup = _backup(tmp_path)
    outside = tmp_path / ("outside" + _FORGED.replace("\n", ""))
    outside.mkdir()
    events = root / "data" / "events"
    events.rename(events.with_name("events.real"))
    events.symlink_to(outside, target_is_directory=True)
    capsys.readouterr()

    assert _verify(root, backup, "--verify") == 2
    err = capsys.readouterr().err
    assert _all_printable(err) and "\\x1b[2J" in err, repr(err[-400:])
    assert list(outside.iterdir()) == [], "the verifier wrote outside the lab root"


@pytest.mark.security
@pytest.mark.parametrize("shape", ["readable", "dangling", "unsearchable"])
def test_a_symlinked_live_store_is_a_finding_and_the_report_survives(
    tmp_path: Path, shape: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: ``--verify-restore`` never walked the live store's path, so
    ``EventStore.open``'s confine raised and the bare error replaced the whole report.
    It is now walked as the backup side's is, and the other findings still print.

    The walk must come before the ``is_file()`` check, which follows the link: a
    dangling link read as "no store at", and one into a directory this account cannot
    search raised out of it (found by review: a readable target alone did not pin it).
    """
    if shape == "unsearchable" and not _dac_enforced(tmp_path):
        pytest.skip("this process bypasses DAC checks, so the result would be vacuous")
    root, backup = _backup(tmp_path, report=True)
    live = root / _STORE
    vault = tmp_path / "vault"
    vault.mkdir()
    real = vault / "store.sqlite3"
    live.rename(real)
    live.symlink_to(real if shape != "dangling" else vault / "nowhere")
    (root / _REPORT).write_text("# a different incident\n", encoding="utf-8")
    before = _fingerprint(real)
    capsys.readouterr()

    if shape == "unsearchable":
        vault.chmod(0o000)
    try:
        code = _verify(root, backup, "--verify-restore")
    finally:
        vault.chmod(0o700)
    captured = capsys.readouterr()
    assert code == 1
    assert captured.err == "", captured.err[-400:]
    assert f"the live store {_STORE} passes through the symlink {_STORE}" in captured.out
    assert "no store at" not in captured.out, captured.out
    assert f"ALTERED: {_REPORT}" in captured.out, "the rest of the report was lost"
    assert _fingerprint(real) == before


@pytest.mark.security
@pytest.mark.parametrize("shape", ["outside-the-root", "inside-the-root", "dangling"])
def test_a_take_names_a_symlinked_tree_it_did_not_copy(
    tmp_path: Path, shape: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: a symlinked ``data/reports`` was skipped without a word, so a take
    exited 0 with every report absent and nothing in ``refused``. Three shapes, each of
    which a narrower check would miss: a containment-only check passes the link inside
    the root, and one gated on ``is_dir()`` skips the dangling link."""
    root = _lab(tmp_path)
    target = {
        "outside-the-root": tmp_path / "outside",
        "inside-the-root": root / "data" / "elsewhere",
        "dangling": tmp_path / "nowhere",
    }[shape]
    if shape != "dangling":
        target.mkdir()
        (target / "r.md").write_text("# incident\n", encoding="utf-8")
    (root / "data" / "reports").symlink_to(target, target_is_directory=True)
    capsys.readouterr()

    assert backup_main(["--root", str(root), "--name", "b", "--caller", "test"]) == 0
    out = capsys.readouterr().out
    manifest = json.loads((root / "data/backups/b/manifest.json").read_text(encoding="utf-8"))
    named = "tree data/reports passes through the symlink data/reports"
    assert any(entry.startswith(named) for entry in manifest["refused"]), manifest["refused"]
    assert not any(entry["path"].startswith("data/reports/") for entry in manifest["files"])
    assert named in out, out
    # Refused and not also followed: without the `continue`, the take listed the link's
    # target, outside the root, into the manifest and stdout (found by review).
    assert not any(entry.startswith("source data/reports/") for entry in manifest["refused"])
    assert "r.md" not in json.dumps(manifest) and "r.md" not in out, out


@pytest.mark.security
@pytest.mark.parametrize("mode", ["--verify", "--verify-restore"])
def test_a_symlink_loop_at_the_backup_path_is_a_refusal_not_a_traceback(
    tmp_path: Path, mode: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: ``Path.resolve()`` raises RuntimeError on a loop on 3.11 and 3.12,
    and nothing caught it, so a planted ``data/backups/latest -> latest`` was a traceback
    after the gate decision was recorded."""
    root, _backup_dir = _backup(tmp_path)
    loop = root / "data" / "backups" / "loop"
    loop.symlink_to(loop)
    capsys.readouterr()

    assert _verify(root, loop, mode) == 1
    assert "this is not a backup" in capsys.readouterr().err


@pytest.mark.security
def test_an_unencodable_character_does_not_cut_the_report_short(tmp_path: Path) -> None:
    """Found by review: escaping control characters left the encoding. Under a non-UTF-8
    stdout an accented letter in a manifest path raised partway through the report. The
    child runs with an ASCII stdout, which ``capsys`` cannot reproduce."""
    root, backup = _backup(tmp_path, report=True)
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].insert(
        0, {"path": "data/reports/r\u00e9sum\u00e9.md", "size": 1, "sha256": "0" * 64}
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    (backup / _REPORT).write_text("# a different incident\n", encoding="utf-8")

    result = _run_isolated(
        ["--root", str(root), "--caller", "test", "--verify", str(backup)],
        env={**os.environ, "PYTHONIOENCODING": "ascii"},
    )

    assert result.returncode == 1, result.stdout[-400:] + result.stderr[-400:]
    assert "Traceback" not in result.stderr, result.stderr[-800:]
    assert "r\\xe9sum\\xe9.md is missing" in result.stdout, result.stdout[-400:]
    assert str(_REPORT) in result.stdout, "the finding after the entry was lost"


@pytest.mark.security
@pytest.mark.parametrize("suffix", ["-wal", "-journal", "-shm"])
def test_a_sidecar_that_cannot_be_checked_is_refused_not_taken_as_absent(
    tmp_path: Path, suffix: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Found by review: nothing pinned this branch, so treating any ``lstat`` error as
    "absent" passed every test. Not walkable is not safe."""
    import scripts.run_backup as run_backup

    db = tmp_path / "events.sqlite3"
    db.write_bytes(b"x")
    real_lstat = os.lstat

    def refusing(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if os.fspath(path).endswith(suffix):  # type: ignore[call-overload]
            raise PermissionError(13, "Permission denied", os.fspath(path))  # type: ignore[call-overload]
        return real_lstat(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(run_backup.os, "lstat", refusing)
    # Through run_backup's own call site, so this pins that it passes the reason on.
    reason = run_backup._unsafe_to_open(db, what="the store")
    assert reason is not None and f"its {suffix} cannot be checked (PermissionError)" in reason


@pytest.mark.security
@pytest.mark.parametrize("mode", ["--verify", "--verify-restore"])
def test_a_symlink_chain_too_deep_to_follow_is_a_refusal_not_a_traceback(
    tmp_path: Path, mode: str, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Found by review: ``realpath`` recurses once per link on 3.11 and 3.12, so a chain
    of about a thousand links raised RecursionError out of the pass. Raised here for the
    argument alone, because 3.13 resolves the same chain iteratively and a real chain
    would test the interpreter rather than the CLI."""
    import scripts.run_backup as run_backup

    root, backup = _backup(tmp_path)
    real_realpath = os.path.realpath

    def too_deep(path: object, *args: object, **kwargs: object) -> str:
        if os.fspath(path) == str(backup):  # type: ignore[call-overload]
            raise RecursionError("maximum recursion depth exceeded")
        return real_realpath(path, *args, **kwargs)  # type: ignore[call-overload,no-any-return]

    monkeypatch.setattr(run_backup.os.path, "realpath", too_deep)
    capsys.readouterr()

    assert _verify(root, backup, mode) == 1
    assert "more symbolic links than can be followed" in capsys.readouterr().err


@pytest.mark.security
def test_every_offending_sidecar_is_named(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: nothing pinned "each offending sidecar is named", and a version
    that stopped at the first let a FIFO hide behind a benign-looking link count."""
    root, backup = _backup(tmp_path)
    target = backup / _STORE
    _plant(target.with_name(target.name + "-journal"), "symlink-to-file", backup / "manifest.json")
    _plant(target.with_name(target.name + "-shm"), "hard-link", backup / "manifest.json")
    capsys.readouterr()

    assert _verify(root, backup, "--verify") == 1
    out = capsys.readouterr().out
    assert "its -journal is a symlink, not a regular file" in out, out
    assert "its -shm (" in out and "has 2 links" in out, out


@pytest.mark.security
@pytest.mark.parametrize("mode", ["--verify", "--verify-restore"])
@pytest.mark.parametrize("verdict", ["verified", "failed"])
def test_the_subject_and_success_lines_reach_the_terminal_escaped(
    tmp_path: Path, mode: str, verdict: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: the subject and success lines carry the resolved backup path,
    and reverting them to a bare ``print`` passed every test. A directory name can then
    forge a "verified" line over a FAILED verdict."""
    root, backup = _backup(tmp_path)
    hostile = backup.with_name("probe" + _FORGED.replace("/", ""))
    backup.rename(hostile)
    if verdict == "failed":
        _edit_attestation(hostile, "injected", 1)
    capsys.readouterr()

    assert _verify(root, hostile, mode) == (0 if verdict == "verified" else 1)
    out = capsys.readouterr().out
    assert _all_printable(out), repr(out[-400:])
    assert "probe\\x1b[2J" in out, out


@pytest.mark.security
def test_ordinary_text_is_not_escaped(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The other side of the escaping: a printable non-ASCII name reaches a UTF-8
    terminal as itself. An escaper that turned every non-ASCII character into an escape
    passed every other test (found by review)."""
    root, backup = _backup(tmp_path)
    accented = "data/reports/r\u00e9sum\u00e9.md"
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].insert(0, {"path": accented, "size": 1, "sha256": "0" * 64})
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    capsys.readouterr()

    assert _verify(root, backup, "--verify") == 1
    assert f"{accented} is missing" in capsys.readouterr().out


@pytest.mark.security
def test_a_refused_startup_creates_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: nothing pinned the audit confine running before the lock is
    prepared, and moved after it a refused run created ``data/backups/backup.lock`` and
    abandoned the descriptor."""
    root = tmp_path / "lab"
    (root / "data").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "data" / "events").symlink_to(outside, target_is_directory=True)
    capsys.readouterr()

    assert backup_main(["--root", str(root), "--name", "b", "--caller", "test"]) == 2
    assert "is a symlink" in capsys.readouterr().err
    assert not (root / "data" / "backups").exists(), "a refused startup created the lock"
    assert list(outside.iterdir()) == []


@pytest.mark.security
def test_an_unsearchable_events_directory_is_an_unusable_audit_log(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: the audit confine turned an unsearchable ``data/events`` into a
    bare errno at exit 2, the arguments' code, where it had been exit 1 "audit log
    unusable". The symlink refusal stays exit 2."""
    if not _dac_enforced(tmp_path):
        pytest.skip("this process bypasses DAC checks, so the result would be vacuous")
    root = _lab(tmp_path)
    events = root / "data" / "events"
    events.chmod(0o600)
    try:
        code = backup_main(["--root", str(root), "--name", "b", "--caller", "test"])
    finally:
        events.chmod(0o700)
    assert code == 1
    assert "audit log unusable, refusing to run" in capsys.readouterr().err


@pytest.mark.security
@pytest.mark.parametrize("kind", ["subdirectory", "fifo"])
def test_a_take_names_a_report_entry_it_cannot_copy(
    tmp_path: Path, kind: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: a subdirectory, or a special file, in ``data/reports`` was left
    out of the backup without a word, at exit 0. It is now named like a symlink is."""
    root = _lab(tmp_path)
    reports = root / "data" / "reports"
    reports.mkdir()
    (reports / "r.md").write_text("# incident\n", encoding="utf-8")
    entry = reports / "sub"
    if kind == "subdirectory":
        entry.mkdir()
        (entry / "c.md").write_text("# nested\n", encoding="utf-8")
    else:
        os.mkfifo(entry, 0o600)
    capsys.readouterr()

    assert backup_main(["--root", str(root), "--name", "b", "--caller", "test"]) == 0
    out = capsys.readouterr().out
    manifest = json.loads((root / "data/backups/b/manifest.json").read_text(encoding="utf-8"))
    named = "source data/reports/sub is not a regular file, so it is not in this backup"
    assert named in manifest["refused"], manifest["refused"]
    assert named in out, out
    assert {"data/reports/r.md"} <= {item["path"] for item in manifest["files"]}


@pytest.mark.security
def test_a_device_sidecar_is_named_as_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The device kinds cannot be created without CAP_MKNOD, so an existing node's
    ``lstat`` stands in, the approach ``test_cli_startup_failclosed.py`` takes. A block
    device has no node guaranteed on every runner and is left unexercised."""
    import scripts.run_backup as run_backup

    db = tmp_path / "events.sqlite3"
    db.write_bytes(b"x")
    real_lstat = os.lstat
    device = real_lstat("/dev/null")

    def as_device(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if os.fspath(path).endswith("-wal"):  # type: ignore[call-overload]
            return device
        return real_lstat(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(run_backup.os, "lstat", as_device)
    reason = run_backup._unsafe_to_open(db, what="the store")
    assert reason is not None and "its -wal is a character device, not a regular file" in reason
