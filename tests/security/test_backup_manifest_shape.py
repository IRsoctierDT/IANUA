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
import shutil
import sqlite3
import time
from pathlib import Path

import pytest

from ingest import normalize
from scripts.run_backup import main as backup_main
from store import EventStore

_RECORD = 'type=USER_AUTH msg=audit(1760000000.1:1): acct="svc-%d" addr=203.0.113.9 res=failed'
_FORMAT = "ianua.backup.v1"


def _backup(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "lab"
    root.mkdir()
    now = time.time()
    with EventStore.open(root) as store:
        for index in range(12):
            store.append(normalize(_RECORD % index), ingested_at=store.next_stamp(now + index))
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


_STORE = Path("data") / "events" / "events.sqlite3"
_CHAIN = "data/events/audit.log"


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
    assert "only path a backup writes" in capsys.readouterr().err


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


_MALFORMED: dict[str, object] = {
    "array": [],
    "store-is-string": {"format": _FORMAT, "store": "x", "files": [], "chains": {}},
    "attestation-events-null": {
        "format": _FORMAT,
        "store": _store(None),
        "files": [],
        "chains": {},
    },
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
    assert "manifest.json" in err and "refusing to verify" in err, err
    assert len(err) < 2048, "the refusal echoed the manifest's content"
