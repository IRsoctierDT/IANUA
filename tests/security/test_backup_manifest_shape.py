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
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ingest import normalize
from scripts.run_backup import MANIFEST_FORMAT
from scripts.run_backup import main as backup_main
from store import EventStore

_RECORD = 'type=USER_AUTH msg=audit(1760000000.1:1): acct="svc-%d" addr=203.0.113.9 res=failed'
# The current format, so each hostile manifest reaches the shape check it names
# rather than being refused one step earlier as superseded.
_FORMAT = MANIFEST_FORMAT


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


_REPO_ROOT = Path(__file__).resolve().parents[2]
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
@pytest.mark.parametrize("suffix", ["-journal", "-wal"])
def test_a_fifo_sidecar_is_refused_rather_than_opened(
    tmp_path: Path, mode: str, suffix: str
) -> None:
    """Measured, found by review of the merge: a FIFO ``-journal`` hung both verifiers
    inside ``EventStore.open`` while they held the backup lock, so a scheduled take
    skipped at exit 0.

    The verifier runs in a subprocess with a timeout, as in ``test_audit_lock_path.py``,
    because the failure under test is a hang. An alarm does not do it: measured on the
    pre-fix verifier, a 30s ``SIGALRM`` never raised while the open blocked inside
    SQLite, and the suite hung rather than failed.
    """
    root, backup = _backup(tmp_path)
    target = (backup if mode == "--verify" else root) / _STORE
    side = target.with_name(target.name + suffix)
    os.mkfifo(side, 0o600)
    argv = ["--root", str(root), "--caller", "test", mode, str(backup)]
    code = f"import sys\nfrom scripts.run_backup import main\nsys.exit(main({argv!r}))\n"
    try:
        result = subprocess.run(  # noqa: S603 - fixed interpreter, literal code, test paths
            [sys.executable, "-c", code],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"the verifier opened a FIFO {suffix} and blocked")
    assert result.returncode == 1, result.stdout[-400:] + result.stderr[-400:]
    out = result.stdout
    assert f"{suffix} beside it that is not a regular file" in out, out
    assert side.exists() and not side.is_file(), "the verifier removed the FIFO"


@pytest.mark.security
@pytest.mark.parametrize("mode", ["--verify", "--verify-restore"])
@pytest.mark.parametrize(
    "path", ["data/reports/\x00x", "data/" + "z" * 300], ids=["nul", "overlong-component"]
)
def test_an_unwalkable_file_path_is_a_finding_not_an_os_error(
    tmp_path: Path, mode: str, path: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """The store-path fix, for ``files[]``: these raised a bare error in place of the
    whole report, so a genuine mismatch beside them was never shown."""
    root, backup = _backup(tmp_path)
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].append({"path": path, "size": 1, "sha256": "0" * 64})
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    capsys.readouterr()

    assert _verify(root, backup, mode) == 1
    captured = capsys.readouterr()
    assert "cannot be checked" in captured.out, captured
    assert captured.err == "", captured.err


@pytest.mark.security
def test_a_mismatched_digest_is_echoed_capped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Measured on the merge: a 2,000,000-character digest became 2 MB of output."""
    root, backup = _backup(tmp_path)
    _edit_attestation(backup, "digest", "a" * 2_000_000)
    capsys.readouterr()

    assert _verify(root, backup, "--verify") == 1
    out = capsys.readouterr().out
    assert "store attestation digest" in out and len(out) < 8192, len(out)


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
