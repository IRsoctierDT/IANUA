# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The restore drill: a backup nobody has restored is not a backup.

This is the only test in the suite that destroys the whole lab-data root and
puts it back, because that is the scenario ``docs/RESTORE.md`` documents and
the one claim a backup makes. It drives the real CLIs, not the library APIs,
so the thing under test is the procedure an operator would follow.

Three properties, and each one failed somewhere before this existed:

* **the copy is complete** — ``EventStore.attest`` digests every ``event_id``
  with the row count, because content addressing proves each row is what was
  written and proves nothing about whether all of them are there (deleting 100
  of 400 rows leaves ``integrity_check``, ``count()``, ``query()`` and
  ``high_water_mark()`` all silent);
* **recovery loses nothing** — the store is restored and the *positions are
  discarded*, so re-collection re-reads the sources and content addressing
  drops what is already stored;
* **the restored tree is owner-only** — a copy that came back world-readable
  would have given away the evidence it was taken to protect.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from scripts.run_backup import main as backup_main
from scripts.run_collector import main as collect_main
from store import EventStore

_LINES = 600
_BACKUP_AT = 400


def _source(path: Path, lines: int) -> None:
    """A plain syslog source — the format ``collect/`` is documented to read."""
    path.write_text(
        "".join(
            f"Oct 15 09:{index // 60:02d}:{index % 60:02d} web-01 sshd[1]: "
            f"Failed password for u{index} from 203.0.113.{index % 250} port 22 ssh2\n"
            for index in range(lines)
        ),
        encoding="utf-8",
    )


def _count(root: Path) -> int:
    with EventStore.open(root) as store:
        return store.count()


def _collect(root: Path, source: Path) -> int:
    return collect_main(["--root", str(root), "--source", str(source), "--json"])


@pytest.mark.integration
def test_a_destroyed_lab_root_recovers_with_no_loss(tmp_path: Path) -> None:
    """Seed, back up, grow, destroy everything, restore, recover.

    The backup is deliberately *stale* when the disaster happens — it holds
    400 of the 600 lines the source has by then — because a backup that is
    current at the moment of loss is the easy case and not the one an operator
    gets.
    """
    root = tmp_path / "lab"
    root.mkdir()
    source = tmp_path / "auth.log"

    _source(source, _BACKUP_AT)
    assert _collect(root, source) == 0
    assert _count(root) == _BACKUP_AT

    assert backup_main(["--root", str(root), "--name", "drill", "--json"]) == 0
    backup = root / "data" / "backups" / "drill"
    # Kept outside the root, because the next step destroys the root — which
    # is also the point an operator has to get right.
    held = tmp_path / "offsite" / "drill"
    held.parent.mkdir()
    shutil.copytree(backup, held)

    _source(source, _LINES)
    assert _collect(root, source) == 0
    assert _count(root) == _LINES, "the live store should hold everything before the loss"

    shutil.rmtree(root / "data")
    assert not (root / "data").exists()

    # The documented restore: copy the backup's `data/` tree back. The
    # positions are not in it, so there is nothing to get wrong.
    (root / "data").mkdir()
    shutil.copytree(held / "data", root / "data", dirs_exist_ok=True)
    assert not (root / "data" / "collect" / "offsets.json").exists()
    assert not (root / "data" / "pipeline" / "cursor.json").exists()
    assert _count(root) == _BACKUP_AT, "the restored store is the backup, not the live store"

    assert backup_main(["--root", str(root), "--verify", str(held), "--json"]) == 0

    # Re-collection closes the gap: every line is re-read, and content
    # addressing stores only the ones the backup did not already have.
    assert _collect(root, source) == 0
    assert _count(root) == _LINES, "recovery must lose nothing and duplicate nothing"


@pytest.mark.integration
def test_a_backup_taken_while_a_writer_holds_the_store_is_complete(tmp_path: Path) -> None:
    """The case a file copy gets silently wrong, which is why one is not used.

    Measured before this: while a writer holds the connection, the main
    ``.sqlite3`` file carried 4 KiB of a 548 KiB database and the rest sat in
    the ``-wal``. A copy of the main file alone passes ``PRAGMA
    integrity_check``, opens through ``EventStore.open()`` without raising,
    and reports a plausible count — 353 of 400 in one run — so the loss is
    invisible. ``sqlite3.Connection.backup`` is the online backup API and is
    correct whatever the WAL holds, so this asserts the count rather than
    trusting it.
    """
    root = tmp_path / "lab"
    root.mkdir()
    # A live writer, deliberately still open across the backup.
    with EventStore.open(root) as live:
        from ingest import normalize

        for index in range(_BACKUP_AT):
            live.append(
                normalize(
                    f"Failed password for u{index} from 203.0.113.{index % 250} port 22 ssh2"
                ),
                ingested_at=1_760_000_000.0 + index,
            )
        database = root / "data" / "events" / "events.sqlite3"
        uncheckpointed = (database.parent / "events.sqlite3-wal").exists()
        assert backup_main(["--root", str(root), "--name", "hot", "--json"]) == 0

    # The scenario is only meaningful if the WAL really was holding data.
    assert uncheckpointed, "expected an un-checkpointed WAL while the writer was open"
    backup = root / "data" / "backups" / "hot"
    assert _count(backup) == _BACKUP_AT, "a hot backup must capture the whole database"
    assert backup_main(["--root", str(root), "--verify", str(backup), "--json"]) == 0


@pytest.mark.integration
def test_keeping_current_offsets_over_a_restored_store_loses_telemetry(tmp_path: Path) -> None:
    """Why the backup excludes positions, demonstrated rather than asserted.

    This is the one unrecoverable skew of the four: offsets *newer* than the
    store. The collector reports ``events_stored: 0, lines_read: 0`` and exits
    0 while every unread line still sits in the source, and offsets are never
    rewound — so the window is gone and every signal reads healthy. The test
    shows the loss, then shows that the documented procedure avoids it.
    """
    root = tmp_path / "lab"
    root.mkdir()
    source = tmp_path / "auth.log"

    _source(source, _BACKUP_AT)
    assert _collect(root, source) == 0
    assert backup_main(["--root", str(root), "--name", "old", "--json"]) == 0
    backup = root / "data" / "backups" / "old"
    held = tmp_path / "offsite"
    shutil.copytree(backup, held)

    # The source grows and is collected, so the offsets move past the backup.
    _source(source, _LINES)
    assert _collect(root, source) == 0
    assert _count(root) == _LINES
    offsets = (root / "data" / "collect" / "offsets.json").read_text(encoding="utf-8")

    # The mistake: roll the store back to the backup and keep the offsets.
    shutil.rmtree(root / "data" / "events")
    shutil.copytree(held / "data" / "events", root / "data" / "events")
    (root / "data" / "collect" / "offsets.json").write_text(offsets, encoding="utf-8")

    assert _collect(root, source) == 0
    assert _count(root) == _BACKUP_AT, (
        "the collector cannot re-read what its offsets have already passed, so the "
        "200 lines between the backup and the loss are gone"
    )

    # The documented procedure: discard the positions. Nothing else changes.
    (root / "data" / "collect" / "offsets.json").unlink()
    assert _collect(root, source) == 0
    assert _count(root) == _LINES, "discarding the positions recovers the whole window"


@pytest.mark.integration
def test_the_verifier_refuses_a_backup_that_lost_rows(tmp_path: Path) -> None:
    """The completeness attestation, which is the only thing that can tell.

    Rows are removed from the copy with SQL, which is what a truncated
    transfer or a copy that raced a writer produces. Nothing else in the
    platform notices: the file is valid SQLite and every surviving row still
    hashes to its own id.
    """
    import sqlite3

    root = tmp_path / "lab"
    root.mkdir()
    source = tmp_path / "auth.log"
    _source(source, _BACKUP_AT)
    assert _collect(root, source) == 0
    assert backup_main(["--root", str(root), "--name", "drill", "--json"]) == 0

    backup = root / "data" / "backups" / "drill"
    database = backup / "data" / "events" / "events.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM events WHERE rowid <= 100")

    # Valid SQLite, and every remaining row is intact...
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    with EventStore.open(backup) as copy:
        assert len(copy.query()) == _BACKUP_AT - 100  # reads back without raising

    # ...and the verifier still refuses it, naming both the count and the digest.
    assert backup_main(["--root", str(root), "--verify", str(backup), "--json"]) == 1


@pytest.mark.integration
def test_the_restored_tree_is_owner_only(tmp_path: Path) -> None:
    """Including the directories, which is where this script's first run slipped.

    ``mkdir(mode=…, parents=True)`` sets the mode on the leaf only, so the
    backup's own intermediate ``data/`` came out at the process umask until a
    final narrowing sweep replaced the per-call modes.
    """
    root = tmp_path / "lab"
    root.mkdir()
    source = tmp_path / "auth.log"
    _source(source, 20)
    assert _collect(root, source) == 0
    assert backup_main(["--root", str(root), "--name", "drill", "--json"]) == 0

    backup = root / "data" / "backups" / "drill"
    wide = [path for path in (backup, *backup.rglob("*")) if path.stat().st_mode & 0o077]
    assert wide == [], f"group/world-accessible paths in a backup: {wide}"


@pytest.mark.integration
def test_a_symlink_pointing_inside_the_root_is_refused_as_well(tmp_path: Path) -> None:
    """What the per-component walk catches that the containment check does not.

    A symlink out of the root is caught twice — by the component walk and by
    `resolve()` landing outside — so a plant that checked only the leaf still
    passed the out-of-root tests. This is the case that separates them: a link
    whose target is *inside* the root resolves legitimately, and following it
    would copy the event store into the backup labelled as a report, with the
    manifest describing it as one. Evidence misattribution rather than
    exfiltration, which is why it is refused too.
    """
    root = tmp_path / "lab"
    root.mkdir()
    source = tmp_path / "auth.log"
    _source(source, 20)
    assert _collect(root, source) == 0

    reports = root / "data" / "reports"
    reports.mkdir(parents=True)
    (reports / "not-a-report.md").symlink_to(root / "data" / "events" / "events.sqlite3")

    assert backup_main(["--root", str(root), "--name", "probe", "--json"]) == 0
    backup = root / "data" / "backups" / "probe"
    assert not (backup / "data" / "reports" / "not-a-report.md").exists()
    manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    assert any("not-a-report.md" in entry for entry in manifest["refused"]), manifest["refused"]
    assert all("not-a-report" not in entry["path"] for entry in manifest["files"])


@pytest.mark.integration
def test_an_in_root_symlinked_directory_is_what_the_component_walk_is_for(
    tmp_path: Path,
) -> None:
    """The only case the per-component walk catches alone.

    Four plants were needed to find it. A symlink *out* of the root is caught
    twice — by the walk and by `resolve()` landing outside — and an in-root
    symlinked *file* is caught by a leaf-only check. What separates them is an
    in-root symlinked *directory*: `data/compliance/` pointing at
    `data/events/`. Its contents resolve legitimately inside the root, so
    containment passes, and the leaf is a real file, so a leaf-only check
    passes — only walking every component refuses it. Following it would copy
    the collector's own chain into the backup as `data/compliance/audit.log`,
    and the manifest would describe it as the compliance chain.
    """
    root = tmp_path / "lab"
    root.mkdir()
    source = tmp_path / "auth.log"
    _source(source, 20)
    assert _collect(root, source) == 0

    # The real compliance directory is absent in this root; point it at the
    # collector's, which holds a file of the declared name after a pass.
    (root / "data" / "compliance").symlink_to(root / "data" / "collect", target_is_directory=True)
    assert (root / "data" / "compliance" / "audit.log").is_file()  # via the link

    assert backup_main(["--root", str(root), "--name", "probe", "--json"]) == 0
    backup = root / "data" / "backups" / "probe"
    manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    assert any(
        "data/compliance" in entry and "symlink" in entry for entry in manifest["refused"]
    ), manifest["refused"]
    assert all(not entry["path"].startswith("data/compliance") for entry in manifest["files"])


@pytest.mark.integration
def test_a_symlinked_event_store_is_refused_outright(tmp_path: Path) -> None:
    """The one source that is fatal rather than skipped, matching `store/`.

    `store/paths.py::confine` already refuses a symlinked component on the way
    to the database, so `EventStore.open()` would not open one either — this
    keeps the backup consistent with that rather than inventing a new rule.
    And a backup with no store restores as an empty store nothing can
    distinguish from a real one, so proceeding without it is not an option.
    """
    root = tmp_path / "lab"
    root.mkdir()
    source = tmp_path / "auth.log"
    _source(source, 20)
    assert _collect(root, source) == 0

    database = root / "data" / "events" / "events.sqlite3"
    elsewhere = tmp_path / "relocated.sqlite3"
    database.rename(elsewhere)
    database.symlink_to(elsewhere)

    assert backup_main(["--root", str(root), "--name", "probe", "--json"]) == 1
    assert not (root / "data" / "backups" / "probe").exists()


@pytest.mark.integration
def test_a_backup_refuses_to_write_an_empty_store(tmp_path: Path) -> None:
    """The failure that reads as success, refused at the source.

    A copy of a store that is absent restores as a store that is present and
    empty, and nothing downstream can tell those apart — ``EventStore.open``
    raises nothing, reports zero events, and stamps a fresh schema. So a
    backup of a root with no store is an error, not an empty backup.
    """
    root = tmp_path / "lab"
    root.mkdir()
    assert backup_main(["--root", str(root), "--name", "drill", "--json"]) == 1
    assert not (root / "data" / "backups" / "drill").exists()


@pytest.mark.integration
def test_a_symlinked_source_is_refused_and_named_rather_than_followed(tmp_path: Path) -> None:
    """`is_file()` follows symlinks, and so does `shutil.copy2`.

    Reproduced on the first version of this script: a symlink in
    `data/reports/` pointing outside the lab root was copied into the backup
    as a regular file, carrying the target's contents, at exit 0. The backup
    still completes — one planted file must not stop every backup — but the
    refusal is named in both the manifest and the report, because silently
    omitting evidence an operator believes is covered is worse than the leak.
    """
    root = tmp_path / "lab"
    root.mkdir()
    source = tmp_path / "auth.log"
    _source(source, 20)
    assert _collect(root, source) == 0

    outside = tmp_path / "outside.txt"
    outside.write_text("SECRET-OUTSIDE-THE-LAB-ROOT", encoding="utf-8")
    reports = root / "data" / "reports"
    reports.mkdir(parents=True)
    (reports / "leak.md").symlink_to(outside)

    assert backup_main(["--root", str(root), "--name", "probe", "--json"]) == 0
    backup = root / "data" / "backups" / "probe"
    contents = "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in backup.rglob("*")
        if path.is_file() and path.suffix in {".md", ".json", ".log", ".jsonl"}
    )
    assert "SECRET-OUTSIDE-THE-LAB-ROOT" not in contents
    assert not (backup / "data" / "reports" / "leak.md").exists()

    manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    assert any("leak.md" in entry and "symlink" in entry for entry in manifest["refused"]), (
        manifest["refused"]
    )


@pytest.mark.integration
def test_a_symlinked_directory_is_refused_too(tmp_path: Path) -> None:
    """Every component, not only the leaf — a symlinked directory escapes as well.

    A plant that checked only the final component still passed the
    symlinked-*file* test above, so this covers the case that distinguishes
    them: `data/collect/` itself replaced by a link, with the tamper-evidence
    chain on the other side of it.
    """
    root = tmp_path / "lab"
    root.mkdir()
    source = tmp_path / "auth.log"
    _source(source, 20)
    assert _collect(root, source) == 0

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "audit.log").write_text("SECRET-OUTSIDE-THE-LAB-ROOT\n", encoding="utf-8")
    shutil.rmtree(root / "data" / "collect")
    (root / "data" / "collect").symlink_to(elsewhere, target_is_directory=True)

    assert backup_main(["--root", str(root), "--name", "probe", "--json"]) == 0
    backup = root / "data" / "backups" / "probe"
    contents = "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in backup.rglob("*")
        if path.is_file()
    )
    assert "SECRET-OUTSIDE-THE-LAB-ROOT" not in contents
    manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    assert any("symlink" in entry for entry in manifest["refused"]), manifest["refused"]


@pytest.mark.integration
@pytest.mark.parametrize("hostile", ["/etc/hostname", "../../../../etc/hostname"])
def test_the_verifier_will_not_follow_a_manifest_path_out_of_the_backup(
    tmp_path: Path, hostile: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """A manifest is untrusted data inside the artifact being verified.

    `directory / entry["path"]` is not confinement: pathlib discards the left
    side for an absolute right side, and `..` walks out. Reproduced on the
    first version: a manifest naming `/etc/hostname` made the verifier stat
    and sha256 that file and print the real digest in its failure report — an
    arbitrary-read oracle for anything the account can read. The path is now
    refused *before* any stat, and reported as a problem rather than raised so
    an operator sees every reason the backup is untrustworthy at once.
    """
    root = tmp_path / "lab"
    root.mkdir()
    source = tmp_path / "auth.log"
    _source(source, 20)
    assert _collect(root, source) == 0
    assert backup_main(["--root", str(root), "--name", "probe", "--json"]) == 0

    backup = root / "data" / "backups" / "probe"
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].append({"path": hostile, "size": 1, "sha256": "0" * 64})
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    # Exit 1 alone proves nothing: without the guard the verifier reaches the
    # file, finds a size/digest mismatch, and also exits 1. The property is
    # that it refused *by path* and never read what lies outside the backup —
    # so the problem must name the path rule, and no digest of the external
    # file may appear. A plant removing the guard passed an exit-code-only
    # assertion, which is why this asserts the text.
    capsys.readouterr()  # drain the earlier --json report
    assert backup_main(["--root", str(root), "--verify", str(backup), "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    named = [entry for entry in report["problems"] if hostile in entry]
    assert named, report["problems"]
    assert any("absolute" in entry or "traversal" in entry for entry in named), named
    outside = Path("/etc/hostname")
    if outside.is_file():
        digest = hashlib.sha256(outside.read_bytes()).hexdigest()
        assert digest not in json.dumps(report), "the file outside the backup was hashed"


@pytest.mark.integration
def test_the_manifest_records_what_it_excluded_and_why(tmp_path: Path) -> None:
    """The ordering rule is in the artifact, not only in the runbook.

    Offsets newer than the store are the one unrecoverable skew — the
    collector reports success and reads nothing while the source still holds
    every line — so a reader of a backup should not have to find a document to
    learn that positions are absent on purpose.
    """
    root = tmp_path / "lab"
    root.mkdir()
    source = tmp_path / "auth.log"
    _source(source, 20)
    assert _collect(root, source) == 0
    assert backup_main(["--root", str(root), "--name", "drill", "--json"]) == 0

    manifest = json.loads(
        (root / "data" / "backups" / "drill" / "manifest.json").read_text(encoding="utf-8")
    )
    assert set(manifest["excluded"]) == {
        "data/collect/offsets.json",
        "data/pipeline/cursor.json",
    }
    assert "unrecoverable" in manifest["excluded"]["data/collect/offsets.json"]
    assert manifest["store"]["attestation"]["events"] == 20
