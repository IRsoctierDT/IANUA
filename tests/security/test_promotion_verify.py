# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""A restored root that lost evidence must not verify.

``--verify`` checks a backup against its own manifest *before* a restore.
Nothing checked the live tree *after* one, and ``docs/RESTORE.md`` step 4 is a
bare ``cp -a``. That is the dangerous direction, and the reason is measured
rather than argued: a store missing most of its pages **opens cleanly through**
``EventStore.open`` **and reports a plausible count** — 353 of 400 events in
``tests/integration/test_restore_drill.py``, and 353 is not an obvious zero. An
interrupted copy therefore leaves a *working* SOC quietly short of evidence, at
the one moment an operator is least able to notice.

This is a ``tests/security`` module and not a unit one because the property is
evidence completeness (AGENTS.md §5 treats logs as sensitive by default, and
§6.2 requires a security case where a boundary is involved). The boundary here
is the one between "the SOC's memory is intact" and "the SOC's memory is
quietly incomplete", which is exactly what a promotion decision turns on.

**The control direction is asserted both ways on purpose.** Every refusal below
is paired with :func:`test_a_correct_restore_verifies`, because a check that
refuses everything would satisfy all of them and be worthless. And the
*added*-events case is asserted to be reported as **not** loss, because a gate
that cried loss over an ordinary re-collection would be turned off by the first
operator who met it.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

import pytest

from ingest import normalize
from scripts.run_backup import main as backup_main
from store import EventStore

_RECORD = 'type=USER_AUTH msg=audit(1760000000.1:1): acct="svc-%d" addr=203.0.113.9 res=failed'
_EVENTS = 40


def _seed(root: Path, *, count: int = _EVENTS, label: str = "svc") -> None:
    """A store with ``count`` real events, written through the real append path."""
    now = time.time()
    with EventStore.open(root) as store:
        for index in range(count):
            record = _RECORD % index
            if label != "svc":
                record = record.replace("svc-", f"{label}-")
            store.append(normalize(record), ingested_at=store.next_stamp(now + index))


def _take(root: Path) -> Path:
    """Take a real backup through the real CLI and return its directory."""
    assert backup_main(["--root", str(root), "--caller", "test"]) == 0
    backups = sorted((root / "data" / "backups").glob("backup-*"))
    assert len(backups) == 1, f"expected one backup, found {backups}"
    return backups[0]


def _restore(backup: Path, into: Path) -> Path:
    """Replay ``docs/RESTORE.md`` step 4 into a fresh root: a plain ``cp -a``."""
    import shutil

    (into / "data").mkdir(parents=True, exist_ok=True)
    shutil.copytree(backup / "data", into / "data", dirs_exist_ok=True)
    return into


def _verify_restore(root: Path, backup: Path) -> int:
    return backup_main(["--root", str(root), "--caller", "test", "--verify-restore", str(backup)])


@pytest.mark.security
def test_a_correct_restore_verifies(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The control, and it is not optional.

    Every assertion in this file is a refusal; a gate wired to refuse
    unconditionally would pass all of them. This is the one that says the gate
    can also say yes.

    It also pins something the design turns on: the gate decision this very
    command writes **appends to** ``data/events/audit.log`` before the check
    reads it, so a byte-equality comparison against the manifest would fail
    here on a perfectly correct restore. The prefix comparison is what makes
    this green.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)

    assert _verify_restore(_restore(backup, live), backup) == 0
    out = capsys.readouterr().out
    assert "restore verified" in out, out
    assert "says nothing about the fence" in out, (
        "a green verdict must carry the caveat that it speaks only about the copy — an "
        "operator will quote this line as justification for promoting"
    )


@pytest.mark.security
def test_a_restore_that_lost_events_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The headline case: the loss that looks like a healthy small store.

    Rows are deleted from the *restored* store, which is what a truncated
    transfer or a raced copy produces. Nothing structural notices — the
    database opens, ``count()`` answers, ``quick_check`` is ``ok`` — so the
    only thing that can catch it is the count and digest the backup carried.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)

    database = live / "data" / "events" / "events.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("DELETE FROM events WHERE rowid IN (SELECT rowid FROM events LIMIT 10)")
    connection.commit()
    connection.close()

    # The damaged store is still perfectly openable, which is the whole point.
    with EventStore.open(live) as store:
        assert store.count() == _EVENTS - 10

    assert _verify_restore(live, backup) == 1
    out = capsys.readouterr().out
    assert "LOSS" in out and "10 are missing" in out, out


@pytest.mark.security
def test_a_substituted_store_with_the_same_count_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Equal counts, unequal contents — what a count-only check would wave through.

    This is why the manifest carries a digest over every ``event_id`` and not
    just the row count: restoring the wrong backup, or a store from another
    node, can match on count alone.
    """
    source, other, live = tmp_path / "source", tmp_path / "other", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)

    # Same number of events, different events.
    (live / "data" / "events" / "events.sqlite3").unlink()
    _seed(other, count=_EVENTS, label="other")
    (live / "data" / "events" / "events.sqlite3").write_bytes(
        (other / "data" / "events" / "events.sqlite3").read_bytes()
    )

    assert _verify_restore(live, backup) == 1
    out = capsys.readouterr().out
    assert "SUBSTITUTED" in out, out


@pytest.mark.security
def test_a_missing_store_is_refused_and_none_is_created(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A read-only check must not create the thing it was asked to inspect.

    ``EventStore.open`` **creates** the database when absent. Opening it blind
    would have this verification manufacture an empty store and then report the
    loss of every event — a misleading finding *and* a write from a read-only
    pass, on a root an operator is mid-restore on. Existence is therefore
    checked first, and this asserts the file is still absent afterwards.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)
    database = live / "data" / "events" / "events.sqlite3"
    database.unlink()

    assert _verify_restore(live, backup) == 1
    assert "no store at" in capsys.readouterr().out
    assert not database.exists(), (
        "the verification created a store while checking for one — a read-only pass wrote "
        "to a root mid-restore, and the operator's next read would find an empty SOC"
    )


@pytest.mark.security
@pytest.mark.parametrize("position", ["data/collect/offsets.json", "data/pipeline/cursor.json"])
def test_a_position_left_in_the_live_root_is_refused(
    position: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``docs/RESTORE.md`` step 3 deletes these, and skipping it costs telemetry.

    Offsets newer than the store are the one unrecoverable skew the runbook
    names: the collector reports success, reads nothing, and never rewinds,
    while every unread line still sits in the source. No backup carries a
    position, so one present in a restored root means step 3 was skipped.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)
    path = live / position
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}", encoding="utf-8")

    assert _verify_restore(live, backup) == 1
    assert "POSITION PRESENT" in capsys.readouterr().out


@pytest.mark.security
def test_a_rewritten_declared_file_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Append-only means the backup's bytes stay a prefix; a rewrite is not growth.

    Exercised on ``data/compliance/evidence.jsonl`` rather than on
    ``data/events/audit.log``, and the reason is worth recording: that log is
    the chain *this CLI itself* appends its gate decision to, so damaging it
    fails earlier — measured, truncating it mid-line makes the chain
    unparseable and the pass exits 1 at "could not record the gate decision",
    before the file comparison runs at all. Correct fail-closed ordering, and
    it means the prefix branch has to be proven on one of the other declared
    files.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    evidence = source / "data" / "compliance" / "evidence.jsonl"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(
        "".join(json.dumps({"control": f"CTRL-{i}", "status": "pass"}) + "\n" for i in range(20)),
        encoding="utf-8",
    )
    backup = _take(source)
    _restore(backup, live)

    restored = live / "data" / "compliance" / "evidence.jsonl"
    assert restored.is_file(), "the backup did not carry the evidence trail"
    original = restored.read_bytes()
    # Same length, different history: growth would be fine, rewriting is not.
    restored.write_bytes(b"x" * len(original))

    assert _verify_restore(live, backup) == 1
    assert "REWRITTEN" in capsys.readouterr().out


@pytest.mark.security
def test_a_truncated_declared_file_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An append-only artifact cannot legitimately shrink."""
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    evidence = source / "data" / "compliance" / "evidence.jsonl"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(
        "".join(json.dumps({"control": f"CTRL-{i}", "status": "pass"}) + "\n" for i in range(20)),
        encoding="utf-8",
    )
    backup = _take(source)
    _restore(backup, live)

    restored = live / "data" / "compliance" / "evidence.jsonl"
    data = restored.read_bytes()
    restored.write_bytes(data[: len(data) // 3])

    assert _verify_restore(live, backup) == 1
    assert "TRUNCATED" in capsys.readouterr().out


@pytest.mark.security
def test_added_events_are_reported_as_addition_and_not_as_loss(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Re-collection grows the store, and that must not read as evidence loss.

    ``docs/RESTORE.md`` step 5 re-collects every source, so a root checked
    after step 5 legitimately holds more than the backup attested. The gate
    still refuses — it is an exact comparison and the operator ran it outside
    its window — but it has to say *which direction*, because "you already
    re-collected" and "evidence is missing" demand opposite responses. A gate
    that confuses the two gets switched off.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)

    now = time.time()
    with EventStore.open(live) as store:
        for index in range(5):
            store.append(
                normalize(_RECORD.replace("svc-", "later-") % index),
                ingested_at=store.next_stamp(now + 10_000 + index),
            )

    assert _verify_restore(live, backup) == 1
    out = capsys.readouterr().out
    assert "ADDED" in out, out
    assert "NOT evidence loss" in out, out
    assert "LOSS" not in out.replace("NOT evidence loss", ""), (
        "an ordinary re-collection was reported as loss; this is the false alarm that "
        "would get the gate turned off"
    )
