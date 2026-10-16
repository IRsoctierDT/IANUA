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


# --- the manifest carries it; the comparison must read it ----------------------
#
# Three defects of one shape, found by review on the merged gate and fixed
# together because they live in one loop. Each is paired with a control
# direction: a check that refuses everything satisfies every refusal here.


def _with_report(root: Path, name: str, body: str) -> Path:
    """Write a report into the live root, as the dashboard's tree would hold it."""
    reports = root / "data" / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    path = reports / name
    path.write_text(body, encoding="utf-8")
    return path


@pytest.mark.security
def test_a_report_that_grew_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Prefix comparison was wrong for a report, and review found it.

    A live report holding the backed-up bytes **followed by anything at all**
    passed ``_digest_prefix`` and produced a green promotion verdict. Measured
    on the merged gate: a 40-byte declared report, 94 bytes live with 54
    appended — exit 0.

    A report has no legitimate append behaviour. It is rewritten whole, and
    inside this check's window (``docs/RESTORE.md`` between steps 4 and 5)
    nothing writes one at all, so growth means the live copy is not the
    backed-up copy.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    _with_report(source, "incident.md", "# Incident\nStore held 40 events.\n")
    backup = _take(source)
    _restore(backup, live)

    report = live / "data" / "reports" / "incident.md"
    report.write_text(
        report.read_text(encoding="utf-8") + "\n## APPENDED\nStore held 9000 events.\n",
        encoding="utf-8",
    )

    assert _verify_restore(live, backup) == 1
    assert "ALTERED" in capsys.readouterr().out


@pytest.mark.security
def test_a_report_rewritten_to_the_same_length_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The digest branch, not the size branch — a size check alone is not enough.

    Asserted separately because the two branches fail for different reasons and
    a same-length rewrite is the one a size comparison waves through. This is
    the report equivalent of the ``REWRITTEN`` case on an append-only stream.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    _with_report(source, "incident.md", "# Incident\nStore held 40 events.\n")
    backup = _take(source)
    _restore(backup, live)

    report = live / "data" / "reports" / "incident.md"
    original = report.read_bytes()
    report.write_bytes(b"x" * len(original))
    assert report.stat().st_size == len(original), "this test's premise is a same-size rewrite"

    assert _verify_restore(live, backup) == 1
    assert "ALTERED" in capsys.readouterr().out


@pytest.mark.security
def test_an_append_only_stream_may_still_grow(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control direction for the strict comparison, and it is load-bearing.

    Tightening reports to exact equality must **not** tighten the hash chains
    and the evidence stream, which grow by design — this command's own gate
    decision appends to ``data/events/audit.log`` before the check reads it, so
    demanding equality there would fail every correct restore. If this test and
    :func:`test_a_report_that_grew_is_refused` are ever both green for the wrong
    reason, the classifier has collapsed into one rule.
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
    with restored.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"control": "CTRL-20", "status": "pass"}) + "\n")

    assert _verify_restore(live, backup) == 0, (
        "an append-only stream that grew was refused; the strict comparison for reports "
        "has leaked onto the streams that legitimately append"
    )
    assert "restore verified" in capsys.readouterr().out


@pytest.mark.security
def test_a_report_the_manifest_never_listed_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The reverse direction, which the gate never walked.

    ``docs/RESTORE.md`` step 4 is a bare ``cp -a``, which **merges** into a
    nonempty destination rather than replacing it. So a report written after the
    backup was taken survives the restore, and the old loop — which iterated
    ``manifest["files"]`` only — could not see it. Measured on the merged gate: a
    backup at 20 events with one declared report, a live root grown to 35 events
    and a second report describing them, store deleted and ``cp -a`` applied —
    exit 0, with the later report still claiming "Correlated 35 events" over a
    store holding 20.

    ``dashboard/app.py`` reads this tree, so that report would be presented
    against the restored store. The finding says ``UNDECLARED`` rather than
    ``LOSS`` because the directions demand opposite responses.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    _with_report(source, "incident-old.md", "# Before the backup\n")
    backup = _take(source)
    _restore(backup, live)

    # The report that outlived the restore.
    _with_report(live, "incident-new.md", "# After the backup\nCorrelated 9000 events.\n")

    assert _verify_restore(live, backup) == 1
    out = capsys.readouterr().out
    assert "UNDECLARED" in out, out
    assert "incident-new.md" in out, "the finding must name the file an operator has to remove"
    assert "NOT store evidence loss" in out, (
        "a stale report and a short store demand opposite responses, so the direction "
        "has to be unambiguous"
    )


@pytest.mark.security
def test_observables_lost_without_events_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The headline of the three: every event-level check passes.

    ``attest()``'s digest is a sha256 over the sorted ``event_id`` set, so
    observables are **not** in the preimage. A restore that loses observable
    rows and no event rows satisfies ``quick_check``, the event count and the
    digest together. Measured on the merged gate: 20 observables deleted of 20,
    events untouched, digest equal — exit 0, on a store whose indicator pivots
    then return nothing, because ``correlation/entities.py`` joins on this
    table.

    The number was already in the manifest: ``attestation.to_dict()`` is stored
    whole, so the fix reads a field that was sitting in the file the gate had
    just parsed.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)

    database = live / "data" / "events" / "events.sqlite3"
    connection = sqlite3.connect(database)
    attested = connection.execute("SELECT COUNT(*) FROM observables").fetchone()[0]
    assert attested > 0, "this test's premise is that the seed produced observables"
    connection.execute("DELETE FROM observables")
    connection.commit()
    connection.close()

    # Every event-shaped property still holds, which is the whole point.
    with EventStore.open(live) as store:
        assert store.count() == _EVENTS
        assert store.attest().observables == 0

    assert _verify_restore(live, backup) == 1
    out = capsys.readouterr().out
    assert "LOSS" in out and "observable" in out, out


@pytest.mark.security
def test_more_observables_than_attested_reads_as_addition(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Re-collection grows both tables, and that must not read as loss.

    The control direction for the observables check. ``docs/RESTORE.md`` step 5
    re-collects, so a root checked after it legitimately holds more of both. The
    gate still refuses — it is an exact comparison run outside its window — but
    "you already re-collected" and "evidence is missing" demand opposite
    responses, and a gate that confuses them gets switched off.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)

    now = time.time()
    with EventStore.open(live) as store:
        for index in range(5):
            store.append(
                normalize(
                    _RECORD.replace("svc-", "later-").replace("203.0.113.9", "198.51.100.7") % index
                ),
                ingested_at=store.next_stamp(now + 10_000 + index),
            )

    assert _verify_restore(live, backup) == 1
    out = capsys.readouterr().out
    assert "ADDED" in out, out
    assert "NOT evidence loss" in out, out
