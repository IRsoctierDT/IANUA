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
import shutil
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ingest import normalize
from scripts.run_backup import (
    ATTESTATION_FIELDS,
    MANIFEST_FORMAT,
    SUPERSEDED_FORMATS,
    _live_tree_inventory,
)
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
    # The finding used to assert "NOT evidence loss"; review showed a count plus
    # a whole-set digest cannot establish that once rows were added, so it now
    # names the expected cause and the caveat instead.
    assert "treat this as SUBSTITUTED" in out, out
    assert "LOSS:" not in out, (
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
    assert "treat this as SUBSTITUTED" in out, out
    assert "LOSS:" not in out, out


@pytest.mark.security
def test_a_symlinked_report_tree_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Two guards exist for this and each declined it for a different reason.

    Review found it. A backup that declared **no** reports, restored over a root
    whose ``data/reports`` is a symlink to a directory outside the root, exited
    ``0`` on the first version of the reverse walk: there were no manifest report
    entries so ``_unsafe_path`` never ran, and the tree root was a symlink so the
    walk skipped it. ``dashboard/app.py`` reads that path, so a planted file
    would have been presented as this node's report.

    The skip was lifted from ``_copied_paths``, where it is right — a backup must
    not copy *through* a link and pull outside content in. Here the direction is
    reversed and so is the correct behaviour.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)

    reports = live / "data" / "reports"
    if reports.exists():
        shutil.rmtree(reports)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "planted.md").write_text("# Out of root\nCorrelated 9000 events.\n", "utf-8")
    reports.symlink_to(outside, target_is_directory=True)
    assert (reports / "planted.md").is_file(), "the premise is that the dashboard would read it"

    # Asserted on the function's own return value, not on a word in the CLI's
    # output blob. The first version of this test checked `"symlink" in out` and
    # PASSED under a plant that disabled the symlink branch — because `is_dir()`
    # follows the link, so the walk descended it and flagged the file inside as
    # UNDECLARED, keeping the exit code at 1. A substring of a large report is a
    # weak assertion: two different defects produce two different findings and
    # both contain the word "UNDECLARED".
    #
    # The property that matters is that the walk does NOT descend the link: the
    # tree root itself is the finding, and no path inside it is returned.
    found, unsafe = _live_tree_inventory(live)
    assert found == [], (
        f"the walk descended the symlink and returned {[str(p) for p in found]} — it must "
        "report the link itself, not enumerate whatever is behind it"
    )
    assert len(unsafe) == 1 and "symlink" in unsafe[0], unsafe

    assert _verify_restore(live, backup) == 1
    out = capsys.readouterr().out
    assert "data/reports in the live root is a symlink" in out, out


@pytest.mark.security
@pytest.mark.parametrize("value", [None, "20", 20.0, True, [20]])
def test_a_manifest_without_a_usable_observable_count_is_refused(
    value: object, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A guard that skips on malformed input is a fail-open, and this one was.

    Review found it inside the fix for a family of fail-opens, which is the part
    worth remembering. The first version guarded the observables comparison with
    ``isinstance(...) and isinstance(...)`` and silently skipped it otherwise —
    measured, deleting ``observables`` from a v1 manifest *and* deleting every
    live observable row gave exit ``0``, and so did a string ``"20"``.
    ``_verify_backup`` compares only the keys it finds, so nothing else caught it.

    The manifest is untrusted input here — ``_unsafe_path`` already treats its
    paths that way — so absence or a wrong type has to fail closed. ``True`` is
    in the parameters because ``bool`` is an ``int`` subclass and would otherwise
    compare as 1.

    Since the manifest format bump, both absence and type are caught one layer
    earlier and by name: ``_attestation_gaps`` requires every attestation field
    with its type before the store is compared at all, so the ``None`` row
    (which pops the key) reads ``has no 'observables'``, the wrong-type rows
    read ``'observables' is not an integer``, and in every case the store
    comparison is refused rather than run on what is left. The guard that used
    to live beside the comparison is gone — review found that ``events`` next
    to it was being *coerced* with ``int()`` rather than checked.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)

    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if value is None:
        manifest["store"]["attestation"].pop("observables")
    else:
        manifest["store"]["attestation"]["observables"] = value
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert _verify_restore(live, backup) == 1
    out = capsys.readouterr().out
    if value is None:
        assert "has no 'observables'" in out, out
    else:
        assert "'observables' is not an integer" in out, out
    assert "store was not compared" in out, out


def _verify_backup(root: Path, backup: Path) -> int:
    """The pre-restore self-check, ``--verify``, through the real CLI."""
    return backup_main(["--root", str(root), "--caller", "test", "--verify", str(backup)])


def _rewrite_manifest(backup: Path, mutate: Callable[[dict[str, Any]], None]) -> None:
    """Edit the manifest in place, the way a damaged or hostile copy would present."""
    path = backup / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    mutate(manifest)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


_MODES = pytest.mark.parametrize("mode", ["verify", "verify-restore"])


def _run(mode: str, root: Path, backup: Path) -> int:
    return _verify_backup(root, backup) if mode == "verify" else _verify_restore(root, backup)


@pytest.mark.security
def test_the_cli_writes_the_current_format_with_an_observables_digest(tmp_path: Path) -> None:
    """Pin the format literal and the attestation's field set.

    Nothing in the suite named ``ianua.backup.v1`` while it was the format, so
    a silent bump — or a silent revert — would have changed what every backup
    says about itself with no test going red. This names the literal, and
    checks the digest this version exists to add is there and is a sha256.
    """
    source = tmp_path / "source"
    _seed(source)
    backup = _take(source)
    manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["format"] == MANIFEST_FORMAT == "ianua.backup.v2"
    attestation = manifest["store"]["attestation"]
    assert set(attestation) == set(ATTESTATION_FIELDS), set(attestation) ^ set(ATTESTATION_FIELDS)
    assert "observables_digest" in ATTESTATION_FIELDS
    digest = attestation["observables_digest"]
    assert isinstance(digest, str) and len(digest) == 64 and int(digest, 16) >= 0, digest


@pytest.mark.security
def test_one_for_one_observable_substitution_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The finding that forced the format bump.

    Count equal, event count equal, event digest equal, ``quick_check`` clean —
    and every indicator pivot joins on a value the backup never held. On the
    v1 gate this exited 0; nothing it compared could see it. The premise is
    asserted (every other attested field unchanged) so that a red here means
    the digest caught it and not something else.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)
    expected = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))["store"][
        "attestation"
    ]

    connection = sqlite3.connect(live / "data" / "events" / "events.sqlite3")
    try:
        event, value = connection.execute(
            "SELECT event_id, value FROM observables ORDER BY event_id, value LIMIT 1"
        ).fetchone()
        connection.execute(
            "DELETE FROM observables WHERE event_id = ? AND value = ?", (event, value)
        )
        connection.execute(
            "INSERT INTO observables (event_id, value) VALUES (?, ?)",
            (event, f"{value}.substituted"),
        )
        connection.commit()
    finally:
        connection.close()

    with EventStore.open(live) as store:
        attested = store.attest().to_dict()
    for field in ("events", "observables", "digest", "schema_version"):
        assert attested[field] == expected[field], (field, attested[field], expected[field])
    assert attested["observables_digest"] != expected["observables_digest"]

    assert _verify_restore(live, backup) == 1
    out = capsys.readouterr().out
    assert "SUBSTITUTED" in out and "observable" in out, out
    assert "LOSS" not in out, "the direction is wrong: nothing was lost, something was swapped"


@pytest.mark.security
@_MODES
# The literal is named here as well as read from the map, so the parameter set
# can never be empty and v1 is pinned BY NAME: with the v1 entry removed from
# SUPERSEDED_FORMATS the map-only form silently tested nothing (found by review).
@pytest.mark.parametrize("superseded", sorted({"ianua.backup.v1", *SUPERSEDED_FORMATS}))
def test_a_superseded_manifest_format_is_refused_and_the_recourse_is_named(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: str, superseded: str
) -> None:
    """A v1 backup can never satisfy this gate, and the operator must read that.

    Refused outright rather than verified "as far as possible": passing a
    backup on the checks a verifier happens to be able to run is how a
    substituted observables table reached a green verdict. The refusal is not
    a verdict on the copy, says so, and names the recourse — the revision that
    wrote it can verify it — because an operator holding only v1 backups in a
    disaster will otherwise read this as "the restore is bad".
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)
    _rewrite_manifest(backup, lambda m: m.__setitem__("format", superseded))

    assert _run(mode, live, backup) == 1
    err = capsys.readouterr().err
    assert superseded in err and MANIFEST_FORMAT in err, err
    assert "superseded" in err and "not a verdict on the copy" in err, err
    assert "revision that wrote it" in err and "fresh backup" in err, err


@pytest.mark.security
@_MODES
@pytest.mark.parametrize("unknown", ["ianua.backup.v3", "", 2, None, "IANUA.BACKUP.V2"])
def test_an_unknown_manifest_format_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: str, unknown: object
) -> None:
    """Anything that is not exactly the current format is refused, naming it."""
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)
    _rewrite_manifest(backup, lambda m: m.__setitem__("format", unknown))

    assert _run(mode, live, backup) == 1
    err = capsys.readouterr().err
    assert "unknown backup format" in err and MANIFEST_FORMAT in err, err


@pytest.mark.security
@_MODES
@pytest.mark.parametrize("field", ATTESTATION_FIELDS)
def test_a_manifest_missing_an_attestation_field_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: str, field: str
) -> None:
    """Every attestation field is required before any is compared.

    ``_verify_backup`` compared only the keys it found, so deleting a field
    from the manifest removed that check — the fail-open shape review found in
    ``_verify_restore``'s observables guard, one function over. Both verifiers
    now refuse on absence; parametrized over the dataclass's own field list so
    a field added later is covered without anyone remembering to add it here.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)
    _rewrite_manifest(backup, lambda m: m["store"]["attestation"].__delitem__(field))

    assert _run(mode, live, backup) == 1
    out = capsys.readouterr().out
    assert f"has no {field!r}" in out, out


@pytest.mark.security
@_MODES
@pytest.mark.parametrize("value", [None, 20, True, ["x"], {"sha256": "x"}])
def test_a_non_string_observables_digest_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: str, value: object
) -> None:
    """A digest that is present but not a string is refused, not skipped.

    The comparison arm is guarded by ``isinstance(want_digest, str)``; this is
    what makes that guard a refusal rather than a silent skip — the gap is
    reported as a finding before the arm is reached.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)
    _rewrite_manifest(
        backup, lambda m: m["store"]["attestation"].__setitem__("observables_digest", value)
    )

    assert _run(mode, live, backup) == 1
    out = capsys.readouterr().out
    assert "'observables_digest' is not a string" in out, out


@pytest.mark.security
def test_verify_names_a_missing_store_file_instead_of_crashing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The regression the independent review caught before this shipped.

    Binding the attestation only in the branch that opens the store, and then
    reading it in the return on every path, raised ``UnboundLocalError`` on a
    backup whose store file was gone — the most basic truncated-copy damage
    this gate exists to name. The base branch printed ``... is missing``; the
    first version of this change printed a traceback to stderr, nothing to
    stdout, and never wrote the pass's audit record. No test covered it.
    """
    source = tmp_path / "source"
    _seed(source)
    backup = _take(source)
    (backup / "data" / "events" / "events.sqlite3").unlink()

    assert _verify_backup(source, backup) == 1
    captured = capsys.readouterr()
    assert "is missing" in captured.out, captured.out
    assert captured.err == "", captured.err


@pytest.mark.security
def test_verify_names_an_escaping_store_path_instead_of_crashing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Same regression, second path: a manifest store path ``_unsafe_path`` refuses."""
    source = tmp_path / "source"
    _seed(source)
    backup = _take(source)
    _rewrite_manifest(backup, lambda m: m["store"].__setitem__("path", "../../../etc/passwd"))

    assert _verify_backup(source, backup) == 1
    captured = capsys.readouterr()
    assert "manifest store path" in captured.out, captured.out
    assert captured.err == "", captured.err


@pytest.mark.security
@_MODES
@pytest.mark.parametrize("value", ["40", 40.9, True, [40], {"n": 40}, None])
def test_a_non_integer_event_count_is_refused_not_coerced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: str, value: object
) -> None:
    """``int()`` is coercion, not a check — found by review.

    ``"40"`` and ``40.9`` compared equal to a live count of 40 and the gate
    exited 0 saying it "holds the 40.9 event(s)"; ``null`` and a list raised a
    bare ``TypeError`` traceback. Every attestation field is now type-checked
    in ``_attestation_gaps`` for both verifiers, and ``bool`` is refused
    because it is an ``int`` subclass.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)
    _rewrite_manifest(backup, lambda m: m["store"]["attestation"].__setitem__("events", value))

    assert _run(mode, live, backup) == 1
    captured = capsys.readouterr()
    assert "'events' is not an integer" in captured.out, captured.out
    assert captured.err == "", captured.err


def _whole(replacement: object) -> Callable[[dict[str, Any]], None]:
    def mutate(manifest: dict[str, Any]) -> None:
        manifest.clear()
        manifest["__replace_with__"] = replacement

    return mutate


@pytest.mark.security
@_MODES
@pytest.mark.parametrize(
    ("mutate", "phrase"),
    [
        pytest.param(_whole(None), "not a JSON object", id="null-document"),
        pytest.param(_whole([]), "not a JSON object", id="array-document"),
        pytest.param(lambda m: m.__delitem__("store"), "has no 'store'", id="no-store"),
        pytest.param(
            lambda m: m.__setitem__("store", "x"), "'store' is not an object", id="store-string"
        ),
        pytest.param(lambda m: m.__delitem__("files"), "has no 'files'", id="no-files"),
        pytest.param(
            lambda m: m.__setitem__("files", {}), "'files' is not a list", id="files-object"
        ),
        pytest.param(lambda m: m.__delitem__("chains"), "has no 'chains'", id="no-chains"),
        pytest.param(
            lambda m: m.__setitem__("chains", []), "'chains' is not an object", id="chains-list"
        ),
    ],
)
def test_a_manifest_damaged_above_the_attestation_is_refused_by_name(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    mode: str,
    mutate: Callable[[dict[str, Any]], None],
    phrase: str,
) -> None:
    """Containers above the attestation were indexed blind — found by review.

    A manifest that is JSON ``null``, or whose ``store`` is a string, or that
    lacks ``files``, surfaced as an ``AttributeError``/``TypeError``/``KeyError``
    traceback. Refused by name on stderr (nothing in such a manifest can be
    compared, so this is a refusal and not a finding), exit 1, no traceback.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)
    path = backup / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    mutate(manifest)
    document = manifest.get("__replace_with__", manifest)
    path.write_text(json.dumps(document) + "\n", encoding="utf-8")

    assert _run(mode, live, backup) == 1
    captured = capsys.readouterr()
    assert phrase in captured.err, captured.err
    assert "Traceback" not in captured.err, captured.err


@pytest.mark.security
@_MODES
def test_a_missing_attestation_is_a_finding_in_both_modes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: str
) -> None:
    """No ``attestation`` at all is a finding on stdout, not a bare ``error: 'attestation'``."""
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)
    _rewrite_manifest(backup, lambda m: m["store"].__delitem__("attestation"))

    assert _run(mode, live, backup) == 1
    captured = capsys.readouterr()
    assert "has no 'attestation'" in captured.out, captured.out
    assert captured.err == "", captured.err


@pytest.mark.security
@pytest.mark.parametrize(
    ("field", "edit"),
    [
        pytest.param("schema_version", lambda v: v + 1, id="schema-version"),
        pytest.param("high_water", lambda v: (v or 0.0) + 1.0, id="high-water"),
    ],
)
def test_verify_restore_compares_the_two_fields_it_used_to_skip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], field: str, edit: Callable[[Any], Any]
) -> None:
    """``--verify`` compared all six attestation fields; ``--verify-restore`` four.

    Found by review: a live store whose mark had been changed verified green
    here while ``--verify`` on identical bytes was red. ``schema_version`` is
    compared always; ``high_water`` when the event count matches, since with
    rows added or lost the mark necessarily moved and LOSS/ADDED names that.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    _seed(source)
    backup = _take(source)
    _restore(backup, live)
    _rewrite_manifest(
        backup,
        lambda m: m["store"]["attestation"].__setitem__(
            field, edit(m["store"]["attestation"][field])
        ),
    )

    assert _verify_restore(live, backup) == 1
    out = capsys.readouterr().out
    assert f"store attestation {field}:" in out, out
    assert "LOSS" not in out and "ADDED" not in out, out
