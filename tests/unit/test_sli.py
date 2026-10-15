# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Behaviour of the service-level indicators: both directions of every grade.

The failure mode this package exists to prevent is a monitor that reads
healthy while the subsystem behind it is not, so most of these tests assert
the *unhealthy* direction: that an unmeasurable signal is not a pass, that a
negative lag does not satisfy an "at most" target, and that a cursor ahead of
the store is reported rather than scored.
"""

from __future__ import annotations

import contextlib
import io
import json
import sqlite3
import time
from pathlib import Path

import pytest

from collect import MAX_BYTES_PER_RUN, Position, offsets_path, save_offsets
from ingest import normalize
from pipeline import DEFAULT_BATCH, Cursor, cursor_path, save_cursor
from sli import (
    BY_ID,
    CHAIN_FILES,
    MEASURERS,
    OBJECTIVES,
    Direction,
    Measurement,
    Status,
    measure,
)
from sli.indicators import BACKUP_SUBDIR, MANIFEST_FILE
from sli.report import Indicator, SliReport
from store import EventStore

_AUDITD = "type=SYSCALL msg=audit(1760000001.200:2): node=web-01 auid=svc-deploy comm=bash"
_CLOUD = json.dumps(
    {
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "eventTime": "2026-10-15T09:00:02Z",
    }
)


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "lab"
    root.mkdir()
    return root


def _populated(tmp_path: Path) -> Path:
    """A root that has been collected into, cycled, and backed up."""
    from scripts.run_backup import main as backup_main
    from scripts.run_collector import main as collect_main
    from scripts.run_pipeline import main as pipeline_main

    root = _root(tmp_path)
    log = tmp_path / "app.log"
    log.write_text(f"{_AUDITD}\n{_CLOUD}\n", encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        assert collect_main(["--root", str(root), "--source", str(log)]) == 0
        assert pipeline_main(["--root", str(root)]) == 0
        assert backup_main(["--root", str(root)]) == 0
    return root


# ----------------------------------------------------------- the definition


@pytest.mark.unit
def test_every_objective_has_a_measurer_and_every_measurer_an_objective() -> None:
    """A package with a measurer nobody calls is the shape ``prune`` shipped in.

    ``EventStore.prune`` shipped with no caller outside tests — a mechanism
    with no policy — and that is what this asserts cannot happen in the
    opposite direction either.
    """
    assert {objective.id for objective in OBJECTIVES} == set(MEASURERS)
    assert len(OBJECTIVES) == len(BY_ID), "two objectives share an id"


@pytest.mark.unit
def test_every_target_records_where_its_number_came_from() -> None:
    """A threshold with no provenance is one nobody dares to change."""
    unexplained = [objective.id for objective in OBJECTIVES if len(objective.rationale) < 40]
    assert not unexplained, f"{unexplained} have no recorded derivation"


@pytest.mark.unit
def test_the_derivable_targets_are_imported_rather_than_retyped() -> None:
    """A retyped constant is a constant that drifts.

    Two targets have a source in the repository, and both must move when it
    does: one collector pass's byte cap and one cycle's batch size.
    """
    assert BY_ID["collection-pending"].target == float(MAX_BYTES_PER_RUN)
    assert BY_ID["detection-backlog"].target == float(DEFAULT_BATCH)


@pytest.mark.unit
def test_the_chain_list_agrees_with_the_backup_cli() -> None:
    """Two declared lists of the same chains; four copies is how three stay fixed.

    ``sli`` declares its own rather than importing ``scripts.run_backup``,
    because a package importing a CLI inverts the layering — so the agreement
    is asserted instead of assumed. A new audit chain must be added to both.
    """
    from scripts.run_backup import CHAIN_FILES as BACKUP_CHAINS

    assert set(CHAIN_FILES) == set(BACKUP_CHAINS)


# ------------------------------------------------------------- the grading


@pytest.mark.unit
def test_an_unmeasurable_indicator_is_not_healthy() -> None:
    """The one property every other fail-open defect in this repository shares."""
    assert Status.MET.healthy is True
    assert Status.BREACHED.healthy is False
    assert Status.UNKNOWN.healthy is False


@pytest.mark.unit
@pytest.mark.parametrize(
    ("direction", "target", "value", "expected"),
    [
        (Direction.AT_MOST, 10.0, 9.0, Status.MET),
        (Direction.AT_MOST, 10.0, 10.0, Status.MET),
        (Direction.AT_MOST, 10.0, 10.5, Status.BREACHED),
        (Direction.AT_MOST, 10.0, None, Status.UNKNOWN),
        (Direction.AT_LEAST, 1.0, 1.0, Status.MET),
        (Direction.AT_LEAST, 1.0, 0.5, Status.BREACHED),
        (Direction.AT_LEAST, 1.0, None, Status.UNKNOWN),
    ],
)
def test_an_objective_grades_its_own_measurement(
    direction: Direction, target: float, value: float | None, expected: Status
) -> None:
    """Both directions and both boundaries, because the comparison exists once.

    It exists once deliberately — seven indicators grading themselves would be
    seven chances to invert a target — which also means one wrong comparison
    here would be wrong everywhere, so the table covers each edge.
    """
    objective = BY_ID["ingest-freshness"]
    graded = type(objective)(
        id="probe",
        title="probe",
        unit="units",
        direction=direction,
        target=target,
        rationale="a test probe, long enough to satisfy the provenance assertion above",
    )
    assert graded.evaluate(value) is expected


@pytest.mark.unit
def test_a_report_is_healthy_only_when_every_objective_is_met(tmp_path: Path) -> None:
    """Written as a conjunction, not as "nothing is breached".

    The second spelling is the fail-open one and it is the spelling a reader
    reaches for: a report of all-unknown has nothing breached.
    """
    report = measure(_root(tmp_path), now=time.time())
    assert report.unknown, "the empty root must leave indicators unmeasurable"
    assert not report.breached or report.unknown, "nothing to grade"
    assert report.healthy is False
    assert len(report.met) + len(report.breached) + len(report.unknown) == len(report.indicators)


@pytest.mark.unit
def test_a_probe_that_raises_does_not_cost_the_whole_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A monitor that returns nothing when one probe breaks goes dark on cue.

    Same two-layer shape as ``ingest.normalize_many``, and asserted the same
    way: the report must still arrive, the broken probe must be named, and it
    must not be counted as healthy.
    """

    def explode(root: Path, now: float) -> Measurement:
        raise RuntimeError("probe failure")

    patched = dict(MEASURERS)
    patched["store-readable"] = explode
    monkeypatch.setattr("sli.report.MEASURERS", patched)

    report = measure(Path("/nonexistent-root-for-this-test"), now=0.0)

    broken = [item for item in report.indicators if item.objective.id == "store-readable"]
    assert len(broken) == 1
    assert broken[0].status is Status.UNKNOWN
    assert "RuntimeError" in broken[0].detail
    assert len(report.indicators) == len(OBJECTIVES), "the other probes were lost"


# ---------------------------------------------------------- the measurements


@pytest.mark.unit
def test_an_empty_root_measures_as_unmeasurable_not_healthy(tmp_path: Path) -> None:
    """Nothing has run yet, so almost nothing can be measured — and none of it passes."""
    report = measure(_root(tmp_path), now=time.time())
    by_id = {item.objective.id: item for item in report.indicators}

    for name in (
        "collection-pending",
        "ingest-freshness",
        "detection-lag",
        "detection-backlog",
        "store-readable",
        "audit-chains-intact",
    ):
        assert by_id[name].status is Status.UNKNOWN, f"{name}: {by_id[name].detail}"
        assert by_id[name].detail, f"{name} is unmeasurable and does not say why"

    # Absence of a backup is a *measured* fact, not an unmeasurable one: the
    # platform is genuinely not restorable.
    assert by_id["backup-present"].status is Status.BREACHED
    assert by_id["backup-present"].value == 0.0


@pytest.mark.unit
def test_a_fully_exercised_root_measures_as_healthy(tmp_path: Path) -> None:
    """The other direction, or every assertion above is satisfied by refusing everything.

    Three CLIs are run for real — collector, cycle, backup — so this is the
    whole chain rather than a hand-built tree that happens to satisfy the
    probes.
    """
    report = measure(_populated(tmp_path), now=time.time())
    assert report.healthy, report.headline()
    assert len(report.met) == len(OBJECTIVES)


@pytest.mark.unit
def test_the_backlog_is_exact_rather_than_over_counted(tmp_path: Path) -> None:
    """The subtraction version reported the whole store as backlog, forever.

    ``count() - count_before(cursor.ingested_at)`` over-counts by every event
    sharing the cursor's own stamp, which is one ``append_many`` commit. On a
    freshly caught-up store holding one commit of two events it reported a
    backlog of 2 against a true backlog of 0 — on a low-volume deployment,
    where every pass is one commit, that reads as "nothing is ever processed".
    Measured, which is why the keyset probe replaced it.
    """
    root = _populated(tmp_path)
    report = measure(root, now=time.time())
    backlog = next(i for i in report.indicators if i.objective.id == "detection-backlog")
    assert backlog.value == 0.0, backlog.detail


@pytest.mark.unit
def test_an_unread_tail_shows_up_as_pending_bytes(tmp_path: Path) -> None:
    """The indicator a permanently stalled source appears in.

    Computed from ``Position.size`` minus ``Position.offset`` — both recorded
    by the collector inside the lab root — so it measures what the collector
    itself saw and could not finish, and needs no reach outside the root.
    """
    root = _root(tmp_path)
    save_offsets(
        offsets_path(root),
        {"/var/log/stalled.log": Position(offset=10, inode=1, device=1, size=10 + 9_000_000)},
    )
    report = measure(root, now=time.time())
    pending = next(i for i in report.indicators if i.objective.id == "collection-pending")
    assert pending.status is Status.BREACHED, pending.detail
    assert pending.value == 9_000_000.0
    assert "stalled.log" in pending.detail


@pytest.mark.unit
def test_a_cursor_ahead_of_the_store_is_reported_not_scored(tmp_path: Path) -> None:
    """A negative lag satisfies an "at most" target, which is the trap.

    ``docs/RESTORE.md`` records this skew as the one unrecoverable direction:
    ``next_stamp`` compares the clock against the store's high-water mark and
    not the cursor, so after a backward clock step re-collected events are
    stamped below the cursor and the strictly-after keyset never reads them.
    Grading it ``MET`` would report the unrecoverable state as healthy.

    **Both** cursor-reading indicators are asserted, which is the fix to this
    test rather than to the code it guards. The first version built this exact
    state and checked ``detection-lag`` alone, while ``detection-backlog`` sat
    in the same report reading ``met, 0 event(s) not yet processed`` —
    character-for-character the caught-up sentence. A strictly-after count
    cannot see the events stranded behind the cursor, so zero is what it must
    return; the defect was grading that zero.
    """
    root = _populated(tmp_path)
    with EventStore.open(root) as store:
        mark = store.high_water_mark()
    assert mark is not None
    save_cursor(cursor_path(root), Cursor(ingested_at=mark + 3600.0, event_id="z" * 64))

    report = measure(root, now=time.time())
    lag = next(i for i in report.indicators if i.objective.id == "detection-lag")
    assert lag.status is Status.UNKNOWN, lag.detail
    assert "ahead" in lag.detail

    backlog = next(i for i in report.indicators if i.objective.id == "detection-backlog")
    assert backlog.status is Status.UNKNOWN, backlog.detail
    assert backlog.value is None, "a count of the reachable rows was graded as the backlog"
    assert "ahead" in backlog.detail and "stranded" in backlog.detail


@pytest.mark.unit
def test_a_retention_pass_that_empties_the_store_still_measures_met(tmp_path: Path) -> None:
    """The false alarm the fix above was one condition away from inventing.

    ``high_water_mark`` is a stored mark rather than a ``MAX`` over the rows,
    so it outlives them: after pruning every event the mark still reads, and
    the cursor still names a row that is gone. Measured before the cursor-ahead
    branch was written, precisely because the tempting spelling of that branch
    — refuse whenever the cursor names an event the store no longer holds —
    turns a retention pass doing its job into a breach. A true backlog of zero
    is zero.
    """
    root = _populated(tmp_path)
    with EventStore.open(root) as store:
        mark = store.high_water_mark()
        assert mark is not None
        assert store.prune(before=mark + 1.0) == 2

    report = measure(root, now=mark + 2.0)
    by_id = {indicator.objective.id: indicator for indicator in report.indicators}
    assert by_id["detection-backlog"].status is Status.MET, by_id["detection-backlog"].detail
    assert by_id["detection-backlog"].value == 0.0
    assert by_id["detection-lag"].status is Status.MET, by_id["detection-lag"].detail


@pytest.mark.unit
def test_an_offset_past_the_recorded_size_is_not_a_fully_read_source(tmp_path: Path) -> None:
    """The second site of the same shape: a clamped negative read as the best news.

    ``max(0, size - offset)`` made an offset past the observed size zero, and
    zero pending bytes printed *the caught-up sentence* — so the two states
    were indistinguishable in the report, which this test asserts they are
    not. The collector never writes this: ``collect.tail._resume_from`` returns
    ``(0, "truncated")`` whenever the file is shorter than the stored offset,
    which is why the refusal belongs in the monitor and not in ``load``.
    """
    root = _root(tmp_path)
    caught_up = Position(offset=4096, inode=1, device=1, size=4096)
    save_offsets(offsets_path(root), {"/var/log/app.log": caught_up})
    healthy = next(
        i
        for i in measure(root, now=time.time()).indicators
        if i.objective.id == "collection-pending"
    )
    assert healthy.status is Status.MET, healthy.detail

    impossible = Position(offset=9000, inode=1, device=1, size=4096)
    save_offsets(offsets_path(root), {"/var/log/app.log": impossible})
    damaged = next(
        i
        for i in measure(root, now=time.time()).indicators
        if i.objective.id == "collection-pending"
    )
    assert damaged.status is Status.UNKNOWN, damaged.detail
    assert damaged.value is None
    assert damaged.detail != healthy.detail, "damage and a caught-up source read alike"
    assert "app.log" in damaged.detail and "damaged" in damaged.detail


@pytest.mark.unit
def test_an_event_stamped_in_the_future_is_reported_not_scored(tmp_path: Path) -> None:
    """The same trap on the freshness indicator, from the other side.

    ``now - mark`` is negative when the store holds a stamp ahead of the
    clock this measurement was given, and a negative age meets an "at most"
    target. One of the two clocks is wrong and neither reading is a pass.
    """
    root = _populated(tmp_path)
    report = measure(root, now=0.0)
    freshness = next(i for i in report.indicators if i.objective.id == "ingest-freshness")
    assert freshness.status is Status.UNKNOWN, freshness.detail
    assert "future" in freshness.detail


@pytest.mark.unit
def test_a_backup_with_no_manifest_is_not_a_backup(tmp_path: Path) -> None:
    """An empty backup directory must not satisfy "restorable"."""
    root = _root(tmp_path)
    (root / BACKUP_SUBDIR / "backup-empty").mkdir(parents=True)
    report = measure(root, now=time.time())
    backup = next(i for i in report.indicators if i.objective.id == "backup-present")
    assert backup.status is Status.BREACHED
    assert "no backup manifest" in backup.detail

    (root / BACKUP_SUBDIR / "backup-empty" / MANIFEST_FILE).write_text("{}", encoding="utf-8")
    report = measure(root, now=time.time())
    backup = next(i for i in report.indicators if i.objective.id == "backup-present")
    assert backup.status is Status.MET


@pytest.mark.unit
def test_a_corrupt_offsets_file_is_unmeasurable_not_zero(tmp_path: Path) -> None:
    """ "Never collected" and "position lost" must not look alike.

    ``collect.load`` refuses a corrupt offsets file deliberately, for that
    reason. Reporting zero pending bytes for it would turn the refusal into a
    green signal.
    """
    root = _root(tmp_path)
    path = offsets_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ not json", encoding="utf-8")
    report = measure(root, now=time.time())
    pending = next(i for i in report.indicators if i.objective.id == "collection-pending")
    assert pending.status is Status.UNKNOWN
    assert "unreadable" in pending.detail


@pytest.mark.unit
def test_the_report_round_trips_through_json(tmp_path: Path) -> None:
    """The CLI's ``--json`` and the compliance evidence both depend on this."""
    report = measure(_root(tmp_path), now=1_760_000_000.0)
    payload = json.loads(json.dumps(report.to_dict(), sort_keys=True))
    assert payload["healthy"] is False
    assert payload["measured_at"] == 1_760_000_000.0
    assert len(payload["indicators"]) == len(OBJECTIVES)
    assert {item["id"] for item in payload["indicators"]} == set(MEASURERS)
    assert all(item["status"] in {"met", "breached", "unknown"} for item in payload["indicators"])


@pytest.mark.unit
def test_the_headline_names_what_is_wrong(tmp_path: Path) -> None:
    """An operator reads one line; it must say which objective, not just a count."""
    report = measure(_root(tmp_path), now=time.time())
    assert "backup-present" in report.headline()


@pytest.mark.unit
def test_a_report_of_nothing_but_unknowns_is_not_healthy() -> None:
    """The fail-open spelling is "nothing is breached", and this is what it misses.

    Added after planting it: replacing ``healthy`` with ``not self.breached``
    was caught by **one** test, the empty-table one, and by nothing that
    asserted the all-unknown case — because on a bare root ``backup-present``
    is genuinely breached, so the plant failed for an unrelated reason. A
    report built entirely of unmeasurable indicators has nothing breached and
    must still not be healthy, which is the exact shape of a monitor that has
    lost sight of the platform.
    """
    objective = BY_ID["ingest-freshness"]
    blind = SliReport(
        measured_at=0.0,
        indicators=tuple(
            Indicator(objective=objective, status=Status.UNKNOWN, value=None, detail="no signal")
            for _ in range(3)
        ),
    )
    assert blind.breached == ()
    assert blind.healthy is False, "a report that measured nothing reported healthy"
    assert "unmeasurable" in blind.headline()


@pytest.mark.unit
def test_a_report_with_no_indicators_is_not_healthy() -> None:
    """``all([])`` is ``True``, which would make an emptied table report green.

    Found while writing the test above: the first version of ``healthy`` was
    ``all(item.status.healthy for ...)``, and the assertion I had written for
    it accepted a no-indicator report as healthy. An objective table that
    lost its rows — a bad merge, a refactor, a conditional registration — is
    exactly how a monitor goes silently green, and it is the same
    "assertion true of the empty set" shape this repository has found in its
    own tests more than once.
    """
    assert SliReport(measured_at=0.0, indicators=()).healthy is False


@pytest.mark.unit
def test_store_intact_catches_the_damage_the_readability_sample_cannot(
    tmp_path: Path,
) -> None:
    """Why there are two store objectives and not one widened one.

    ``store-readable`` reads a fixed 100 rows from the two ends however large
    the store is, and its own docstring concedes that. Measured on a
    1200-event / 525-page store, zeroing each page in turn: **116 of 524**
    single-page losses leave it reading ``1.0`` and the caught-up sentence
    while ``integrity_check`` raises, and ``verify_integrity`` refuses **116 of
    116**. The other 408 now read ``breached`` rather than ``unknown``, because
    ``store/`` maps corruption to a ``StoreError``.

    This test asserts the discriminating case rather than the easy one: a page
    whose loss the **sample does not notice**. If no such page exists in the
    fixture the test says so and fails, because a page both indicators catch
    would prove nothing about why they are separate.
    """
    root = _root(tmp_path)
    with EventStore.open(root) as store:
        store.append_many(
            tuple(
                normalize(
                    json.dumps(
                        {
                            "eventSource": "s3.amazonaws.com",
                            "eventName": "GetObject",
                            "eventTime": f"2026-10-15T09:00:{index % 60:02d}Z",
                            "sourceIPAddress": f"10.0.{index // 256 % 256}.{index % 256}",
                            "userIdentity": {"userName": f"svc-{index:06d}"},
                        }
                    )
                )
                for index in range(600)
            ),
            ingested_at=1_760_000_000.0,
        )
    database = root / "data" / "events" / "events.sqlite3"
    folding = sqlite3.connect(database)
    try:
        folding.execute("PRAGMA journal_mode=DELETE")
        page_size = int(folding.execute("PRAGMA page_size").fetchone()[0])
    finally:
        folding.close()
    pristine = database.read_bytes()

    discriminating = 0
    for pageno in range(2, len(pristine) // page_size + 1):
        offset = (pageno - 1) * page_size
        database.write_bytes(pristine[:offset] + bytes(page_size) + pristine[offset + page_size :])
        by_id = {
            indicator.objective.id: indicator
            for indicator in measure(root, now=time.time()).indicators
        }
        if by_id["store-readable"].status is not Status.MET:
            continue  # the sample caught it; not the case under test
        discriminating += 1
        assert by_id["store-intact"].status is Status.BREACHED, (
            f"page {pageno}: the sample read met and store-intact did not breach "
            f"({by_id['store-intact'].status.value}: {by_id['store-intact'].detail})"
        )
        assert by_id["store-intact"].value == 0.0
        assert "damaged" in by_id["store-intact"].detail
    database.write_bytes(pristine)

    assert discriminating, (
        "no page's loss escaped the readability sample, so this fixture cannot "
        "distinguish the two objectives"
    )


@pytest.mark.unit
def test_store_intact_is_unmeasurable_rather_than_sound_when_there_is_no_store(
    tmp_path: Path,
) -> None:
    """An absent store must not read as a sound one.

    ``0.0`` is reserved for "the signal was read and the evidence is damaged".
    A root with no database at all is a different conversation, and grading it
    ``1.0`` would be the fail-open this whole package exists to prevent.
    """
    report = measure(_root(tmp_path), now=time.time())
    intact = next(i for i in report.indicators if i.objective.id == "store-intact")
    assert intact.status is Status.UNKNOWN, intact.detail
    assert intact.value is None
    assert "no event store" in intact.detail


@pytest.mark.unit
def test_a_sound_store_reads_met_on_both_store_objectives(tmp_path: Path) -> None:
    """The other direction, or every assertion above is satisfied by refusing."""
    report = measure(_populated(tmp_path), now=time.time())
    by_id = {indicator.objective.id: indicator for indicator in report.indicators}
    assert by_id["store-intact"].status is Status.MET, by_id["store-intact"].detail
    assert by_id["store-intact"].value == 1.0
    assert by_id["store-readable"].status is Status.MET
