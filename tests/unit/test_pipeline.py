# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Behaviour of the scheduled detection cycle and its cursor.

The tests that matter here are about *not losing a window* and *not
reprocessing forever*. Those are the same test seen from two sides, and the
reason they are not trivial is that :meth:`EventStore.append_many` stamps one
``ingested_at`` across a whole batch — so equal timestamps are the normal
case, not an edge case. A cursor that stores only a timestamp has to choose
between skipping the rest of a tied batch and re-reading it on every run,
forever. Most of this file pins the composite cursor that avoids that choice.

The other half is the resume contract: the cursor advances only after a cycle
succeeds, so a crash re-reads rather than steps over. Each test says which of
the two failures it is holding closed.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from correlation import Thresholds
from ingest import normalize
from pipeline import (
    CURSOR_VERSION,
    DEFAULT_LOOKBACK,
    Cursor,
    CursorError,
    CursorPathError,
    CycleResult,
    cursor_path,
    load_cursor,
    reference,
    run_cycle,
    save_cursor,
)
from store import MAX_QUERY_LIMIT, EventStore

# Shapes the committed parsers accept; mirrors tests/unit/test_correlation.py
# so a parser change breaks both files together rather than silently making
# this one assemble nothing.
_CLOUD = {
    "eventVersion": "1.08",
    "eventSource": "sts.amazonaws.com",
    "eventName": "AssumeRole",
    "eventTime": "2026-10-14T01:00:00Z",
    "awsRegion": "us-east-1",
    "recipientAccountId": "1",
    "userIdentity": {"type": "IAMUser", "userName": "svc-deploy"},
    "sourceIPAddress": "198.51.100.7",
    "eventID": "e1",
}
_IDENTITY = {
    "userPrincipalName": "svc-deploy@corp.example",
    "ipAddress": "198.51.100.7",
    "createdDateTime": "2026-10-14T01:05:00Z",
    "id": "e2",
    "appDisplayName": "Portal",
    "status": {"errorCode": 0},
    "userDisplayName": "Svc Deploy",
}
_ENDPOINT = {"type": "SYSCALL", "node": "web-01", "auid": "svc-deploy", "comm": "bash"}
_LATER = {"type": "SYSCALL", "node": "web-01", "auid": "svc-deploy", "comm": "curl"}


def _seed(root: Path, records: tuple[Mapping[str, Any], ...], *, at: float) -> None:
    """Append records under one ingestion timestamp — the tie-producing case."""
    with EventStore.open(root) as store:
        store.append_many(tuple(normalize(record) for record in records), ingested_at=at)


# --------------------------------------------------------------------------
# The cursor
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_an_absent_cursor_reads_as_none_not_an_error(tmp_path: Path) -> None:
    """First run of a new deployment. Must start from the beginning of history.

    ``None`` specifically, and not an exception: a scheduler whose very first
    invocation exits non-zero looks like a broken install.
    """
    assert load_cursor(cursor_path(tmp_path)) is None


@pytest.mark.unit
def test_a_cursor_round_trips(tmp_path: Path) -> None:
    path = cursor_path(tmp_path)
    cursor = Cursor(ingested_at=1700000000.5, event_id="abc123")
    save_cursor(path, cursor)
    assert load_cursor(path) == cursor


@pytest.mark.unit
def test_saving_twice_replaces_rather_than_appends(tmp_path: Path) -> None:
    """Idempotence: a re-run must not leave two cursors in one file."""
    path = cursor_path(tmp_path)
    save_cursor(path, Cursor(ingested_at=1.0, event_id="first"))
    save_cursor(path, Cursor(ingested_at=2.0, event_id="second"))
    assert load_cursor(path) == Cursor(ingested_at=2.0, event_id="second")
    # Exactly one JSON document, not an append. json.loads refuses trailing
    # content, so this fails if the second save appended rather than replaced.
    assert json.loads(path.read_text(encoding="utf-8"))["event_id"] == "second"


@pytest.mark.unit
def test_a_cursor_records_its_version(tmp_path: Path) -> None:
    """So a future format change can be detected rather than misread."""
    path = cursor_path(tmp_path)
    save_cursor(path, Cursor(ingested_at=1.0, event_id="x"))
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == CURSOR_VERSION


@pytest.mark.unit
@pytest.mark.parametrize(
    "payload",
    [
        "{not json",
        "[]",
        '{"version": 1}',
        '{"version": 1, "ingested_at": "soon", "event_id": "x"}',
        '{"version": 99, "ingested_at": 1.0, "event_id": "x"}',
        '{"version": 1, "ingested_at": 1.0}',
    ],
)
def test_an_unreadable_cursor_is_refused_not_treated_as_absent(
    tmp_path: Path, payload: str
) -> None:
    """The distinction that matters: absent means "start over", corrupt does not.

    Treating a corrupt cursor as absent would silently reprocess all of
    history; treating it as "no new events" would silently skip all of it.
    Refusing is the only option that tells someone.
    """
    path = cursor_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(CursorError):
        load_cursor(path)


@pytest.mark.unit
def test_as_keyset_orders_the_pair_the_way_the_query_expects() -> None:
    cursor = Cursor(ingested_at=12.5, event_id="abc")
    assert cursor.as_keyset() == (12.5, "abc")


# --------------------------------------------------------------------------
# The cycle: not losing, not repeating
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_a_first_cycle_reads_everything_and_assembles(tmp_path: Path) -> None:
    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)
    with EventStore.open(tmp_path) as store:
        result = run_cycle(store)
    assert result.events_read == 3
    assert not result.idle
    assert result.started_from is None
    assert result.cursor is not None
    assert result.incidents, "three joined events across three domains must assemble"


@pytest.mark.unit
def test_a_second_cycle_over_a_tied_batch_reads_nothing(tmp_path: Path) -> None:
    """The failure this whole design exists to prevent.

    All three events share one ``ingested_at``. A timestamp-only cursor with
    ``>`` would have skipped two of them on the first pass; with ``>=`` it
    would re-read all three on every pass, forever.
    """
    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)
    with EventStore.open(tmp_path) as store:
        first = run_cycle(store)
        second = run_cycle(store, cursor=first.cursor)
    assert second.events_read == 0
    assert second.idle
    assert second.incidents == ()


@pytest.mark.unit
def test_an_idle_cycle_returns_no_cursor_so_the_caller_cannot_rewind(
    tmp_path: Path,
) -> None:
    """``None`` means "leave the stored cursor alone", not "reset it".

    If an idle cycle returned the cursor it was given, a caller that saved
    unconditionally would be fine — but a caller that saved only on a
    non-``None`` value would also be fine, and the two would disagree the
    moment the semantics drifted. Returning ``None`` makes the correct caller
    the obvious one.
    """
    _seed(tmp_path, (_CLOUD,), at=1000.0)
    with EventStore.open(tmp_path) as store:
        first = run_cycle(store)
        idle = run_cycle(store, cursor=first.cursor)
    assert idle.cursor is None
    assert idle.started_from == first.cursor


@pytest.mark.unit
def test_only_events_newer_than_the_cursor_are_read(tmp_path: Path) -> None:
    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)
    with EventStore.open(tmp_path) as store:
        first = run_cycle(store)
    _seed(tmp_path, (_LATER,), at=2000.0)
    with EventStore.open(tmp_path) as store:
        second = run_cycle(store, cursor=first.cursor)
    assert second.events_read == 1


@pytest.mark.unit
def test_a_crash_before_the_cursor_is_saved_re_reads_rather_than_skips(
    tmp_path: Path,
) -> None:
    """At-least-once, stated as a test rather than as a docstring claim.

    The cursor from a successful cycle is deliberately *not* persisted here,
    simulating a crash between the cycle and the save. The next cycle must see
    the same window again — duplicate incidents are noise an analyst dismisses,
    while a skipped window is a blind spot nobody is told about.
    """
    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)
    with EventStore.open(tmp_path) as store:
        crashed = run_cycle(store)
        replayed = run_cycle(store)  # same (absent) cursor: nothing was saved
    assert replayed.events_read == crashed.events_read
    assert [reference(i) for i in replayed.incidents] == [reference(i) for i in crashed.incidents]


@pytest.mark.unit
def test_paging_one_event_at_a_time_through_a_tie_loses_and_repeats_nothing(
    tmp_path: Path,
) -> None:
    """A batch smaller than a tied group is the adversarial case for a cursor.

    Four events, three of them sharing an ``ingested_at``, read one per cycle.
    Every event must appear exactly once.
    """
    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)
    _seed(tmp_path, (_LATER,), at=2000.0)
    seen: list[str] = []
    cursor: Cursor | None = None
    with EventStore.open(tmp_path) as store:
        for _ in range(10):  # bounded, so a non-advancing cursor fails loudly
            page = run_cycle(store, cursor=cursor, batch=1)
            if page.idle:
                break
            assert page.cursor is not None
            seen.append(page.cursor.event_id)
            cursor = page.cursor
    assert len(seen) == 4, f"expected every event exactly once, got {seen}"
    assert len(set(seen)) == 4, f"an event was read twice: {seen}"


@pytest.mark.unit
def test_a_cycle_reads_oldest_first(tmp_path: Path) -> None:
    """A pipeline advances through history forwards.

    The store's default is newest-first, because that is what a dashboard
    wants. Reading in that order here would make the cursor move backwards.
    """
    _seed(tmp_path, (_CLOUD,), at=1000.0)
    _seed(tmp_path, (_LATER,), at=2000.0)
    with EventStore.open(tmp_path) as store:
        first = run_cycle(store, batch=1)
    assert first.cursor is not None
    assert first.cursor.ingested_at == 1000.0


@pytest.mark.unit
def test_a_batch_below_one_is_refused_rather_than_clamped(tmp_path: Path) -> None:
    """A scheduler configured with batch 0 would otherwise run forever idle."""
    with EventStore.open(tmp_path) as store:
        for batch in (0, -1):
            with pytest.raises(ValueError, match="batch must be >= 1"):
                run_cycle(store, batch=batch)


@pytest.mark.unit
def test_a_batch_above_the_store_ceiling_is_clamped_not_refused(tmp_path: Path) -> None:
    """The ceiling is the store's, so asking for more is a cap, not an error."""
    _seed(tmp_path, (_CLOUD,), at=1000.0)
    with EventStore.open(tmp_path) as store:
        result = run_cycle(store, batch=MAX_QUERY_LIMIT * 10)
    assert result.events_read == 1


@pytest.mark.unit
def test_thresholds_reach_assembly(tmp_path: Path) -> None:
    """An operator override must change what the cycle calls an incident."""
    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)
    with EventStore.open(tmp_path) as store:
        permissive = run_cycle(store, thresholds=Thresholds(min_events=2))
        strict = run_cycle(store, thresholds=Thresholds(min_events=99))
    assert permissive.incidents
    assert strict.incidents == ()
    assert strict.events_read == 3, "a strict threshold must not stop the cursor advancing"


# --------------------------------------------------------------------------
# Incident reference
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_a_replayed_incident_has_the_same_reference(tmp_path: Path) -> None:
    """What makes an at-least-once duplicate recognizable as one."""
    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)
    with EventStore.open(tmp_path) as store:
        first = run_cycle(store)
        again = run_cycle(store)
    assert reference(first.incidents[0]) == reference(again.incidents[0])


@pytest.mark.unit
def test_a_reference_does_not_depend_on_event_order(tmp_path: Path) -> None:
    """Derived from the sorted ids, so it is a property of membership only."""
    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)
    with EventStore.open(tmp_path) as store:
        incident = run_cycle(store).incidents[0]
    shuffled = type(incident)(
        **{
            **{f: getattr(incident, f) for f in incident.__dataclass_fields__},
            "event_ids": tuple(reversed(incident.event_ids)),
        }
    )
    assert reference(shuffled) == reference(incident)


@pytest.mark.unit
def test_a_different_membership_gives_a_different_reference(tmp_path: Path) -> None:
    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)
    with EventStore.open(tmp_path) as store:
        incident = run_cycle(store).incidents[0]
    trimmed = type(incident)(
        **{
            **{f: getattr(incident, f) for f in incident.__dataclass_fields__},
            "event_ids": incident.event_ids[:-1],
        }
    )
    assert reference(trimmed) != reference(incident)


# --------------------------------------------------------------------------
# Cursor path
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_the_cursor_lands_under_the_gitignored_lab_root(tmp_path: Path) -> None:
    path = cursor_path(tmp_path)
    assert path.parent == tmp_path.resolve() / "data" / "pipeline"


@pytest.mark.unit
@pytest.mark.parametrize("filename", ["../escape.json", "a/b.json", "", ".", "..", "a\x00.json"])
def test_a_filename_that_could_escape_is_refused(tmp_path: Path, filename: str) -> None:
    with pytest.raises(CursorPathError):
        cursor_path(tmp_path, filename=filename)


# --------------------------------------------------------------------------
# The CLI's exit-code contract
# --------------------------------------------------------------------------
#
# A scheduler acts on the exit code and nothing else, so the codes are an
# interface. These assert the documented ones, including the distinction a
# cron-mailed failure depends on: a bad argument (2) is a misconfiguration
# someone must fix, while a failed cycle (1) may be transient.


def _cli_main() -> Any:
    """Import the CLI's entry point.

    Imported inside the tests rather than at module scope: ``scripts/`` is
    importable but the module inserts the repo root into ``sys.path`` at
    import time, and keeping that out of collection makes the ordering
    explicit.
    """
    from scripts.run_pipeline import main

    return main


@pytest.mark.unit
def test_a_first_run_exits_zero_and_advances(tmp_path: Path) -> None:
    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)
    assert _cli_main()(["--root", str(tmp_path)]) == 0
    assert load_cursor(cursor_path(tmp_path)) is not None


@pytest.mark.unit
def test_an_idle_run_exits_zero(tmp_path: Path) -> None:
    """Idle is the common outcome; a non-zero exit would page someone nightly."""
    _seed(tmp_path, (_CLOUD,), at=1000.0)
    main = _cli_main()
    assert main(["--root", str(tmp_path)]) == 0
    assert main(["--root", str(tmp_path)]) == 0


@pytest.mark.unit
def test_a_dry_run_reports_without_advancing(tmp_path: Path) -> None:
    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)
    assert _cli_main()(["--root", str(tmp_path), "--dry-run"]) == 0
    assert load_cursor(cursor_path(tmp_path)) is None, "a dry run advanced the cursor"


@pytest.mark.unit
@pytest.mark.parametrize(
    "argv,reason",
    [
        (["--batch", "0"], "a batch of zero is a misconfiguration, not a failed cycle"),
        (["--min-events", "0"], "a threshold that cannot mean anything"),
        (["--caller", "ivan|root"], "an actor that could forge the audit preimage"),
        (["--caller", "a b"], "an actor outside the principal alphabet"),
        (["--policy", "/nonexistent/policy.json"], "a missing policy must fail closed"),
    ],
)
def test_a_bad_argument_exits_two(tmp_path: Path, argv: list[str], reason: str) -> None:
    assert _cli_main()(["--root", str(tmp_path), *argv]) == 2, reason


@pytest.mark.unit
def test_a_run_is_audited_in_the_pipeline_directory(tmp_path: Path) -> None:
    """The record an operator reads to see the cycle happened at all."""
    _seed(tmp_path, (_CLOUD, _ENDPOINT), at=1000.0)
    assert _cli_main()(["--root", str(tmp_path), "--caller", "soc-timer"]) == 0
    log = cursor_path(tmp_path).parent / "audit.log"
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert [r["actor"] for r in records] == ["pipeline/soc-timer"] * 2, (
        "expected a gate record and an outcome record, both attributed"
    )
    assert records[-1]["action"].startswith("pipeline_cycle:")
    # Future tense, deliberately: the record is written BEFORE the save that
    # decides it, so a past-tense claim would be falsified by a failed save.
    assert "advancing cursor to" in records[-1]["reason"]
    assert "cursor advanced" not in records[-1]["reason"], (
        "the record must not assert an outcome the save has not yet decided"
    )


@pytest.mark.unit
def test_the_audit_chain_from_a_run_verifies(tmp_path: Path) -> None:
    """A cycle must not write a record that breaks the chain it appends to."""
    from agents.policies.audit import AuditLogger

    _seed(tmp_path, (_CLOUD, _ENDPOINT), at=1000.0)
    main = _cli_main()
    assert main(["--root", str(tmp_path), "--caller", "ivan"]) == 0
    _seed(tmp_path, (_LATER,), at=2000.0)
    assert main(["--root", str(tmp_path), "--caller", "ivan"]) == 0
    assert AuditLogger(cursor_path(tmp_path).parent / "audit.log").verify()


@pytest.mark.unit
def test_a_corrupt_cursor_stops_the_run_rather_than_reprocessing(tmp_path: Path) -> None:
    """Exit 1, not 0: the window is neither consumed nor silently replayed."""
    _seed(tmp_path, (_CLOUD,), at=1000.0)
    path = cursor_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{truncated", encoding="utf-8")
    assert _cli_main()(["--root", str(tmp_path)]) == 1


@pytest.mark.unit
def test_json_output_is_parseable_and_names_the_incident(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The machine-readable form a log shipper consumes."""
    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)
    assert _cli_main()(["--root", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["events_read"] == 3
    assert payload["cursor_advancing"] is True
    assert payload["idle"] is False
    assert len(payload["incidents"][0]["reference"]) == 16


# --------------------------------------------------------------------------
# The cursor actually reaches the cycle
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_the_cli_applies_the_cursor_it_loaded(tmp_path: Path) -> None:
    """The single most important thing the CLI does, and it was untested.

    Every other test here passed with ``cursor=cursor`` deleted from the
    ``run_cycle`` call — which would make the pipeline re-read the entire store
    on every invocation, forever, while still exiting 0 and reporting
    "cursor advanced". Asserted on the audit record's event count rather than
    on stdout, because that count is what the cycle actually read.
    """
    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)
    main = _cli_main()
    assert main(["--root", str(tmp_path)]) == 0
    _seed(tmp_path, (_LATER,), at=2000.0)
    assert main(["--root", str(tmp_path)]) == 0

    log = cursor_path(tmp_path).parent / "audit.log"
    outcomes = [
        json.loads(line)
        for line in log.read_text(encoding="utf-8").splitlines()
        if json.loads(line)["action"].startswith("pipeline_cycle:")
    ]
    counts = [int(record["action"].split(":")[1]) for record in outcomes]
    assert counts == [3, 1], (
        f"second cycle read {counts[1:]} events; with the cursor applied it must "
        "read only the one appended after it"
    )


@pytest.mark.unit
def test_a_blocked_policy_exits_three_and_still_records_the_decision(
    tmp_path: Path,
) -> None:
    """The fail-closed claim, which had no test at all.

    Swallowing ``ToolBlockedError`` instead of returning 3 kept every test
    green. The gate decision must still be recorded: a refusal nobody can see
    afterwards is not a control.
    """
    bundle = tmp_path / "deny.json"
    bundle.write_text(json.dumps({"version": 1, "policy": {"read_only": "deny"}}), encoding="utf-8")
    assert _cli_main()(["--root", str(tmp_path), "--policy", str(bundle)]) == 3
    log = cursor_path(tmp_path).parent / "audit.log"
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert records, "a blocked cycle must still leave the gate decision in the chain"
    assert records[-1]["decision"] == "deny"
    assert load_cursor(cursor_path(tmp_path)) is None, "a blocked cycle advanced the cursor"


@pytest.mark.unit
def test_a_cycle_reads_no_more_than_assemble_will_look_at(tmp_path: Path) -> None:
    """``assemble`` truncates its input silently, so the read must be clamped.

    With ``max_events`` below ``batch``, a cycle that read the full batch would
    advance the cursor over events ``assemble`` discarded — a blind spot with
    no signal. Every event must eventually be correlated, across however many
    cycles that takes.
    """
    records = tuple(
        {"type": "SYSCALL", "node": f"web-{index:02d}", "auid": "svc-deploy", "comm": "bash"}
        for index in range(10)
    )
    _seed(tmp_path, records, at=1000.0)
    thresholds = Thresholds(max_events=3)
    seen, cursor = 0, None
    with EventStore.open(tmp_path) as store:
        for _ in range(10):
            page = run_cycle(store, cursor=cursor, batch=10, thresholds=thresholds)
            if page.idle:
                break
            assert page.events_read <= 3, "read past the correlation ceiling"
            seen += page.events_read
            cursor = page.cursor
    assert seen == 10, f"only {seen} of 10 events were ever correlated"


# --------------------------------------------------------------------------
# The correlation window: the defect that made this stage not work
# --------------------------------------------------------------------------
#
# A cursor partitions the event stream. Cross-domain correlation is windowed,
# not partitioned. Handing assemble() only the events since the cursor means an
# incident whose steps arrive in different cycles is never assembled at all,
# and once the cursor passes them nothing can recover it — reported as
# "0 incident(s)" and exit 0, which is the silent blind spot DESIGN.md §5
# boundary 13 refuses to accept. These tests pin the trailing overlap that
# fixes it, and its limit.


def _interleaved(
    root: Path, arrivals: tuple[tuple[Mapping[str, Any], float], ...], **kwargs: Any
) -> list[CycleResult]:
    """Append, run a cycle, append, run a cycle — the real steady state.

    The helper exists because every earlier test in this file seeded a whole
    batch *before* the first cycle, which put the entire story inside one
    window and hid the defect completely.
    """
    results: list[CycleResult] = []
    cursor: Cursor | None = None
    for record, at in arrivals:
        with EventStore.open(root) as store:
            store.append_many((normalize(record),), ingested_at=at)
        with EventStore.open(root) as store:
            page = run_cycle(store, cursor=cursor, **kwargs)
        results.append(page)
        if page.cursor is not None:
            cursor = page.cursor
    return results


@pytest.mark.unit
def test_an_incident_spanning_three_cycles_is_still_assembled(tmp_path: Path) -> None:
    """The reproduction, turned into a regression test.

    Three attack steps five minutes apart, a cycle between each — the only way
    this ever runs in production. With no lookback every cycle reports nothing
    and the story is lost permanently.
    """
    results = _interleaved(tmp_path, ((_CLOUD, 1000.0), (_IDENTITY, 1300.0), (_ENDPOINT, 1600.0)))
    assert [r.events_read for r in results] == [1, 1, 1], "each cycle sees one new event"
    best = max(
        (incident for page in results for incident in page.fresh),
        key=lambda incident: incident.score,
        default=None,
    )
    assert best is not None, "the story was never assembled by any cycle"
    assert sorted(best.domains) == ["cloud", "endpoint", "identity"], (
        f"only {sorted(best.domains)} were correlated together"
    )
    assert len(best.event_ids) == 3


@pytest.mark.unit
def test_without_a_lookback_the_same_story_is_lost(tmp_path: Path) -> None:
    """The counter-test, so the one above cannot pass for an unrelated reason.

    ``lookback=0`` is the old partitioning behaviour, kept because a backfill
    occasionally wants it. It must demonstrably lose the incident — otherwise
    the test above proves nothing about the overlap.
    """
    results = _interleaved(
        tmp_path, ((_CLOUD, 1000.0), (_IDENTITY, 1300.0), (_ENDPOINT, 1600.0)), lookback=0
    )
    assert all(page.fresh == () for page in results), (
        "lookback=0 must partition the stream; if it assembles the story, the "
        "lookback test above is not testing the lookback"
    )


@pytest.mark.unit
def test_an_incident_spanning_longer_than_the_lookback_is_still_cut(tmp_path: Path) -> None:
    """The limit of a stateless window, asserted rather than left implicit.

    This is why persisted, mergeable incidents remain the end state. Pinning it
    means nobody later reads the lookback as a complete solution.
    """
    far_apart = ((_CLOUD, 1000.0), (_IDENTITY, 1000.0 + DEFAULT_LOOKBACK * 3))
    results = _interleaved(tmp_path, far_apart)
    assert all(page.fresh == () for page in results), (
        "events this far apart cannot be correlated by a window this size; if "
        "they are, the lookback is not bounded by DEFAULT_LOOKBACK"
    )


@pytest.mark.unit
def test_an_idle_cycle_correlates_nothing_despite_the_lookback(tmp_path: Path) -> None:
    """A lookback must not manufacture work when nothing arrived.

    Re-correlating recent history on every firing regardless of new input would
    re-report every incident forever and turn an idle pipeline into an alert
    storm.
    """
    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)
    with EventStore.open(tmp_path) as store:
        first = run_cycle(store)
        idle = run_cycle(store, cursor=first.cursor)
    assert first.fresh, "the first cycle should have found the story"
    assert idle.idle and idle.events_read == 0
    assert idle.incidents == () and idle.fresh == ()
    assert idle.events_correlated == 0


@pytest.mark.unit
def test_a_re_assembled_incident_is_not_reported_as_new(tmp_path: Path) -> None:
    """The lookback re-assembles history by design; it must not re-alert.

    An incident every one of whose events sits at or before the starting cursor
    cannot be news. Derived from the event ids, so no state is persisted to
    know it — which is what keeps the overlap from duplicating every alert for
    its whole duration.
    """
    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)
    with EventStore.open(tmp_path) as store:
        first = run_cycle(store)
    assert len(first.fresh) == 1
    # One unrelated event arrives: the cycle is not idle, so the lookback pulls
    # the earlier story back in, and it must come back as a repeat not news.
    _seed(
        tmp_path,
        ({"type": "SYSCALL", "node": "other-host", "auid": "alice", "comm": "ls"},),
        at=1100.0,
    )
    with EventStore.open(tmp_path) as store:
        second = run_cycle(store, cursor=first.cursor)
    assert second.events_read == 1
    assert second.events_correlated > 1, "the lookback did not widen the window"
    assert second.repeats >= 1, "the earlier incident was not re-assembled at all"
    # The new event is a lone, uncorroborated action on an unrelated host by an
    # unrelated user, so nothing new can legitimately come of it. Everything
    # the lookback re-assembled must therefore land in `repeats`, not `fresh`.
    assert second.fresh == (), (
        "an incident built entirely from already-consumed events was reported as new"
    )


@pytest.mark.unit
def test_a_negative_lookback_is_refused(tmp_path: Path) -> None:
    with (
        EventStore.open(tmp_path) as store,
        pytest.raises(ValueError, match="lookback must be >= 0"),
    ):
        run_cycle(store, lookback=-1.0)


@pytest.mark.unit
def test_the_correlation_window_never_passes_the_cursor_being_saved(tmp_path: Path) -> None:
    """The window is bounded above by the cursor this cycle will save.

    The store grows continuously under a collector, so the widened read can
    return events newer than the progress window. Correlating those would
    report incidents built partly from events this cycle never consumed — and
    the next cycle would read them again and report a second, overlapping
    version of the same story.
    """
    _seed(tmp_path, (_CLOUD,), at=1000.0)
    with EventStore.open(tmp_path) as store:
        # batch=1 makes the progress window strictly narrower than the store.
        _seed(tmp_path, (_IDENTITY, _ENDPOINT), at=1100.0)
        page = run_cycle(store, cursor=None, batch=1)
    assert page.events_read == 1
    assert page.cursor is not None
    assert page.events_correlated == 1, (
        f"correlated {page.events_correlated} events for a 1-event progress window; "
        "the widened read was not bounded by the cursor being saved"
    )


@pytest.mark.unit
def test_the_cli_accepts_a_lookback_and_refuses_a_negative_one(tmp_path: Path) -> None:
    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)
    main = _cli_main()
    assert main(["--root", str(tmp_path), "--lookback", "60"]) == 0
    assert main(["--root", str(tmp_path), "--lookback", "-5"]) == 2


@pytest.mark.unit
@pytest.mark.parametrize("suffix", ["typo", "not/created/yet"])
def test_a_root_that_does_not_exist_is_refused(tmp_path: Path, suffix: str) -> None:
    """A mistyped --root is a silent blind spot, so it must be loud instead.

    Reproduced before this check existed: a one-character typo in a cron line
    built an entire shadow data tree, found an empty store, printed
    "idle: no new events" and exited 0 — forever. Every signal reads healthy
    while the SOC sees nothing, which is the same class of failure as a cycle
    that correlates nothing.

    The pipeline creates its subdirectories but never the root, which is what
    makes the distinction possible: an operator deploys to a directory that
    exists, so a missing root is a misconfiguration and not a fresh install.
    """
    missing = tmp_path / suffix
    assert _cli_main()(["--root", str(missing)]) == 2
    assert not (missing / "data").exists(), "a refused root still built a shadow tree"


@pytest.mark.unit
def test_a_root_that_is_a_file_is_refused(tmp_path: Path) -> None:
    """``exists()`` would accept it and the first mkdir would then traceback."""
    not_a_dir = tmp_path / "root"
    not_a_dir.write_text("", encoding="utf-8")
    assert _cli_main()(["--root", str(not_a_dir)]) == 2


@pytest.mark.unit
@pytest.mark.parametrize(
    "batch,max_events,lookback",
    [
        (200, 500, 900.0),  # the backlog case: more history than the ceiling
        (200, 500, 0.0),  # no overlap
        (50, 60, 900.0),  # budget almost exhausted by the progress window
        (500, 500, 900.0),  # ceiling exactly equals the batch: no room for context
        (1, 2, 900.0),  # smallest useful window
    ],
)
def test_every_consumed_event_is_inside_the_correlation_window(
    tmp_path: Path, batch: int, max_events: int, lookback: float
) -> None:
    """``progress`` must be a subset of what ``assemble`` saw, always.

    This is the invariant that the earlier coverage test only *looked* like it
    asserted: summing ``events_read`` across cycles proves every event was
    consumed, not that any of it was correlated. With the widened read limited
    newest-first and filtered afterwards, a backlogged store consumed 200
    events and correlated 0 — cursor advancing over a window nothing had looked
    at — and the suite stayed green.

    Parameterised across the boundary shapes because the failure needed a store
    larger than the correlation ceiling to appear at all.
    """
    for block in range(6):
        records = tuple(
            {"type": "SYSCALL", "node": f"h{block}-{index}", "auid": f"u{index}", "comm": "ls"}
            for index in range(300)
        )
        _seed(tmp_path, records, at=1000.0 + block)

    thresholds = Thresholds(max_events=max_events)
    cursor: Cursor | None = None
    with EventStore.open(tmp_path) as store:
        for _ in range(12):
            page = run_cycle(
                store, cursor=cursor, batch=batch, thresholds=thresholds, lookback=lookback
            )
            if page.idle:
                break
            assert page.events_correlated >= page.events_read, (
                f"consumed {page.events_read} events but correlated only "
                f"{page.events_correlated}; the cursor advances over events nothing saw"
            )
            assert page.events_correlated <= max_events, (
                f"correlated {page.events_correlated} events past the {max_events} ceiling"
            )
            cursor = page.cursor


@pytest.mark.unit
def test_a_batch_cut_does_not_lose_an_incident(tmp_path: Path) -> None:
    """The other half of the window defect: a BATCH boundary, not a time one.

    999 unrelated events, then the three correlated ones. The first cycle fills
    its batch with noise and the second sees only the tail — so without the
    overlap the analyst is shown a two-domain score-30 incident instead of the
    three-domain score-52 one, with the cloud leg silently dropped. Distinct
    mechanism from the timer case, so it gets its own test.
    """
    noise = tuple(
        {"type": "SYSCALL", "node": f"h{index}", "auid": f"u{index}", "comm": "ls"}
        for index in range(999)
    )
    _seed(tmp_path, noise, at=500.0)
    _seed(tmp_path, (_CLOUD,), at=1000.0)
    _seed(tmp_path, (_IDENTITY,), at=1001.0)
    _seed(tmp_path, (_ENDPOINT,), at=1002.0)

    best, cursor = None, None
    with EventStore.open(tmp_path) as store:
        for _ in range(5):
            page = run_cycle(store, cursor=cursor)
            if page.idle:
                break
            top = max(page.fresh, key=lambda incident: incident.score, default=None)
            if top is not None and (best is None or top.score > best.score):
                best = top
            cursor = page.cursor
    assert best is not None, "the story was never assembled"
    assert sorted(best.domains) == ["cloud", "endpoint", "identity"], (
        f"the batch cut lost a domain: {sorted(best.domains)}"
    )


@pytest.mark.unit
def test_a_failed_report_leaves_the_cursor_where_it_was(tmp_path: Path) -> None:
    """The alerts live only in stdout, so they are written before the cursor.

    If the cursor advanced first and the report then failed — a full disk under
    the run log, a closed pipe — the window would be consumed with its
    incidents lost, and nothing would ever look at those events again. Writing
    the report first means a failed write re-reads and re-reports, which is
    what at-least-once promises for every other step.
    """
    from unittest import mock

    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)

    real_print = print

    def fail_on_the_report(*args: Any, **kwargs: Any) -> None:
        text = str(args[0]) if args else ""
        if kwargs.get("file") is None and ("event(s)" in text or '"events_read"' in text):
            raise OSError("No space left on device")
        real_print(*args, **kwargs)

    with mock.patch("builtins.print", fail_on_the_report):
        assert _cli_main()(["--root", str(tmp_path)]) == 1
    assert load_cursor(cursor_path(tmp_path)) is None, (
        "the cursor advanced over a window whose alerts were never written"
    )


@pytest.mark.unit
def test_the_lookback_never_loses_what_the_narrow_window_found(tmp_path: Path) -> None:
    """Widening is not monotonic, so the overlap has to be strictly additive.

    ``assemble`` demotes an entity appearing in more than ``max_entity_fanout``
    events to reported context rather than a join key — correctly, since
    grouping transitively on a shared gateway collapses a window into one false
    incident. But the history a lookback pulls in inflates exactly those
    counts, so an entity that was a valid join key over the new events alone can
    become context over the wider window and the link is never made.

    Measured before the fix: a score-30 two-domain incident reported at
    ``lookback=0`` vanished entirely at ``lookback=900``. A window meant to find
    *more* was losing detections it already had.
    """
    history = tuple(
        {"type": "SYSCALL", "node": f"h{index}", "auid": "svc-deploy", "comm": "ls"}
        for index in range(12)
    )
    _seed(tmp_path, history, at=1000.0)
    _seed(tmp_path, (_CLOUD, _ENDPOINT), at=1100.0)

    thresholds = Thresholds(max_entity_fanout=10)  # history alone exceeds this
    with EventStore.open(tmp_path) as store:
        consumed = run_cycle(store, batch=12, thresholds=thresholds)
        narrow = run_cycle(
            store, cursor=consumed.cursor, batch=12, thresholds=thresholds, lookback=0
        )
        wide = run_cycle(
            store, cursor=consumed.cursor, batch=12, thresholds=thresholds, lookback=900.0
        )

    narrow_best = max((incident.score for incident in narrow.fresh), default=None)
    wide_best = max((incident.score for incident in wide.fresh), default=None)
    assert narrow_best is not None, "the test shape does not exercise the claim"
    assert wide_best is not None, (
        "the lookback suppressed a detection the narrow window reported: "
        f"narrow top score {narrow_best}, wide found nothing"
    )
    assert wide_best >= narrow_best, (
        f"the lookback degraded a detection: {narrow_best} -> {wide_best}"
    )


@pytest.mark.unit
def test_the_additive_union_does_not_double_report_one_story(tmp_path: Path) -> None:
    """A narrow incident covered by a wide one is the same story, less context.

    Without the subset check the union would emit both the two-domain and the
    three-domain version of one attack every cycle, which is the duplicate
    storm the ``fresh`` derivation exists to avoid.
    """
    _seed(tmp_path, (_CLOUD, _IDENTITY, _ENDPOINT), at=1000.0)
    with EventStore.open(tmp_path) as store:
        page = run_cycle(store)
    assert len(page.incidents) == 1, (
        f"one story was reported {len(page.incidents)} times: "
        f"{[sorted(i.domains) for i in page.incidents]}"
    )


@pytest.mark.unit
def test_include_seen_surfaces_a_story_the_fresh_proxy_suppresses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Raising --lookback must actually surface what the wider window finds.

    ``fresh`` means "involves an event this cycle had not consumed", which is a
    proxy for "not already reported" — and the proxy is wrong in exactly the
    case an operator hits when remediating a miss. Two correlated events are
    consumed in separate cycles with no overlap, so neither cycle correlates
    them; a later run with a lookback assembles the story from events that are
    all behind the cursor, and it is suppressed as re-seen having never been
    reported once.

    Reproduced before ``--include-seen`` existed: the cloud+endpoint story was
    assembled (``total_incidents=1``) and emitted by nothing.
    """
    _seed(tmp_path, (_CLOUD,), at=1000.0)
    _seed(tmp_path, (_ENDPOINT,), at=1100.0)
    main = _cli_main()

    # Consume both events one at a time with no overlap, as a narrow
    # configuration would.
    assert main(["--root", str(tmp_path), "--batch", "1", "--lookback", "0"]) == 0
    assert main(["--root", str(tmp_path), "--batch", "1", "--lookback", "0"]) == 0
    capsys.readouterr()

    # The operator widens the window. A new event makes the cycle non-idle.
    _seed(
        tmp_path, ({"type": "SYSCALL", "node": "other", "auid": "alice", "comm": "ls"},), at=1200.0
    )

    assert main(["--root", str(tmp_path), "--batch", "1", "--lookback", "900", "--json"]) == 0
    default = json.loads(capsys.readouterr().out.strip())
    assert default["incidents"] == [], "the default view should still suppress re-seen stories"
    assert default["repeats"] >= 1, "the story was not assembled at all; test shape is wrong"

    # Same window, asking for everything: the story must appear.
    _seed(
        tmp_path, ({"type": "SYSCALL", "node": "other2", "auid": "bob", "comm": "ls"},), at=1300.0
    )
    assert (
        main(
            [
                "--root",
                str(tmp_path),
                "--batch",
                "1",
                "--lookback",
                "900",
                "--include-seen",
                "--json",
            ]
        )
        == 0
    )
    everything = json.loads(capsys.readouterr().out.strip())
    assert everything["include_seen"] is True
    assert any(i["events"] >= 2 for i in everything["incidents"]), (
        "--include-seen did not surface the multi-event story the window assembled"
    )
