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
from pipeline import (
    CURSOR_VERSION,
    Cursor,
    CursorError,
    CursorPathError,
    cursor_path,
    load_cursor,
    reference,
    run_cycle,
    save_cursor,
)
from store import MAX_QUERY_LIMIT, EventStore

from ingest import normalize

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
    assert "cursor advanced" in records[-1]["reason"]


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
    assert payload["cursor_advanced"] is True
    assert payload["idle"] is False
    assert len(payload["incidents"][0]["reference"]) == 16
