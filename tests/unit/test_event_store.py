"""Behaviour of the append-only event store.

The store is the platform's first durable component, so these tests pin the
properties everything above it will come to assume: that an event survives a
round trip unchanged, that replaying a batch does not duplicate history, that
a time window means what it says, and that retention removes what it reports.

The awkward cases get their own tests because they are the ones that produce
wrong analyses rather than errors: an event with no source timestamp, two
adjacent windows meeting on a boundary, and a batch that overlaps one already
stored.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from ingest.schema import NormalizedEvent
from store import (
    ALL,
    SCHEMA_VERSION,
    EventStore,
    Query,
    StoreIntegrityError,
    canonical_json,
    event_id,
)

from ingest import normalize

_SYSLOG = "Failed password for root from 10.0.0.5 port 22 ssh2"
_CLOUDTRAIL = {
    "eventVersion": "1.08",
    "eventSource": "sts.amazonaws.com",
    "eventName": "AssumeRole",
    "eventTime": "2026-10-14T01:00:00Z",
    "awsRegion": "us-east-1",
    "recipientAccountId": "123456789012",
    "userIdentity": {"type": "IAMUser", "userName": "svc-deploy"},
    "sourceIPAddress": "198.51.100.7",
    "eventID": "abc-123",
}


# --------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_open_creates_the_database_under_the_lab_root(tmp_path: Path) -> None:
    with EventStore.open(tmp_path) as store:
        assert store.path.exists()
        assert store.path.parent == (tmp_path / "data" / "events").resolve()
        assert store.count() == 0


@pytest.mark.unit
def test_reopening_the_same_store_sees_its_events(tmp_path: Path) -> None:
    """Durability is the whole point — assert it across connections."""
    with EventStore.open(tmp_path) as store:
        store.append(normalize(_SYSLOG), ingested_at=1.0)
    with EventStore.open(tmp_path) as reopened:
        assert reopened.count() == 1
        assert reopened.query()[0].event.message


@pytest.mark.unit
def test_two_stores_can_coexist_under_different_filenames(tmp_path: Path) -> None:
    with EventStore.open(tmp_path, filename="a.sqlite3") as a:
        a.append(normalize(_SYSLOG), ingested_at=1.0)
    with EventStore.open(tmp_path, filename="b.sqlite3") as b:
        assert b.count() == 0


@pytest.mark.unit
def test_schema_version_is_recorded_on_creation(tmp_path: Path) -> None:
    with EventStore.open(tmp_path) as store:
        row = store._conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        assert row["value"] == str(SCHEMA_VERSION)


# --------------------------------------------------------------------------
# Append
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_append_returns_the_content_address(tmp_path: Path) -> None:
    event = normalize(_SYSLOG)
    with EventStore.open(tmp_path) as store:
        identifier = store.append(event, ingested_at=1.0)
    assert identifier == event_id(canonical_json(event.to_dict()))


@pytest.mark.unit
def test_appending_the_same_event_twice_stores_it_once(tmp_path: Path) -> None:
    """Collection retries and replays rotated files; duplicates would inflate
    every rate and correlation drawn from the store."""
    with EventStore.open(tmp_path) as store:
        first = store.append(normalize(_CLOUDTRAIL), ingested_at=1.0)
        second = store.append(normalize(_CLOUDTRAIL), ingested_at=9_999.0)
        assert first == second
        assert store.count() == 1
        # The original ingestion time wins: INSERT OR IGNORE keeps the first row.
        assert store.query()[0].ingested_at == 1.0


@pytest.mark.unit
def test_append_many_reports_only_what_was_new(tmp_path: Path) -> None:
    events = (normalize(_SYSLOG), normalize(_CLOUDTRAIL))
    with EventStore.open(tmp_path) as store:
        assert store.append_many(events, ingested_at=1.0) == 2
        assert store.append_many(events, ingested_at=2.0) == 0
        assert store.count() == 2


@pytest.mark.unit
def test_a_bad_event_rolls_back_the_whole_batch(tmp_path: Path) -> None:
    """A partially ingested window looks complete to a later query."""
    oversized = NormalizedEvent(
        source_type="unknown",
        vendor="hand-built",
        vendor_event_id=None,
        timestamp=None,
        message="m",
        activity=None,
        parse_status="text",
        raw_excerpt="x" * 70_000,
    )
    with EventStore.open(tmp_path) as store:
        with pytest.raises(StoreIntegrityError):
            store.append_many((normalize(_SYSLOG), oversized), ingested_at=1.0)
        assert store.count() == 0, "the good event in the batch must not survive"


@pytest.mark.unit
def test_observables_are_indexed_for_the_intel_pivot(tmp_path: Path) -> None:
    event = normalize(_SYSLOG)
    assert event.observables, "fixture must carry an observable for this to mean anything"
    with EventStore.open(tmp_path) as store:
        store.append(event, ingested_at=1.0)
        for value in event.observables:
            assert len(store.query(Query(observable=value))) == 1
        assert store.query(Query(observable="no-such-value")) == ()


# --------------------------------------------------------------------------
# Round trip
# --------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("record", [_SYSLOG, _CLOUDTRAIL], ids=["text", "cloud"])
def test_an_event_survives_storage_unchanged(
    tmp_path: Path, record: str | Mapping[str, Any]
) -> None:
    original = normalize(record)
    with EventStore.open(tmp_path) as store:
        store.append(original, ingested_at=1.0)
        assert store.query()[0].event == original


@pytest.mark.unit
def test_stored_facts_accompany_the_event(tmp_path: Path) -> None:
    with EventStore.open(tmp_path) as store:
        identifier = store.append(normalize(_SYSLOG), ingested_at=1_700_000_000.0)
        stored = store.query()[0]
        assert stored.event_id == identifier
        assert stored.ingested_at == 1_700_000_000.0


# --------------------------------------------------------------------------
# Query
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_filters_narrow_to_the_right_events(tmp_path: Path) -> None:
    with EventStore.open(tmp_path) as store:
        store.append(normalize(_SYSLOG), ingested_at=1.0)
        store.append(normalize(_CLOUDTRAIL), ingested_at=2.0)
        assert len(store.query(Query(source_type="cloud"))) == 1
        assert len(store.query(Query(vendor="aws-cloudtrail"))) == 1
        assert len(store.query(Query(user_name="svc-deploy"))) == 1
        assert store.query(Query(user_name="nobody")) == ()
        assert len(store.query(ALL)) == 2


@pytest.mark.unit
def test_an_ip_matches_on_either_side_of_the_connection(tmp_path: Path) -> None:
    """An address is interesting whichever end of the flow it sat on."""
    with EventStore.open(tmp_path) as store:
        store.append(normalize(_CLOUDTRAIL), ingested_at=1.0)
        matched = store.query(Query(ip="198.51.100.7"))
        assert len(matched) == 1
        assert matched[0].event.src_endpoint.ip == "198.51.100.7"
        assert store.query(Query(ip="203.0.113.1")) == ()


@pytest.mark.unit
def test_filters_combine_as_and_not_or(tmp_path: Path) -> None:
    with EventStore.open(tmp_path) as store:
        store.append(normalize(_CLOUDTRAIL), ingested_at=1.0)
        assert len(store.query(Query(source_type="cloud", user_name="svc-deploy"))) == 1
        # One side false must empty the result, not fall back to the other.
        assert store.query(Query(source_type="endpoint", user_name="svc-deploy")) == ()


@pytest.mark.unit
def test_the_time_window_is_half_open(tmp_path: Path) -> None:
    """Adjacent windows must not both claim an event on their shared edge."""
    event = normalize(_CLOUDTRAIL)
    assert event.timestamp is not None
    at = event.timestamp
    with EventStore.open(tmp_path) as store:
        store.append(event, ingested_at=1.0)
        assert len(store.query(Query(since=at, until=at + 1))) == 1, "since is inclusive"
        assert store.query(Query(since=at + 1, until=at + 2)) == ()
        assert store.query(Query(since=at - 2, until=at)) == (), "until is exclusive"


@pytest.mark.unit
def test_an_undated_event_is_excluded_by_any_time_filter(tmp_path: Path) -> None:
    """``ingest/`` never back-fills "now", so position in time is unknown.

    Treating unknown as in-range would put the event inside every window a
    caller ever asks about — the quiet kind of wrong.
    """
    undated = normalize(_SYSLOG)
    assert undated.timestamp is None, "fixture must carry no source timestamp"
    with EventStore.open(tmp_path) as store:
        store.append(undated, ingested_at=1.0)
        assert store.count() == 1
        assert store.query(Query(since=0.0)) == ()
        assert store.query(Query(until=4e9)) == ()
        assert store.query(Query(since=0.0, until=4e9)) == ()
        # Still reachable without a time filter — excluded, never lost.
        assert len(store.query()) == 1


@pytest.mark.unit
def test_ordering_follows_newest_first_by_default(tmp_path: Path) -> None:
    with EventStore.open(tmp_path) as store:
        store.append(normalize(_SYSLOG), ingested_at=1.0)
        store.append(normalize(_CLOUDTRAIL), ingested_at=2.0)
        assert [s.ingested_at for s in store.query()] == [2.0, 1.0]
        assert [s.ingested_at for s in store.query(Query(newest_first=False))] == [1.0, 2.0]


@pytest.mark.unit
def test_limit_bounds_the_page(tmp_path: Path) -> None:
    with EventStore.open(tmp_path) as store:
        store.append(normalize(_SYSLOG), ingested_at=1.0)
        store.append(normalize(_CLOUDTRAIL), ingested_at=2.0)
        assert len(store.query(Query(limit=1))) == 1
        assert len(store.query(Query(limit=2))) == 2


# --------------------------------------------------------------------------
# Retention
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_prune_removes_and_counts_what_it_removed(tmp_path: Path) -> None:
    with EventStore.open(tmp_path) as store:
        store.append(normalize(_SYSLOG), ingested_at=100.0)
        store.append(normalize(_CLOUDTRAIL), ingested_at=200.0)
        assert store.prune(before=150.0) == 1
        assert store.count() == 1
        assert store.query()[0].ingested_at == 200.0


@pytest.mark.unit
def test_prune_cascades_to_observables(tmp_path: Path) -> None:
    """An orphaned observable would keep matching an event that is gone."""
    event = normalize(_SYSLOG)
    assert event.observables
    with EventStore.open(tmp_path) as store:
        store.append(event, ingested_at=100.0)
        assert store.prune(before=150.0) == 1
        orphans = store._conn.execute("SELECT COUNT(*) AS n FROM observables").fetchone()
        assert orphans["n"] == 0
        assert store.query(Query(observable=event.observables[0])) == ()


@pytest.mark.unit
def test_prune_keys_on_ingestion_not_source_time(tmp_path: Path) -> None:
    """A source with a wrong clock must not control its own retention."""
    event = normalize(_CLOUDTRAIL)
    assert event.timestamp is not None
    with EventStore.open(tmp_path) as store:
        # Source time is 2026; ingestion time is deliberately tiny.
        store.append(event, ingested_at=10.0)
        assert store.prune(before=event.timestamp) == 1, (
            "pruning must use ingested_at, which this store controls"
        )


@pytest.mark.unit
def test_prune_on_an_empty_store_is_a_no_op(tmp_path: Path) -> None:
    with EventStore.open(tmp_path) as store:
        assert store.prune(before=1.0) == 0
