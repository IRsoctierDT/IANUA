# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

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

import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from ingest import normalize
from ingest.schema import NormalizedEvent
from store import (
    ALL,
    ATTEST_COUNTS_SQL,
    ATTEST_IDS_SQL,
    ATTEST_OBSERVABLES_SQL,
    SCHEMA_VERSION,
    EventStore,
    Query,
    StoreIntegrityError,
    canonical_json,
    event_id,
)

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


# --------------------------------------------------------------------------
# attest() — the completeness control, which had no direct test at all
# --------------------------------------------------------------------------


def _seeded(root: Path, count: int) -> EventStore:
    """A store holding ``count`` DISTINCT events.

    Distinct content matters: ``event_id`` is a sha256 over the projection, so
    appending the same line twice is a deliberate no-op. A fixture that loops
    over one identical line yields a store of **one** row — measured while
    writing this, when a 500-iteration loop attested as ``events=1``.
    """
    store = EventStore.open(root)
    for index in range(count):
        store.append(
            normalize(f"Failed password for u{index} from 10.0.0.{index % 250} port 22 ssh2"),
            ingested_at=1_760_000_000.0 + index,
        )
    return store


@pytest.mark.unit
def test_attestation_is_stable_across_a_reopen(tmp_path: Path) -> None:
    """The digest describes content, not layout, or a verified copy is useless."""
    with _seeded(tmp_path, 50) as store:
        first = store.attest()
    with EventStore.open(tmp_path) as reopened:
        second = reopened.attest()
    assert first == second
    assert first.events == 50
    assert first.observables > 0


@pytest.mark.unit
def test_an_attestation_commits_to_its_own_count(tmp_path: Path) -> None:
    """A prefix of one store cannot digest the same as another store's whole set.

    The documented reason the count goes into the preimage. Asserted by
    building the prefix for real rather than by reading the code: a 20-event
    store and the first 20 events of a 40-event store hold the same ids, and
    must still attest differently from the larger store.
    """
    small, large = tmp_path / "small", tmp_path / "large"
    small.mkdir()
    large.mkdir()
    with _seeded(small, 20) as store:
        twenty = store.attest()
    with _seeded(large, 40) as store:
        forty = store.attest()
    assert twenty.events == 20
    assert forty.events == 40
    assert twenty.digest != forty.digest

    # And the same content attests identically in a different store.
    other = tmp_path / "other"
    other.mkdir()
    with _seeded(other, 20) as store:
        assert store.attest().digest == twenty.digest


@pytest.mark.unit
def test_attesting_refuses_when_the_count_and_the_id_scan_disagree(tmp_path: Path) -> None:
    """The digest must commit to what it actually hashed.

    The count and the id stream are two separate statements, so the preimage
    could commit to a number that did not equal the number of ids hashed into
    it — an attestation internally inconsistent, well-formed, and comparing
    unequal for a reason nobody could read off it.

    **This test is the teeth for that guard, and it needs the injection**
    because on a healthy store the two numbers always agree, so a guard
    asserting they do cannot fail on any real fixture. Removing the check
    makes this test red and nothing else in the suite notices.

    Honest about provenance: the shape that prompted the guard was an
    adversarial measurement reporting ``COUNT(*)`` of 1500 against 1502
    streamed ids on a database SQLite called malformed. I could not reproduce
    it — a bluntly truncated copy raises ``DatabaseError: database disk image
    is malformed`` out of SQLite first — so the guard rests on the plain
    argument rather than on that measurement, and this test injects the
    disagreement rather than pretending to produce it naturally.
    """
    with _seeded(tmp_path, 10) as store:
        assert store.attest().events == 10, "the fixture is not what this test needs"

        # A proxy rather than a patched method: `sqlite3.Connection.execute`
        # is read-only on the instance, so the injection has to sit one level
        # out. Found by trying the simpler thing first.
        real = store._conn
        store._conn = _CountInflater(real, 999)  # type: ignore[assignment]
        try:
            with pytest.raises(StoreIntegrityError, match="attestation is inconsistent"):
                store.attest()
        finally:
            store._conn = real

        # And the healthy path still works once the injection is removed.
        assert store.attest().events == 10


class _OneRow:
    """A stand-in for the single ``sqlite3.Row`` the counts query returns."""

    def __init__(self, values: dict[str, int]) -> None:
        self._values = values

    def fetchone(self) -> dict[str, int]:
        return self._values


class _CountInflater:
    """A connection proxy that lies about ``COUNT(*)`` and nothing else.

    Everything else delegates, so the id scan returns the store's real ids and
    the disagreement is exactly the one the guard is for.
    """

    def __init__(self, real: Any, events: int) -> None:
        self._real = real
        self._events = events

    def execute(self, sql: str, *args: Any, **kwargs: Any) -> Any:
        if "COUNT(*) FROM events" in sql:
            return _OneRow({"events": self._events, "observables": self._events})
        return self._real.execute(sql, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


@pytest.mark.unit
def test_the_observables_digest_commits_to_values_and_not_only_to_their_count(
    tmp_path: Path,
) -> None:
    """Replacing observable rows one-for-one must change the attestation.

    The count cannot see it, the event digest cannot see it (observables are
    not in its preimage), and ``quick_check`` cannot see it. This is the state
    review found the promotion gate exiting 0 on. The substitution is made
    through raw SQLite because the store's own API exposes no way to make it,
    which is the point: this is what a damaged or hostile copy looks like, not
    what a writer does.
    """
    with _seeded(tmp_path, 20) as store:
        before = store.attest()
    assert before.observables > 0, "the fixture produced no observables; the test is vacuous"

    connection = sqlite3.connect(tmp_path / "data" / "events" / "events.sqlite3")
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

    with EventStore.open(tmp_path) as store:
        after = store.attest()
    # The premise: every other field is unchanged.
    assert (after.events, after.observables, after.digest) == (
        before.events,
        before.observables,
        before.digest,
    )
    assert after.observables_digest != before.observables_digest


@pytest.mark.unit
def test_the_observables_digest_frames_each_field_by_length(tmp_path: Path) -> None:
    """Rows whose fields concatenate to the same bytes must digest differently.

    ``(E, "abc")`` and ``(E + "a", "bc")`` are one row each, same count, and
    their fields joined without framing are byte-identical — ``E + "abc"``.
    A digest that separated fields with a character a value may contain would
    give these two the same answer. Each field is length-prefixed so the row
    boundary is unforgeable; this is the test that says so, built through raw
    SQLite because no writer produces such rows (the second event_id does not
    exist, and foreign keys are off on a raw connection, which is exactly the
    kind of copy this digest has to be able to see).
    """
    digests = []
    for index, (suffix, value) in enumerate((("", "abc"), ("a", "bc"))):
        root = tmp_path / f"store{index}"
        root.mkdir()
        with _seeded(root, 1) as store:
            (event,) = [str(row["event_id"]) for row in store._conn.execute(ATTEST_IDS_SQL)]
        connection = sqlite3.connect(root / "data" / "events" / "events.sqlite3")
        try:
            connection.execute("DELETE FROM observables")
            connection.execute(
                "INSERT INTO observables (event_id, value) VALUES (?, ?)", (event + suffix, value)
            )
            connection.commit()
        finally:
            connection.close()
        with EventStore.open(root) as store:
            attested = store.attest()
        assert attested.observables == 1, attested
        digests.append(attested.observables_digest)
    assert digests[0] != digests[1], "fields are not framed: a boundary shift was invisible"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("statement", "plans"),
    [
        pytest.param(
            ATTEST_IDS_SQL,
            ("SCAN events USING COVERING INDEX sqlite_autoindex_events_1",),
            id="id-stream",
        ),
        pytest.param(
            ATTEST_COUNTS_SQL,
            (
                "SCAN events USING COVERING INDEX events_ingested_at",
                "SCAN observables USING COVERING INDEX observables_value",
            ),
            id="counts",
        ),
        pytest.param(
            ATTEST_OBSERVABLES_SQL,
            ("SCAN observables USING COVERING INDEX sqlite_autoindex_observables_1",),
            id="observables-stream",
        ),
    ],
)
def test_every_attest_statement_is_a_covering_index_scan(
    tmp_path: Path, statement: str, plans: tuple[str, ...]
) -> None:
    """``attest()`` never reads a table page; ``quick_check`` is what does.

    That property used to live in a docstring ("both statements are
    covering-index scans — measured"). A docstring measured once is a claim;
    this is the measurement, run every time, against the same SQL text the
    method executes (imported, not retyped). If an index is dropped or a
    column added, this is what goes red.
    """
    with _seeded(tmp_path, 20) as store:
        assert store.attest().observables > 0
        plan = "\n".join(
            str(row["detail"]) for row in store._conn.execute(f"EXPLAIN QUERY PLAN {statement}")
        )
    for expected in plans:
        assert expected in plan, f"{statement!r} planned as:\n{plan}"
    # Every line that touches a table must do so through a covering index. The
    # first version checked only for a bare "SCAN <table>" line, which could not
    # see "SCAN events USING INDEX x" — a non-covering scan that reads row pages
    # — so its message claimed a reach it did not have (found by review).
    table_lines = [line for line in plan.splitlines() if "events" in line or "observables" in line]
    assert table_lines, f"no table access planned for {statement!r}:\n{plan}"
    for line in table_lines:
        assert "USING COVERING INDEX" in line, f"reads row pages: {line!r} in\n{plan}"


@pytest.mark.unit
def test_the_observables_digest_distinguishes_a_blob_from_the_text_of_its_repr(
    tmp_path: Path,
) -> None:
    """A BLOB ``b"x"`` and the TEXT ``b'x'`` must not digest the same.

    ``value`` is TEXT by affinity only; a damaged or hostile copy can hold a
    BLOB there, and ``str()`` of Python bytes is the text of their repr — so a
    digest over ``str(field)`` was not injective across storage classes (found
    by independent review before this shipped). Each field is now framed with
    its storage class and raw bytes, and never decoded, so bytes that are not
    UTF-8 attest rather than abort. Built through raw SQLite because no writer
    produces such rows, which is the point.
    """
    digests = []
    for index, value in enumerate((b"evil.example", "b'evil.example'", b"\xff\xfe not utf-8")):
        root = tmp_path / f"store{index}"
        root.mkdir()
        with _seeded(root, 1) as store:
            (event,) = [str(row["event_id"]) for row in store._conn.execute(ATTEST_IDS_SQL)]
        connection = sqlite3.connect(root / "data" / "events" / "events.sqlite3")
        try:
            connection.execute("DELETE FROM observables")
            connection.execute(
                "INSERT INTO observables (event_id, value) VALUES (?, ?)", (event, value)
            )
            connection.commit()
            assert connection.execute("SELECT typeof(value) FROM observables").fetchone()[0] == (
                "blob" if isinstance(value, bytes) else "text"
            ), "the storage class did not land as intended; the test would be vacuous"
        finally:
            connection.close()
        with EventStore.open(root) as store:
            attested = store.attest()  # must not raise on the non-UTF-8 blob either
        assert attested.observables == 1
        digests.append(attested.observables_digest)
    assert len(set(digests)) == 3, digests
