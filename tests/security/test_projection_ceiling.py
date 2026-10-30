# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""One ingested record cannot stop a collector source.

The event store refuses a canonical projection past ``MAX_PROJECTION_BYTES``,
``append_many`` refuses a whole batch over one such event, and the collector
advances a source's offset only once that source's batch is stored. Every
bound ``ingest`` applied was per field, and a sum of bounded fields has no
ceiling of its own. Measured on ``2c92e3f`` through
``scripts/run_collector.py``: a 61,670-byte Defender line with thirty
2,000-character URLs, under ``collect/``'s 64 KiB line cap, projected to
66,729 bytes. Every pass over a three-line log stored 0 of 3 events at exit 1
with the offsets held, and a line appended afterwards was never stored either.
Whoever can get one such record logged could do that to a source, so it was a
way to evade detection.

The owner chose two layers. ``ingest`` fits every event under the ceiling
with one cap on every value (``fit_projection``), and the collector stores a
content-free placeholder for an event the store still refuses, for a reason
nobody has listed yet, so the source advances anyway.
"""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from hypothesis import find, given, settings, target
from hypothesis import strategies as st

import store.schema as store_schema
from collect import MAX_LINE_BYTES
from ingest import normalize, normalize_many
from ingest.parsers.endpoint import _SYSMON_DATA_FIELDS
from ingest.schema import (
    _UNCUT,
    MAX_FIELD_LEN,
    MAX_OBSERVABLES,
    MAX_PROJECTION_BYTES,
    Actor,
    CloudContext,
    Device,
    EmailContext,
    Endpoint,
    NormalizedEvent,
    _capped,
    _cuttable_lengths,
    canonical_json,
    fit_projection,
    projection_size,
)
from store import EventStore, Query, StoreIntegrityError

#: The module, not the function ``ingest`` exports under the same name, for
#: :func:`_unfitted`: what ``normalize`` built before the ceiling was applied.
_NORMALIZE = sys.modules["ingest.normalize"]

_FIXTURES = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "ingest_fixtures.json").read_text(
        encoding="utf-8"
    )
)
_PHISH: dict[str, Any] = _FIXTURES["defender_email_phish"]["record"]


def _urls(count: int, width: int = 2000) -> list[str]:
    return [f"http://partner-invoices.example/{'p' * width}/{index}" for index in range(count)]


#: The inputs measured over the ceiling, by name. The first three are the ones
#: the defect was reported with. The two URL lines are over 64 KiB, so the
#: collector's line cap cuts them into unparseable text before ``normalize``
#: sees them, and through the collector they did not stall. The recipient line
#: is 65,168 bytes, under the cap, and stalled a source on ``2c92e3f`` (two
#: passes, exit 1, 0 stored). ``sub-cap`` is a smaller line that stalls the
#: same way. ``sysmon-cjk`` holds no list entries at all, which is why cutting
#: lists alone could not have been the fix.
_OVERSIZED: dict[str, bytes] = {
    "brief-32-urls": json.dumps(dict(_PHISH, UrlList=_urls(32))).encode(),
    "brief-64-urls": json.dumps(dict(_PHISH, UrlList=_urls(64))).encode(),
    "brief-32-recipients": json.dumps(
        dict(_PHISH, RecipientEmailAddress=[f"{'r' * 2000}{i}@corp.example" for i in range(32)])
    ).encode(),
    "sub-cap": json.dumps(dict(_PHISH, UrlList=_urls(30)), separators=(",", ":")).encode(),
    "sysmon-cjk": json.dumps(
        {
            "Provider": "Microsoft-Windows-Sysmon",
            "EventID": 1,
            "EventData": {
                **dict.fromkeys(_SYSMON_DATA_FIELDS, "\u4e2d" * 2048),
                "UtcTime": "2026-10-20 10:00:00.000",
            },
        },
        ensure_ascii=False,
    ).encode(),
}
_STALLING = _OVERSIZED["sub-cap"]


def _unfitted(raw: bytes) -> NormalizedEvent:
    """``normalize`` without the fit: the event the store used to be handed."""
    event: NormalizedEvent = _NORMALIZE._normalize(raw)
    return event


def _stored_back(tmp_path: Path, event: NormalizedEvent) -> NormalizedEvent:
    with EventStore.open(tmp_path) as store:
        store.append(event, ingested_at=1.0)
        (row,) = store.query(Query())
    return row.event


# --------------------------------------------------------------------------
# The measured records
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize("name", sorted(_OVERSIZED))
def test_each_measured_record_is_over_the_ceiling_without_the_fit(name: str) -> None:
    """The teeth for every test below: these inputs still reproduce the defect.

    Without this, a later change that made them small for some other reason
    would leave the tests below green while testing nothing.
    """
    assert projection_size(_unfitted(_OVERSIZED[name])) > MAX_PROJECTION_BYTES


@pytest.mark.security
@pytest.mark.parametrize("name", sorted(_OVERSIZED))
def test_each_measured_record_now_fits_and_is_stored(tmp_path: Path, name: str) -> None:
    """Fitted, stored, read back identically, and marked as cut."""
    before = _unfitted(_OVERSIZED[name])
    event = normalize(_OVERSIZED[name])
    assert projection_size(event) <= MAX_PROJECTION_BYTES
    assert _stored_back(tmp_path, event) == event
    assert event.parse_status == "partial", "a cut event must not read as a clean parse"
    assert event.notes[-1].startswith(f"projection of {projection_size(before)} bytes exceeded")
    # Every entry is kept, shortened: the cap cuts values, never list entries.
    assert len(event.email.urls) == len(before.email.urls)
    assert len(event.email.recipients) == len(before.email.recipients)


@pytest.mark.security
def test_the_note_names_the_cap_and_every_field_it_cut() -> None:
    note = normalize(_STALLING).notes[-1]
    assert note == (
        "projection of 66729 bytes exceeded the store's 65536-byte ceiling; every value "
        "longer than 1996 characters was cut to 1996 (email.urls: 30 of 30 entries, "
        "raw_excerpt)"
    ), note
    assert len(note) <= MAX_FIELD_LEN


@pytest.mark.security
@pytest.mark.parametrize(
    ("name", "whole"),
    [
        ("sub-cap", True),
        ("brief-32-recipients", True),
        ("brief-32-urls", False),
        ("brief-64-urls", False),
    ],
)
def test_which_measured_lines_the_collector_reads_whole(name: str, whole: bool) -> None:
    """Under the line cap, a line reaches ``normalize`` intact, and these stalled a source.

    Over it, the collector cuts the line into text that no longer parses, and
    that path never stalled. Pinned so the end-to-end test below keeps using a
    line the collector really delivers whole.
    """
    assert (len(_OVERSIZED[name]) <= MAX_LINE_BYTES) is whole


# --------------------------------------------------------------------------
# End to end, through the collector
# --------------------------------------------------------------------------


def _collect(root: Path, log: Path, capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    from scripts.run_collector import main

    capsys.readouterr()
    assert main(["--root", str(root), "--source", str(log), "--json"]) == 0
    report: dict[str, Any] = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    return report


@pytest.mark.security
def test_the_line_that_stalled_a_source_is_stored_and_the_source_advances(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The measured stall, replayed: 0 of 3 stored at exit 1 on every pass, before."""
    root = tmp_path / "root"
    root.mkdir()
    log = tmp_path / "app.log"
    first = json.dumps(dict(_PHISH, Subject="first good line"))
    third = json.dumps(dict(_PHISH, Subject="third good line"))
    log.write_bytes(first.encode() + b"\n" + _STALLING + b"\n" + third.encode() + b"\n")

    report = _collect(root, log, capsys)
    assert report["events_stored"] == 3
    assert report["events_refused"] == 0, "the fit, not the placeholder, carried this record"
    assert report["offsets_advancing"] is True

    assert _collect(root, log, capsys)["lines_read"] == 0, "the offset moved past all three"
    with log.open("ab") as handle:
        handle.write(json.dumps(dict(_PHISH, Subject="appended later")).encode() + b"\n")
    assert _collect(root, log, capsys)["events_stored"] == 1, "a later line is reached"

    with EventStore.open(root) as store:
        assert store.count() == 4
        subjects = {row.event.email.subject for row in store.query(Query())}
    assert {"first good line", "third good line", "appended later"} <= subjects


# --------------------------------------------------------------------------
# The property
# --------------------------------------------------------------------------

#: Characters chosen for what they cost in the projection: one byte, two once
#: escaped, two to four in UTF-8, and a line separator JSON writes as itself.
_FILLS = ("a", '"', "\\", "\u00e9", "\u4e2d", "\U0001f600", "\u2028")


def _inflated(node: Any, fill: str, width: int, entries: int) -> Any:
    """Every string in ``node`` replaced by ``fill * width``; every list lengthened."""
    if isinstance(node, dict):
        return {key: _inflated(value, fill, width, entries) for key, value in node.items()}
    if isinstance(node, list):
        return [f"{index}{fill * width}" for index in range(entries)] or node
    if isinstance(node, str):
        return fill * width
    return node


def _keeps_its_parser(name: str, key: str) -> bool:
    """Whether inflating ``key`` alone leaves the fixture claimed by its own parser."""
    record = _FIXTURES[name]["record"]
    inflated = {**record, key: _inflated(record[key], "a", 300, 3)}
    return normalize(inflated).vendor == normalize(record).vendor


#: Per fixture, the top-level keys that can be padded without the record being
#: claimed by no parser. An unclaimed record keeps only a bounded excerpt, so a
#: draw that broke recognition would test the path that cannot overflow.
_INFLATABLE = {
    name: tuple(key for key in sorted(case["record"]) if _keeps_its_parser(name, key))
    for name, case in sorted(_FIXTURES.items())
}


@st.composite
def _records(draw: st.DrawFn) -> bytes:
    """A committed fixture, still claimed by its parser, with its fields padded.

    Drawn: which fixture, which of its paddable keys, the character (for what
    it costs once projected), the width of every string, how many entries
    every list gets, and whether non-ASCII is escaped in the line.
    """
    name = draw(st.sampled_from(sorted(_FIXTURES)))
    record = dict(_FIXTURES[name]["record"])
    fill = draw(st.sampled_from(_FILLS))
    # Two bands each, small and near the bound, so a draw is either ordinary
    # or large enough to matter rather than spread thinly between.
    width = draw(st.integers(0, 64) | st.integers(MAX_FIELD_LEN // 2, MAX_FIELD_LEN + 64))
    entries = draw(st.integers(0, 4) | st.integers(MAX_OBSERVABLES // 2, MAX_OBSERVABLES + 8))
    paddable = _INFLATABLE[name]
    keys = (
        paddable if draw(st.booleans()) else draw(st.lists(st.sampled_from(paddable), unique=True))
    )
    for key in keys:
        record[key] = _inflated(record[key], fill, width, entries)
    return json.dumps(record, ensure_ascii=draw(st.booleans())).encode()


@pytest.mark.security
def test_the_strategy_reaches_past_the_ceiling() -> None:
    """The teeth of the property below: without this it could pass by never trying.

    An earlier draft of the strategy restored the fields a recognizer keys on
    after padding, and the lists came back with them: measured, none of 150
    draws was over the ceiling, and the property was green with the fit
    removed. ``find`` fails if no draw the strategy can make goes past it.
    """
    # Mapped to its size, so what ``find`` reports is a number and not a
    # 60 KB line: Hypothesis warns about a repr that large.
    size = find(
        _records().map(lambda raw: projection_size(_unfitted(raw))),
        lambda measured: measured > MAX_PROJECTION_BYTES,
        settings=settings(max_examples=500, derandomize=True, database=None),
    )
    assert size > MAX_PROJECTION_BYTES


@pytest.mark.security
@settings(max_examples=150, derandomize=True, deadline=None)
@given(raw=_records())
def test_normalize_never_returns_an_event_the_store_refuses(raw: bytes) -> None:
    """The brief's property: no input yields a projection past the ceiling.

    Checked the way the store checks it, strict ``encode`` included, and read
    back through ``from_dict`` as the store does before every write. ``target``
    steers the search toward the largest unfitted projections, where the fit
    has work to do.
    """
    target(float(projection_size(_unfitted(raw))), label="unfitted projection bytes")
    event = normalize(raw)
    projection = canonical_json(event.to_dict())
    assert len(projection.encode("utf-8")) <= MAX_PROJECTION_BYTES
    assert NormalizedEvent.from_dict(json.loads(projection)) == event
    assert normalize(raw) == event, "the cut must be deterministic"


@st.composite
def _events(draw: st.DrawFn) -> NormalizedEvent:
    """Any event a direct caller could build within the per-field bounds.

    Every optional string is absent or ``fill * width`` and every list has a
    drawn length, so the draw covers shapes no parser produces today, the ones
    a future parser might.
    """
    fill = draw(st.sampled_from(_FILLS))

    def value() -> str | None:
        width = draw(st.none() | st.integers(0, 64) | st.integers(1024, MAX_FIELD_LEN))
        return None if width is None else fill * width

    def entries() -> tuple[str, ...]:
        count = draw(st.integers(0, 4) | st.integers(24, MAX_OBSERVABLES))
        width = draw(st.integers(1, 64) | st.integers(512, MAX_FIELD_LEN - 4))
        return tuple(f"{index}{fill * width}" for index in range(count))

    def group(kind: type[Any]) -> Any:
        return kind(**{f.name: value() for f in dataclasses.fields(kind)})

    return NormalizedEvent(
        source_type="network",
        vendor="hand-built",
        vendor_event_id=value(),
        timestamp=1.0,
        message=value() or "",
        activity=value(),
        parse_status="structured",
        actor=group(Actor),
        device=group(Device),
        src_endpoint=group(Endpoint),
        dst_endpoint=group(Endpoint),
        cloud=group(CloudContext),
        email=dataclasses.replace(group(EmailContext), recipients=entries(), urls=entries()),
        observables=entries(),
        raw_excerpt=fill * draw(st.integers(0, 4096)),
        notes=entries(),
    )


@pytest.mark.security
@settings(max_examples=150, derandomize=True, deadline=None)
@given(event=_events())
def test_bounded_makes_any_event_storable(event: NormalizedEvent) -> None:
    """``bounded()``'s own promise, over every field shape at once.

    Also: idempotent, so bounding a stored event's rebuild changes nothing;
    every kept observable is one the event carried, exactly; and every list
    keeps all its entries.
    """
    target(float(projection_size(event)), label="projection bytes before")
    bounded = event.bounded()
    projection = canonical_json(bounded.to_dict())
    assert len(projection.encode("utf-8")) <= MAX_PROJECTION_BYTES
    assert NormalizedEvent.from_dict(json.loads(projection)) == bounded
    assert bounded.bounded() == bounded
    assert set(bounded.observables) <= set(event.observables)
    assert len(bounded.email.urls) == len(event.email.urls)
    assert len(bounded.notes) == len(event.notes)


@pytest.mark.security
@settings(max_examples=60, derandomize=True, deadline=None)
@given(
    payload=st.dictionaries(
        st.text(min_size=1, max_size=24),
        st.one_of(
            st.text(max_size=3000),
            st.lists(st.text(max_size=3000), max_size=40),
            st.integers(),
        ),
        max_size=40,
    )
)
def test_an_arbitrary_record_never_yields_an_event_the_store_refuses(
    payload: dict[str, Any],
) -> None:
    """The same property where no fixture shapes the input: unclaimed records.

    Unlike the test above, this one stays green with the fit removed (measured
    by planting that). An unclaimed record keeps only its bounded excerpt, its
    summary and the indicators inside them, so it cannot reach the ceiling
    today. It is here as a guard on that path, which a change to what an
    excerpt retains could widen.
    """
    event = normalize(json.dumps(payload, ensure_ascii=False).encode())
    assert len(canonical_json(event.to_dict()).encode("utf-8")) <= MAX_PROJECTION_BYTES


@pytest.mark.security
def test_normalize_many_fits_the_event_its_outer_layer_builds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The batch boundary's second layer is fitted too, not only ``normalize``.

    No committed input reaches that layer, which is the point of it, so the
    raise and an over-ceiling result from it are both planted.
    """

    def raises(_raw: object) -> NormalizedEvent:
        raise RuntimeError("planted")

    over = _refused()
    assert projection_size(over) > MAX_PROJECTION_BYTES
    monkeypatch.setattr(_NORMALIZE, "_normalize", raises)
    monkeypatch.setattr(_NORMALIZE, "_normalization_raised", lambda _record, _exc: over)
    (event,) = normalize_many([b"anything"])
    assert projection_size(event) <= MAX_PROJECTION_BYTES


# --------------------------------------------------------------------------
# What the fit does not change
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize("name", sorted(_FIXTURES))
def test_an_event_within_the_ceiling_is_returned_unchanged(name: str) -> None:
    """No event the store could already hold gets a new ``event_id``.

    So re-reading a log line stored by an earlier build stores nothing new.
    """
    raw = json.dumps(_FIXTURES[name]["record"]).encode()
    event = _unfitted(raw)
    assert fit_projection(event) == (event, None)
    assert fit_projection(event)[0] is event
    assert normalize(raw) == event


@pytest.mark.security
def test_the_same_bytes_are_cut_to_the_same_event() -> None:
    first, second = normalize(_STALLING), normalize(_STALLING)
    assert first == second
    assert canonical_json(first.to_dict()) == canonical_json(second.to_dict())


# --------------------------------------------------------------------------
# One cap on every value
# --------------------------------------------------------------------------


@pytest.mark.security
def test_padding_the_other_urls_cannot_push_one_out() -> None:
    """The weakness of cutting in a fixed order, which the owner chose against.

    Sixty-three padded URLs and a short malicious one placed last: dropping
    entries from the end would lose exactly the one that matters. A single cap
    shortens the padded ones and leaves the short one whole.
    """
    malicious = "http://login-verify.example/x"
    raw = json.dumps(dict(_PHISH, UrlList=[*_urls(63), malicious])).encode()
    assert projection_size(_unfitted(raw)) > MAX_PROJECTION_BYTES
    event = normalize(raw)
    assert projection_size(event) <= MAX_PROJECTION_BYTES
    assert event.email.urls[-1] == malicious
    assert len(event.email.urls) == 64
    assert event.email.sender == _PHISH["SenderFromAddress"]


@pytest.mark.security
def test_observables_are_dropped_whole_and_never_shortened() -> None:
    """A cut indicator is a false join key, so the cap removes observables instead."""
    observables = ("198.51.100.7", "a" * 64, f"http://long.example/{'q' * 240}", "b" * 40)
    padding = tuple("\U0001f600" * MAX_FIELD_LEN for _ in range(MAX_OBSERVABLES))
    event = dataclasses.replace(
        normalize(json.dumps(_PHISH)),
        observables=observables,
        raw_excerpt="x" * 4096,
        email=EmailContext(urls=padding, recipients=padding),
    )
    fitted, cap = fit_projection(event)
    assert cap is not None
    assert cap < 240, "the probe must put the cap below the long observable"
    assert set(fitted.observables) <= set(observables), "every kept observable is exact"
    assert fitted.observables == tuple(value for value in observables if len(value) <= cap)


def _worst(fill: str) -> NormalizedEvent:
    """Every field at its bound in ``fill`` and every list full."""
    value = fill * MAX_FIELD_LEN

    def full(group: type[Any]) -> Any:
        return group(**{f.name: value for f in dataclasses.fields(group)})

    entries = tuple(f"{index}{value}"[:MAX_FIELD_LEN] for index in range(MAX_OBSERVABLES))
    return NormalizedEvent(
        source_type="email",
        vendor="hand-built",
        vendor_event_id=value,
        timestamp=1.0,
        message=value,
        activity=value,
        parse_status="structured",
        actor=full(Actor),
        device=full(Device),
        src_endpoint=full(Endpoint),
        dst_endpoint=full(Endpoint),
        cloud=full(CloudContext),
        email=EmailContext(
            sender=value,
            subject=value,
            message_id=value,
            delivery_action=value,
            recipients=entries,
            urls=entries,
        ),
        observables=entries,
        raw_excerpt=fill * 4096,
        notes=entries,
    )


@pytest.mark.security
@pytest.mark.parametrize("fill", ["a", '"', "\U0001f600"])
def test_the_worst_case_event_fits_and_is_stored(tmp_path: Path, fill: str) -> None:
    """About thirty-six times the ceiling in four-byte characters, and it still fits."""
    worst = _worst(fill)
    assert projection_size(worst) > 8 * MAX_PROJECTION_BYTES
    bounded = worst.bounded()
    assert projection_size(bounded) <= MAX_PROJECTION_BYTES
    assert _stored_back(tmp_path, bounded) == bounded
    assert len(bounded.message) >= 64, "the cap stays far above zero"


@pytest.mark.security
def test_the_floor_fits_with_every_uncut_field_at_its_bound() -> None:
    """At a cap of zero only :data:`_UNCUT` and the keys remain, well inside the ceiling."""
    floor = _capped(dataclasses.replace(_worst("\U0001f600"), vendor="\U0001f600" * 2048), 0)
    assert projection_size(floor) < 10 * 1024


@pytest.mark.security
def test_the_cap_reaches_every_field_but_the_uncut_ones() -> None:
    """Anti-drift, by reflection: a field added to the schema is cut without an edit.

    At a cap of zero every string the cap may shorten is empty and every
    observable is gone, so anything still holding text is a field ``_capped``
    forgot.
    """
    worst = _worst("a")
    floor = _capped(worst, 0).to_dict()
    assert max(_cuttable_lengths(floor), default=0) == 0
    assert floor["observables"] == []
    whole = worst.to_dict()
    assert {key: floor[key] for key in _UNCUT} == {key: whole[key] for key in _UNCUT}


@pytest.mark.security
def test_ingest_and_the_store_measure_one_projection_against_one_ceiling() -> None:
    """One definition each, so the fit and the refusal cannot drift apart."""
    assert store_schema.MAX_PROJECTION_BYTES is MAX_PROJECTION_BYTES
    assert store_schema.canonical_json is canonical_json
    for raw in (
        *_OVERSIZED.values(),
        *(json.dumps(c["record"]).encode() for c in _FIXTURES.values()),
    ):
        event = normalize(raw)
        assert projection_size(event) == len(canonical_json(event.to_dict()).encode("utf-8"))


# --------------------------------------------------------------------------
# The store's stand-in hook
# --------------------------------------------------------------------------


def _refused() -> NormalizedEvent:
    """An event the store refuses: every field within bound, the whole past the ceiling."""
    return _unfitted(_STALLING)


def _good(subject: str) -> NormalizedEvent:
    return normalize(json.dumps(dict(_PHISH, Subject=subject)))


@pytest.mark.security
def test_without_a_stand_in_one_refused_event_still_refuses_the_batch(tmp_path: Path) -> None:
    """The default contract every other caller relies on is unchanged."""
    with EventStore.open(tmp_path) as store:
        with pytest.raises(StoreIntegrityError, match="ceiling"):
            store.append_many((_good("a"), _refused(), _good("b")), ingested_at=1.0)
        assert store.count() == 0


@pytest.mark.security
def test_a_stand_in_takes_only_the_refused_events_place(tmp_path: Path) -> None:
    seen: list[tuple[NormalizedEvent, Exception]] = []
    marker = _good("stood in")

    def stand_in(event: NormalizedEvent, refusal: Exception) -> NormalizedEvent:
        seen.append((event, refusal))
        return marker

    with EventStore.open(tmp_path) as store:
        added = store.append_many(
            (_good("a"), _refused(), _good("b")), ingested_at=1.0, stand_in=stand_in
        )
        subjects = {row.event.email.subject for row in store.query(Query())}
    assert added == 3
    assert subjects == {"a", "stood in", "b"}
    ((event, refusal),) = seen
    assert event == _refused()
    assert isinstance(refusal, StoreIntegrityError)


@pytest.mark.security
def test_a_stand_in_the_store_also_refuses_refuses_the_batch(tmp_path: Path) -> None:
    """A stand-in is projected like any event, never stored on trust."""
    with EventStore.open(tmp_path) as store:
        with pytest.raises(StoreIntegrityError, match="ceiling"):
            store.append_many(
                (_good("a"), _refused()), ingested_at=1.0, stand_in=lambda event, _e: event
            )
        assert store.count() == 0


@pytest.mark.security
def test_memory_error_is_never_handed_to_a_stand_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one exception that says something about the process, not the event."""

    def exhausted(event: NormalizedEvent) -> tuple[str, str]:
        raise MemoryError

    calls: list[Exception] = []

    def stand_in(event: NormalizedEvent, refusal: Exception) -> NormalizedEvent:
        calls.append(refusal)
        return event

    with EventStore.open(tmp_path) as store:
        monkeypatch.setattr(EventStore, "_project", staticmethod(exhausted))
        with pytest.raises(MemoryError):
            store.append_many((_good("a"),), ingested_at=1.0, stand_in=stand_in)
    assert calls == []


# --------------------------------------------------------------------------
# The collector's placeholder
# --------------------------------------------------------------------------


@pytest.mark.security
def test_a_refused_record_is_held_by_a_placeholder_and_its_source_advances(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the fit ever regresses, the second layer still keeps the source moving.

    ``normalize_many`` is replaced by the pre-fit build, so the stalling line
    reaches the store over the ceiling exactly as it did on ``2c92e3f``.
    """
    import scripts.run_collector as collector

    monkeypatch.setattr(
        collector, "normalize_many", lambda lines: [_unfitted(line) for line in lines]
    )
    root = tmp_path / "root"
    root.mkdir()
    log = tmp_path / "app.log"
    good = json.dumps(dict(_PHISH, Subject="good line")).encode()
    log.write_bytes(good + b"\n" + _STALLING + b"\n")

    report = _collect(root, log, capsys)
    assert report["events_stored"] == 2
    assert report["events_refused"] == 1
    assert report["sources"][0]["refused"] == 1
    assert report["offsets_advancing"] is True
    assert _collect(root, log, capsys)["lines_read"] == 0, "the offset moved past both"

    with EventStore.open(root) as store:
        (placeholder,) = [
            row.event for row in store.query(Query()) if row.event.message.startswith("placeholder")
        ]
    assert placeholder.notes[0] == "refused by the event store: StoreIntegrityError"
    assert placeholder.notes[1].startswith("refused event: sha256:")
    projection = canonical_json(placeholder.to_dict())
    for fragment in ("partner-invoices", _PHISH["Subject"], _PHISH["SenderFromAddress"], "ppp"):
        assert fragment not in projection, f"the placeholder carries record content: {fragment!r}"
    audit = (root / "data" / "collect" / "audit.log").read_text(encoding="utf-8")
    assert "1 event(s) refused by the store were stored as placeholders" in audit


@pytest.mark.security
def test_two_refused_records_keep_two_placeholders() -> None:
    """The digest keeps refused records apart, so the count of them survives."""
    from scripts.run_collector import placeholder_for

    refusal = StoreIntegrityError("over the ceiling")
    one = placeholder_for(_refused(), refusal)
    two = placeholder_for(_unfitted(_OVERSIZED["brief-32-urls"]), refusal)
    assert one != two
    assert placeholder_for(_refused(), refusal) == one, "a re-read stores nothing new"


@pytest.mark.security
@pytest.mark.parametrize(
    "hostile",
    [
        {"vendor": "attacker-chosen"},
        {"vendor": ["unhashable"], "source_type": ["unhashable"]},
        {"message": object()},
    ],
)
def test_a_placeholder_is_total_and_carries_nothing_the_record_chose(
    tmp_path: Path, hostile: dict[str, Any]
) -> None:
    """It must not raise, or it would refuse the batch it exists to save."""
    from scripts.run_collector import placeholder_for

    event = dataclasses.replace(_refused(), **hostile)
    placeholder = placeholder_for(event, TypeError("unserializable"))
    assert placeholder.vendor in {"defender-o365", "unrecognized"}
    assert placeholder.vendor != "attacker-chosen"
    assert placeholder.timestamp is None
    assert _stored_back(tmp_path, placeholder) == placeholder
