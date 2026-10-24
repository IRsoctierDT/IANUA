# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Evidence keeps non-ASCII text as written, and no string can stall the store.

Two defects with one root: how a character outside ASCII travels from a record
into the store. Both were measured on ``2090519``.

* ``raw_excerpt`` was rendered with ``json.dumps``' default
  ``ensure_ascii=True``. An indicator is extracted as written, so on the
  unclaimed path, where the excerpt *is* the evidence, it was not in the
  excerpt it came from: the observable ``https://café.example/x`` against the
  excerpt ``{"msg": "go https://caf\\u00e9.example/x"}``. Each escaped
  character also spent six of :data:`MAX_RAW_EXCERPT`'s characters, or twelve
  outside the BMP, so a field of 2048 ``é`` kept 681 of them.
* A lone surrogate reached the store. ``json.loads`` turns the six-character
  escape ``\\ud800`` into one, ``text()`` kept it, ``canonical_json`` keeps
  non-ASCII as written, and the store then encodes the projection as UTF-8 to
  check its size, which refuses it with a bare ``UnicodeEncodeError``. Through
  ``scripts/run_collector.py``, a three-line, all-ASCII log stored 0 of 3
  events on every pass with its offsets held and exit 1, so no later line of
  that source was ever stored.

The excerpt's escaping was the only thing keeping a surrogate out of the
excerpt, so the two are fixed together: ``text()`` replaces every surrogate
with U+FFFD, and the excerpt is then rendered with ``ensure_ascii=False``.
Surrogates in this file are built with ``chr`` or written as JSON escapes, so
its own source holds none.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from ingest import MAX_FIELD_LEN, MAX_RAW_EXCERPT, normalize, normalize_many
from ingest.schema import NormalizedEvent
from store import EventStore
from store.schema import MAX_PROJECTION_BYTES, canonical_json, event_id

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FIXTURES = _REPO_ROOT / "tests" / "fixtures" / "ingest_fixtures.json"

#: Built from its code point, so this file's source never holds one.
_SURROGATE = chr(0xD800)
_REPLACEMENT = "\ufffd"

#: The record from the measurement, and the indicator it carries.
_CAFE_URL = "https://café.example/x"
_CAFE_RECORD = {"msg": f"go {_CAFE_URL}"}


def _fixture(name: str) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(_FIXTURES.read_text(encoding="utf-8"))[name]["record"]
    return record


def _fixture_names() -> list[str]:
    return sorted(json.loads(_FIXTURES.read_text(encoding="utf-8")))


def _surrogates_in(text: str) -> list[str]:
    """Every surrogate code point in ``text``, written as ``U+XXXX``."""
    return [f"U+{ord(char):04X}" for char in text if 0xD800 <= ord(char) <= 0xDFFF]


def _hashable(event: NormalizedEvent) -> str:
    """The store's own write path up to the insert: project, then hash.

    The store encodes the projection as UTF-8 twice, to check its size and to
    hash it, and the first of those refused a surrogate. ``event_id`` performs
    the same encode. Returned so a caller can compare ids.
    """
    return event_id(canonical_json(event.to_dict()))


# --------------------------------------------------------------------------
# The excerpt keeps non-ASCII as written
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize(
    "raw",
    [
        json.dumps(_CAFE_RECORD).encode("ascii"),
        json.dumps(_CAFE_RECORD, ensure_ascii=False).encode("utf-8"),
    ],
    ids=["escaped-by-the-shipper", "utf-8-as-written"],
)
def test_an_unclaimed_indicator_is_a_substring_of_its_excerpt(raw: bytes) -> None:
    """The measured record, through the bytes path ``collect/`` uses.

    Both spellings a shipper may write decode to the same record, so they
    must render the same excerpt. Before, the indicator was extracted as
    written and retained as ``caf\\u00e9``, so the check this file is named
    for failed on every non-ASCII indicator.
    """
    event = normalize(raw)

    assert event.vendor == "unrecognized"
    assert event.observables == (_CAFE_URL,)
    assert event.raw_excerpt == '{"msg": "go https://café.example/x"}'
    for observable in event.observables:
        assert observable in event.raw_excerpt, f"{observable!r} is not in its excerpt"


@pytest.mark.security
@pytest.mark.parametrize(
    "character", ["é", "東", "\U0001f600"], ids=["two-byte", "three-byte", "astral"]
)
def test_a_non_ascii_character_spends_one_character_of_the_excerpt(character: str) -> None:
    """One modelled field at the per-field bound, every character outside ASCII.

    Measured before: 681, 681 and 340 of the 2048 characters kept, because
    ``\\u00e9`` costs six characters of the bound and an astral character's
    surrogate-pair escape costs twelve. Now every one of them is kept.
    """
    event = normalize({"msg": character * MAX_FIELD_LEN})

    assert event.vendor == "unrecognized"
    assert event.raw_excerpt.count(character) == MAX_FIELD_LEN
    assert len(event.raw_excerpt) <= MAX_RAW_EXCERPT


@pytest.mark.security
def test_the_excerpt_bound_still_counts_characters() -> None:
    """Past the budget the excerpt is cut at :data:`MAX_RAW_EXCERPT`, as before.

    The bound is in characters on both sides (``schema.from_dict`` validates
    it there), so keeping a character as itself changes how much evidence
    fits in it and nothing about where it is cut.
    """
    wide = "東" * MAX_FIELD_LEN
    event = normalize({"ProviderV2": "x", "Channel": wide, "CommandLine": wide, "Subject": wide})

    assert event.vendor == "unrecognized"
    assert len(event.raw_excerpt) == MAX_RAW_EXCERPT
    assert _hashable(event)


@pytest.mark.security
def test_a_leaf_after_a_non_ascii_leaf_is_still_scanned() -> None:
    """The excerpt and the fragments it is searched for must share one encoder.

    ``_retained_values`` keeps a leaf only when the leaf's JSON fragment is
    found in the rendered excerpt, and stops at the first one it cannot find.
    So an excerpt rendered as written, searched for an *escaped* fragment,
    loses the indicators in the first non-ASCII value and in every value
    after it, and keeps those before it (measured by planting exactly that).
    ``Channel`` sorts before ``Subject``, which is what puts the URL behind
    one here.
    """
    url = "http://modelled.example/path"
    event = normalize({"ProviderV2": "x", "Channel": "Sécurité", "Subject": f"visit {url}"})

    assert event.vendor == "unrecognized"
    assert event.raw_excerpt.index("Sécurité") < event.raw_excerpt.index(url)
    assert url in event.observables, "a leaf after a non-ASCII leaf was never scanned"


@pytest.mark.security
def test_format_characters_are_kept_as_written() -> None:
    """The owner's decision: stored evidence is exact, and is escaped where printed.

    U+202E and U+200B already reached the typed fields as written, because
    ``text()`` removes control characters and keeps format characters. The
    excerpt now agrees with them, and the indicator the URL yields is a
    substring of it. Rendering for a terminal is ``scripts/_terminal.printable``'s
    job, at the print.
    """
    url = "http://bidi.example/a\u200bb"
    event = normalize({"msg": f"invoice\u202egpj.exe {url}"})

    assert event.vendor == "unrecognized"
    assert "\u202e" in event.raw_excerpt
    assert "\u200b" in event.raw_excerpt
    assert url in event.observables
    for observable in event.observables:
        assert observable in event.raw_excerpt, f"{observable!r} is not in its excerpt"


@pytest.mark.security
def test_the_excerpt_and_the_stored_projection_write_unicode_the_same_way() -> None:
    """``canonical_json`` keeps Unicode as written, and now so does the excerpt.

    Before, the stored projection held ``caf\\\\u00e9``: the excerpt's own
    escape, with its backslash escaped again by the store. Every entry path
    must reach one event, and one id, for one record.
    """
    escaped = json.dumps(_CAFE_RECORD).encode("ascii")
    as_written = json.dumps(_CAFE_RECORD, ensure_ascii=False)
    events = [
        normalize(escaped),
        normalize(as_written.encode("utf-8")),
        normalize(as_written),
        normalize(_CAFE_RECORD),
    ]

    assert len({_hashable(event) for event in events}) == 1
    projection = canonical_json(events[0].to_dict())
    assert "café" in projection
    assert "\\u00e9" not in projection


@pytest.mark.security
def test_the_event_id_of_a_non_ascii_record_is_the_same_in_every_process() -> None:
    """Deterministic across interpreters, not only within one.

    ``sort_keys`` everywhere means no dict or set order reaches the bytes,
    so a different hash seed must give the same id. Checked in child
    processes rather than argued, on a record with several observables, so
    an order taken from a ``set`` would show: with one, every order agrees.
    """
    code = (
        "import json, sys\n"
        "from ingest import normalize\n"
        "from store.schema import canonical_json, event_id\n"
        "event = normalize(json.loads(sys.argv[1]))\n"
        "print(event_id(canonical_json(event.to_dict())))\n"
    )
    record = {
        **_CAFE_RECORD,
        "Subject": "東京 \U0001f600 from 198.51.100.7 via mail.example.com",
        "Channel": "Sécurité",
    }
    expected = _hashable(normalize(record))
    assert len(normalize(record).observables) >= 3, "the record must carry several observables"
    for seed in ("1", "2", "3", "4"):
        result = subprocess.run(  # noqa: S603 - our own interpreter, literal program, test data
            [sys.executable, "-c", code, json.dumps(record)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=_REPO_ROOT,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == expected, f"hash seed {seed} gave another id"


# --------------------------------------------------------------------------
# No surrogate reaches the store
# --------------------------------------------------------------------------


def _defender_with_subject(subject: str) -> bytes:
    """The committed Defender record with ``subject``, as a shipper writes it.

    ``json.dumps`` escapes a surrogate as ``\\udXXX``, so the line is ASCII,
    which is the measured shape: nothing about the bytes looks unusual.
    """
    return json.dumps({**_fixture("defender_email_phish"), "Subject": subject}).encode("ascii")


#: One case per route a string takes into an event: a typed field, an excerpt
#: value, a key name, and text carried verbatim from a JSON string and from a
#: caller's ``str``.
_SURROGATE_ROUTES: dict[str, str | bytes] = {
    "claimed-typed-field": _defender_with_subject(f"x {_SURROGATE} y"),
    "unclaimed-excerpt-value": json.dumps({"msg": f"x {_SURROGATE} y"}).encode("ascii"),
    "unclaimed-key-name": json.dumps({"msg": "m", f"k{_SURROGATE}": "v"}).encode("ascii"),
    "verbatim-prose": f"session opened for x {_SURROGATE} y",
    "verbatim-malformed-json": '{"msg": "x ' + _SURROGATE,
}


@pytest.mark.security
@pytest.mark.parametrize("raw", list(_SURROGATE_ROUTES.values()), ids=list(_SURROGATE_ROUTES))
def test_a_lone_surrogate_is_stored_as_a_replacement_character(
    tmp_path: Path, raw: str | bytes
) -> None:
    """Every route is stored, with U+FFFD where the surrogate stood.

    Measured on ``main`` before: four of the five raised ``UnicodeEncodeError``
    from the store's write path. They were the claimed typed field, the
    unclaimed key name (the withheld-field note names it), and both verbatim
    routes. Only the unclaimed excerpt value was stored, because the excerpt
    escaped it, and an excerpt written as itself would refuse it the same way.
    Two of the four arrive as bytes, which is the route ``collect/`` uses, so
    each was a way to stall a source. The replacement is visible in the event,
    so an operator still sees that something stood there.
    """
    event = normalize(raw)
    projection = canonical_json(event.to_dict())

    assert not _surrogates_in(projection), "a surrogate reached the projection"
    assert _REPLACEMENT in projection, "the surrogate vanished instead of being replaced"
    with EventStore.open(tmp_path) as store:
        identifier = store.append(event, ingested_at=1000.0)
        (stored,) = store.query()
    assert stored.event_id == identifier == _hashable(event)
    assert stored.event == event


@pytest.mark.security
def test_a_record_that_raised_keeps_its_key_names_as_written() -> None:
    """``normalize_many``'s fallback renders key names through the same encoder.

    A mapping whose values cannot be read raises inside ``normalize``, and the
    batch keeps it as a degraded event carrying its key names only, the one
    rendering that cannot raise. Those names are written as themselves too, and
    a surrogate in one is replaced, so the event the guard builds is one the
    store accepts rather than the next thing to stall a source.
    """

    class UnreadableValues(Mapping[str, object]):
        def __init__(self, keys: list[str]) -> None:
            self._keys = keys

        def __iter__(self) -> Iterator[str]:
            return iter(self._keys)

        def __len__(self) -> int:
            return len(self._keys)

        def __getitem__(self, key: str) -> object:
            raise RuntimeError("value refused")

    (event,) = normalize_many([UnreadableValues(["clé", "k" + _SURROGATE])])

    assert any("raised RuntimeError" in note for note in event.notes), event.notes
    assert event.raw_excerpt == f'["clé", "k{_REPLACEMENT}"]'
    assert _hashable(event)


@pytest.mark.security
def test_a_claimed_record_keeps_its_attribution_with_the_replacement() -> None:
    """U+FFFD is a character, so recognition and parsing are unaffected."""
    event = normalize(_defender_with_subject(f"x {_SURROGATE} y"))

    assert event.vendor == "defender-o365"
    assert event.email.subject == f"x {_REPLACEMENT} y"


@pytest.mark.security
def test_a_line_carrying_a_lone_surrogate_no_longer_stalls_its_source(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The measured stall, through the real collector.

    Before: ``0 event(s) stored; offsets held.`` and exit 1 on every pass,
    because the collector advances a source only once its batch is durable,
    and ``append_many`` refused the whole batch for one event. So the healthy
    line *after* the planted one was never stored, and nor was anything
    appended to that log later. Now the batch is stored, the source advances,
    and a second pass has nothing new to read.
    """
    from scripts.run_collector import main

    record = _fixture("defender_email_phish")
    lines = [
        json.dumps(record),
        json.dumps({**record, "Subject": f"x {_SURROGATE} y", "NetworkMessageId": "planted"}),
        json.dumps({**record, "NetworkMessageId": "after-the-planted-line"}),
    ]
    log = tmp_path / "logs" / "mail.log"
    log.parent.mkdir()
    log.write_text("\n".join(lines) + "\n", encoding="ascii")
    root = tmp_path / "root"
    root.mkdir()

    assert main(["--root", str(root), "--source", str(log)]) == 0
    with EventStore.open(root) as store:
        subjects = sorted(stored.event.email.subject or "" for stored in store.query())
    assert len(subjects) == 3, f"{len(subjects)} of 3 events stored"
    assert f"x {_REPLACEMENT} y" in subjects

    capsys.readouterr()
    assert main(["--root", str(root), "--source", str(log), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["lines_read"] == 0, "the source did not advance past the planted line"
    assert report["events_stored"] == 0


def _string_sites(node: Any, path: tuple[Any, ...] = ()) -> Iterator[tuple[str, tuple[Any, ...]]]:
    """Every place a record holds a string: each string value, and each key."""
    if isinstance(node, dict):
        for key, child in node.items():
            yield "key", (*path, key)
            yield from _string_sites(child, (*path, key))
    elif isinstance(node, list):
        for index, child in enumerate(node):
            yield from _string_sites(child, (*path, index))
    elif isinstance(node, str):
        yield "value", path


def _planted(record: dict[str, Any], kind: str, path: tuple[Any, ...]) -> dict[str, Any]:
    """A copy of ``record`` with a surrogate added to one string site."""
    clone = copy.deepcopy(record)
    parent: Any = clone
    for step in path[:-1]:
        parent = parent[step]
    last = path[-1]
    if kind == "value":
        parent[last] = parent[last] + _SURROGATE
    else:
        parent[last + _SURROGATE] = parent.pop(last)
    return clone


@pytest.mark.security
@pytest.mark.parametrize("claimed", [True, False], ids=["claimed", "unclaimed"])
def test_no_string_in_any_fixture_can_carry_a_surrogate_into_the_store(
    claimed: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A surrogate at every string site of every committed fixture, both entry paths.

    The claim being tested is that ``text()`` is the only way a string enters
    an event. A parser that assigned a record's value without it would let a
    surrogate through here, and the store would refuse that event. The
    unclaimed leg empties the signature registry, as
    ``test_every_observable_is_findable_in_the_retained_evidence`` does, so
    every fixture is projected through the full union of declared paths.
    """
    if not claimed:
        monkeypatch.setattr(sys.modules["ingest.normalize"], "SIGNATURES", ())

    refused: list[str] = []
    planted = 0
    for name in _fixture_names():
        record = _fixture(name)
        for kind, path in _string_sites(record):
            mutated = _planted(record, kind, path)
            for entry, raw in (
                ("bytes", json.dumps(mutated).encode("ascii")),
                ("mapping", mutated),
            ):
                planted += 1
                event = normalize(raw)
                projection = canonical_json(event.to_dict())
                where = f"{name} {kind} {'.'.join(map(str, path))} via {entry}"
                if _surrogates_in(projection):
                    refused.append(where)
                    continue
                _hashable(event)

    assert planted > 400, f"only {planted} plants: the fixtures stopped exercising this"
    assert not refused, f"{len(refused)} plant(s) reached the projection: {refused[:5]}"


# --------------------------------------------------------------------------
# What keeping non-ASCII costs the projection
# --------------------------------------------------------------------------


def _widest_unclaimed_record() -> dict[str, Any]:
    """An unclaimed record built to maximise every field the projection retains.

    Three early-sorting modelled fields of seven distinct four-byte-character
    URLs each fill the excerpt and ``message`` and yield the most observables
    the retained text allows. Forty withheld key names of sixty four-byte
    characters fill the withheld-field note. The widest case a search over
    those two dimensions found.
    """
    record: dict[str, Any] = {}
    for index, key in enumerate(("@timestamp", "AuthenticationDetails", "Channel")):
        record[key] = " ".join(
            "http://" + chr(0x1F600 + index) * 200 + chr(0x1F680 + url) * 56 for url in range(7)
        )
    for name in range(40):
        record[chr(0x1F300 + name) * 60] = "x"
    return record


@pytest.mark.security
def test_an_unclaimed_record_cannot_outgrow_the_store_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keeping four-byte characters as themselves still fits the 64 KiB ceiling.

    The unclaimed path retains four text fields, and each is bounded in
    characters: the excerpt at 4096, ``message`` at 2048, the withheld-field
    note at 2048, and the observables, which must lie inside the retained
    excerpt, at its 4096. At four bytes a character that is about 50 KiB, and
    measured on this record it is 46,668 bytes. A record no signature claims
    therefore cannot reach the size at which the store refuses a whole batch,
    which is the stall this change must not create on the path it widens.
    """
    monkeypatch.setattr(sys.modules["ingest.normalize"], "SIGNATURES", ())
    event = normalize(_widest_unclaimed_record())
    size = len(canonical_json(event.to_dict()).encode("utf-8"))

    assert event.vendor == "unrecognized"
    assert len(event.raw_excerpt) == MAX_RAW_EXCERPT, "the record no longer fills the excerpt"
    assert size > 40_000, f"the record is no longer adversarial ({size} bytes)"
    assert size <= MAX_PROJECTION_BYTES, f"{size} bytes, over the {MAX_PROJECTION_BYTES} ceiling"
