# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The event store holds evidence — hold its properties closed.

``store/`` is the first package in this platform that writes a database, and
it writes one whose rows are security evidence. Three classes of failure
matter, and each gets assertions rather than a comment:

* **Integrity** — history cannot be rewritten (the engine refuses ``UPDATE``),
  and a row edited outside this platform is detected on read rather than
  returned as a plausible event.
* **Containment** — the database cannot escape the gitignored lab-data root,
  the package reaches no network or subprocess, and it reads no clock.
* **Injection** — no caller value becomes SQL text. Asserted over the AST,
  because "we used parameters" is a property of today's code and this test is
  what keeps it a property of tomorrow's.

The store also inherits ``ingest/``'s no-message-body invariant, and that is
checked here on the *read* path: an email body smuggled into a stored row
must not survive reconstruction.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import sqlite3
import typing
from pathlib import Path
from typing import Any

import pytest
from ingest.errors import MalformedProjectionError
from ingest.schema import (
    MAX_FIELD_LEN,
    MAX_NOTES,
    MAX_OBSERVABLES,
    MAX_RAW_EXCERPT,
    NormalizedEvent,
)
from store import (
    MAX_PROJECTION_BYTES,
    MAX_QUERY_LIMIT,
    EventStore,
    Query,
    SchemaVersionError,
    StoreIntegrityError,
    StorePathError,
    canonical_json,
    event_id,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_STORE_ROOT = _REPO_ROOT / "store"

#: The store needs sqlite3, hashlib, json, re and pathlib. It must not be able
#: to reach the network, spawn anything, or import code dynamically.
_BANNED_IMPORTS = {
    "socket",
    "subprocess",
    "requests",
    "urllib",
    "http",
    "ftplib",
    "telnetlib",
    "smtplib",
    "importlib",
    "pickle",
    "shelve",
    "ctypes",
}
_BANNED_CALLS = {"eval", "exec", "compile", "__import__", "input"}

#: Two distinct records, so a refused second write is distinguishable from a
#: content-addressed no-op.
_RECORD = "Failed password for root from 10.0.0.5 port 22 ssh2"
_OTHER_RECORD = "Accepted password for alice from 10.0.0.9 port 22 ssh2"

#: A literal is "SQL-ish" if it carries a statement keyword. Used to decide
#: which strings must never be built by interpolation.
_SQL_KEYWORDS = (
    "SELECT ",
    "INSERT ",
    "UPDATE ",
    "DELETE ",
    "WHERE ",
    "ORDER BY",
    "FROM ",
    "CREATE ",
    "DROP ",
    "PRAGMA ",
)


def _store_modules() -> list[Path]:
    return sorted(_STORE_ROOT.rglob("*.py"))


def _is_sql(text: str) -> bool:
    upper = text.upper()
    return any(keyword in upper for keyword in _SQL_KEYWORDS)


# --------------------------------------------------------------------------
# Injection
# --------------------------------------------------------------------------


@pytest.mark.security
def test_no_sql_statement_is_built_by_interpolation() -> None:
    """No f-string, ``%``, or ``.format()`` may produce SQL text.

    The three real injection vectors, each checked separately so a failure
    names which one appeared. A fragment assembled from module literals is
    fine — what must never happen is a caller's value reaching the statement
    as text instead of as a bound parameter.
    """
    for path in _store_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            # f"... {value} ..." containing SQL
            if isinstance(node, ast.JoinedStr):
                literal = "".join(
                    part.value
                    for part in node.values
                    if isinstance(part, ast.Constant) and isinstance(part.value, str)
                )
                assert not _is_sql(literal), f"{path}: SQL built by f-string: {literal!r}"
            # "SELECT ..." % value
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                left = node.left
                if isinstance(left, ast.Constant) and isinstance(left.value, str):
                    assert not _is_sql(left.value), f"{path}: SQL built by %: {left.value!r}"
            # "SELECT ...".format(value)
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
                and isinstance(node.func.value, ast.Constant)
                and isinstance(node.func.value.value, str)
            ):
                assert not _is_sql(node.func.value.value), (
                    f"{path}: SQL built by .format(): {node.func.value.value!r}"
                )


@pytest.mark.security
def test_a_quote_in_a_filter_value_cannot_alter_the_query(tmp_path: Path) -> None:
    """The positive half: a classic payload matches nothing, and does not error."""
    with EventStore.open(tmp_path) as store:
        store.append(
            normalize("Failed password for root from 10.0.0.5 port 22 ssh2"), ingested_at=1.0
        )
        store.append(
            normalize("Accepted password for alice from 10.0.0.9 port 22 ssh2"), ingested_at=2.0
        )
        assert store.count() == 2
        for payload in ("' OR '1'='1", "'; DROP TABLE events; --", '" OR 1=1 --'):
            assert store.query(Query(user_name=payload)) == ()
            assert store.query(Query(hostname=payload)) == ()
            assert store.query(Query(observable=payload)) == ()
        # The table is still there, which a successful DROP would have ended.
        assert store.count() == 2


# --------------------------------------------------------------------------
# Integrity
# --------------------------------------------------------------------------


@pytest.mark.security
def test_stored_events_cannot_be_rewritten(tmp_path: Path) -> None:
    """Append-only is enforced by the engine, not by API discipline."""
    event = normalize("Failed password for root from 10.0.0.5 port 22 ssh2")
    assert event.observables, (
        "this test needs an event with an observable: a BEFORE UPDATE trigger "
        "fires per matched row, so an empty observables table would make the "
        "second assertion below pass vacuously"
    )
    with EventStore.open(tmp_path) as store:
        identifier = store.append(event, ingested_at=1.0)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._conn.execute(
                "UPDATE events SET projection = ? WHERE event_id = ?", ("{}", identifier)
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._conn.execute(
                "UPDATE observables SET value = ? WHERE event_id = ?", ("x", identifier)
            )
        # Unchanged, and still readable.
        assert len(store.query()) == 1


@pytest.mark.security
def test_a_row_edited_outside_the_platform_is_detected_on_read(tmp_path: Path) -> None:
    """Content addressing makes tampering loud instead of plausible."""
    with EventStore.open(tmp_path) as store:
        store.append(normalize("sshd: session opened for user root"), ingested_at=1.0)
        # UPDATE is refused, so forge by inserting a row whose projection does
        # not hash to its id — the shape a direct sqlite3 edit would leave.
        with store._conn:
            store._conn.execute(
                "INSERT INTO events (event_id, ingested_at, occurred_at, source_type, "
                "vendor, parse_status, user_name, hostname, src_ip, dst_ip, projection) "
                "VALUES (?, ?, NULL, 'unknown', 'forged', 'text', NULL, NULL, NULL, NULL, ?)",
                ("0" * 64, 2.0, "{}"),
            )
        with pytest.raises(StoreIntegrityError, match="modified outside this platform"):
            store.query()


@pytest.mark.security
def test_a_schema_written_by_another_version_is_refused(tmp_path: Path) -> None:
    """No implicit migration: old rows must not be read into a new shape."""
    with EventStore.open(tmp_path) as store, store._conn:
        store._conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
    with pytest.raises(SchemaVersionError, match="version 99"):
        EventStore.open(tmp_path).close()


# --------------------------------------------------------------------------
# Containment
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize(
    "filename",
    [
        "../escape.sqlite3",
        "../../escape.sqlite3",
        "/etc/passwd",
        "sub/dir.sqlite3",
        "..",
        ".",
        ".hidden",
        "",
        "a\x00b",
    ],
)
def test_the_database_cannot_escape_the_events_directory(tmp_path: Path, filename: str) -> None:
    with pytest.raises(StorePathError):
        EventStore.open(tmp_path, filename=filename).close()


@pytest.mark.security
def test_the_database_lands_under_the_gitignored_lab_root(tmp_path: Path) -> None:
    with EventStore.open(tmp_path) as store:
        assert store.path.parent == (tmp_path / "data" / "events").resolve()


@pytest.mark.security
def test_store_imports_nothing_that_could_reach_out_or_execute() -> None:
    for path in _store_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in _BANNED_IMPORTS, f"{path}: {alias.name}"
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in _BANNED_IMPORTS, f"{path}: {node.module}"


@pytest.mark.security
def test_store_calls_no_executor() -> None:
    for path in _store_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in _BANNED_CALLS, f"{path}: calls {node.func.id}()"


@pytest.mark.security
def test_store_reads_no_clock() -> None:
    """``ingested_at`` is injected, so the storage timeline is reproducible.

    Asserted over the AST rather than the raw source, because the package
    docstring deliberately shows a *caller* passing ``time.time()`` in. A
    text search cannot tell the documented caller apart from the module doing
    it itself, and the property under test is only the latter.
    """
    forbidden = {"now", "utcnow", "today", "time", "monotonic", "time_ns"}
    for path in _store_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in forbidden, (
                    f"{path}: reads the clock via .{node.func.attr}()"
                )


@pytest.mark.security
def test_store_adds_no_runtime_dependency() -> None:
    """``dependencies = []`` is a load-bearing repository property.

    Read from ``pyproject.toml``, not installed metadata, so this runs
    everywhere rather than skipping wherever the package is not pip-installed.
    Installed metadata is checked too when available, since that would also
    catch a dependency the build backend injected rather than one declared
    here.
    """
    import tomllib

    config = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = config["project"]["dependencies"]
    assert declared == [], f"store must not introduce runtime dependencies: {declared}"

    import importlib.metadata as metadata

    try:
        installed = metadata.requires("ianua") or []
    except metadata.PackageNotFoundError:
        return  # not installed here; the committed declaration is the contract
    runtime = [req for req in installed if "extra ==" not in req]
    assert runtime == [], f"installed metadata declares runtime dependencies: {runtime}"


# --------------------------------------------------------------------------
# Bounds
# --------------------------------------------------------------------------


@pytest.mark.security
def test_an_oversized_projection_is_refused(tmp_path: Path) -> None:
    """A hand-built event that skipped ingest/'s bounds does not get stored."""
    huge = NormalizedEvent(
        source_type="unknown",
        vendor="hand-built",
        vendor_event_id=None,
        timestamp=None,
        message="m",
        activity=None,
        parse_status="text",
        raw_excerpt="x" * (MAX_PROJECTION_BYTES + 1),
    )
    with EventStore.open(tmp_path) as store:
        with pytest.raises(StoreIntegrityError, match="ceiling"):
            store.append(huge, ingested_at=1.0)
        assert store.count() == 0, "a refused event must leave nothing behind"


# --------------------------------------------------------------------------
# What is writable must be readable back
#
# `query` rebuilds every row it returns through `NormalizedEvent.from_dict`
# and raises on the first bad one, so a single unreadable row denied the whole
# window and the cursor could never advance past it. `UPDATE` is
# trigger-refused and `prune` takes only a time cutoff, so the sanctioned
# recovery was destroying the store. These assert that the store refuses on
# write exactly what it would refuse on read.
# --------------------------------------------------------------------------


def _hand_built(**overrides: Any) -> NormalizedEvent:
    """An event that skipped ingest/'s bounds, as a direct caller would build."""
    base: dict[str, Any] = {
        "source_type": "unknown",
        "vendor": "hand-built",
        "vendor_event_id": None,
        "timestamp": None,
        "message": "m",
        "activity": None,
        "parse_status": "text",
    }
    return NormalizedEvent(**{**base, **overrides})


#: One case per bound `from_dict` enforces that the size ceiling does not
#: catch. Each is far under MAX_PROJECTION_BYTES, which is the whole point.
_UNREADABLE: dict[str, dict[str, Any]] = {
    "message": {"message": "x" * (MAX_FIELD_LEN + 1)},
    "raw_excerpt": {"raw_excerpt": "y" * (MAX_RAW_EXCERPT + 1)},
    "one_long_note": {"notes": ("z" * (MAX_FIELD_LEN + 1),)},
    "too_many_notes": {"notes": tuple(f"n{index}" for index in range(MAX_NOTES + 1))},
    "too_many_observables": {
        "observables": tuple(f"10.0.0.{index}" for index in range(MAX_OBSERVABLES + 1))
    },
}


@pytest.mark.security
@pytest.mark.parametrize("case", sorted(_UNREADABLE), ids=lambda value: value)
def test_append_refuses_exactly_what_query_would_refuse(tmp_path: Path, case: str) -> None:
    """The symmetry, asserted as one property rather than two bound lists.

    Both sides must reject the same event, and with the same error — which is
    what makes "append refuses iff query refuses" checkable instead of a
    comment. The projection is well inside the byte ceiling in every case, so
    the pre-existing size check cannot be what catches it.
    """
    event = _hand_built(**_UNREADABLE[case])
    projection = canonical_json(event.to_dict())
    assert len(projection.encode("utf-8")) < MAX_PROJECTION_BYTES, "size check would mask this"

    # The read path refuses it...
    with pytest.raises(MalformedProjectionError):
        NormalizedEvent.from_dict(json.loads(projection))

    # ...so the write path must too, and must leave nothing behind.
    with EventStore.open(tmp_path) as store:
        store.append(normalize("sshd: session opened for user root"), ingested_at=1.0)
        with pytest.raises(MalformedProjectionError):
            store.append(event, ingested_at=2.0)
        assert store.count() == 1
        assert len(store.query()) == 1, "the store must still read after a refusal"


@pytest.mark.security
def test_one_unreadable_row_can_no_longer_wedge_every_later_query(tmp_path: Path) -> None:
    """The consequence, asserted through the store rather than argued.

    Before this, the refused event was *stored*: `append` returned an id and
    every subsequent `query` raised for the entire result set, so detection
    stopped permanently while the collector kept exiting 0.
    """
    with EventStore.open(tmp_path) as store:
        store.append(
            normalize("Failed password for a from 203.0.113.1 port 22 ssh2"), ingested_at=1.0
        )
        with pytest.raises(MalformedProjectionError):
            store.append(_hand_built(message="x" * (MAX_FIELD_LEN + 1)), ingested_at=2.0)
        # The store keeps working: reads succeed and later writes still land,
        # which is what the cursor needs in order to advance.
        store.append(
            normalize("Failed password for b from 203.0.113.2 port 22 ssh2"), ingested_at=3.0
        )
        assert store.count() == 2
        assert len(store.query()) == 2
    # And again after a reopen, since the row is simply not there.
    with EventStore.open(tmp_path) as store:
        assert len(store.query()) == 2


@pytest.mark.security
def test_a_batch_holding_one_unreadable_event_is_refused_whole(tmp_path: Path) -> None:
    """All-or-nothing: the projection pass completes before the transaction opens."""
    good = normalize("Accepted password for v from 10.0.0.1 port 22 ssh2")
    with EventStore.open(tmp_path) as store:
        with pytest.raises(MalformedProjectionError):
            store.append_many(
                (good, _hand_built(message="x" * (MAX_FIELD_LEN + 1))), ingested_at=1.0
            )
        assert store.count() == 0, "a refused batch must not store its good events"
        assert store.append_many((good,), ingested_at=1.0) == 1


#: Fields no value can overfill: two closed vocabularies and an epoch float.
#: Named so the reflection below cannot quietly cover nothing and pass.
_UNOVERFILLABLE = frozenset({"source_type", "parse_status", "timestamp"})


def _one_overfilled_field(name: str) -> NormalizedEvent:
    """An event valid everywhere except ``name``, which is one past its bound.

    One field at a time, deliberately. An event overfilled in *every* field
    exceeds MAX_PROJECTION_BYTES and is caught by the size ceiling, so it
    never reaches the read-back — it is the few-fields case that falls in the
    gap between the two checks, and that is the case this covers.
    """
    if name in _UNOVERFILLABLE:
        raise AssertionError(f"{name} has no overfillable value")
    hints = typing.get_type_hints(NormalizedEvent)
    annotation = hints[name]
    long_text = "A" * (MAX_FIELD_LEN + 1)
    if name == "raw_excerpt":
        return _hand_built(raw_excerpt="A" * (MAX_RAW_EXCERPT + 1))
    if dataclasses.is_dataclass(annotation) and isinstance(annotation, type):
        group = typing.cast("type[Any]", annotation)
        group_hints = typing.get_type_hints(group)
        scalar = next(f.name for f in dataclasses.fields(group) if group_hints[f.name] is not tuple)
        return _hand_built(**{name: group(**{scalar: long_text})})
    if typing.get_origin(annotation) is tuple:
        return _hand_built(**{name: (long_text,)})
    return _hand_built(**{name: long_text})


#: Parametrized over the overfillable fields only, so the test body carries no
#: skip branch. The coverage check below is what stops this list from quietly
#: shrinking to nothing.
_OVERFILLABLE = sorted(
    f.name for f in dataclasses.fields(NormalizedEvent) if f.name not in _UNOVERFILLABLE
)


@pytest.mark.security
@pytest.mark.parametrize("name", _OVERFILLABLE)
def test_every_field_past_its_bound_is_refused_on_write(tmp_path: Path, name: str) -> None:
    """By reflection over the dataclass, so a new field is covered unasked.

    For each field: one past its bound is refused with the error the *read*
    path raises, and the same event through ``bounded()`` is accepted. That
    ties the three pieces together — ``bounded()`` is what makes an event
    storable, and the store refuses anything it did not fix.
    """
    event = _one_overfilled_field(name)
    projection = canonical_json(event.to_dict())
    assert len(projection.encode("utf-8")) < MAX_PROJECTION_BYTES, "size check would mask this"
    with EventStore.open(tmp_path) as store:
        with pytest.raises(MalformedProjectionError):
            store.append(event, ingested_at=1.0)
        assert store.count() == 0
        store.append(event.bounded(), ingested_at=1.0)
        assert store.count() == 1
        assert len(store.query()) == 1


@pytest.mark.security
def test_the_reflection_above_covers_every_field_it_can() -> None:
    """A parametrized test covering nothing would pass in silence."""
    names = {f.name for f in dataclasses.fields(NormalizedEvent)}
    assert names > _UNOVERFILLABLE, "a field named in _UNOVERFILLABLE no longer exists"
    assert set(_OVERFILLABLE) == names - _UNOVERFILLABLE
    assert len(_OVERFILLABLE) >= 12, f"only {len(_OVERFILLABLE)} fields exercised"
    for name in sorted(_UNOVERFILLABLE):
        with pytest.raises(AssertionError):
            _one_overfilled_field(name)


@pytest.mark.security
def test_a_query_limit_cannot_exceed_the_ceiling(tmp_path: Path) -> None:
    with EventStore.open(tmp_path) as store:
        store.append(normalize("sshd: session opened for user root"), ingested_at=1.0)
        # Asking for more than the ceiling is clamped, not honored.
        assert len(store.query(Query(limit=MAX_QUERY_LIMIT * 100))) == 1
        # A non-positive limit yields nothing rather than everything.
        for limit in (0, -1, -10_000):
            assert store.query(Query(limit=limit)) == ()


# --------------------------------------------------------------------------
# Inherited invariant: no message body, including on the read path
# --------------------------------------------------------------------------


@pytest.mark.security
def test_a_smuggled_email_body_cannot_survive_reconstruction(tmp_path: Path) -> None:
    """``from_dict`` rejects undeclared keys, so the no-body rule holds on read.

    ``ingest/`` proves no parser *reads* a body. This is the other direction:
    if a row somehow carries one, rebuilding the event refuses rather than
    quietly dropping it — a silent drop would let the field round-trip through
    storage for anything reading the raw projection.
    """
    event = normalize("sshd: session opened for user root")
    payload = event.to_dict()
    payload["email"]["body"] = "secret contents"
    forged = canonical_json(payload)
    with EventStore.open(tmp_path) as store:
        with store._conn:
            store._conn.execute(
                "INSERT INTO events (event_id, ingested_at, occurred_at, source_type, "
                "vendor, parse_status, user_name, hostname, src_ip, dst_ip, projection) "
                "VALUES (?, ?, NULL, 'unknown', 'forged', 'text', NULL, NULL, NULL, NULL, ?)",
                (event_id(forged), 1.0, forged),
            )
        with pytest.raises(Exception, match="undeclared key"):
            store.query()


@pytest.mark.security
def test_a_bound_is_reasserted_on_read_not_trusted(tmp_path: Path) -> None:
    """The writer bounded the field, but the bytes have been on disk since."""
    event = normalize("sshd: session opened for user root")
    payload = event.to_dict()
    payload["raw_excerpt"] = "x" * (MAX_RAW_EXCERPT + 1)
    forged = canonical_json(payload)
    with EventStore.open(tmp_path) as store:
        with store._conn:
            store._conn.execute(
                "INSERT INTO events (event_id, ingested_at, occurred_at, source_type, "
                "vendor, parse_status, user_name, hostname, src_ip, dst_ip, projection) "
                "VALUES (?, ?, NULL, 'unknown', 'forged', 'text', NULL, NULL, NULL, NULL, ?)",
                (event_id(forged), 1.0, forged),
            )
        with pytest.raises(Exception, match="exceeds"):
            store.query()


@pytest.mark.security
def test_a_symlinked_events_directory_cannot_relocate_the_database(tmp_path: Path) -> None:
    """The one escape a filename cannot express, so the path check must catch it.

    The filename regex forbids separators and traversal, which makes the
    containment check look redundant. It is not: if ``data/events`` is itself a
    symlink pointing elsewhere, every valid filename resolves outside the root.
    Relocating an evidence database by planting a symlink is precisely the move
    the check exists for.
    """
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    events = tmp_path / "data" / "events"
    events.parent.mkdir(parents=True)
    events.symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(StorePathError, match="is a symlink"):
        EventStore.open(tmp_path).close()


@pytest.mark.security
def test_a_store_with_tables_but_no_version_row_is_refused(tmp_path: Path) -> None:
    """Re-stamping the current version would assert what cannot be known.

    Creation writes the tables and the version row in one transaction, so this
    state only arises if the row was removed. Treating it as a fresh database
    would re-stamp the running version onto rows of unknown provenance — a
    fail-open, and the reason this refuses instead.
    """
    with EventStore.open(tmp_path) as store, store._conn:
        store._conn.execute("DELETE FROM meta WHERE key = 'schema_version'")
    with pytest.raises(SchemaVersionError, match="no recorded schema version"):
        EventStore.open(tmp_path).close()


@pytest.mark.security
def test_a_projection_that_is_not_json_is_refused(tmp_path: Path) -> None:
    """Hash-consistent but undecodable: a row only a direct edit could produce."""
    forged = "this is not json"
    with EventStore.open(tmp_path) as store:
        with store._conn:
            store._conn.execute(
                "INSERT INTO events (event_id, ingested_at, occurred_at, source_type, "
                "vendor, parse_status, user_name, hostname, src_ip, dst_ip, projection) "
                "VALUES (?, ?, NULL, 'unknown', 'forged', 'text', NULL, NULL, NULL, NULL, ?)",
                (event_id(forged), 1.0, forged),
            )
        with pytest.raises(StoreIntegrityError, match="not JSON"):
            store.query()


@pytest.mark.security
def test_a_symlinked_database_file_cannot_relocate_the_store(tmp_path: Path) -> None:
    """The file-level twin of the directory case, checked for the same reason."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    decoy = elsewhere / "real.sqlite3"
    decoy.touch()
    events = tmp_path / "data" / "events"
    events.mkdir(parents=True)
    (events / "events.sqlite3").symlink_to(decoy)
    with pytest.raises(StorePathError, match="is a symlink"):
        EventStore.open(tmp_path).close()


# --------------------------------------------------------------------------
# Ingestion order is a control, not a contract on callers
# --------------------------------------------------------------------------


@pytest.mark.security
def test_a_write_behind_the_high_water_mark_is_refused(tmp_path: Path) -> None:
    """Stage 4 documented this as a collector's responsibility; that was not enough.

    The pipeline pages by a ``(ingested_at, event_id)`` keyset, so an event
    stamped earlier than one already stored sits behind a cursor that has
    already passed it — never read, by any cycle, ever. Silent data loss in the
    layer whose purpose is not having blind spots, which is why it is refused at
    write time rather than left to whoever writes next.
    """
    from store import IngestionOrderError

    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD),), ingested_at=200.0)
        before = store.count()
        with pytest.raises(IngestionOrderError, match="behind the high-water mark"):
            store.append_many((normalize(_OTHER_RECORD),), ingested_at=150.0)
        assert store.count() == before, "a refused batch still wrote rows"


@pytest.mark.security
def test_the_high_water_mark_survives_retention(tmp_path: Path) -> None:
    """Which is the whole reason it is stored rather than derived from MAX().

    A derived watermark resets the moment a window ages out, and a collector
    could then stamp an event behind a cursor that had already passed it. The
    mark lives in the existing ``meta`` table — a new *row*, so the DDL is
    unchanged and no ``SCHEMA_VERSION`` bump is provoked.
    """
    from store import IngestionOrderError

    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD),), ingested_at=200.0)
        assert store.prune(before=1_000.0) == 1
        assert store.count() == 0
        assert store.high_water_mark() == 200.0
        with pytest.raises(IngestionOrderError):
            store.append_many((normalize(_OTHER_RECORD),), ingested_at=100.0)


@pytest.mark.security
def test_an_existing_store_written_before_this_control_is_not_defenceless(
    tmp_path: Path,
) -> None:
    """The population that matters most: a database already in service.

    ``SCHEMA_VERSION`` is deliberately unchanged, so every store written by
    stages 1-4 opens with rows and no ``meta`` entry. Returning ``None`` there
    left the control inert exactly where there was already history to get
    behind — the first write after the upgrade could land under its own rows
    and sit behind a cursor that had passed it. Found by review and reproduced
    before the fix.

    Simulated by deleting the meta row from a store that has rows, which is
    byte-for-byte the state an upgraded database is in.
    """
    import sqlite3

    from store import IngestionOrderError
    from store.schema import HIGH_WATER_KEY

    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD),), ingested_at=1_000.0)
        database = store.path

    connection = sqlite3.connect(database)
    with connection:
        connection.execute("DELETE FROM meta WHERE key = ?", (HIGH_WATER_KEY,))
    connection.close()

    with EventStore.open(tmp_path) as store:
        assert store.high_water_mark() == 1_000.0, "the mark was not derived from the rows"
        assert store.next_stamp(500.0) > 1_000.0
        with pytest.raises(IngestionOrderError):
            store.append_many((normalize(_OTHER_RECORD),), ingested_at=500.0)


@pytest.mark.security
def test_the_stored_mark_wins_over_the_derived_one(tmp_path: Path) -> None:
    """The fallback is for a missing row, never a preference.

    Checking the rows first would let the mark move *backwards* whenever the
    newest rows go away while the stored row remains — and a mark that moves
    backwards re-opens exactly the window it exists to close, because the
    pipeline's cursor has already passed the value it used to hold.

    Reached here by deleting the newest row directly, because
    :meth:`EventStore.prune` is keyed on ``ingested_at`` and so only ever
    removes a *prefix*: under pruning alone ``MAX(ingested_at)`` either equals
    the mark or the table is empty, and both orderings agree. A test built on
    ``prune`` therefore cannot fail, which is how the first version of this one
    was written. The deletion below is not hypothetical — the store is a plain
    SQLite file, and an operator clearing a bad batch or a restore from an
    older snapshot produces precisely this state.
    """
    import sqlite3

    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD),), ingested_at=2_000.0)
        store.append_many((normalize(_OTHER_RECORD),), ingested_at=3_000.0)
        database = store.path

    connection = sqlite3.connect(database)
    with connection:
        connection.execute("DELETE FROM events WHERE ingested_at >= ?", (3_000.0,))
        rows = connection.execute("SELECT MAX(ingested_at) AS mark FROM events").fetchone()
    connection.close()
    assert rows[0] == 2_000.0, "the fixture no longer leaves the rows behind the stored mark"

    with EventStore.open(tmp_path) as store:
        assert store.high_water_mark() == 3_000.0, (
            "the mark regressed to the rows' maximum; an event re-stamped at 2000 would "
            "sit behind a cursor that has already passed 3000"
        )


@pytest.mark.security
def test_an_equal_timestamp_is_accepted(tmp_path: Path) -> None:
    """Batches share one ``ingested_at`` by design, so equality must pass.

    Refusing it would break ``append_many``'s own batching, and the composite
    cursor exists precisely because ties are the normal case.
    """
    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD),), ingested_at=200.0)
        store.append_many((normalize(_OTHER_RECORD),), ingested_at=200.0)
        assert store.count() == 2


@pytest.mark.security
def test_an_empty_batch_is_not_order_checked(tmp_path: Path) -> None:
    """It writes nothing, so there is nothing to place out of order."""
    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD),), ingested_at=200.0)
        assert store.append_many((), ingested_at=1.0) == 0


@pytest.mark.security
def test_the_mark_does_not_break_the_stores_idempotence(tmp_path: Path) -> None:
    """Content idempotence and ingestion order are different promises.

    Re-appending identical content at the *current* time is a no-op that stores
    nothing new — the honest form of a replay, since it is being ingested now
    rather than then.
    """
    with EventStore.open(tmp_path) as store:
        assert store.append_many((normalize(_RECORD),), ingested_at=200.0) == 1
        assert store.append_many((normalize(_RECORD),), ingested_at=300.0) == 0
        assert store.count() == 1


@pytest.mark.security
def test_the_schema_version_is_unchanged_by_the_watermark(tmp_path: Path) -> None:
    """A new ``meta`` row must not look like a new schema to an older build.

    ``SchemaVersionError`` refuses a differing version, so storing the mark as a
    column would have forced a migration on every existing store.
    """
    from store.schema import SCHEMA_VERSION

    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD),), ingested_at=200.0)
    # Re-opening is what would raise if the version had moved.
    with EventStore.open(tmp_path) as reopened:
        assert reopened.high_water_mark() == 200.0
    assert SCHEMA_VERSION == 1


@pytest.mark.security
def test_append_is_order_checked_too_not_only_append_many(tmp_path: Path) -> None:
    """The monotonicity tests covered only the batch path.

    Both of ``append``'s high-water-mark calls could be deleted with the suite
    green — found by review. ``append`` is public API, so a caller using it
    must hit the same control.
    """
    from store import IngestionOrderError

    with EventStore.open(tmp_path) as store:
        store.append(normalize(_RECORD), ingested_at=200.0)
        assert store.high_water_mark() == 200.0, "append did not advance the mark"
        before = store.count()
        with pytest.raises(IngestionOrderError):
            store.append(normalize(_OTHER_RECORD), ingested_at=100.0)
        assert store.count() == before


@pytest.mark.security
@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_a_non_finite_ingestion_time_is_refused(tmp_path: Path, bad: float) -> None:
    """NaN would disable the control rather than violate it.

    It compares false against every bound, so it slips past the ordering check
    and then poisons the mark for every later write; an infinity raises the
    mark beyond anything a clock can reach, wedging the store permanently.
    Found by review.
    """
    from store import IngestionOrderError

    with EventStore.open(tmp_path) as store:
        with pytest.raises(IngestionOrderError, match="finite"):
            store.append_many((normalize(_RECORD),), ingested_at=bad)
        assert store.count() == 0
        assert store.high_water_mark() is None, "a refused write moved the mark"


@pytest.mark.security
def test_next_stamp_is_strictly_after_the_mark(tmp_path: Path) -> None:
    """Equality is permitted for batching, and that is what the hazard needs.

    The pipeline's keyset is strictly after ``(ingested_at, event_id)``, so an
    event written at exactly the mark with a lower event_id sits behind a
    cursor that has already passed it. A caller clamping with
    ``max(now, mark)`` walks into that on any backwards clock step — four
    events stored, three ever read. The store hands out the safe stamp because
    the mark and the cursor contract are both its own.
    """
    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD),), ingested_at=1_000.0)
        mark = store.high_water_mark()
        assert mark is not None
        assert store.next_stamp(mark - 60.0) > mark, "a behind clock stamped at or below"
        assert store.next_stamp(mark) > mark, "an equal clock stamped at the mark"
        assert store.next_stamp(mark + 60.0) == mark + 60.0, "an ahead clock was altered"
    with pytest.raises(ValueError, match="finite"), EventStore.open(tmp_path) as store:
        store.next_stamp(float("nan"))


@pytest.mark.security
def test_events_written_at_the_safe_stamp_are_all_reachable(tmp_path: Path) -> None:
    """End to end, because the defect lived in the interaction and not in a layer.

    Reproduced before the fix: four events accepted by the store, three ever
    read by the pipeline.
    """
    from pipeline import run_cycle

    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD), normalize(_OTHER_RECORD)), ingested_at=1_000.0)
        first = run_cycle(store, lookback=0)
        stamp = store.next_stamp(first.cursor.ingested_at - 60.0)  # type: ignore[union-attr]
        store.append_many(
            (normalize("sshd: third record"), normalize("sshd: fourth record")),
            ingested_at=stamp,
        )
        second = run_cycle(store, cursor=first.cursor, lookback=0)
        assert first.events_read + second.events_read == store.count(), (
            "the store accepted events the cursor can never reach"
        )
