# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Durable, append-only event store over the canonical ``NormalizedEvent``.

``ingest/`` translates ten formats into one shape but holds nothing: it is a
pure function library whose invariant is no clock, no filesystem, no network,
no subprocess. That is the right shape for a parser and the wrong shape for a
SOC, which needs to ask what happened *before* the alert. This module is the
other half — the one allowed to touch a disk — and it is a separate package
for exactly that reason, the same split the platform already made between
``ingest/`` (normalize) and ``correlation/`` (resolve).

What it provides, and why each property is load-bearing:

* **Append-only, enforced in the engine.** SQLite triggers refuse ``UPDATE``
  (``store/schema.py``). Security evidence that can be edited in place is not
  evidence. Deletion exists only as counted retention pruning.
* **Idempotent by content address.** Appending the same event twice stores it
  once. Collection retries and replays rotated files; a store that counted
  those separately would inflate every rate and correlation drawn from it.
* **Tamper-evident on read.** Every row's projection is re-hashed against its
  ``event_id``, so a database edited outside this platform raises instead of
  returning a plausible event.
* **No ambient clock.** ``ingested_at`` is injected by the caller, following
  the ``as_of`` discipline in ``intel/``. The store never asks the host what
  time it is, so its behavior is reproducible in a test and in CI.
* **Bounded reads.** Every query has a ceiling, applied even when the caller
  asks for more — an unbounded read of an event store is how a dashboard
  query becomes an out-of-memory restart mid-incident.

Security considerations (AGENTS.md §3, §5):

* **Lab-scoped data path.** The database lives under the gitignored
  ``data/events/`` root. A filename that escapes it is refused, not
  normalized (:class:`store.errors.StorePathError`).
* **Parameterized SQL only.** Every value reaches SQLite as a bound
  parameter; no statement is assembled from caller input. Asserted over this
  module's AST in ``tests/security/test_store_hardening.py``.
* **No network, no subprocess, no dynamic execution.** Also asserted over the
  AST, the same way ``ingest/`` and ``intel/`` are.
* **Single-threaded connections.** Each thread opens its own store. The
  default ``sqlite3`` same-thread check is left on deliberately rather than
  disabled for convenience, which would trade a loud error for a data race.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from ingest.schema import NormalizedEvent

from store.errors import (
    SchemaVersionError,
    StoreIntegrityError,
    StorePathError,
)
from store.schema import (
    DDL,
    MAX_PROJECTION_BYTES,
    MAX_QUERY_LIMIT,
    SCHEMA_VERSION,
    VERSION_KEY,
    canonical_json,
    event_id,
)

#: Fixed location under the repository's gitignored lab-data root. Not a
#: caller knob: an event store is lab data by definition (AGENTS.md §5), and
#: letting a caller choose the directory is how evidence ends up committed.
EVENTS_SUBDIR = Path("data") / "events"

DEFAULT_FILENAME = "events.sqlite3"

#: A filename, not a path. No separators, no traversal, no leading dot.
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


@dataclass(frozen=True, slots=True)
class StoredEvent:
    """One event as the store holds it: the event plus its storage facts."""

    #: Content address of the canonical projection.
    event_id: str
    #: Epoch seconds at which this platform stored it (injected, not read).
    ingested_at: float
    event: NormalizedEvent


@dataclass(frozen=True, slots=True)
class Query:
    """A bounded query over stored events.

    Every field is an AND-ed filter; all unset means "everything, up to
    ``limit``". The filter set is deliberately the correlator's pivots rather
    than a general query language — a store that accepts arbitrary predicates
    from a caller is one injection bug away from arbitrary SQL, and nothing
    above this layer needs that power.
    """

    #: ``occurred_at >= since``. Events with no source timestamp are excluded
    #: by any time filter, because their position in time is unknown — an
    #: unknown time silently treated as "in range" would put an undated event
    #: inside every window a caller asks about.
    since: float | None = None
    #: ``occurred_at < until`` (half-open, so adjacent windows cannot
    #: double-count an event that lands exactly on a boundary).
    until: float | None = None
    source_type: str | None = None
    vendor: str | None = None
    user_name: str | None = None
    hostname: str | None = None
    #: Matches either endpoint — an address is interesting whichever side of
    #: the connection it sat on.
    ip: str | None = None
    #: Exact match against an extracted observable (hash, domain, URL).
    observable: str | None = None
    #: Newest first when true, which is what an analyst opening a view wants.
    newest_first: bool = True
    limit: int = 1_000


#: "Everything, up to the default limit." A module-level singleton rather
#: than a call in a default argument: Query is frozen, so one shared instance
#: cannot be mutated by a caller.
ALL = Query()


class EventStore:
    """An open, append-only event database.

    Use as a context manager so the connection closes on the way out::

        with EventStore.open(Path(".")) as store:
            store.append(event, ingested_at=time.time())
    """

    __slots__ = ("_conn", "_path")

    def __init__(self, conn: sqlite3.Connection, path: Path) -> None:
        """Not the entry point — use :meth:`open`, which validates the path."""
        self._conn = conn
        self._path = path

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    def open(cls, root: Path, *, filename: str = DEFAULT_FILENAME) -> Self:
        """Open (creating if absent) the store under ``root/data/events/``.

        Raises :class:`StorePathError` for a filename that is not a plain
        filename or that resolves outside the events directory, and
        :class:`SchemaVersionError` if the database was written by a different
        schema version.
        """
        path = cls._resolve(root, filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        try:
            # WAL lets a dashboard read while collection writes. FULL
            # synchronous trades throughput for durability, which is the right
            # trade for evidence: an event acknowledged as stored must survive
            # the crash that often follows the activity that produced it.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            # Required for the observables ON DELETE CASCADE to actually fire;
            # SQLite leaves foreign keys off per-connection by default, so
            # pruning would otherwise orphan every observable row.
            conn.execute("PRAGMA foreign_keys=ON")
            cls._apply_schema(conn)
        except Exception:
            conn.close()
            raise
        return cls(conn, path)

    @staticmethod
    def _resolve(root: Path, filename: str) -> Path:
        """Validate the filename and confine the database to the events dir."""
        if filename in {".", ".."} or not _SAFE_FILENAME.fullmatch(filename):
            raise StorePathError(
                f"store filename must match {_SAFE_FILENAME.pattern!r}, got {filename!r}"
            )
        # Resolve the ROOT, then append the subdirectory without resolving it:
        # resolving the events directory first would follow a symlink planted
        # there and then happily confirm the database sits inside its own
        # target. The containment check has to be made against where the
        # directory is *supposed* to be.
        events_dir = root.resolve() / EVENTS_SUBDIR
        candidate = events_dir / filename
        # A symlinked events directory, or a symlinked database file, relocates
        # the evidence outside the lab root while every filename still looks
        # valid. Refused rather than followed: moving an event store to another
        # volume is a deployment decision (see docs/PRODUCTION_SOC_PLAN.md
        # stage 9), not something a planted link should accomplish silently.
        for path in (events_dir, candidate):
            if path.exists() and path.resolve() != path:
                raise StorePathError(
                    f"{path} resolves to {path.resolve()}; refusing to relocate the "
                    "event store outside the lab-data root"
                )
        if not candidate.is_relative_to(events_dir):  # pragma: no cover
            # Unreachable while _SAFE_FILENAME holds: a name with no separator
            # cannot escape its parent lexically, and the symlink checks above
            # cover the resolve-based escapes. Kept as a structural backstop so
            # that loosening that regex does not silently open a traversal —
            # marked no-cover rather than given a test that cannot be written
            # honestly.
            raise StorePathError(f"store path {candidate} escapes {events_dir}")
        return candidate

    @staticmethod
    def _apply_schema(conn: sqlite3.Connection) -> None:
        """Create the schema, or verify the existing one matches exactly."""
        if _has_meta(conn):
            row = conn.execute("SELECT value FROM meta WHERE key = ?", (VERSION_KEY,)).fetchone()
            if row is None:
                # Tables but no version row. The creation transaction below
                # writes both together, so this state cannot arise from normal
                # use — the row was removed. Re-stamping the current version
                # would be fail-open: it would assert that existing rows were
                # written by this schema, which is exactly what cannot be known
                # any more.
                raise SchemaVersionError(
                    "event store has tables but no recorded schema version; it was "
                    "created atomically with one, so the version row was removed — "
                    "refusing to assume the existing rows match version "
                    f"{SCHEMA_VERSION}"
                )
            found = str(row["value"])
            if found != str(SCHEMA_VERSION):
                raise SchemaVersionError(
                    f"event store was written by schema version {found}, this "
                    f"build speaks version {SCHEMA_VERSION}; migration is "
                    "explicit (no implicit upgrade — see "
                    "store.errors.SchemaVersionError)"
                )
            return
        # Fresh database: tables and version land in one transaction, so a
        # store can never exist with tables but no recorded version.
        with conn:
            conn.executescript(DDL)
            conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?)",
                (VERSION_KEY, str(SCHEMA_VERSION)),
            )

    def close(self) -> None:
        """Close the underlying connection. Idempotent."""
        self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def path(self) -> Path:
        """Where this store lives on disk."""
        return self._path

    # -- writes ------------------------------------------------------------

    def append(self, event: NormalizedEvent, *, ingested_at: float) -> str:
        """Store one event and return its content address.

        Idempotent: re-appending an identical event is a no-op that returns
        the same id. ``ingested_at`` is injected rather than read from a clock
        here, so callers control (and tests pin) the storage timeline.
        """
        projection, identifier = self._project(event)
        with self._conn:
            self._insert(event, projection, identifier, float(ingested_at))
        return identifier

    def append_many(self, events: tuple[NormalizedEvent, ...], *, ingested_at: float) -> int:
        """Store a batch in one transaction; return how many were *new*.

        All-or-nothing: one bad event rolls the whole batch back rather than
        leaving a partially ingested window that looks complete to a later
        query. The return value is the new count rather than the input length,
        so a caller replaying an overlapping batch sees that it added nothing
        instead of reporting work it did not do.
        """
        projected = [(event, *self._project(event)) for event in events]
        before = self.count()
        with self._conn:
            for event, projection, identifier in projected:
                self._insert(event, projection, identifier, float(ingested_at))
        return self.count() - before

    @staticmethod
    def _project(event: NormalizedEvent) -> tuple[str, str]:
        """Serialize to canonical JSON and content-address it, bound-checked."""
        projection = canonical_json(event.to_dict())
        size = len(projection.encode("utf-8"))
        if size > MAX_PROJECTION_BYTES:
            raise StoreIntegrityError(
                f"projection is {size} bytes, over the {MAX_PROJECTION_BYTES}-byte "
                "ceiling; ingest/ bounds every field, so an event this large was "
                "not built through it"
            )
        return projection, event_id(projection)

    def _insert(
        self,
        event: NormalizedEvent,
        projection: str,
        identifier: str,
        ingested_at: float,
    ) -> None:
        """The write itself. The caller owns the transaction, so a batch is atomic."""
        self._conn.execute(
            "INSERT OR IGNORE INTO events (event_id, ingested_at, occurred_at, "
            "source_type, vendor, parse_status, user_name, hostname, src_ip, "
            "dst_ip, projection) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                identifier,
                ingested_at,
                event.timestamp,
                event.source_type,
                event.vendor,
                event.parse_status,
                event.actor.user_name,
                event.device.hostname,
                event.src_endpoint.ip,
                event.dst_endpoint.ip,
                projection,
            ),
        )
        self._conn.executemany(
            "INSERT OR IGNORE INTO observables (event_id, value) VALUES (?, ?)",
            [(identifier, value) for value in event.observables],
        )

    # -- reads -------------------------------------------------------------

    def count(self) -> int:
        """Total events held."""
        row = self._conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        return int(row["n"])

    def query(self, spec: Query = ALL) -> tuple[StoredEvent, ...]:
        """Return matching events, newest first by default.

        The ``limit`` is clamped to :data:`store.schema.MAX_QUERY_LIMIT` rather
        than honored, and a non-positive limit yields nothing rather than
        everything — a caller computing a limit arithmetically should get an
        empty page from a bad computation, not the whole store.
        """
        limit = min(spec.limit, MAX_QUERY_LIMIT)
        if limit <= 0:
            return ()
        clauses: list[str] = []
        params: list[Any] = []
        # Each fragment below is a literal; only values are bound. There is no
        # path by which caller input becomes SQL text.
        if spec.since is not None:
            clauses.append("e.occurred_at IS NOT NULL AND e.occurred_at >= ?")
            params.append(float(spec.since))
        if spec.until is not None:
            clauses.append("e.occurred_at IS NOT NULL AND e.occurred_at < ?")
            params.append(float(spec.until))
        for column, value in (
            ("source_type", spec.source_type),
            ("vendor", spec.vendor),
            ("user_name", spec.user_name),
            ("hostname", spec.hostname),
        ):
            if value is not None:
                clauses.append(_EQUALITY[column])
                params.append(value)
        if spec.ip is not None:
            clauses.append("(e.src_ip = ? OR e.dst_ip = ?)")
            params.extend((spec.ip, spec.ip))
        if spec.observable is not None:
            clauses.append(
                "EXISTS (SELECT 1 FROM observables o WHERE o.event_id = e.event_id AND o.value = ?)"
            )
            params.append(spec.observable)
        # The statement is assembled only from literals declared in this
        # module: _SELECT, the _PREDICATE fragments, and one of two _ORDER
        # constants. No caller value is ever concatenated into SQL text — the
        # values travel as bound parameters, and the AST check in
        # tests/security/test_store_hardening.py proves no interpolation
        # (f-string, %, or .format) reaches an execute call.
        parts = [_SELECT]
        if clauses:
            parts.append(" WHERE ")
            parts.append(" AND ".join(clauses))
        parts.append(_ORDER_NEWEST if spec.newest_first else _ORDER_OLDEST)
        statement = "".join(parts)
        params.append(limit)
        rows = self._conn.execute(statement, tuple(params)).fetchall()
        return tuple(_rebuild(row) for row in rows)

    # -- retention ---------------------------------------------------------

    def prune(self, *, before: float) -> int:
        """Delete events stored before ``before`` (epoch seconds); return count.

        Keyed on ``ingested_at`` rather than ``occurred_at`` for two reasons:
        it is always present, and it is the only one of the two this platform
        controls — retaining by source-reported time would let a source with a
        wrong clock keep its events forever or have them pruned on arrival.

        Observables cascade. The only sanctioned deletion path, and counted so
        a retention job can report what it removed.
        """
        with self._conn:
            cursor = self._conn.execute(
                "DELETE FROM events WHERE ingested_at < ?", (float(before),)
            )
        return int(cursor.rowcount)


#: The query's fixed pieces. Declared as constants so that every character of
#: every statement this module runs is traceable to a literal written here.
_SELECT = "SELECT event_id, ingested_at, projection FROM events e"
#: Ordering is on ``ingested_at``, not ``occurred_at``: it is always present
#: (a source may carry no timestamp) and it is the one of the two this
#: platform controls, so a source with a wrong clock cannot reorder the view.
_ORDER_NEWEST = " ORDER BY e.ingested_at DESC LIMIT ?"
_ORDER_OLDEST = " ORDER BY e.ingested_at ASC LIMIT ?"

#: Equality fragments, written out so the column name in every statement is a
#: literal from this module rather than a value threaded in from a caller.
_EQUALITY = {
    "source_type": "e.source_type = ?",
    "vendor": "e.vendor = ?",
    "user_name": "e.user_name = ?",
    "hostname": "e.hostname = ?",
}


def _has_meta(conn: sqlite3.Connection) -> bool:
    """Whether this database has been initialized at all."""
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", ("meta",)
    ).fetchone()
    return row is not None


def _rebuild(row: sqlite3.Row) -> StoredEvent:
    """Rebuild one row, verifying it is what this store wrote."""
    projection = str(row["projection"])
    identifier = str(row["event_id"])
    if event_id(projection) != identifier:
        raise StoreIntegrityError(
            f"event {identifier}: projection does not hash to its event_id; "
            "the database was modified outside this platform"
        )
    try:
        payload = json.loads(projection)
    except ValueError as exc:
        raise StoreIntegrityError(f"event {identifier}: projection is not JSON") from exc
    return StoredEvent(
        event_id=identifier,
        ingested_at=float(row["ingested_at"]),
        event=NormalizedEvent.from_dict(payload),
    )
