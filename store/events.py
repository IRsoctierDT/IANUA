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

import functools
import hashlib
import json
import math
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, ParamSpec, Self, TypeVar

from ingest.schema import NormalizedEvent
from store.errors import (
    IngestionOrderError,
    SchemaVersionError,
    StoreCorruptionError,
    StoreIntegrityError,
    StorePathError,
)
from store.paths import confine
from store.schema import (
    DDL,
    DIGEST_PREFIX,
    HIGH_WATER_KEY,
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


#: SQLite's two verdicts that mean the file is damaged, by name rather than by
#: number so the predicate reads as the condition it tests. Measured on this
#: build: ``SQLITE_CORRUPT`` is 11 ("database disk image is malformed") and
#: ``SQLITE_NOTADB`` is 26 ("file is not a database").
_CORRUPTION_NAMES = frozenset({"SQLITE_CORRUPT", "SQLITE_NOTADB"})

_P = ParamSpec("_P")
_R = TypeVar("_R")


def _is_corruption(exc: sqlite3.Error) -> bool:
    """Whether ``exc`` means the database file is damaged, and nothing else.

    The three exclusions are each a measured false positive, not caution. All
    three are ``sqlite3.DatabaseError`` subclasses, so a mapping written on the
    class alone relabels every one of them as evidence damage:

    * ``IntegrityError`` is **the append-only trigger firing** —
      ``SQLITE_CONSTRAINT_TRIGGER`` (1811), measured, with the message
      ``events is append-only: rewriting a stored event is refused``. Mapping
      it would report a security control *working* as a damaged store.
    * ``ProgrammingError`` is a caller bug: a closed store, a bad bind type.
      Reporting corruption for it sends an operator to the backups over a
      programming mistake.
    * ``SQLITE_BUSY`` (5, ``OperationalError``, "database is locked") is
      contention. Measured on the blocked connection at that very moment,
      ``PRAGMA quick_check`` returns ``ok`` — so calling it corruption is a
      claim the engine contradicts in the same breath, and
      ``sli.measure_store_readable`` grades any ``StoreError`` as ``0.0``, a
      breach. A second writer must not breach the store's health indicator.

    Gated on the error *name* rather than the class alone for exactly that
    reason: the class hierarchy does not carry the distinction.
    """
    if isinstance(exc, sqlite3.IntegrityError | sqlite3.ProgrammingError):
        return False
    if not isinstance(exc, sqlite3.DatabaseError):
        return False
    return getattr(exc, "sqlite_errorname", "") in _CORRUPTION_NAMES


def _refuse_corruption(method: Callable[_P, _R]) -> Callable[_P, _R]:
    """Turn a damaged-file error out of ``method`` into a ``StoreError``.

    Applied at the **public method boundary**, which is the one placement the
    measurements permit, and both halves of that were found by measuring:

    * Not at the connection. ``tests/security`` proves the append-only trigger
      lives in the engine by running ``UPDATE`` through ``store._conn``
      directly and asserting ``sqlite3.IntegrityError``; a connection-level
      proxy is the only wrap shape that breaks the suite, and that is the test
      it breaks.
    * Not through a ``self._execute(sql, params)`` choke point. Seven of the
      nineteen SQL sites here run on a *local* ``conn`` with no instance in
      scope (``open``, ``_apply_schema``, ``_has_meta``), so a method on the
      instance cannot reach them — and a wrapper that hands back a cursor
      cannot see an error raised during the *fetch*. ``PRAGMA quick_check``
      raises at ``fetchone()``, not at ``execute()``, measured on two damaged
      pages, so :meth:`EventStore.verify_integrity` could not be written
      through such a wrapper at all.

    Wrapping the whole body covers the fetch by construction, which is the
    point. One copy of the policy, because eight copies is how seven stay
    fixed and one does not — a shape ``_resolve``'s own comment in this module
    records this repository already paying for.
    """

    @functools.wraps(method)
    def guarded(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        try:
            return method(*args, **kwargs)
        except sqlite3.DatabaseError as exc:
            if not _is_corruption(exc):
                raise
            raise StoreCorruptionError(
                f"the event store's database is damaged, so {method.__name__}() "
                f"cannot be trusted: {exc}"
            ) from exc

    return guarded


def _verdict_reason(verdict: str) -> str:
    """The informative part of a ``quick_check`` verdict, bounded.

    The first line is sometimes only the banner ``*** in database main ***``,
    which tells an operator nothing — the reason is on the next line
    (``Tree 4 page 185: btreeInitPage() returns error``). Measured both ways on
    one page-zeroing construction: which of the two shapes SQLite produces
    depends on which pages were lost. Bounded at three lines because the
    verdict is a report whose length is not this module's to choose.
    """
    lines = [line.strip() for line in verdict.splitlines() if line.strip()]
    return " / ".join(lines[:3]) if lines else "no verdict"


@dataclass(frozen=True, slots=True)
class Attestation:
    """What this store holds, in a form a later copy can be checked against.

    Content addressing proves every row is what was written. It proves
    *nothing* about whether all of them are there — deleting 100 of 400 rows
    leaves ``PRAGMA integrity_check``, :meth:`EventStore.count`,
    :meth:`EventStore.query` and :meth:`EventStore.high_water_mark` all
    silent, which was measured before this existed. So a partial copy is
    indistinguishable from a store that legitimately holds fewer events, and
    that is the one thing a restore has to be able to tell.

    ``digest`` covers the ``event_id`` of every row, in sorted order, so it is
    independent of insertion order and of the page layout a copy may differ
    in. ``events`` and ``observables`` are carried alongside it because a
    digest that happens to match tells you less than a count that also does.

    Both of those are read from covering indexes, which is why
    :meth:`EventStore.attest` gates on ``PRAGMA quick_check`` before it
    computes them: ids and a count that agree prove the *indexes* are intact
    and, on their own, say nothing about whether a single row body is
    readable. Measured — see that method.
    """

    #: Rows in ``events``.
    events: int
    #: Rows in ``observables``. Derived from the events, and separately
    #: truncatable, so it is attested separately.
    observables: int
    #: sha256 over the sorted ``event_id`` sequence. See :meth:`EventStore.attest`.
    digest: str
    #: The mark at the moment of attestation, or ``None`` for an empty store.
    high_water: float | None
    #: The schema the attestation was taken under. A copy restored onto a
    #: different version is a migration question, not a completeness one.
    schema_version: int

    def to_dict(self) -> dict[str, Any]:
        """Allow-list projection, for a manifest a human and a gate both read."""
        return {
            "events": self.events,
            "observables": self.observables,
            "digest": self.digest,
            "high_water": self.high_water,
            "schema_version": self.schema_version,
        }


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
    #: Keyset cursor: return only events ingested strictly after this
    #: ``(ingested_at, event_id)`` pair. This is the filter a continuous
    #: pipeline pages with, and it is a *pair* rather than a timestamp for a
    #: reason that is not obvious: :meth:`EventStore.append_many` stamps one
    #: ``ingested_at`` across a whole batch, so ties are the normal case, not
    #: an edge case. A cursor on the timestamp alone must then choose between
    #: ``>`` (skipping the rest of the batch) and ``>=`` (reprocessing it
    #: forever) — the first silently drops security events.
    #:
    #: Keyed on ``ingested_at``, never ``occurred_at``: ingestion time is
    #: always present, whereas an event whose source carried no timestamp is
    #: excluded from every ``since``/``until`` window. A pipeline paging by
    #: ``occurred_at`` would therefore have a permanent blind spot for exactly
    #: the undated events ``ingest/`` deliberately produces.
    ingested_after: tuple[float, str] | None = None
    #: ``ingested_at >= ingested_from``. The inclusive lower edge of an
    #: ingestion-time window, which is what a correlator needs and what
    #: :data:`ingested_after` deliberately is not: that one *excludes* the
    #: cursor so a pipeline makes progress, while this one *includes* a
    #: trailing region so a story spanning two cycles can still be seen whole.
    #:
    #: Keyed on ``ingested_at`` rather than ``occurred_at`` for the same reason
    #: :data:`ingested_after` is: an event whose source carried no timestamp is
    #: excluded from every ``since``/``until`` window, so a correlator paging by
    #: source time would have a permanent blind spot for exactly the undated
    #: events ``ingest/`` deliberately produces.
    ingested_from: float | None = None
    #: Return only events ingested strictly *before* this ``(ingested_at,
    #: event_id)`` pair — the exclusive upper edge, mirroring
    #: :data:`ingested_after`'s exclusive lower edge. A correlator reading
    #: context *behind* a window needs this: bounding the read in SQL rather
    #: than filtering rows afterwards is the difference between a budgeted read
    #: that returns the newest context below the boundary and one whose row
    #: limit is spent on rows above it that the filter then discards.
    ingested_before: tuple[float, str] | None = None
    #: Newest first when true, which is what an analyst opening a view wants.
    newest_first: bool = True
    limit: int = 1_000


#: "Everything, up to the default limit." A module-level singleton rather
#: than a call in a default argument: Query is frozen, so one shared instance
#: cannot be mutated by a caller.
ALL = Query()


#: Owner-only, matching ``pipeline/cursor.py``, ``collect/offsets.py`` and the
#: audit log. The directory mode is what actually protects the contents; the
#: file mode is defence in depth on top of it.
_DIR_MODE = 0o700
_FILE_MODE = 0o600


def _sidecar(path: Path, suffix: str) -> Path:
    """The ``-wal``/``-shm`` companion SQLite creates beside the database."""
    return path.with_name(path.name + suffix)


def _narrow(path: Path, mode: int) -> None:
    """Set ``mode`` if ``path`` exists, ignoring a filesystem that cannot.

    Absent is the normal case for a sidecar on a freshly opened store, and a
    filesystem without POSIX modes is not a reason to refuse to store events —
    the confinement in :func:`store.paths.confine` is the control that must not
    fail, and it is unaffected.
    """
    try:
        if path.exists():
            path.chmod(mode)
    except OSError:  # pragma: no cover - filesystem without mode support
        pass


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
    @_refuse_corruption
    def open(cls, root: Path, *, filename: str = DEFAULT_FILENAME) -> Self:
        """Open (creating if absent) the store under ``root/data/events/``.

        Raises :class:`StorePathError` for a filename that is not a plain
        filename or that resolves outside the events directory, and
        :class:`SchemaVersionError` if the database was written by a different
        schema version.
        """
        path = cls._resolve(root, filename)
        # Owner-only, matching the cursor, the offsets and the audit log. The
        # database holding every collected event was the ONE piece of state
        # under the lab-data root created at the process umask and never
        # narrowed: measured at 0o644 inside 0o755 directories, while a byte
        # offset in data/pipeline/ was deliberately 0o600 inside 0o700. The
        # asymmetry ran the wrong way round — bookkeeping protected, evidence
        # readable by every local account — and it matters far more once the
        # telemetry is real. Found by review.
        path.parent.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        # `mkdir(mode=...)` is masked by umask and does nothing to a directory
        # that already exists, so the mode is also set explicitly. Same reason
        # `pipeline/cursor.py` chmods rather than relying on a creation mode.
        _narrow(path.parent, _DIR_MODE)
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
            # After the PRAGMA, because WAL mode is what creates the sidecars.
            #
            # Stated precisely, since the stronger claim would be false: SQLite
            # creates each of these at the umask default and may recreate the
            # sidecars on any later write, so there is a window in which they
            # are wider than 0o600 and this cannot close it. What makes the
            # contents unreachable throughout is the enclosing directory being
            # 0o700 — the file modes are defence in depth on top of it, exactly
            # as `pipeline/cursor.py` documents for the same trade.
            for candidate in (path, _sidecar(path, "-wal"), _sidecar(path, "-shm")):
                _narrow(candidate, _FILE_MODE)
        except Exception:
            conn.close()
            raise
        return cls(conn, path)

    @staticmethod
    def _resolve(root: Path, filename: str) -> Path:
        """Confine the database to the events directory under the lab-data root.

        Delegates to :func:`store.paths.confine`, which ``pipeline/`` and
        ``collect/`` also use. The check used to live here in a copy that
        examined only the leaf directory and the file — so a symlink at
        ``data`` relocated the whole evidence database — and the identical bug
        existed in ``pipeline/``. One implementation, one place to fix.
        """
        return confine(root, EVENTS_SUBDIR, filename, error=StorePathError, what="event store")

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

    @_refuse_corruption
    def append(self, event: NormalizedEvent, *, ingested_at: float) -> str:
        """Store one event and return its content address.

        Idempotent: re-appending an identical event is a no-op that returns
        the same id. ``ingested_at`` is injected rather than read from a clock
        here, so callers control (and tests pin) the storage timeline.

        Raises :class:`IngestionOrderError` if ``ingested_at`` is behind the
        high-water mark — see :meth:`append_many` — and
        ``MalformedProjectionError`` if the event could not be read back, for
        the reasons in :meth:`_project`.
        """
        projection, identifier = self._project(event)
        stamp = float(ingested_at)
        with self._conn:
            self._require_monotonic(stamp)
            self._insert(event, projection, identifier, stamp)
            self._advance_high_water(stamp)
        return identifier

    @_refuse_corruption
    def append_many(self, events: tuple[NormalizedEvent, ...], *, ingested_at: float) -> int:
        """Store a batch in one transaction; return how many were *new*.

        All-or-nothing: one bad event rolls the whole batch back rather than
        leaving a partially ingested window that looks complete to a later
        query. The return value is the new count rather than the input length,
        so a caller replaying an overlapping batch sees that it added nothing
        instead of reporting work it did not do.

        **Ingestion order is enforced, not assumed.** ``ingested_at`` must be at
        or after the highest value ever written, or this raises
        :class:`IngestionOrderError` before touching a row. The pipeline pages
        by a ``(ingested_at, event_id)`` keyset, so an event stamped earlier
        than one already stored would sit behind a cursor that has already
        passed and would never be read by any cycle — silent data loss in the
        layer whose purpose is not having blind spots. Stage 4 documented this
        as a contract on collectors; enforcing it here makes it unrepresentable
        instead, which is the difference between a rule and a control.

        An empty batch is a no-op and is not order-checked: it writes nothing,
        so there is nothing to place out of order.

        One unreadable event also rolls back the whole batch: the projection
        pass runs to completion before the transaction opens, so a batch
        containing an event no ``query`` could return is refused in full
        rather than stored up to the bad one (:meth:`_project`).
        """
        if not events:
            return 0
        projected = [(event, *self._project(event)) for event in events]
        stamp = float(ingested_at)
        before = self.count()
        with self._conn:
            self._require_monotonic(stamp)
            for event, projection, identifier in projected:
                self._insert(event, projection, identifier, stamp)
            self._advance_high_water(stamp)
        return self.count() - before

    @_refuse_corruption
    def high_water_mark(self) -> float | None:
        """The highest ``ingested_at`` ever written, or ``None`` if never written.

        Exposed so a collector can call :meth:`next_stamp` and stay monotone
        across a clock that steps backwards, rather than discovering the
        constraint by being refused.

        **Falls back to the rows when the meta row is absent.** ``SCHEMA_VERSION``
        is deliberately unchanged by this control, so every database written
        before it existed opens with rows but no ``meta`` entry — and returning
        ``None`` there left the one population that matters undefended: an
        existing deployment's first write after the upgrade could go behind its
        own rows, which is precisely the silent blind spot this enforces
        against. Found by review. Derived once; the next append writes the row
        and the cheap path takes over.

        The stored row still wins when it exists, because it outlives the rows
        it describes: retention prunes old events, and a mark derived from
        ``MAX(ingested_at)`` after a prune would move *backwards*, re-opening
        the window for exactly the event ordering the mark exists to refuse.
        """
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = ?", (HIGH_WATER_KEY,)
        ).fetchone()
        if row is not None:
            return float(row["value"])
        derived = self._conn.execute("SELECT MAX(ingested_at) AS mark FROM events").fetchone()
        if derived is None or derived["mark"] is None:
            return None
        return float(derived["mark"])

    @_refuse_corruption
    def next_stamp(self, now: float) -> float:
        """An ``ingested_at`` that is safe to write, at or after ``now``.

        Monotonicity alone is not enough, and the gap was found by review and
        reproduced. The mark permits **equality**, which it must — a single
        ``append_many`` stamps one time across a whole batch. But the pipeline's
        keyset is *strictly* after ``(ingested_at, event_id)``, so an event
        written at exactly the mark, with an ``event_id`` sorting below the
        cursor's, sits behind a cursor that has already passed it and is never
        read. Four events stored, three ever seen.

        A caller clamping with ``max(now, mark)`` walks straight into it
        whenever the clock is at or behind the mark — which is what an NTP step
        backwards produces. So the safe stamp is strictly after the mark, and it
        lives here because the mark and the cursor contract are both this
        layer's.

        Raises:
            ValueError: for a non-finite ``now``. A NaN would compare false
                against everything and silently disable the ordering control;
                an infinity would raise the mark to a value nothing can ever
                exceed, permanently wedging the store.
        """
        if not math.isfinite(now):
            raise ValueError(f"ingestion time must be finite, got {now!r}")
        mark = self.high_water_mark()
        if mark is None or now > mark:
            return now
        return math.nextafter(mark, math.inf)

    def _require_monotonic(self, ingested_at: float) -> None:
        """Refuse a write that would land behind the high-water mark.

        Checked inside the caller's transaction and before any insert, so a
        refused batch leaves the database exactly as it was.
        """
        if not math.isfinite(ingested_at):
            # NaN compares false against every bound, so it would slip past the
            # check below and then poison the mark for every later write;
            # infinity would raise the mark beyond anything a clock can reach.
            raise IngestionOrderError(
                f"ingested_at must be finite, got {ingested_at!r}; a non-finite "
                "stamp would disable the ordering control rather than violate it"
            )
        mark = self.high_water_mark()
        if mark is not None and ingested_at < mark:
            raise IngestionOrderError(
                f"ingested_at {ingested_at!r} is behind the high-water mark {mark!r}; "
                "the pipeline's cursor has already passed that point, so these events "
                "would never be read. Stamp the current time instead — a replay is "
                "being ingested now, not then."
            )

    def _advance_high_water(self, ingested_at: float) -> None:
        """Raise the mark. Written in the same transaction as the rows it covers."""
        self._conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (HIGH_WATER_KEY, repr(float(ingested_at))),
        )

    @staticmethod
    def _project(event: NormalizedEvent) -> tuple[str, str]:
        """Serialize to canonical JSON, content-address it, and refuse what cannot be read.

        Two checks, and the second exists because the first was not enough.

        **The size ceiling** bounds the whole projection. It caught an event
        far larger than any ``ingest/`` output, which is what it was for.

        **The read-back** refuses a projection this store could not return.
        ``_rebuild`` reconstructs every row a query yields through
        ``NormalizedEvent.from_dict``, which validates each field against *its
        own* bound — while this method validated only the projection's total
        size, which a 2049-character ``message`` sails under at 64 KiB. So the
        store accepted an event and then refused to read it, and because
        ``query`` rebuilds every row in its window and raises on the first bad
        one, a single such row stopped **every future detection cycle on that
        store**: the cursor could not advance past it, ``UPDATE`` is
        trigger-refused so it could not be repaired, and ``prune`` takes only a
        time cutoff — so the sanctioned recovery was destroying the whole
        store. Meanwhile the collector kept exiting 0, so two of the three
        subsystems read green while detection was dead. Reproduced end to end
        before the fix.

        This is the third appearance of one defect class in this layer: a bound
        asserted on read and not applied on write. The first two were
        ``_unrecognized``'s ``message`` and the parser-assembled ``message``,
        both fixed inside ``ingest/``. This one is fixed *here*, because the
        store is the boundary that outlives any single producer — a direct
        caller, a replay tool, or a future collector that does not route
        through ``ingest.normalize`` inherits the refusal rather than having to
        remember the rule. It is deliberately the reader itself that is called,
        not a second list of bounds, because a list is what drifts.

        Raises:
            StoreIntegrityError: the projection exceeds the size ceiling.
            MalformedProjectionError: the projection is within the ceiling but
                some field is not, so a later ``query`` would refuse it. The
                same error the read path raises, so "append refuses exactly
                what query refuses" is one assertion rather than two.
        """
        projection = canonical_json(event.to_dict())
        size = len(projection.encode("utf-8"))
        if size > MAX_PROJECTION_BYTES:
            raise StoreIntegrityError(
                f"projection is {size} bytes, over the {MAX_PROJECTION_BYTES}-byte "
                "ceiling; ingest/ bounds every field, so an event this large was "
                "not built through it"
            )
        # The write-side twin of `_rebuild`'s read. Checked before any insert,
        # and `append_many` projects the whole batch before opening its
        # transaction, so a refused event leaves the database untouched.
        NormalizedEvent.from_dict(json.loads(projection))
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

    @_refuse_corruption
    def count(self) -> int:
        """Total events held."""
        row = self._conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        return int(row["n"])

    @_refuse_corruption
    def verify_integrity(self) -> None:
        """Refuse if the database file is damaged. Cheap enough to gate on.

        One copy, because it has two callers that each need it for a different
        reason, and a check a caller must remember is a check three callers
        keep and one forgets:

        * :meth:`attest` — its digest and its count are both covering-index
          scans, so without this they describe the *indexes* and say nothing
          about whether a row body is readable. Zeroing a 400-event store's
          134 table leaf pages produced a bit-identical digest and count.
        * ``scripts/run_retention.py`` — it reports from :meth:`count` and
          :meth:`count_before`, which are *also* covering-index reads, so it
          exited ``0`` on a store from which no row could be read and wrote
          ``would remove 200 of 200 event(s)`` into a hash chain that then
          verified. That is the same defect as attest's, in the one CLI that
          can delete evidence.

        ``quick_check`` rather than ``integrity_check``, priced at three sizes
        rather than guessed:

            events     MiB   quick_check   integrity_check   50+50 sample
             10,000   16.7       24.4 ms           67.5 ms       10.40 ms
             40,000   67.1       90.3 ms          419.0 ms       14.76 ms
            120,000  202.2      220.2 ms         1439.7 ms       12.07 ms

        ``quick_check`` is roughly linear at 1.1-1.5 ms/MiB and is cheaper than
        a full table scan (144 ms at 67.1 MiB), because it walks pages without
        decoding rows into Python. ``integrity_check`` is *super*-linear and is
        therefore not a candidate for anything on a ``*/5`` schedule.

        What it does **not** catch is a structurally valid page carrying
        another generation's rows. That needs ``integrity_check``, and it is
        only reachable through a page- or frame-shipping replication scheme
        this repository does not have — ``DESIGN.md`` §11 records an
        ``integrity_check`` on promotion as a precondition of any such scheme.

        Raises:
            StoreCorruptionError: if the file is damaged, whether SQLite
                reports that as a verdict or raises it.
        """
        verdict = str(self._conn.execute("PRAGMA quick_check").fetchone()[0])
        if verdict != "ok":
            raise StoreCorruptionError(
                f"the event store's database is damaged: {_verdict_reason(verdict)}"
            )

    @_refuse_corruption
    def attest(self) -> Attestation:
        """Attest what this store holds, so a copy of it can be verified.

        The completeness control the store did not have. Read-only, streamed
        rather than materialized — a 15-million-row store is digested without
        loading a row into Python beyond one id at a time, which matters
        because this is meant to be cheap enough to run on every backup.

        The digest commits to the row count as well as the ids, so a store
        whose ids are a prefix of another's cannot collide with it. Ordered by
        ``event_id`` rather than by ``ingested_at`` or ``rowid``, because a
        valid copy may differ in physical layout and must still attest
        identically; ``event_id`` is a sha256 over the canonical projection,
        so the order is total and stable.

        This is not a tamper control on its own. An attacker who can rewrite
        rows can recompute a digest over them — ``UPDATE`` is trigger-refused
        and the audit chain is the tamper evidence. What this catches is
        *loss*: a truncated transfer, a copy that raced a writer, a half
        restore, a prune nobody meant to run.

        **The count it commits to is the count it actually digested.** The
        count and the id stream are two separate statements, so the preimage
        could previously commit to a number that did not equal the number of
        ids hashed into it — an attestation internally inconsistent, yet
        well-formed and comparing unequal for a reason nobody could read off
        it. The ids are now counted as they stream and the two are asserted
        equal, which costs one integer and turns that case from a mismatched
        digest into a named error.

        Honest about the provenance: the shape that prompted this was an
        adversarial measurement reporting ``COUNT(*)`` of 1500 against 1502
        streamed ids on a database SQLite called malformed, taken with a
        three-file-copy race harness. **I could not reproduce that shape** —
        a bluntly truncated copy raises ``DatabaseError: database disk image
        is malformed`` out of SQLite before this method can return anything.
        So this change does not rest on that measurement. It rests on the
        plain argument that a digest should commit to what it hashed, which
        holds whether or not the corrupt case is reachable.

        **It reads a table page before it attests, and it did not used to.**
        Both statements below are covering-index scans — measured, with
        ``EXPLAIN QUERY PLAN``: the id stream is ``SCAN events USING COVERING
        INDEX sqlite_autoindex_events_1`` and the count is ``SCAN events USING
        COVERING INDEX events_ingested_at``. Neither touches a row. Zeroing
        all 134 table leaf pages of a 400-event store while leaving every
        index page intact produced a **bit-identical digest and count** while
        ``query()`` raised ``database disk image is malformed``: the only
        completeness control this store has, signing off on a store that had
        lost every row. That is not a tamper scenario — it is "a truncated
        transfer, a half restore", which is the loss this method's own
        paragraph above claims to catch.

        ``quick_check`` and not ``integrity_check``, priced rather than
        guessed. On 40,000 events / 67.1 MiB: the attestation scan 35 ms,
        ``quick_check`` 70 ms, ``integrity_check`` 331 ms, a full table scan
        144 ms. ``quick_check`` is the cheapest thing that reads the table at
        all — cheaper than scanning it, because it walks pages without
        decoding rows into Python — and doubling the cost of an operation that
        is already copying the whole file is the right side of that trade.
        The digest's *definition* is deliberately unchanged, so every manifest
        already written stays valid; this adds a gate, not a new preimage.

        That gate now lives in :meth:`verify_integrity` rather than inline
        here, because it acquired a second caller that needs it for the same
        reason: ``scripts/run_retention.py`` reports from :meth:`count` and
        :meth:`count_before`, which are *also* covering-index reads, and so
        exited ``0`` on a store from which no row could be read. Both of
        SQLite's answers — it raises for some losses and reports a verdict for
        others, measured both ways on one construction — are handled there, and
        the pricing is recorded there too.

        Raises:
            StoreCorruptionError: if the database file is damaged.
            StoreIntegrityError: if the count and the id stream disagree.
        """
        self.verify_integrity()
        counts = self._conn.execute(
            "SELECT (SELECT COUNT(*) FROM events) AS events, "
            "(SELECT COUNT(*) FROM observables) AS observables"
        ).fetchone()
        events = int(counts["events"])
        running = hashlib.sha256()
        # The count goes into the preimage first, so a prefix of one store's
        # ids cannot digest the same as another store's whole set.
        running.update(f"{DIGEST_PREFIX}{events}\n".encode())
        streamed = 0
        for row in self._conn.execute("SELECT event_id FROM events ORDER BY event_id"):
            running.update(str(row["event_id"]).encode("ascii"))
            running.update(b"\n")
            streamed += 1
        if streamed != events:
            raise StoreIntegrityError(
                f"attestation is inconsistent: the digest commits to {events} event(s) "
                f"but {streamed} id(s) were read. The count and the id scan are separate "
                "statements and disagreed, so this store cannot be attested."
            )
        return Attestation(
            events=events,
            observables=int(counts["observables"]),
            digest=running.hexdigest(),
            high_water=self.high_water_mark(),
            schema_version=SCHEMA_VERSION,
        )

    @_refuse_corruption
    def count_before(self, *, before: float) -> int:
        """How many events :meth:`prune` would delete at this threshold.

        Exists so retention can be reported before it is applied. ``prune``
        returns a count *after* deleting, which is no use to an operator
        deciding whether to delete at all — and deletion here is irreversible
        in a way the rest of the platform is not: the collector's offsets live
        in a separate file and are never rewound, so content removed from the
        store cannot be re-collected from a source that still holds it.

        A ``COUNT`` rather than a ``query``: counting must not depend on every
        projection in range parsing cleanly, because the operator most needs
        this number when something is wrong with the data.
        """
        if not math.isfinite(before):
            raise ValueError(f"retention threshold must be finite, got {before!r}")
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE ingested_at < ?", (float(before),)
        ).fetchone()
        return int(row["n"])

    @_refuse_corruption
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
        if spec.ingested_after is not None:
            # Strictly after the pair, in the same total order as the ORDER BY.
            clauses.append(_INGESTED_AFTER)
            at, identifier = spec.ingested_after
            params.extend((float(at), float(at), identifier))
        if spec.ingested_before is not None:
            # Strictly before the pair, in the same total order as the ORDER BY.
            clauses.append(_INGESTED_BEFORE)
            at, identifier = spec.ingested_before
            params.extend((float(at), float(at), identifier))
        if spec.ingested_from is not None:
            # Inclusive, so the lower edge of a lookback window is not itself
            # the thing that falls out of it.
            clauses.append(_INGESTED_FROM)
            params.append(float(spec.ingested_from))
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

    @_refuse_corruption
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
#: Keyset pagination: strictly after ``(ingested_at, event_id)``.
_INGESTED_AFTER = "(e.ingested_at > ? OR (e.ingested_at = ? AND e.event_id > ?))"
#: Inclusive lower edge of an ingestion-time window.
_INGESTED_FROM = "e.ingested_at >= ?"
#: Keyset upper edge: strictly before ``(ingested_at, event_id)``.
_INGESTED_BEFORE = "(e.ingested_at < ? OR (e.ingested_at = ? AND e.event_id < ?))"
#: Ordering is on ``ingested_at``, not ``occurred_at``: it is always present
#: (a source may carry no timestamp) and it is the one of the two this
#: platform controls, so a source with a wrong clock cannot reorder the view.
#: Ordering includes ``event_id`` as a tie-break, which makes the sequence a
#: TOTAL order. Ordering by ``ingested_at`` alone leaves ties in whatever
#: sequence the engine happens to return, and keyset paging over a
#: non-deterministic order skips or repeats rows. The content address is the
#: natural tie-break: it is unique, stable, and already indexed as the
#: primary key.
#:
#: Deliberately NOT backed by a composite ``(ingested_at, event_id)`` index:
#: adding one would change the schema, and this store refuses to open a
#: database written under a different ``SCHEMA_VERSION``. The existing
#: ``events_ingested_at`` index covers the selective range scan; the
#: tie-break sorts within one timestamp. A composite index is a deliberate
#: migration, not a thing to smuggle in behind a query change.
_ORDER_NEWEST = " ORDER BY e.ingested_at DESC, e.event_id DESC LIMIT ?"
_ORDER_OLDEST = " ORDER BY e.ingested_at ASC, e.event_id ASC LIMIT ?"

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
