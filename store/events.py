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
  module's AST in ``tests/security/test_store_hardening.py``, at each
  ``execute`` call rather than by matching constructs: the statement must be
  traceable to string literals declared in this package, and any expression
  the check cannot account for fails. It resolves the module constants at the
  foot of this file, ``_EQUALITY``'s values, the clause list ``query``
  accumulates, and ``DDL`` across the import from :mod:`store.schema`.
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
import operator
import re
import sqlite3
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, ParamSpec, Self, SupportsFloat, SupportsIndex, TypeVar

from ingest.errors import MalformedProjectionError
from ingest.schema import NormalizedEvent
from store.errors import (
    IngestionOrderError,
    SchemaVersionError,
    StoreCorruptionError,
    StoreFileError,
    StoreIntegrityError,
    StorePathError,
    StoreSidecarError,
)
from store.paths import confine
from store.schema import (
    DDL,
    DIGEST_PREFIX,
    HIGH_WATER_KEY,
    MAX_PROJECTION_BYTES,
    MAX_QUERY_LIMIT,
    OBSERVABLES_DIGEST_PREFIX,
    SCHEMA_VERSION,
    VERSION_KEY,
    canonical_json,
    event_id,
)

#: Fixed location under the repository's gitignored lab-data root. Not a
#: caller knob: an event store is lab data by definition (AGENTS.md §5), and
#: letting a caller choose the directory is how evidence ends up committed.
EVENTS_SUBDIR = Path("data") / "events"

#: The statements :meth:`EventStore.attest` runs, named so the test that pins
#: their query plans (``tests/unit/test_event_store.py``) reads the same text
#: the method executes. Every one is a covering-index scan — that is a
#: property the completeness control depends on, and a constant a test
#: imports cannot drift from the code the way a docstring can.
ATTEST_IDS_SQL = "SELECT event_id FROM events ORDER BY event_id"
ATTEST_COUNTS_SQL = (
    "SELECT (SELECT COUNT(*) FROM events) AS events, "
    "(SELECT COUNT(*) FROM observables) AS observables"
)
# typeof() and CAST(... AS BLOB), not the columns themselves: SQLite is
# dynamically typed, so a damaged or hostile copy can hold a BLOB in a TEXT
# column, and str() of the bytes b"x" is the four-character text "b'x'" — two
# different rows with one digest. Framing the storage class and the raw bytes
# is injective over both. The aliases must not shadow the ORDER BY columns:
# measured, `CAST(value AS BLOB) AS value` adds USE TEMP B-TREE to the plan.
ATTEST_OBSERVABLES_SQL = (
    "SELECT typeof(event_id) AS kind_id, CAST(event_id AS BLOB) AS raw_id, "
    "typeof(value) AS kind_value, CAST(value AS BLOB) AS raw_value "
    "FROM observables ORDER BY event_id, value"
)

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
      ``sli.measure_store_readable`` grades a corruption error as ``0.0``, a
      breach, whether ``open`` or a query raises it. A second writer must not
      breach the store's health indicator.

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

    Applied to the methods that **execute** SQL, which is why
    :meth:`EventStore.next_stamp` does not carry it: it runs no statement of
    its own and delegates to :meth:`high_water_mark`, so a corruption error is
    already mapped before it returns. It had the decorator briefly, and a plant
    removing it stayed green in every regime — a guard no test can make fire is
    the shape this module has spent the day removing, so it went rather than
    becoming decoration. ``tests/security`` still exercises ``next_stamp``,
    because the property asserted there is about what reaches a *caller*, not
    about where the guard sits.
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


#: How much of the reader's refusal a read-path error carries. See
#: :func:`_rebuild_reason`.
_REASON_CHARS = 200


def _rebuild_reason(exc: MalformedProjectionError) -> str:
    """The reader's refusal of a stored row, bounded.

    The reader's own sentence rather than a second description of its bounds,
    because a second description is what drifts. Bounded because two of its
    sentences quote the row: ``_literal`` renders the stored value and
    ``_require_exact_keys`` the undeclared key names, and a forged row chooses
    both. Measured: a 50,000-character ``source_type`` made a 50,107-character
    refusal, which ``sli.measure_store_readable`` would carry verbatim into the
    detail ``AUD-03`` tells an operator to record. The sentences that name a
    bound quote nothing (``event.message: 100000 chars exceeds the 2048-char
    bound`` is 55 characters), and those are the ones the defects recorded in
    ``DESIGN.md`` §11 wrote, so the cut costs nothing on the case it exists
    for. Both quoting shapes go through ``repr``, which escapes control
    characters, so what survives the cut cannot steer a terminal.
    """
    text = str(exc)
    if len(text) <= _REASON_CHARS:
        return text
    return f"{text[:_REASON_CHARS]}... ({len(text)} chars, cut)"


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

    ``digest`` does **not** cover the ``observables`` table, and a count is
    not a commitment to contents: review of the promotion gate showed that
    replacing observable rows one-for-one leaves the count, the event digest
    and ``quick_check`` all satisfied while every indicator pivot joins on
    substituted keys. ``observables_digest`` closes that — a sha256 over every
    ``(event_id, value)`` row, sorted, each field framed as its SQLite storage
    class, byte length and raw bytes, so neither a value nor a storage class
    can be confused with a row boundary or with each other. ``digest``'s
    definition is unchanged on purpose; this is a second field, not a
    redefinition.

    All of those are read from covering indexes, which is why
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
    #: sha256 over the sorted ``(event_id, value)`` rows of ``observables``.
    #: Commits to contents, not only to the count above.
    observables_digest: str
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
            "observables_digest": self.observables_digest,
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


#: Every file SQLite opens by name beside the database, in the order its open
#: reaches them. ``-journal`` is read even in WAL mode: the hot-journal probe
#: on open is what blocked on a FIFO.
SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")

#: A noun for each file type that is not a regular file, for the refusal.
_FILE_KINDS = {
    stat.S_IFLNK: "a symlink",
    stat.S_IFIFO: "a FIFO",
    stat.S_IFDIR: "a directory",
    stat.S_IFSOCK: "a socket",
    stat.S_IFCHR: "a character device",
    stat.S_IFBLK: "a block device",
}


def _sidecar(path: Path, suffix: str) -> Path:
    """The ``-wal``/``-shm`` companion SQLite creates beside the database."""
    return path.with_name(path.name + suffix)


def _file_problem(path: Path) -> str | None:
    """Why SQLite must not be handed ``path``, or ``None`` if it is absent or safe.

    One ``lstat``, never following a link. Absent is ``None``: ``ENOENT``, and
    ``ENOTDIR`` (an ancestor is not a directory, so nothing can exist here, and
    the ``mkdir`` in :meth:`EventStore.open` raises the honest error). Any other
    ``stat`` failure is a problem rather than absent, because the open it
    precedes would fail on it anyway. Present must be a regular file with exactly
    one link. Size and content are not examined. The one rule behind both
    :func:`refuse_unsafe_database` and :func:`refuse_unsafe_sidecars`, so the
    two cannot drift.
    """
    try:
        found = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as exc:
        return f"cannot be stated ({exc.strerror or exc})"
    kind = stat.S_IFMT(found.st_mode)
    if kind != stat.S_IFREG:
        return f"is not a regular file ({_FILE_KINDS.get(kind, 'an unrecognised type')})"
    if found.st_nlink != 1:
        return f"has {found.st_nlink} hard links"
    return None


def refuse_unsafe_database(database: Path) -> None:
    """Refuse the database file itself unless SQLite may open it.

    The same rule as :func:`refuse_unsafe_sidecars`, applied to the one file
    that check deliberately did not state: absent (a fresh root, which
    :meth:`EventStore.open` then creates) or a regular file with exactly one
    link. :func:`store.paths.confine` already refuses a symlink here; this adds
    everything else. Measured on the tree before it, through the CLIs except
    where noted (:class:`store.errors.StoreFileError` has the detail):

    * **One link.** SQLite writes the database in place, so a second name is a
      second file written. A ``cp -al`` snapshot of the store gained 4 KiB and a
      new digest when the collector ran; a 0-byte file outside ``data/`` linked
      in at this path was initialised as a store, 0 -> 61440 bytes, by the
      collector, the pipeline and retention at exit 0, and by the SLI reporter.
    * **Not a FIFO.** SQLite falls back to a read-only open after ``EACCES``,
      and a read-only open of a FIFO blocks until a writer appears: the
      collector, the pipeline and retention hung holding their locks. A FIFO
      the account can write gave a bare "disk I/O error" instead.
    * **Not a directory or socket**, which SQLite cannot open either: measured
      through :meth:`EventStore.open`, each gave a bare "unable to open database
      file" that named nothing. A device is refused by the same type rule; that
      case was not measured.

    ``scripts/run_backup.py`` calls this rather than keeping a copy, because its
    take reads the live store through ``sqlite3.connect`` and never reaches
    :meth:`EventStore.open`. It catches the error and reports
    :attr:`StoreFileError.problem` beside its other findings.

    **What this does not close.** The ``lstat`` and SQLite's open are separate
    syscalls, and SQLite cannot be handed a descriptor this function has
    checked. Swapping the file between them requires creating names in the
    events directory, which :meth:`EventStore.open` keeps at ``0o700``, and with
    that access the database could be rewritten directly. What this catches is a
    database that is already wrong when the store is opened: a hard-link
    snapshot of ``data/``, a restore made with ``cp -al``, a mistake, or a
    planted file.

    Args:
        database: The database path, already confined by
            :func:`store.paths.confine`. Stated with ``lstat``, never opened.

    Raises:
        StoreFileError: if ``database`` exists and is not a regular, singly
            linked file, or cannot be stated for a reason other than absence.
    """
    problem = _file_problem(database)
    if problem is None:
        return
    raise StoreFileError(
        f"{database} {problem}; the store opens only a regular file with one link (SQLite "
        "would block on a FIFO and write through a second link), so the store was not "
        "opened (see store/README.md, 'The database file itself')",
        problem=problem,
    )


def refuse_unsafe_sidecars(database: Path) -> None:
    """Refuse a sidecar SQLite would open beside ``database`` unless it is safe to.

    One ``lstat`` per name in :data:`SIDECAR_SUFFIXES`, never following a
    link. Absent is the normal case and is accepted. Present must be a
    regular file with exactly one link, and nothing else is examined: a live
    writer legitimately leaves a non-empty ``-wal`` and a ``-shm`` behind, so
    size and content are not this check's business (``scripts/run_backup.py``
    refuses a non-empty ``-wal`` and ``-journal`` for its own reasons).

    ``scripts/run_backup.py`` keeps its own ``_sidecar_problem`` with the same
    rule, because its take reads the live store through ``sqlite3.connect``
    and never reaches this function; a security test pins that the two cover
    the same names.

    Why each rule, all measured through the CLIs before this check or the
    backup CLI's own existed:

    * **Not a FIFO, socket or device.** SQLite's hot-journal probe opens and
      reads ``-journal`` on every open, WAL mode included, and a FIFO with no
      writer blocks there forever; ``SIGALRM`` does not interrupt it. A FIFO
      ``-wal`` was deleted, at exit 0 from the pipeline, retention and the
      backup take.
    * **Not a symlink or directory.** A symlinked ``-shm`` or ``-wal``
      replaced the caller's output with a bare "unable to open database
      file". A directory ``-shm`` did the same in the collector ("attempt to
      write a readonly database") and let the pipeline, retention, the backup
      take and both backup verifiers exit 0 as though nothing were wrong.
    * **One link.** SQLite truncates and rewrites ``-shm`` and writes frames
      into ``-wal`` in place, so a second name for either is a second file
      overwritten. Measured: a 64 KiB file hard-linked as ``-shm`` came back
      as 32 KiB of WAL index through every CLI that opens the store, the
      read-only ``--verify`` included, which still reported every digest
      matching at exit 0.

    **What this does not close, stated rather than implied.** The check and
    SQLite's open are separate syscalls, and SQLite creates and recreates its
    sidecars after it. Winning that race requires creating names in the
    events directory, which :meth:`EventStore.open` keeps at ``0o700``; with
    that access the database itself can be rewritten, the same argument
    AGENTS.md §5 makes for the collector's symlink check. What this catches
    is a sidecar that is already wrong when the store is opened: a mistake,
    a leftover, a hard-link snapshot of ``data/``, or a planted file.

    Args:
        database: The database path. Not opened or stated here; only the
            three names beside it are. :func:`refuse_unsafe_database` states it.

    Raises:
        StoreSidecarError: naming the first sidecar that is not a regular,
            singly linked file, or that cannot be stated at all. A ``stat``
            failure other than "absent" is refused rather than read as
            absent, because the open it precedes would fail on it anyway:
            measured, a database name long enough that ``-journal`` passes
            ``NAME_MAX`` (248 bytes and up) already failed SQLite's own open
            with a bare "unable to open database file".
    """
    for suffix in SIDECAR_SUFFIXES:
        side = _sidecar(database, suffix)
        problem = _file_problem(side)
        if problem is None:
            continue
        raise StoreSidecarError(
            f"{database} has a {suffix} beside it that {problem}; SQLite opens {side.name} "
            "by name with the store and would block on, follow or write through it, so the "
            "store was not opened (see store/README.md, 'Sidecars')",
            suffix=suffix,
            problem=problem,
        )


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


def _finite(value: object, what: str) -> float:
    """Convert ``value`` to a float once and refuse a non-finite result.

    The value checked is the value returned, so what a statement binds is
    what passed the check. That is the whole point: :meth:`EventStore.prune`
    used to run ``math.isfinite(before)`` and then ``float(before)`` — two
    conversions of the same object — and an object whose ``__float__``
    answered ``1.0`` on the first call and ``inf`` on the second passed the
    check and the DELETE ran with ``inf``. Measured, three stored events to
    zero. :meth:`EventStore.count_before` had the same shape (two conversions;
    three for its keyset bound), so the report-then-apply parity it shares
    with ``prune`` held only for stateless values. Not reachable from
    ``scripts/run_retention.py``, which passes argparse floats, and no
    deserialization path builds such an object; closed here because the store
    is the boundary that outlives any one caller.

    The protocol guard keeps the accepted domain exactly what ``math.isfinite``
    accepted — ``__float__`` or ``__index__``. ``float()`` alone also parses
    ``str``, ``bytes``, ``bytearray`` and ``memoryview`` (measured), and a fix
    for a double conversion must not start reading text as a number. The
    ``append`` path already had the safe shape (``float()`` once, the check on
    the result) and is unchanged.

    Raises:
        TypeError: for a value that is not a real number.
        ValueError: for a non-finite value.
    """
    if not isinstance(value, (SupportsFloat, SupportsIndex)):
        raise TypeError(f"{what} must be a real number, not {type(value).__name__}")
    coerced = float(value)
    if not math.isfinite(coerced):
        raise ValueError(f"{what} must be finite, got {coerced!r}")
    return coerced


def _decode_text(raw: bytes) -> str:
    """Decode a TEXT value read from the store, refusing bytes that are not UTF-8.

    Installed as the connection's ``text_factory``, so it covers every TEXT
    column every method reads, in one place. ``sqlite3``'s own decoder raised a
    raw ``OperationalError`` instead, measured from ``open`` (the schema
    version), ``high_water_mark`` and ``attest`` (the stored mark), and
    ``query`` (``projection`` and ``event_id``). That class is not a
    :class:`StoreError`, so it escaped every first-party handler. And its
    message quoted the stored bytes (``… with text 'PLANTED�'``), so a forged
    row chose what an error reported.

    Every write binds ``str``, which ``sqlite3`` encodes as UTF-8, and a ``str``
    that cannot be encoded is refused at bind time, so non-UTF-8 TEXT was
    written outside this platform. The message gives the length, never the
    bytes. Measured at 484 ms against 495 ms for a 10,000-row query with the
    default decoder, so the Python-level call costs nothing measurable beside
    the re-hash and JSON decode each row already pays.

    Raises:
        StoreIntegrityError: raised directly rather than mapped, because an
            exception from a ``text_factory`` reaches the caller unchanged
            (measured) and this one is already the class the decorator lets
            through.
    """
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise StoreIntegrityError(
            f"a stored text value ({len(raw)} bytes) is not valid UTF-8; every write "
            "path stores UTF-8, so the database was modified outside this platform"
        ) from None


def _stored_mark(value: object) -> float:
    """Parse the high-water mark ``meta`` holds, refusing anything not a finite number.

    :meth:`EventStore._advance_high_water` writes ``repr(float)`` into a TEXT
    column, so the value is parsed and not merely converted — :func:`_finite`
    refuses ``str`` by design, and must keep doing so for its other callers.
    The parse is lenient about spelling and strict about meaning: any text
    ``float()`` reads as a finite number is accepted, because a finite forged
    mark cannot be told from a real one by its format, and the hazards measured
    were all non-numbers and non-finite numbers. ``nan`` silently disabled the
    ordering control (an append behind every stored row succeeded and rewrote
    the mark lower), and ``inf`` refused every later append as out of order.

    Raises:
        TypeError: for a value that is not text. TEXT affinity converts a
            number to text on the way in, so only a BLOB arrives here, and
            ``float()`` would otherwise parse one (``b'1.5'`` read as ``1.5``).
        ValueError: for text that is not a number, or is not finite. Raised
            fresh rather than chained from ``float()``, whose message quotes
            the stored text, which a forged row chooses.
    """
    if not isinstance(value, str):
        raise TypeError(f"high-water mark must be text, not {type(value).__name__}")
    try:
        parsed = float(value)
    except ValueError:
        raise ValueError("high-water mark is not a number") from None
    return _finite(parsed, "high-water mark")


#: A recorded schema version as :meth:`EventStore._apply_schema` writes it:
#: ``str()`` of a small integer. ``[0-9]`` rather than ``\d``, which matches
#: every Unicode digit, and nine of them because the version is at 1 and moves
#: once per schema change, so a longer value is not one any build wrote.
_VERSION_TEXT = re.compile(r"[0-9]{1,9}")


def _version_refusal(raw: object) -> str:
    """The :class:`SchemaVersionError` message for a version this build does not speak.

    The recorded version is named only when it has the shape this platform
    writes, because the operator needs it to choose a migration. Anything else
    is described by type and length and never echoed: an allow-list, since a
    length bound alone would still copy what a forged row chose. Measured
    before this change, ``meta.schema_version`` set to ``"9" * 50000`` made
    :meth:`EventStore.open` raise a 50,154-character message, which ``sli``
    carries verbatim into the report detail ``AUD-03`` tells an operator to
    record (50,236 characters for ``store-intact``). And a short value needed no
    length to do harm: ``"2\\x1b[2J\\x1b[31mhealthy"`` put the raw escape
    sequences into that detail, and ``scripts/report_sli.py`` wrote them to the
    terminal, clearing the screen. The same removal of a stored-value echo that
    #268, #269 and #272 made in their own messages.

    TEXT affinity converts a number to text on the way in and the column is
    ``NOT NULL``, so text and a BLOB are the only shapes SQLite can return here.
    """
    if isinstance(raw, str) and _VERSION_TEXT.fullmatch(raw):
        return (
            f"event store was written by schema version {raw}, this build speaks version "
            f"{SCHEMA_VERSION}; migration is explicit (no implicit upgrade — see "
            "store.errors.SchemaVersionError)"
        )
    if isinstance(raw, str):
        shape = f"{len(raw)} character(s) of text that is not a version number"
    elif isinstance(raw, bytes):
        shape = f"a BLOB of {len(raw)} byte(s)"
    else:  # pragma: no cover - TEXT affinity and NOT NULL leave only text and BLOB
        shape = f"a value of type {type(raw).__name__}"
    return (
        f"event store's recorded schema version is {shape}, which no build of this "
        f"platform writes; refusing to assume the existing rows match version {SCHEMA_VERSION}"
    )


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
        filename or that resolves outside the events directory,
        :class:`StoreFileError` (a subclass) for a database file that exists
        and is not a regular, singly linked file, :class:`StoreSidecarError`
        (a subclass of that) for a ``-journal``, ``-wal`` or ``-shm`` beside it
        that is not one either, and :class:`SchemaVersionError` if the database
        was written by a different schema version.
        """
        path = cls._resolve(root, filename)
        # Before anything is created or narrowed, so a refusal leaves the tree
        # as it found it, and before `connect`, which is where SQLite would
        # block on a FIFO or write through a link. The database first, because
        # it is the file SQLite opens first; absent still means "create it".
        # See refuse_unsafe_database and refuse_unsafe_sidecars.
        refuse_unsafe_database(path)
        refuse_unsafe_sidecars(path)
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
        conn.text_factory = _decode_text
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
            if str(row["value"]) != str(SCHEMA_VERSION):
                raise SchemaVersionError(_version_refusal(row["value"]))
            return
        # Fresh database: tables and version land in one transaction, so a
        # store can never exist with tables but no recorded version.
        #
        # The explicit BEGIN is what makes that sentence true. `executescript`
        # COMMITs any pending transaction and then runs its script in
        # autocommit mode — measured: `in_transaction` was False after it, and
        # a second connection could see all three tables before the version
        # row existed. A failure between the two statements therefore left a
        # store the next open refused as "the version row was removed": a
        # fail-closed misdiagnosis an operator could clear only by deleting
        # the file. With BEGIN inside the script the DDL stays uncommitted
        # until `with` commits it alongside the version row, and a failure
        # rolls both back — measured, zero tables after a simulated crash.
        with conn:
            conn.executescript("BEGIN;" + DDL)
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
            self._begin_write()
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
        with self._conn:
            self._begin_write()
            self._require_monotonic(stamp)
            # Counted inside the write lock, so another writer's commit cannot
            # land between the two counts and be reported as this batch's.
            before = self.count()
            for event, projection, identifier in projected:
                self._insert(event, projection, identifier, stamp)
            self._advance_high_water(stamp)
            added = self.count() - before
        return added

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
        It wins only from *above* the rows, though. A stored mark below
        ``MAX(ingested_at)`` is refused, because obeying it is how the window
        re-opens: a ``meta`` value of ``'1.0'`` over rows at 1000 to 1002 let an
        append at 5.0 succeed and moved the mark to 5.0, measured. The ``MAX``
        is one index seek on ``events_ingested_at``, read in the same statement
        as the mark so that both come from one snapshot.

        Raises:
            StoreIntegrityError: for a mark that is not a finite number, from
                either branch. Every write path refuses one (``append`` stamps
                with ``float()`` and :meth:`_require_monotonic` refuses a
                non-finite stamp), so it was written outside this platform.
                Both branches used to convert with ``float()``, which raised a
                bare ``ValueError`` for text — ``sli`` graded three indicators
                "the probe raised" — and accepted the rest silently: a BLOB
                ``b'1.5'``, ``nan`` and ``±inf``. A ``nan`` mark disabled every
                comparison made against it, measured twice: an append behind
                every stored row succeeded, and ``scripts/run_retention.py
                --apply`` skipped its clock-fault guard and deleted 5 of 10
                events at exit 0, where the same store with an intact mark is
                refused at exit 2. In the fallback, SQLite sorts TEXT and BLOB
                above every REAL, so one such ``ingested_at`` is the ``MAX``
                however many good rows sit beside it. The message names the
                type or the infinity, never the stored text. Also for a stored
                mark below the newest stored ``ingested_at``, and for a newest
                ``ingested_at`` that is not a finite number even when a valid
                mark is stored: every write raises the mark with its rows under
                the write lock :meth:`_begin_write` takes, so neither is
                produced by any write path.
        """
        # One statement, so one snapshot. Two autocommit SELECTs each took their
        # own, and a collector committing between them made a healthy store
        # read as tampered: the old mark beside the new MAX. Found by review and
        # reproduced. A read transaction cannot do this job, because this runs
        # inside `_begin_write`'s transaction and `attest`'s snapshot too.
        # `meta.value` is NOT NULL, so a NULL `stored` means no row.
        both = self._conn.execute(
            "SELECT (SELECT value FROM meta WHERE key = ?) AS stored, "
            "(SELECT MAX(ingested_at) FROM events) AS newest",
            (HIGH_WATER_KEY,),
        ).fetchone()
        stored: float | None = None
        if both["stored"] is not None:
            try:
                stored = _stored_mark(both["stored"])
            except (TypeError, ValueError) as exc:
                raise StoreIntegrityError(
                    f"the stored {exc}; every write path refuses that, so the "
                    "database was modified outside this platform"
                ) from exc
        newest: float | None = None
        if both["newest"] is not None:
            try:
                newest = _finite(both["newest"], "the newest ingested_at")
            except (TypeError, ValueError) as exc:
                prefix = "" if stored is not None else "no high-water mark is stored, and "
                raise StoreIntegrityError(
                    f"{prefix}{exc}; every write path refuses that, so the "
                    "database was modified outside this platform"
                ) from exc
        if stored is None:
            return newest
        # A mark above the rows is legitimate: retention prunes rows and the
        # mark outlives them. A mark BELOW the rows is not. Every write raises
        # the mark in the transaction that stores its rows, under the write
        # lock `_begin_write` takes, so no write path leaves one; and obeying
        # it lets the next write land behind rows a cursor may have passed.
        if newest is not None and stored < newest:
            raise StoreIntegrityError(
                f"the stored high-water mark {stored!r} is below the newest stored "
                f"ingested_at {newest!r}; every write raises the mark with the rows "
                "it stores, so the database was modified outside this platform"
            )
        return stored

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

    def _begin_write(self) -> None:
        """Take the write lock before the high-water mark is read.

        ``_require_monotonic`` reads the mark and the caller then inserts, and
        the two are one decision only if no other writer can commit between
        them. The connection's default transaction handling did not make them
        one: it opens a transaction before an ``INSERT`` and never before a
        ``SELECT``, so the mark was read outside the transaction its insert
        then opened. Measured with two connections on one store, a second
        writer committed at 200 between the first writer's check at 150 and
        its insert. Both succeeded, a row at 150 landed behind a stored row at
        200, and the stored mark regressed to 150, below the rows it covers.
        ``IMMEDIATE`` takes the write lock up front, so a second writer waits
        (``SQLITE_BUSY`` after the busy timeout, which the collector already
        treats as retryable) instead of interleaving.

        The only first-party writer, the collector, holds a single-instance
        lock, so this was not reachable from a scheduled pass. It is closed
        here because the store is the boundary that outlives any one caller,
        and because :meth:`high_water_mark` now refuses a mark below the rows:
        that refusal is only sound if no write path can produce one.
        """
        self._conn.execute("BEGIN IMMEDIATE")

    def _require_monotonic(self, ingested_at: float) -> None:
        """Refuse a write that would land behind the high-water mark.

        Checked inside the caller's write transaction, which
        :meth:`_begin_write` opened before this read, and before any insert,
        so a refused batch leaves the database exactly as it was.
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
                read path refuses the same projections and carries this same
                error as its ``__cause__``, so "append refuses exactly what
                query refuses" is still one assertion. What differs is the
                class around it. On write, the fault is the caller's event,
                which is a value error. On read, it is a row the store holds,
                which :func:`_rebuild` raises as :class:`StoreIntegrityError`
                because every ``query`` caller already handles a
                ``StoreError``, and a reader error escaping from a store call
                is how ``store-readable`` graded its own headline failure
                ``UNKNOWN``.
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
        All three statements below are covering-index scans — measured, with
        ``EXPLAIN QUERY PLAN`` on SQLite 3.45.1: the id stream is ``SCAN events
        USING COVERING INDEX sqlite_autoindex_events_1``, the counts are ``SCAN
        events USING COVERING INDEX events_ingested_at`` and ``SCAN observables
        USING COVERING INDEX observables_value``, and the observables stream
        added for ``observables_digest`` is ``SCAN observables USING COVERING
        INDEX sqlite_autoindex_observables_1`` (the primary key is
        ``(event_id, value)``, so the index holds both columns). None touches
        a row, and ``tests/unit/test_event_store.py`` pins all four plans
        rather than leaving them as prose here. Zeroing
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

        **Everything below reads one snapshot.** The verdict, the counts, the
        id stream, the observables stream and the mark are separate
        statements, and without an enclosing transaction each took its own.
        Measured through this method: a writer's commit landing between the
        count statement and the first step of the id stream gave ``COUNT(*)``
        200 against 201 streamed ids and raised the inconsistency error below
        — a damage verdict on a healthy store, reachable by
        ``scripts/run_backup.py --verify-restore`` on a live root, whose
        ``backup.lock`` excludes no writer. The observables stream has the same
        shape against its own count. A deferred ``BEGIN`` in WAL mode blocks
        nobody: the snapshot opens at the first read and ends at the commit the
        ``with`` performs.

        Raises:
            StoreCorruptionError: if the database file is damaged.
            StoreIntegrityError: if the count and the id stream disagree, or a
                stored ``event_id`` is not ASCII. The message gives the id's
                length and never the id.
        """
        with self._conn:
            self._conn.execute("BEGIN")
            return self._attest_in_snapshot()

    def _attest_in_snapshot(self) -> Attestation:
        """Every read :meth:`attest` makes, run inside the snapshot it opened.

        Split out so the whole body sits in one transaction without
        re-indenting it. Called only by :meth:`attest`, whose
        ``_refuse_corruption`` boundary covers it.
        """
        self.verify_integrity()
        counts = self._conn.execute(ATTEST_COUNTS_SQL).fetchone()
        events = int(counts["events"])
        running = hashlib.sha256()
        # The count goes into the preimage first, so a prefix of one store's
        # ids cannot digest the same as another store's whole set.
        running.update(f"{DIGEST_PREFIX}{events}\n".encode())
        streamed = 0
        for row in self._conn.execute(ATTEST_IDS_SQL):
            identifier = str(row["event_id"])
            try:
                encoded = identifier.encode("ascii")
            except UnicodeEncodeError:
                # Measured: a valid-UTF-8, non-ASCII id written outside the API
                # (`"é" * 64`) escaped as a bare UnicodeEncodeError, which no
                # `except StoreError` catches. The backup CLI's handlers reached
                # it only because that class subclasses ValueError, and printed
                # the codec's sentence. Every id this store writes is a sha256
                # hex digest. Suppressed rather than chained, because the
                # error's `object` is the stored id, which a forged row chooses.
                raise StoreIntegrityError(
                    f"a stored event_id ({len(identifier)} characters) is not ASCII; every "
                    "id this store writes is a sha256 hex digest, so the database was "
                    "modified outside this platform"
                ) from None
            running.update(encoded)
            running.update(b"\n")
            streamed += 1
        if streamed != events:
            raise StoreIntegrityError(
                f"attestation is inconsistent: the digest commits to {events} event(s) "
                f"but {streamed} id(s) were read. The count and the id scan are separate "
                "statements and disagreed, so this store cannot be attested."
            )

        # The observables, committed to by content and not only by count. Each
        # field is framed as storage class, byte length and raw bytes: `value`
        # is free text an indicator regex matched, so a separator could appear
        # inside one; and the column is only TEXT by affinity, so a hostile or
        # damaged copy can hold a BLOB there whose str() collides with a real
        # value (found by independent review before this shipped). A digest
        # whose row boundaries or storage classes a value can forge is not a
        # commitment to the rows. Never decoded as text, so bytes that are not
        # UTF-8 attest rather than abort. Sorted by the primary key so a copy
        # that differs in layout attests identically.
        observables = int(counts["observables"])
        running_observables = hashlib.sha256()
        running_observables.update(f"{OBSERVABLES_DIGEST_PREFIX}{observables}\n".encode())
        streamed_observables = 0
        for row in self._conn.execute(ATTEST_OBSERVABLES_SQL):
            for kind, raw in (
                (row["kind_id"], row["raw_id"]),
                (row["kind_value"], row["raw_value"]),
            ):
                # kind is one of SQLite's five storage-class names, so it
                # carries no digit or colon and cannot run into the length.
                payload = b"" if raw is None else bytes(raw)
                running_observables.update(f"{kind}:{len(payload)}:".encode("ascii"))
                running_observables.update(payload)
            running_observables.update(b"\n")
            streamed_observables += 1
        if streamed_observables != observables:
            raise StoreIntegrityError(
                f"attestation is inconsistent: the observables digest commits to "
                f"{observables} row(s) but {streamed_observables} were read. The count and "
                "the row scan are separate statements and disagreed, so this store cannot "
                "be attested."
            )
        return Attestation(
            events=events,
            observables=observables,
            digest=running.hexdigest(),
            observables_digest=running_observables.hexdigest(),
            high_water=self.high_water_mark(),
            schema_version=SCHEMA_VERSION,
        )

    @_refuse_corruption
    def count_before(self, *, before: float, after: tuple[float, str] | None = None) -> int:
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

        ``after`` narrows the count to events strictly after an
        ``(ingested_at, event_id)`` pair — the pipeline cursor's own total
        order, the one :data:`Query.ingested_after` pages with. A *pair* for
        the reason that field documents: :meth:`append_many` stamps one
        ``ingested_at`` across a whole commit, so a bound on the timestamp
        alone cannot say where inside that commit a reader has got to.
        Subtracting two timestamp counts instead over-counts by the part of
        the cursor's own commit the reader has already passed — measured at 40
        of 40 on a single-commit node whose cycle was demonstrably caught up,
        and at 21 of a 40-row commit with the cursor at its midpoint, where
        the true figure was 19. ``sli/indicators.py`` met that defect (2
        reported against a true 0) and answered it with a *bounded* query,
        ``limit=target+1``: enough to grade an objective against a target, and
        not enough for ``scripts/run_retention.py``, which has to state an
        exact figure over a window that can hold the whole store — and to keep
        stating it when a projection will not parse, which is the same reason
        this is a ``COUNT`` at all. So the keyset belongs here too.

        **The two forms are not equally blind to damage, and the difference is
        fail-closed.** Measured by zeroing each of 19 pages of a seeded store
        in turn: on 5 of them the plain count returned a plausible figure
        while the keyset form raised :class:`StoreCorruptionError`, because
        ``events_ingested_at`` covers ``(ingested_at)`` alone, so the plain
        count plans a COVERING index scan and the keyset form plans a
        MULTI-INDEX OR that reaches table pages. The keyset form is therefore
        strictly *less* blind, which is the safe direction; and
        :meth:`verify_integrity` raised on all 18 damaged pages regardless, so
        a caller that verifies first — ``scripts/run_retention.py`` does —
        sees the damage either way. No composite index is added and
        ``SCHEMA_VERSION`` is untouched: the plan reuses
        ``events_ingested_at``, as :data:`_ORDER_NEWEST` requires of any
        change here.

        Security consideration: the statement is concatenated from the module
        literals at the foot of this file and nothing else, and ``after``'s
        values travel as bound parameters. That is now asserted and not only
        written down. This docstring used to disclaim the test — the AST check
        of the day matched three interpolation constructs at the site where
        the SQL literal was written, so a caller value concatenated on with
        ``+`` passed it, measured on exactly this method. The check asserts
        provenance at the ``execute`` call instead, so the ``+`` above is
        verified to join two module constants rather than merely intended to.

        Raises:
            TypeError: for a threshold or keyset bound that is not a real
                number; ``ValueError`` for one that is not finite. Both come
                from :func:`_finite`, which converts once and binds the value
                it checked, and :meth:`prune` goes through the same function —
                so report and apply refuse the same inputs by construction,
                not by two checks kept in step.
        """
        statement = _COUNT_BEFORE
        params: list[float | str] = [_finite(before, "retention threshold")]
        if after is not None:
            at, identifier = after
            bound = _finite(at, "keyset bound")
            statement = _COUNT_BEFORE + _AND + _INGESTED_AFTER
            params.extend((bound, bound, identifier))
        row = self._conn.execute(statement, tuple(params)).fetchone()
        return int(row["n"])

    @_refuse_corruption
    def query(self, spec: Query = ALL) -> tuple[StoredEvent, ...]:
        """Return matching events, newest first by default.

        The ``limit`` is clamped to :data:`store.schema.MAX_QUERY_LIMIT` rather
        than honored, and a non-positive limit yields nothing rather than
        everything — a caller computing a limit arithmetically should get an
        empty page from a bad computation, not the whole store. The time
        bounds are checked first, so an empty limit cannot hide a bad window.

        Raises:
            ValueError: for a time bound that is not finite — ``since``,
                ``until``, ``ingested_from``, or the timestamp of either keyset
                pair. Measured on five stored events, before this check: NaN in
                any of the five returned **0** rows, because SQLite binds NaN as
                NULL and a comparison with NULL matches nothing, and so did an
                infinity on the closed side of a bound (``since=inf``,
                ``until=-inf``). A caller that computed a bad window read "nothing
                happened" from it. The open-side infinities returned all five,
                which is what leaving the field unset already says, so refusing
                every non-finite bound costs no expressiveness and leaves no
                direction-dependent rule to remember. The shape is the one
                :meth:`prune` and :meth:`count_before` use for their thresholds.
            TypeError: for a time bound that is not a real number. ``float()``
                parsed text, so ``since="5"`` used to be read as ``5.0``. And
                for a ``limit`` that is not an integer by the index protocol.
                Measured before: NaN and ``2.5`` raised a raw
                ``sqlite3.IntegrityError`` ("datatype mismatch"), the class
                :func:`_refuse_corruption` reserves for the append-only trigger
                firing; ``inf`` was taken silently as the ceiling; text and
                ``None`` failed on a comparison; and ``5.0`` worked by
                accident. A float is refused whatever its value, since a count
                typed ``int`` that took ``5.0`` and refused ``5.5`` would be a
                rule about values posing as one about types. A ``bool`` is
                refused too, although it has ``__index__``: ``True`` read one
                row and ``False`` none.
        """
        # `bool` first, because it has `__index__`: measured, `limit=True` read
        # one row and `limit=False` none, so a flag passed in the wrong place
        # read as a quiet period rather than as the caller's bug.
        if isinstance(spec.limit, bool):
            raise TypeError("limit must be an integer, not bool")
        # The index protocol, once, and the value it returned is the value used,
        # for the reason `_finite` converts once.
        try:
            requested = operator.index(spec.limit)
        except TypeError:
            raise TypeError(f"limit must be an integer, not {type(spec.limit).__name__}") from None
        limit = min(requested, MAX_QUERY_LIMIT)
        clauses: list[str] = []
        params: list[Any] = []
        # Each fragment below is a literal; only values are bound. There is no
        # path by which caller input becomes SQL text.
        # Every time bound goes through `_finite`, which converts once and binds
        # the value it checked, so a keyset bound is no longer converted twice
        # for its two placeholders.
        if spec.since is not None:
            clauses.append("e.occurred_at IS NOT NULL AND e.occurred_at >= ?")
            params.append(_finite(spec.since, "since"))
        if spec.until is not None:
            clauses.append("e.occurred_at IS NOT NULL AND e.occurred_at < ?")
            params.append(_finite(spec.until, "until"))
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
            bound = _finite(at, "ingested_after")
            params.extend((bound, bound, identifier))
        if spec.ingested_before is not None:
            # Strictly before the pair, in the same total order as the ORDER BY.
            clauses.append(_INGESTED_BEFORE)
            at, identifier = spec.ingested_before
            bound = _finite(at, "ingested_before")
            params.extend((bound, bound, identifier))
        if spec.ingested_from is not None:
            # Inclusive, so the lower edge of a lookback window is not itself
            # the thing that falls out of it.
            clauses.append(_INGESTED_FROM)
            params.append(_finite(spec.ingested_from, "ingested_from"))
        if spec.observable is not None:
            clauses.append(
                "EXISTS (SELECT 1 FROM observables o WHERE o.event_id = e.event_id AND o.value = ?)"
            )
            params.append(spec.observable)
        # After the bounds, not before: an empty limit returned first used to
        # hide a NaN window behind `()`, the silence the checks above refuse.
        if limit <= 0:
            return ()
        # The statement is assembled only from literals declared in this
        # module: _SELECT, the _PREDICATE fragments, and one of two _ORDER
        # constants. No caller value is ever concatenated into SQL text — the
        # values travel as bound parameters, and the AST check in
        # tests/security/test_store_hardening.py requires the text handed to
        # execute() to be traceable to those literals. It follows this exact
        # shape: the clause list, _EQUALITY keyed at runtime, the _ORDER
        # choice, and the two joins. A fragment appended here that is not a
        # literal of this module fails that check, whatever construct puts it
        # there.
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

        Raises:
            ValueError: for a non-finite threshold, exactly as
                :meth:`count_before` does. Measured before this check, on
                three stored events: ``prune(before=inf)`` deleted all three
                and ``prune(before=nan)`` deleted none, both silently, after
                ``count_before`` had raised for the same value — so the report
                could refuse a threshold whose delete still went through.
                Retention is report-then-apply, and the two halves must refuse
                the same inputs. The write-side twin of a read-side bound: the
                defect class :meth:`_project` already records.

                "Exactly as" is by construction: both go through
                :func:`_finite`, which converts once and binds the value it
                checked. The first version of this check converted twice —
                ``math.isfinite(before)`` and then ``float(before)`` — and an
                object whose ``__float__`` answered ``1.0`` first and ``inf``
                second passed it; the DELETE ran with ``inf``. Measured, three
                events to zero. Found by review.
            TypeError: for a threshold that is not a real number, as before.
        """
        threshold = _finite(before, "retention threshold")
        with self._conn:
            cursor = self._conn.execute("DELETE FROM events WHERE ingested_at < ?", (threshold,))
        return int(cursor.rowcount)


#: The query's fixed pieces. Declared as constants so that every character of
#: every statement this module runs is traceable to a literal written here.
_SELECT = "SELECT event_id, ingested_at, projection FROM events e"
#: Keyset pagination: strictly after ``(ingested_at, event_id)``.
_INGESTED_AFTER = "(e.ingested_at > ? OR (e.ingested_at = ? AND e.event_id > ?))"
#: Retention's reporting count. Aliased ``events e`` so :data:`_INGESTED_AFTER`
#: can be appended to it verbatim instead of being written out a second time:
#: two spellings of one total order is how the two come to disagree.
_COUNT_BEFORE = "SELECT COUNT(*) AS n FROM events e WHERE e.ingested_at < ?"
#: The only joiner either count uses. A literal, like every other fragment
#: here, so no statement this module runs is built by interpolation.
_AND = " AND "
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


#: An ``event_id`` as :func:`store.schema.event_id` writes it: a sha256
#: ``hexdigest``, which is lowercase. ``[0-9a-f]`` and ``fullmatch`` for the
#: reasons :data:`_VERSION_TEXT` gives: ``\d`` matches every Unicode digit, and
#: ``$`` accepts a trailing newline.
_EVENT_ID_TEXT = re.compile(r"[0-9a-f]{64}")


def _id_mismatch_refusal(raw: object) -> str:
    """The message for a row whose projection does not hash to its stored ``event_id``.

    The id is named only when it has the shape every id this store writes
    has. Then it is the key an operator finds the row by, and 64 hex
    characters can carry nothing else. Anything else is described by type and
    length and never echoed. That is the allow-list :func:`_version_refusal`
    uses, for the same reason: a length bound alone would still copy what a
    forged row chose. This is the one :func:`_rebuild` message whose id a
    forged row writes, because the other three run after the hash matched,
    when the id is :func:`event_id`'s own output.

    Measured before this change: a forged ASCII id of 50,008 characters made
    a 50,105-character refusal from :meth:`EventStore.query`, which
    ``sli.measure_store_readable`` copies into its detail (50,152
    characters). And a short value did harm without any length: an id of
    ``"\\x1b[2J"`` put a raw ESC into that detail, which
    ``scripts/report_sli.py`` wrote to the terminal.

    ``event_id`` is ``TEXT ... NOT NULL``, and TEXT affinity converts a number
    to text on the way in, so text and a BLOB are the only shapes SQLite can
    return here.
    """
    if isinstance(raw, str) and _EVENT_ID_TEXT.fullmatch(raw):
        return (
            f"event {raw}: projection does not hash to its event_id; the database was "
            "modified outside this platform"
        )
    if isinstance(raw, str):
        shape = f"{len(raw)} character(s) of text that is not a lowercase sha256 hex digest"
    elif isinstance(raw, bytes):
        shape = f"a BLOB of {len(raw)} byte(s)"
    else:  # pragma: no cover - TEXT affinity and NOT NULL leave only text and BLOB
        shape = f"a value of type {type(raw).__name__}"
    return (
        f"a stored event_id is {shape}, which no build of this platform writes, and its "
        "projection does not hash to it; the database was modified outside this platform"
    )


def _rebuild(row: sqlite3.Row) -> StoredEvent:
    """Rebuild one row, verifying it is what this store wrote.

    A projection that will not rebuild is a :class:`StoreIntegrityError`,
    including one that hashes to its ``event_id`` and still fails the reader.
    That case used to escape as the reader's own ``MalformedProjectionError``
    — an ``IngestError``, not a ``StoreError`` — so
    ``sli.measure_store_readable``, whose objective exists for exactly this
    row, missed it in its ``except``, and the report graded the store
    ``UNKNOWN`` with "the probe raised MalformedProjectionError": fail closed,
    but "could not measure" where the truth was "measured and failing".
    Mapped here and not in the monitor, for the reason ``StoreCorruptionError``
    was: a monitor catching a lower layer's error type through the store is
    the wrong shape, and ``measure_detection_backlog`` and ``run_cycle`` read
    through the same ``query``.

    A matching hash does not prove the row is this platform's. ``event_id`` is
    an unkeyed sha256, so anyone who can write the file can recompute it. A row
    that passes the hash and fails the reader was written by an earlier build
    that lacked :meth:`EventStore._project`'s read-back, or written outside the
    API. The reader's error is kept as ``__cause__``, and its sentence goes into
    the message, bounded by :func:`_rebuild_reason`.

    A hash that does *not* match means the stored ``event_id`` is not this
    store's output, so that refusal names it only through
    :func:`_id_mismatch_refusal`'s allow-list.

    Only ``MalformedProjectionError`` is mapped, because it is the one refusal
    ``from_dict`` documents. Anything else it raises is a defect in the reader
    and surfaces as itself.

    The same holds for ``ingested_at``, the one column read here that the hash
    does not cover: a value that is not a finite number is a
    :class:`StoreIntegrityError`, not a bare ``ValueError`` from ``float()``.
    """
    projection = str(row["projection"])
    stored_id = row["event_id"]
    identifier = str(stored_id)
    if event_id(projection) != identifier:
        # The id is whatever a row written outside the API holds, so it goes
        # through the allow-list. Every message below names it as-is, because
        # by then it equals `event_id(projection)`.
        raise StoreIntegrityError(_id_mismatch_refusal(stored_id))
    try:
        payload = json.loads(projection)
    except (ValueError, RecursionError) as exc:
        # RecursionError is json's own and not a ValueError. Measured: a
        # hash-valid projection of 100,000 nested `[` escaped as one on 3.11,
        # 3.12 and 3.13, which the report graded "the probe raised". "Does not
        # decode" rather than "is not JSON", because that projection is JSON:
        # RFC 8259 lets a parser limit nesting, and this one does.
        raise StoreIntegrityError(
            f"event {identifier}: projection does not decode as JSON ({type(exc).__name__})"
        ) from exc
    try:
        event = NormalizedEvent.from_dict(payload)
    except MalformedProjectionError as exc:
        raise StoreIntegrityError(
            f"event {identifier}: projection hashes to its event_id but does not "
            f"rebuild: {_rebuild_reason(exc)}"
        ) from exc
    # The one column read here that the hash does not cover. Through `_finite`
    # rather than `float()`, because `float()` both raised and accepted the
    # wrong things. Measured on rows inserted outside the API: TEXT 'x' and a
    # BLOB b'x' raised a bare ValueError, which `sli` graded "the probe
    # raised", while a BLOB b'1.5' parsed silently as 1.5 and +/-inf read
    # back as stamps. Every write path refuses all of them (`append` stamps
    # with `float()` and `_require_monotonic` refuses a non-finite stamp), and
    # SQLite stores NaN as NULL, which NOT NULL refuses. So each one is a
    # corrupt row, and `_finite` refuses each: TypeError for text and bytes,
    # ValueError for an infinity. Its message names the type or the infinity
    # and never the stored text, which a forged row chooses.
    try:
        ingested_at = _finite(row["ingested_at"], "ingested_at")
    except (TypeError, ValueError) as exc:
        raise StoreIntegrityError(
            f"event {identifier}: {exc}; every write path refuses that, so the "
            "database was modified outside this platform"
        ) from exc
    return StoredEvent(event_id=identifier, ingested_at=ingested_at, event=event)
