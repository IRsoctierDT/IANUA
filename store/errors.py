# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Event-store error taxonomy.

Imports nothing first-party, so the layering is structural and nothing below
this module can create an import cycle — the same discipline as
``ingest/errors.py`` and ``attack/errors.py``.

Every failure here is fail-closed by intent. An event store that silently
accepts a bad path, an unreadable row, or a schema it does not understand
would produce an analysis built on a partial view of history, and a partial
view presented as complete is the blind spot this layer exists to close.
"""

from __future__ import annotations


class StoreError(Exception):
    """Base class for event-store failures."""


class StorePathError(StoreError):
    """The requested store path is outside the permitted root, or unusable.

    Raised before any file is opened. The store writes under the gitignored
    lab-data root; a path that escapes it (``..``, an absolute path elsewhere,
    a symlink out) is refused rather than normalized, because silently
    relocating a security-evidence database is not a repair.
    """


class StoreSidecarError(StorePathError):
    """A file SQLite would open beside the database is not one it may open.

    SQLite opens ``-journal``, ``-wal`` and ``-shm`` *by name* beside the
    database, so whoever can create a name in the events directory chooses
    what the store's own open reads and writes. Measured through every CLI
    that opens the live store, before this check or the backup CLI's own
    ``_sidecar_problem`` existed: a FIFO
    ``-journal`` hung the collector, the pipeline, retention, the backup take
    and the SLI reporter inside SQLite's open, and the four that hold a
    single-instance lock held it while blocked, so every later scheduled pass
    printed "skipped" at exit 0. A ``-shm`` hard-linked to another file had
    that file truncated and rewritten as 32 KiB of WAL index by every one of
    them and by the read-only backup verifier, which still reported every
    digest matching at exit 0. A hard-linked ``-wal`` had its other name
    overwritten with WAL frames by the collector and the take, both at exit 0.
    A FIFO ``-wal`` was deleted.

    A subclass of :class:`StorePathError` because it is the same refusal:
    raised before any file is opened, and every first-party handler catches
    :class:`StoreError`, so no caller changes. ``suffix`` and ``problem`` are
    kept separately so a caller that reports rather than raises can phrase the
    finding in its own terms without parsing the message.
    """

    def __init__(self, message: str, *, suffix: str, problem: str) -> None:
        super().__init__(message)
        self.suffix = suffix
        self.problem = problem


class SchemaVersionError(StoreError):
    """The database was written by a different schema version.

    There is deliberately no implicit migration. ``NormalizedEvent.from_dict``
    requires an exact key match, so reading rows written under another schema
    would either raise per-row or — worse, if the change were additive in the
    other direction — reconstruct events with silently missing fields. A
    version mismatch is therefore a refusal with both versions named, and
    migration is an explicit, reviewed operation.
    """


class StoreIntegrityError(StoreError):
    """A stored row is not what this store wrote.

    Covers a projection whose content hash does not match its ``event_id``,
    and a row whose JSON will not decode. Both mean the database was modified
    outside this platform. The store surfaces that instead of skipping the
    row, because a query that quietly returns fewer events than history holds
    is indistinguishable to the caller from a quiet period.

    Also covers a projection that hashes correctly and still will not rebuild:
    a field past its bound, the case ``DESIGN.md`` §11 records stopping every
    detection cycle on a store. A matching hash does not settle provenance,
    because ``event_id`` is an unkeyed sha256 that anyone who can write the
    file can recompute. So such a row was written by an earlier build that
    lacked the write-side read-back, or written outside the API. The reader's
    ``MalformedProjectionError`` is its ``__cause__``. It used to reach callers
    bare, and as an ``IngestError`` it slipped past every ``except
    StoreError``, including the ``store-readable`` probe that exists for it.
    """


class StoreCorruptionError(StoreIntegrityError):
    """The database file itself is damaged, not a row inside it.

    A subclass rather than a sibling, deliberately. Every first-party caller
    outside ``store/`` catches :class:`StoreError`, so subclassing changes no
    handler, and ``sli/indicators.py`` promises in prose that ``store/`` raises
    :class:`StoreIntegrityError` for a malformed database — subclassing keeps
    that literally true by ``isinstance`` while making the type name itself the
    diagnostic.

    The distinction is a runbook branch, which is why it earns a class.
    :class:`StoreIntegrityError`'s own docstring is about a *row* that "was
    modified outside this platform" — investigate it. A zeroed b-tree page is
    a truncated transfer or a half restore — restore from a backup and verify
    it with ``scripts/run_backup.py``. Those are different actions, and the
    parent class was already carrying three meanings across six raise sites
    before this one.

    Raised only for SQLite's two corruption verdicts, ``SQLITE_CORRUPT`` (11,
    "database disk image is malformed") and ``SQLITE_NOTADB`` (26, "file is not
    a database"), both measured. Everything else SQLite raises keeps its own
    meaning: see ``store/events.py``'s mapping predicate for why
    ``IntegrityError`` (the append-only trigger firing), ``ProgrammingError``
    (a caller bug) and ``SQLITE_BUSY`` (lock contention) must not become this.
    """


class IngestionOrderError(StoreError):
    """A write would place an event before one already ingested.

    The pipeline pages by a ``(ingested_at, event_id)`` keyset, so an event
    stamped *earlier* than the highest already stored would sit behind a cursor
    that has already passed — and would never be read, by any cycle, ever. That
    is silent data loss in the one layer whose purpose is not having blind
    spots, which is why it is refused at write time rather than documented as a
    contract on callers.

    Note what this does **not** contradict. The store is idempotent in
    *content*: re-appending an identical event is a no-op. It is strict in
    *ingestion order*: a replay claiming it was ingested at the original time is
    making a false claim the second time round, because it is being ingested
    now. A replay that stamps the current time succeeds and stores nothing new,
    which is the honest form of the same operation.
    """
