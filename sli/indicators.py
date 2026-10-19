# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""One measurement per objective, each read-only and each failing closed.

Every function here answers one question about durable state under the
lab-data root and returns a :class:`Measurement`: a number, or ``None`` when
the signal could not be read, plus a sentence saying which. ``None`` grades
``UNKNOWN`` in :mod:`sli.objectives`, and ``UNKNOWN`` is not a pass — that is
the whole posture of this package. ``DESIGN.md`` §11 records three signals
that read healthy while the subsystem behind them was not, and the sentence
written there is the brief for this module: an SLI computed over a signal that
fails open measures nothing.

Security considerations, all three load-bearing:

* **Nothing outside the lab-data root is touched.** Not even a ``stat``. The
  obvious way to measure collection backlog is to compare each declared
  source's recorded offset against the file's current size, which means
  reaching out to log paths that live wherever the operator's logs live —
  §5 licenses that reach for ``collect/`` specifically, read-only and
  declared-only, and extending it to a new package would be an amendment
  rather than an implementation. It is not needed: ``Position`` already
  records the ``size`` the collector itself observed, so the backlog is
  computed from a file under ``data/`` and the question never arises.
  ``tests/security`` asserts no path outside the root is opened or stat'ed.
* **Nothing is created.** ``EventStore.open`` *creates* the database and its
  directories if they are absent — correct for a collector, wrong for a
  monitor, and in combination with a mistyped ``--root`` it would build a
  shadow tree and then report it healthy. So the store file's existence is
  checked before it is opened, and every other artifact is read through a
  loader that returns absent rather than initialising.
* **No clock, no network, no subprocess.** ``now`` is a parameter, so these
  functions are pure over (root, now) and a test can place the clock
  anywhere. ``tests/security`` pins all three.
"""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from agents.policies.audit import AuditLogger, verifier_from_env
from collect import OffsetError, Position, load_offsets, offsets_path
from pipeline import CursorError, cursor_path, load_cursor
from sli.objectives import BY_ID
from store import (
    DEFAULT_FILENAME,
    EVENTS_SUBDIR,
    MAX_QUERY_LIMIT,
    EventStore,
    Query,
    StoreError,
    StoreIntegrityError,
)

#: The hash chains under the lab-data root, relative to it.
#:
#: Declared, not discovered, for the reason ``scripts/run_backup.py`` gives for
#: its own identical list: a walk eventually finds a file somebody put there
#: for another purpose. The two lists **must agree**, and a unit test asserts
#: it rather than a comment asking — four copies is how three stay fixed and
#: one does not, which is a defect shape this repository has already paid for.
#: ``sli`` declares its own rather than importing ``scripts.run_backup``
#: because a package importing a CLI inverts the layering.
CHAIN_FILES: tuple[Path, ...] = (
    Path("data") / "collect" / "audit.log",
    Path("data") / "events" / "audit.log",
    Path("data") / "pipeline" / "audit.log",
    Path("data") / "compliance" / "audit.log",
)

#: Where ``scripts/run_backup.py`` writes a backup, relative to the root.
BACKUP_SUBDIR = Path("data") / "backups"
MANIFEST_FILE = "manifest.json"

#: How many rows the readability probe reads from each end of the store. A
#: sample, not a scan: an unreadable row in the middle of a large store is not
#: detected, and saying so is better than a probe that costs a full table scan
#: every five minutes and still only proves the rows it read.
READABILITY_SAMPLE = 50


@dataclass(frozen=True, slots=True)
class Measurement:
    """A number and why, or ``None`` and why not."""

    value: float | None
    detail: str


def _store_path(root: Path) -> Path:
    """Where the event store lives, without creating it."""
    return root / EVENTS_SUBDIR / DEFAULT_FILENAME


def _high_water_mark(root: Path) -> tuple[float | None, str | None]:
    """The newest ``ingested_at`` in the store, or a reason there is none.

    Returns ``(mark, problem)`` where exactly one is set. Shared by three
    indicators so the store is opened once per question rather than three
    times with three slightly different existence checks.
    """
    path = _store_path(root)
    if not path.is_file():
        return None, f"no event store at {path.relative_to(root)}"
    try:
        with EventStore.open(root) as store:
            mark = store.high_water_mark()
    except (StoreError, OSError) as exc:
        return None, f"the event store could not be opened ({type(exc).__name__})"
    if mark is None:
        return None, "the event store holds no events yet"
    return mark, None


def measure_collection_pending(root: Path, now: float) -> Measurement:
    """Bytes the collector had seen and not yet consumed when it last ran.

    Computed from ``Position.size`` minus ``Position.offset``, both recorded
    by the collector in ``data/collect/offsets.json``. That is deliberately
    *not* the same as "bytes pending right now": it does not see growth since
    the last pass, and it cannot, without reaching outside the lab root. What
    it does see is the condition that matters — a source the collector read
    and could not finish, which is what a permanently stalled source looks
    like from inside.

    A corrupt offsets file is ``UNKNOWN`` rather than zero: ``load`` refuses
    it deliberately, because "never collected" and "position lost" demand
    different responses. One corruption *parses*, though, and used to read as
    the healthiest possible answer: an ``offset`` past the recorded ``size``
    made ``max(0, size - offset)`` zero, so the report said "all source(s)
    fully read at the last pass" — byte-identical to a caught-up collector.
    Measured, not argued. It is now ``UNKNOWN``, which is what this
    docstring claimed all along.

    The refusal is here and **not** in ``load_offsets``, deliberately. A
    collector handed that file is not harmed by it: ``collect/tail.py``
    ``_resume_from`` already returns ``(0, "truncated")`` whenever the file is
    shorter than the stored offset, so the pass self-heals and reports why.
    Pushing the check down into the loader would turn a case the collector
    recovers from into a refused pass — fail-closed applied to the one layer
    that was already right. The collector never *writes* this state, so inside
    the monitor it only ever means the file was damaged or hand-edited.
    """
    del now  # Not a time-based measurement; the signature is uniform.
    path = offsets_path(root)
    try:
        positions: dict[str, Position] = load_offsets(path)
    except (OffsetError, OSError) as exc:
        return Measurement(None, f"offsets are unreadable ({type(exc).__name__})")
    if not positions:
        return Measurement(None, "no collector pass has recorded a position yet")
    impossible = sorted(
        key.rsplit("/", 1)[-1]
        for key, position in positions.items()
        if position.offset > position.size
    )
    if impossible:
        return Measurement(
            None,
            f"{len(impossible)} of {len(positions)} source(s) record an offset past "
            f"the size observed with it: {', '.join(impossible[:4])}; the collector "
            "never writes that, so the position file is damaged",
        )
    pending = sum(max(0, position.size - position.offset) for position in positions.values())
    behind = [
        key.rsplit("/", 1)[-1]
        for key, position in sorted(positions.items())
        if position.size > position.offset
    ]
    if behind:
        return Measurement(
            float(pending),
            f"{pending} byte(s) unread across {len(behind)} of {len(positions)} "
            f"source(s) at the last pass: {', '.join(behind[:4])}",
        )
    return Measurement(0.0, f"all {len(positions)} declared source(s) fully read at the last pass")


def measure_ingest_freshness(root: Path, now: float) -> Measurement:
    """Seconds since the newest event was stored."""
    mark, problem = _high_water_mark(root)
    if mark is None:
        return Measurement(None, problem or "unmeasurable")
    age = now - mark
    if age < 0:
        # The store's newest stamp is in the future relative to the clock this
        # measurement was given. Something is wrong with one of them, and
        # grading a negative age against an "at most" target would pass.
        return Measurement(
            None,
            f"the newest event is stamped {-age:.0f}s in the future; "
            "the store's clock and this measurement's disagree",
        )
    return Measurement(age, f"newest event stored {age:.0f}s ago")


def measure_detection_lag(root: Path, now: float) -> Measurement:
    """Seconds of stored time the detection cycle has not reached yet.

    Lag in the *data*, not time since a run: a cycle firing on schedule and
    processing nothing still breaches, which is the failure a "last run at"
    timestamp cannot see.

    A cursor *ahead* of the store's high-water mark grades ``UNKNOWN``, not
    met. ``docs/RESTORE.md`` records that skew as the one unrecoverable
    direction — ``next_stamp`` compares the clock against the store's mark and
    not the cursor, so after a backward clock step re-collected events are
    stamped below the cursor and the strictly-after keyset never reads them.
    A negative lag against an "at most" target would report that as healthy.
    """
    del now  # Measured between two stored positions, not against the clock.
    mark, problem = _high_water_mark(root)
    if mark is None:
        return Measurement(None, problem or "unmeasurable")
    try:
        cursor = load_cursor(cursor_path(root))
    except (CursorError, OSError) as exc:
        return Measurement(None, f"the pipeline cursor is unreadable ({type(exc).__name__})")
    if cursor is None:
        return Measurement(None, "the detection cycle has never recorded a position")
    lag = mark - cursor.ingested_at
    if lag < 0:
        return Measurement(
            None,
            f"the cursor is {-lag:.0f}s ahead of the newest stored event; "
            "re-collected events would land behind it and never be read",
        )
    return Measurement(lag, f"the cycle is {lag:.0f}s behind the newest stored event")


def measure_detection_backlog(root: Path, now: float) -> Measurement:
    """Events stored that the detection cycle has not processed.

    Counted with the store's own keyset filter rather than by subtracting two
    counts, and the difference matters. The subtraction version —
    ``count() - count_before(cursor.ingested_at)`` — over-counts by every
    event sharing the cursor's own stamp, which is one ``append_many``
    commit's worth. Measured on a freshly caught-up store holding one commit
    of two events, it reported a backlog of 2 against a true backlog of 0: on
    a low-volume deployment where each pass is one commit, that reads as
    "nothing is ever processed", forever. "Conservative" is not a defence for
    a signal that is wrong in the normal case.

    So the query asks for one row more than the objective allows. At or under
    that, the count is exact; above it, the backlog already exceeds the target
    and the exact figure does not change the verdict — which is also what
    keeps the cost bounded, since a monitor must not table-scan a
    15-million-row store every five minutes.

    A cursor *ahead* of the store's high-water mark grades ``UNKNOWN``, for
    the same reason :func:`measure_detection_lag` does and found the same way:
    by measurement. A strictly-after count is the count of events the cycle
    *will* read next, which equals "events stored but not yet processed" —
    this objective's actual title — only while the cursor sits at or below the
    newest stored row. Past it, every stranded event is behind the keyset and
    the count is zero, so the report read ``met, 0 event(s) not yet
    processed``: a sentence indistinguishable from a caught-up SOC, printed
    beside a sibling indicator correctly saying the cursor is a day ahead and
    nothing will ever be read. ``tests/unit/test_sli.py`` already built that
    state and asserted only the sibling.

    Note what is **not** refused. An emptied store beneath a live cursor reads
    ``met`` and should: ``high_water_mark`` is a stored mark rather than a
    ``MAX`` over the rows, so it outlives them, and a retention pass that
    deletes every processed event leaves a true backlog of zero. Measured
    before this branch was written, because refusing it would have invented a
    breach out of retention working.
    """
    del now
    path = _store_path(root)
    if not path.is_file():
        return Measurement(None, f"no event store at {path.relative_to(root)}")
    try:
        cursor = load_cursor(cursor_path(root))
    except (CursorError, OSError) as exc:
        return Measurement(None, f"the pipeline cursor is unreadable ({type(exc).__name__})")
    probe = min(int(BY_ID["detection-backlog"].target) + 1, MAX_QUERY_LIMIT)
    spec = (
        Query(limit=probe)
        if cursor is None
        else Query(limit=probe, ingested_after=cursor.as_keyset())
    )
    try:
        with EventStore.open(root) as store:
            # One open for both: the mark decides whether the count means
            # anything, so reading it in a second connection would let the two
            # disagree about which store they measured.
            mark = store.high_water_mark()
            pending = len(store.query(spec))
    except (StoreError, OSError) as exc:
        return Measurement(None, f"the event store could not be queried ({type(exc).__name__})")
    if cursor is not None and mark is not None and mark < cursor.ingested_at:
        return Measurement(
            None,
            f"the cursor is {cursor.ingested_at - mark:.0f}s ahead of the newest stored "
            "event; a strictly-after count cannot see the events stranded behind it",
        )
    if pending >= probe:
        return Measurement(
            float(pending), f"at least {pending} event(s) not yet processed (probe limit)"
        )
    if cursor is None:
        return Measurement(
            float(pending), f"the cycle has never run; {pending} stored event(s) unprocessed"
        )
    return Measurement(float(pending), f"{pending} event(s) not yet processed")


class _OpenRefused(Exception):
    """``EventStore.open`` refused the store; a reason, not a verdict on its pages."""


def _open_store(root: Path) -> EventStore:
    """Open the store for a measurement, telling a refusal apart from damage.

    ``EventStore.open`` raises two kinds of :class:`StoreError`, and they
    belong to different runbook branches. :class:`StoreIntegrityError` — on
    this path always :class:`store.StoreCorruptionError`, which ``open`` raises
    when SQLite reads the file and calls it malformed — is the file itself
    reporting damage, and propagates unchanged. Everything else is a refusal
    that says nothing about whether the file's pages are sound:
    :class:`store.StorePathError` for a path that leaves the root (a symlinked
    ``data/``), its subclass :class:`store.StoreSidecarError` for a FIFO,
    linked or non-regular ``-journal``/``-wal``/``-shm``, and
    :class:`store.SchemaVersionError` for a version this build does not speak.
    Each is re-raised as :class:`_OpenRefused`, which a store measurer grades
    ``UNKNOWN``.

    Measured before this split: all four refusals — a FIFO ``-journal``
    included, refused before SQLite read a byte — read ``store-intact:
    breached`` and "the store's database is damaged". That sentence sends an
    operator to ``docs/RESTORE.md``, and a restore "replaces the SOC's memory"
    with an older copy, which is the wrong response to an intact file. So the
    damage verdict is an allow-list of one class, and a :class:`StoreError`
    added later lands on the refusal side until someone decides otherwise.

    Only the open is classified. A :class:`StoreError` raised by what a
    measurer then runs on the open store is that measurer's to grade, and is
    never relabelled "could not be opened".
    """
    try:
        return EventStore.open(root)
    except StoreIntegrityError:
        raise
    except StoreError as exc:
        raise _OpenRefused(f"{type(exc).__name__}: {exc}") from exc


def measure_store_intact(root: Path, now: float) -> Measurement:
    """Whether the database file itself is structurally sound.

    The companion to :func:`measure_store_readable`, and the two are not
    redundant: this one walks every b-tree page and cannot see an
    application-level failure, that one samples 100 rows and cannot see damage
    outside them. Measured on a 1200-event / 525-page store, zeroing each page
    in turn: 116 of 524 losses left the sample reading ``1.0`` while
    ``integrity_check`` raised, and ``verify_integrity`` refuses 116 of 116.

    ``0.0`` rather than ``None`` for a damaged store, deliberately. The signal
    was read and it said the evidence is damaged; that is a measured breach and
    the most actionable thing this package can report. ``None`` is reserved for
    a store that is not there or will not open, which is a different
    conversation with the operator.

    "Will not open" was not what this function did with it until the open was
    classified. Every :class:`StoreError` read ``0.0`` and "damaged", so a
    symlinked ``data/``, a schema version this build does not speak and a FIFO
    ``-journal`` were each reported as a damaged database. :func:`_open_store`
    now separates them: SQLite calling the file malformed during the open is
    still ``0.0``, and the rest is ``None`` with the store's own reason. Both
    grade not-passing, so the exit code of ``scripts/report_sli.py`` is
    unchanged; what changed is which runbook branch the sentence points at.

    Cost is why this is affordable at the documented ``*/5`` cadence:
    ``quick_check`` is roughly linear at 1.1-1.5 ms/MiB (24 ms at 16.7 MiB,
    90 ms at 67.1 MiB, 220 ms at 202.2 MiB), while ``integrity_check`` is
    super-linear over the same three points (67 / 419 / 1440 ms) and was
    therefore not a candidate. What ``quick_check`` does not catch is a
    structurally valid page carrying another generation's rows — see
    ``EventStore.verify_integrity``.
    """
    del now
    path = _store_path(root)
    if not path.is_file():
        return Measurement(None, f"no event store at {path.relative_to(root)}")
    try:
        with _open_store(root) as store:
            store.verify_integrity()
    except _OpenRefused as refused:
        return Measurement(
            None, f"the store could not be opened, so its pages were not checked: {refused}"
        )
    except StoreIntegrityError as exc:
        return Measurement(0.0, f"the store's database is damaged: {exc}")
    except OSError as exc:
        return Measurement(None, f"the store could not be opened ({type(exc).__name__})")
    return Measurement(1.0, "every b-tree page the quick check walks is sound")


def measure_store_readable(root: Path, now: float) -> Measurement:
    """Whether a bounded query of the store returns rather than raising.

    Both ends are sampled, because a projection written past a bound is
    readable until something queries the window holding it, and the newest
    rows are the ones a cycle reads next while the oldest are the ones a
    report reads. ``1.0`` means both samples came back.

    ``0.0`` means the store accepts writes and cannot be read, and that now
    includes a damaged file. It did not when this indicator was written:
    ``query`` raised ``sqlite3.DatabaseError`` directly, which is not a
    ``StoreError``, so the probe escaped this ``except`` and
    :func:`sli.report.measure`'s per-probe guard graded it ``UNKNOWN`` — fail
    closed, but the detail read ``the probe raised DatabaseError`` instead of
    naming the fault. ``store/`` maps SQLite's two corruption verdicts to
    :class:`store.StoreCorruptionError` (a ``StoreIntegrityError`` subclass, so
    this ``except`` catches it), and the detail now carries the engine's own
    sentence. Deliberately *not* fixed by widening this clause: a monitor
    importing ``sqlite3`` to catch a driver error through two layers is the
    wrong shape, and the leak was on seven of ten store entry points rather
    than only this one.

    It does **not** include a store that refused to open, which read ``0.0``
    here until the open was classified by :func:`_open_store`. "Accepts writes
    and cannot be read" is false of a refused open: every writer runs the same
    ``EventStore.open`` and is refused with it, so a FIFO ``-journal`` or a
    symlinked ``data/`` stops collection too, and this objective's runbook
    branch — prune the unreadable projection — does not apply to a store
    nothing can open. Those are ``None`` with the reason, as they are for
    :func:`measure_store_intact`, so the two store objectives give one cause
    one grade. A ``StoreError`` from either query is still ``0.0``: a query
    that raises is exactly what this measures.

    **The objective's own headline failure had the same leak, and the same
    fix.** A row that hashes to its ``event_id`` and has a field past its
    bound (the over-long ``message`` this objective's rationale cites) made
    ``query`` raise the reader's ``MalformedProjectionError``. That is an
    ``IngestError``, so this ``except`` missed it, and the report read
    ``unknown ... the probe raised MalformedProjectionError``: "could not
    measure" for the one failure this indicator exists to measure. ``store/``
    now raises it as :class:`store.StoreIntegrityError` chained from the
    reader's error, so it reads ``0.0`` with the reader's bounded sentence
    naming the field. It is a ``StoreError`` from a query rather than from the
    open, so it lands on the ``0.0`` branch the paragraph above keeps. Fixed in
    ``store/`` and not here, for the reason given for the ``DatabaseError``
    leak: a monitor catching a driver's or a reader's type is the wrong shape.

    **The sample is still a sample, and ``store-intact`` is what covers it.**
    Measured on a 1200-event / 525-page store: 116 of 524 single-page losses
    leave this probe reading ``1.0`` and the sentence "read 50 newest and 50
    oldest row(s) without error" while ``integrity_check`` raises, because the
    probe reads a fixed 100 rows from the two ends however large the store is.
    :func:`measure_store_intact` refuses 116 of 116 of them. The two stay
    separate rather than merging because they fail differently and an operator
    acts differently: a damaged file is restored, an unreadable projection is
    pruned.
    """
    del now
    path = _store_path(root)
    if not path.is_file():
        return Measurement(None, f"no event store at {path.relative_to(root)}")
    try:
        with _open_store(root) as store:
            newest = store.query(Query(limit=READABILITY_SAMPLE))
            oldest = store.query(Query(limit=READABILITY_SAMPLE, newest_first=False))
    except _OpenRefused as refused:
        return Measurement(None, f"the store could not be opened, so no row was read: {refused}")
    except StoreError as exc:
        return Measurement(0.0, f"the store cannot be read: {type(exc).__name__}: {exc}")
    except OSError as exc:
        return Measurement(None, f"the store could not be opened ({type(exc).__name__})")
    return Measurement(
        1.0, f"read {len(newest)} newest and {len(oldest)} oldest row(s) without error"
    )


def measure_audit_chains_intact(root: Path, now: float) -> Measurement:
    """The fraction of present hash chains that verify.

    An absent chain is not counted either way — a platform that has never run
    retention has no retention chain, and calling that a breach would make the
    indicator unusable on a fresh deployment. An absent chain *set* is
    ``UNKNOWN``. What is never done is reporting a missing chain as intact,
    which is the contract ``scripts/audit_verify.py`` states and the one
    place that forgot it is recorded in ``DESIGN.md`` as a defect.

    Graded on ``intact``, and that is **not** the same as "the hash chain and
    not the signature" — which is what this paragraph used to claim.
    Measured: with a verifier configured, an intact chain whose signature has
    been tampered with reports ``intact=False, signature='invalid'``, so
    ``intact`` incorporates the signature verdict. What the original claim was
    reaching for is true only of the *default* deployment: the verifier comes
    from :func:`verifier_from_env`, so with no key in this process's
    environment there is no verifier, a chain reads ``signature='unsigned'``,
    and that alone cannot breach the objective — which is the configuration
    question the paragraph meant to keep out of the grade. Once a key *is*
    configured, a bad signature breaches, deliberately. The signature states
    are reported in the detail either way so the question stays visible.
    """
    del now
    verifier = verifier_from_env()
    present: list[str] = []
    intact: list[str] = []
    signatures: dict[str, int] = {}
    for relative in CHAIN_FILES:
        logger = AuditLogger(root / relative, signer=verifier)
        try:
            if not logger.exists():
                continue
            report = logger.verify_report()
        except OSError as exc:
            # A chain that is there and cannot be read is a breach, not an
            # absence: counted as present and not intact.
            present.append(str(relative))
            signatures[f"unreadable ({type(exc).__name__})"] = (
                signatures.get(f"unreadable ({type(exc).__name__})", 0) + 1
            )
            continue
        present.append(str(relative))
        signatures[report.signature] = signatures.get(report.signature, 0) + 1
        if report.intact:
            intact.append(str(relative))
    if not present:
        return Measurement(None, "no audit chain exists under the lab-data root yet")
    broken = sorted(set(present) - set(intact))
    states = ", ".join(f"{name}={count}" for name, count in sorted(signatures.items()))
    detail = f"{len(intact)} of {len(present)} chain(s) intact; head signatures: {states}"
    if broken:
        detail = f"{detail}; broken: {', '.join(broken)}"
    return Measurement(len(intact) / len(present), detail)


_NOFOLLOW_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _manifest_mtime(backups_fd: int, name: str) -> float | None:
    """The mtime of ``name/manifest.json`` under ``backups_fd``, or ``None``.

    ``None`` unless ``name`` opens as a directory without following a link and
    its manifest is a regular file by ``lstat`` through that descriptor. An
    entry swapped for a link, a file or nothing since the scan is skipped;
    any other ``OSError`` (an unreadable entry) propagates.
    """
    try:
        entry_fd = os.open(name, _NOFOLLOW_DIR, dir_fd=backups_fd)
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP):
            return None
        raise
    try:
        info = os.stat(MANIFEST_FILE, dir_fd=entry_fd, follow_symlinks=False)
    except (FileNotFoundError, NotADirectoryError):
        return None
    finally:
        os.close(entry_fd)
    return info.st_mtime if stat.S_ISREG(info.st_mode) else None


def measure_backup_present(root: Path, now: float) -> Measurement:
    """Whether any backup exists to restore from, and how old the newest is.

    Graded on existence alone. The age is in the detail rather than in the
    objective because ``docs/RESTORE.md`` documents the procedure and the
    recovery ordering and documents no cadence — a target here would be an
    invented requirement (AGENTS.md §9).

    **A symlink anywhere between the root and a manifest is not followed, and
    the refusal holds against a swap.** ``scripts/run_backup.py`` confines the
    directory it writes with the same walk the store and the cursor use, so a
    link under ``data/backups`` was planted rather than written. ``data`` and
    ``data/backups`` are opened by descriptor with ``O_NOFOLLOW``; a link at
    either grades ``UNKNOWN`` with the reason. Each entry is opened the same
    way relative to that descriptor, and its manifest ``lstat``ed through the
    entry's own descriptor — one ``stat``, which also gives the age — so an
    entry swapped for a link after the scan is skipped rather than followed.
    Measured before this: a linked entry pointing outside the root read
    ``1.0`` and ``stat``ed the far side; after a first fix checked by path, a
    thread flipping an entry between a directory and that link still did both
    (510 counts in 29,581 probes). The root itself is followed: it is the
    operator's argument. An entry the probe cannot open raises, which the
    report grades ``UNKNOWN``.
    """
    no_directory = Measurement(0.0, f"no backup directory at {BACKUP_SUBDIR}")
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    except (FileNotFoundError, NotADirectoryError):
        return no_directory
    try:
        walked = root
        for part in BACKUP_SUBDIR.parts:
            walked = walked / part
            try:
                child = os.open(part, _NOFOLLOW_DIR, dir_fd=fd)
            except OSError as exc:
                if exc.errno not in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP):
                    raise
                if not walked.is_symlink():
                    return no_directory
                return Measurement(
                    None,
                    f"{walked.relative_to(root)} is a symlink; refusing to follow it out of "
                    "the lab-data root",
                )
            os.close(fd)
            fd = child
        with os.scandir(fd) as entries:
            names = sorted(e.name for e in entries if e.is_dir(follow_symlinks=False))
        found = [(_manifest_mtime(fd, name), name) for name in names]
    finally:
        os.close(fd)
    manifests = [(mtime, name) for mtime, name in found if mtime is not None]
    if not manifests:
        return Measurement(0.0, f"no backup manifest under {BACKUP_SUBDIR}")
    newest, name = max(manifests, key=lambda manifest: manifest[0])
    return Measurement(
        1.0,
        f"{len(manifests)} backup(s) present; newest written {(now - newest) / 3600:.1f}h ago "
        f"({name})",
    )


#: Objective id to the function that measures it. The report walks this, so an
#: objective with no measurer — or a measurer with no objective — is a
#: startup-time mismatch a test asserts rather than a silent omission.
MEASURERS: dict[str, Callable[[Path, float], Measurement]] = {
    "collection-pending": measure_collection_pending,
    "ingest-freshness": measure_ingest_freshness,
    "detection-lag": measure_detection_lag,
    "detection-backlog": measure_detection_backlog,
    "store-intact": measure_store_intact,
    "store-readable": measure_store_readable,
    "audit-chains-intact": measure_audit_chains_intact,
    "backup-present": measure_backup_present,
}
