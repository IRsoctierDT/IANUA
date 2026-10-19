# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Telling retryable contention apart from damage, for the scheduled CLIs.

The exit code is the whole interface a scheduler sees. ``scripts/run_backup``,
``run_collector``, ``run_pipeline`` and ``run_retention`` each ran on a timer
and each reported **exit 1** for two situations an operator must treat
oppositely:

* the store failed to open or verify, a schema mismatched, an audit write
  failed — *something is broken, page someone*; and
* a concurrent writer held SQLite's write lock past the busy timeout —
  *nothing is broken, every event is still present, retry.*

``docs/RETENTION.md`` already documented the conflation rather than the code
fixing it, in a paragraph beginning "**Exit 1 is not always damage.**" This
module is what let that paragraph be deleted.

**Why a new code and not ``0``.** Mapping contention to success was considered
and refused: nothing in the platform observes a pass that never ran. Measured
during the AUD-03 work, ``sli/`` reported ``met=8``, ``healthy=True`` and exit
0 both before *and* after a pass removed 120 of 120 events — so a persistent
busy store would silently stop retention forever, unbounded and unobservable.
A distinct non-zero code keeps the pass visible while telling the scheduler
what to do with it.

**Why 4 and not 3.** ``3`` is taken, and the first version of this plan said
to use it. Measured on the code this replaces: ``run_retention.py`` returns 3
for an ungranted ``--apply``, ``docs/RETENTION.md``'s table reads
``| 3 | Blocked by policy …|``, and nine ``return 3`` sites span seven scripts.
Reusing it would have made "retry" and "a human must grant this" the same
signal.

The codes in use across the scheduled CLIs, for the contract this joins:

====  ============================================================
exit  meaning
====  ============================================================
0     a pass ran — reported, applied, or skipped because another
      pass holds the single-instance lock (except a skipped
      ``run_backup --verify`` or ``--verify-restore``: exit 4)
1     damage: the store would not open or verify, a schema
      mismatched, an audit write or report failed
2     refused before doing anything: bad arguments, an unreadable
      cursor, a lock path that is not a regular file, or the
      single-instance lock could not be taken for a reason other
      than contention
3     blocked by policy — a destructive action without its grant
4     retryable contention; retry, do not page. Also a skipped
      ``run_backup --verify`` or ``--verify-restore``: a gate
      that verified nothing must never read as a pass
====  ============================================================
"""

from __future__ import annotations

import sqlite3

#: What a caller returns for contention. Named rather than written as a
#: literal at four call sites, because the whole defect this module fixes was
#: one number meaning two things in four places.
EXIT_RETRYABLE = 4

#: SQLite's *primary* result codes for "someone else holds the lock".
#:
#: ``SQLITE_BUSY`` (5) is the one this platform reaches: a second writer past
#: the busy timeout. ``SQLITE_LOCKED`` (6) is a table lock within one
#: connection's shared cache — **not reachable here**, since nothing in the
#: repository opens a shared-cache connection (``grep -rn 'cache=shared'`` is
#: empty), but it is contention by definition and costs nothing to admit.
#:
#: **The rule for admitting a code to this set**, stated because the first
#: justification given for ``SQLITE_LOCKED`` above is the weak one: a code
#: belongs here only when its meaning is *unambiguously* "not now, and nothing
#: is broken". ``SQLITE_LOCKED`` qualifies on meaning and not on reachability —
#: it is another holder, by definition, whether or not this platform can reach
#: it. ``ENOLCK`` at a ``flock``, weighed for the same treatment in
#: ``scripts/_locking.py`` and refused, does not: the one errno covers a
#: transient kernel shortage *and* a filesystem that cannot lock at all. This
#: is the unsafe side of the contract — a wrong admission here is retried
#: forever and never pages — so an ambiguous code is refused rather than
#: admitted cheaply.
_CONTENTION_PRIMARY_CODES = frozenset({sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED})

#: The low byte of a SQLite result code is its primary code; the high bytes
#: are an extended refinement. Masking is therefore exact *by construction*
#: and needs no list of extended names to be kept current.
_PRIMARY_CODE_MASK = 0xFF


def is_retryable_contention(exc: BaseException) -> bool:
    """Whether ``exc`` means "someone else holds the lock", and nothing worse.

    Gated on SQLite's **primary result code**, not on the exception class and
    not on a set of error names. Each of those alternatives was measured and
    rejected:

    * **Not the class.** ``sqlite3.OperationalError`` covers contention *and*
      a malformed statement, a missing table, a readonly database. The class
      hierarchy does not carry the distinction — the same reason
      ``store/events.py::_is_corruption`` gates on the name rather than on
      ``DatabaseError``.
    * **Not a set of names.** ``sqlite_errorname`` reports the *extended* name,
      and there are seven of them for these two primaries, measured on this
      build: ``SQLITE_BUSY`` (5), ``SQLITE_BUSY_RECOVERY`` (261),
      ``SQLITE_BUSY_SNAPSHOT`` (517), ``SQLITE_BUSY_TIMEOUT`` (773),
      ``SQLITE_LOCKED`` (6), ``SQLITE_LOCKED_SHAREDCACHE`` (262),
      ``SQLITE_LOCKED_VTAB`` (518). A name set would need all seven and would
      be one SQLite release away from missing an eighth. Masking the low byte
      is the rule those names *follow*, so it cannot drift from them.

    Measured on this build, to establish that the production path is the plain
    primary and not an extended one: a second writer blocked against a held
    write transaction raises ``OperationalError`` / ``SQLITE_BUSY`` / code 5 /
    "database is locked" — **after a real busy-timeout expiry** (0.60 s with
    ``timeout=0.6``) as well as with the timeout effectively disabled. And
    ``PRAGMA quick_check`` on the blocked connection returns ``ok`` at that
    very moment, which is what makes "retry" the correct reading rather than a
    hopeful one.

    **The direction of a mistake is deliberate.** A missed contention code
    falls through to the caller's existing exit 1, which pages an operator
    unnecessarily — noisy, and safe. The opposite mistake, reporting damage as
    retryable, would have a scheduler retry a corrupt store forever while
    nothing pages. So this admits only what it can name a reason for:
    ``SQLITE_CORRUPT`` (11) and ``SQLITE_NOTADB`` (26) are primaries 11 and 26
    and are refused here, as well as being mapped to
    :class:`store.errors.StoreCorruptionError` upstream.

    :param exc: the exception a caller's ``except`` clause received. Typed
        ``BaseException`` rather than ``sqlite3.Error`` so a caller can hand
        over whatever it caught without narrowing first — the clauses this
        serves catch four or five types at once.
    :returns: ``True`` only for a SQLite error whose primary code is
        :data:`_CONTENTION_PRIMARY_CODES`.
    """
    if not isinstance(exc, sqlite3.Error):
        return False
    # ``sqlite_errorcode`` is an instance attribute added in 3.11 and is absent
    # on an exception constructed by hand — a test double, or a ``sqlite3.Error``
    # raised by something other than the engine. Absent means "cannot show this
    # is contention", which fails to the safe side.
    code = getattr(exc, "sqlite_errorcode", None)
    if not isinstance(code, int):
        return False
    return (code & _PRIMARY_CODE_MASK) in _CONTENTION_PRIMARY_CODES
