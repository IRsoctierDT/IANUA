# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Single-instance locking for the scheduled CLIs — one copy of one control.

``scripts/run_backup.py``, ``run_collector.py``, ``run_pipeline.py`` and
``run_retention.py`` each run on a timer, and each must refuse to run twice at
once. They did it with four verbatim copies of the same two functions, and the
copies are why this module exists rather than a tidiness preference. The
history is in the repository:

* The ``mkdir``/``touch``/``chmod`` had to move inside the caller's startup
  ``try`` so an unwritable directory becomes a message and exit 2 rather than a
  traceback. That fix landed in three of the four; ``run_pipeline`` had never
  received it at all, and was measured emitting a raw traceback at **exit 1
  where the documented contract says 2** — before its :class:`AuditLogger`
  existed, so the chain recorded nothing.
* Then the ``open`` had to move too, because a lock path that is a *directory*
  still tracebacked with ``IsADirectoryError`` in all three CLIs that had
  received the first fix.

Two fixes, each applied to a subset. The third landed here, once, and is the
reason the module exists rather than a tidiness preference — see
:func:`prepare_lock` for what a hostile object at the lock path did to all
four, measured.

Security consideration — **the extraction is not behaviour-preserving, and
could not be.** The four copies had drifted. Measured on a lock directory that
already exists at ``0o755``, since ``mkdir(exist_ok=True)`` does not change an
existing directory's mode:

===============  ========  =======
CLI              before    after
===============  ========  =======
``run_backup``   ``0o755`` ``0o700``
``run_collector`` ``0o755`` ``0o755``
``run_pipeline`` ``0o755`` ``0o755``
``run_retention`` ``0o755`` ``0o755``
===============  ========  =======

Only ``run_backup`` followed its ``mkdir`` with an explicit
``directory.chmod``. The lock *file* was ``0o600`` in all four — it is the
directory that was left alone, and those directories are ``data/backups/``,
``data/collect/``, ``data/pipeline/`` and ``data/events/`` under the
gitignored lab-data root, which AGENTS.md §5 treats as sensitive by default.
At ``0o755`` any local user can list and traverse them, and ``data/collect/``
holds copies of collected log files, which are stored evidence. A directory
created once by an earlier version, a differently-umasked cron, or a hand-run
runbook step keeps that mode for the life of the node, and nothing reports it.

So this module adopts ``run_backup``'s behaviour: the choice was between
regressing the one CLI that got it right and narrowing the three that did not,
and narrowing is what AGENTS.md §3 ranks first. ``mkdir``'s ``mode`` argument
is masked by the umask and ignored entirely for a directory that already
exists, which is why the explicit ``chmod`` is the control and the ``mode`` is
only the first-creation case.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import TextIO

#: Lab-data directories hold evidence, so they are owner-only. Applied by an
#: explicit ``chmod`` as well as by ``mkdir``, because ``mkdir`` is masked by
#: the umask on creation and does nothing at all to a directory that is
#: already there.
DIR_MODE = 0o700

#: The lock file itself, owner-only. Its contents carry nothing — the open
#: handle carries the lock — but it lives among evidence.
FILE_MODE = 0o600

#: What an operator sees when the lock could not be taken for a reason that is
#: not contention, and the phrase every statement of the exit-code contract has
#: to carry.
#:
#: A named constant rather than four prose paraphrases, because the condition
#: it describes is reachable at exit ``2`` while **none** of the nine places
#: that enumerate the exit codes mentioned a lock at all — all four CLI
#: docstrings, ``scripts/_exit_codes.py``, ``docs/RETENTION.md``,
#: ``docs/RESTORE.md`` and ``docs/PRODUCTION_SOC_PLAN.md`` twice said "bad
#: arguments", so an operator who got a 2 from a broken ``flock`` would read
#: the documented meaning and go checking their argv.
#: ``tests/unit/test_exit_codes.py`` now asserts this literal appears beside
#: every one of those enumerations, so the message and the contract cannot
#: drift apart by paraphrase.
LOCK_UNAVAILABLE_MESSAGE = "the single-instance lock could not be taken"

#: How the lock file is opened. Every flag is load-bearing; see
#: :func:`prepare_lock` for what each one refuses and what it costs.
#:
#: * ``O_RDONLY`` — the least this can ask for, and all a lock needs: ``flock``
#:   keys on the open file description and not on access mode. Measured,
#:   unprivileged — ``LOCK_EX`` acquires on a read-only descriptor and a second
#:   holder is still refused ``EAGAIN``, so exclusion is untouched. It was
#:   ``O_WRONLY | O_APPEND``, mirroring the ``Path.open("a")`` it replaced, and
#:   that asked for a capability nothing exercises: no code in this repository
#:   writes a byte to the handle. Asking anyway was not free — see the ``0o400``
#:   finding in :func:`prepare_lock`.
#: * ``O_CREAT`` — creates the lock at :data:`FILE_MODE` when absent. Legal with
#:   ``O_RDONLY``, and measured: the created file is ``0o600``.
#: * ``O_NONBLOCK`` — what makes the type guard *reachable*, and it keeps that
#:   job under ``O_RDONLY`` with the direction reversed. Measured on a
#:   reader-less FIFO: without it the open blocks indefinitely either way —
#:   ``O_RDONLY`` waiting for a writer, ``O_WRONLY`` waiting for a reader — so
#:   the process never returns to run any guard. With it the open returns and
#:   ``os.fstat`` refuses. What changes is only *which* step refuses: under
#:   ``O_WRONLY`` the open itself failed ``ENXIO``; under ``O_RDONLY`` the open
#:   succeeds and the descriptor's type is the sole guard. It is **not** cleared
#:   afterwards any more — see :func:`prepare_lock`.
#: * ``O_NOFOLLOW`` — a symlink at the final component fails ``ELOOP``, before
#:   anything follows it and chmods whatever it points at.
_OPEN_FLAGS = os.O_RDONLY | os.O_CREAT | os.O_NONBLOCK | os.O_NOFOLLOW

#: What a path actually is, for an error message only — never for a decision.
#:
#: The first version of this mapped ``ENXIO`` to "a FIFO with no reader", which
#: was **wrong**: ``os.open`` returns ``ENXIO`` for a unix socket as well, so a
#: socket at the lock path reported itself as a FIFO. Guessing the object from
#: the errno is the same defect as any other claim the code cannot support, so
#: the object is *looked up* instead.
#:
#: ``lstat`` rather than ``stat``, so a symlink reports as a symlink. This runs
#: only after a refusal has already happened, so it decides nothing and cannot
#: reintroduce a check-then-open window — it explains an error, and if it
#: cannot, the raw errno is raised unchanged.
#:
#: ``S_ISDIR`` is deliberately absent: ``EISDIR``'s own "Is a directory" is
#: already exact, and ``tests/security/test_cli_startup_failclosed.py`` asserts
#: that wording.
_DESCRIBED_TYPES = (
    (stat.S_ISLNK, "a symlink, which is refused at the lock file itself"),
    (stat.S_ISFIFO, "a FIFO"),
    (stat.S_ISSOCK, "a socket"),
    (stat.S_ISCHR, "a character device"),
    (stat.S_ISBLK, "a block device"),
)


class LockUnavailableError(OSError):
    """``flock`` failed for a reason that is **not** another pass holding it.

    A separate type because the two outcomes need opposite handling and the
    errno is the only thing that tells them apart. Contention is the
    documented, correct, exit-0 ``skipped`` path; everything else means the
    lock is not working, and a platform whose single-instance control is not
    working must say so rather than report a benign skip.

    An ``OSError`` subclass, so ``errno`` survives for a caller that wants it
    and a handler written against ``OSError`` still catches this. The callers
    catch *this* type specifically, because their ``with`` block wraps the
    whole pass and a bare ``except OSError`` there would relabel any failure
    inside the pass as a lock problem.
    """


def _describe(path: Path) -> str | None:
    """Name what is at ``path``, or ``None`` if it is nothing worth naming."""
    try:
        mode = path.lstat().st_mode
    except OSError:
        return None
    for predicate, description in _DESCRIBED_TYPES:
        if predicate(mode):
            return description
    return None


def _refuse(path: Path, fallback: int) -> OSError:
    """The refusal to raise for a lock path that cannot hold a lock."""
    description = _describe(path)
    if description is None:
        return OSError(fallback, "lock path is not a regular file", str(path))
    return OSError(errno.EINVAL, f"lock path is {description}", str(path))


def prepare_lock(directory: Path, filename: str) -> TextIO:
    """Create and open the lock file, before any lock is attempted.

    Separated from :func:`single_instance` so that every step that can fail on
    a bad filesystem — ``mkdir``, ``chmod``, ``touch`` and the ``open`` — runs
    inside the caller's startup ``try``, where an unwritable directory becomes
    a message and exit 2 rather than a traceback. Inside the context manager
    they ran at ``__enter__``, outside every ``try``, and reached the terminal
    raw. The ``open`` belongs here for the same reason and not a weaker one: a
    lock path that is a *directory* raises ``IsADirectoryError``, and the
    caller has to be the one to translate that.

    Opens read-only and never truncates: the handle carries the lock, not the
    contents, and ``flock`` needs no write access to do it.

    **The lock path must be a regular file, and the old code never checked.**
    It did ``touch`` then ``chmod`` then ``Path.open("a")``, and all three
    follow a symlink while none of them asks what is there. Measured across all
    four CLIs:

    * a **FIFO with no reader** blocked forever — exit 124 under ``timeout``,
      *zero bytes on either stream*, still blocked at 30 s with ``wchan =
      wait_for_partner``. Indefinite by construction: nothing but a reader or a
      signal ends it, so every later scheduled pass blocks identically and the
      documented exit-2 refusal is unreachable.
    * a **FIFO with a reader** was worse than the hang. The open returned at
      once, ``flock`` succeeded *on the pipe*, and the pass ran its full work —
      the collector committed an event at exit 0, the cycle ran at exit 0, and
      retention, whose ``--apply`` path is destructive, ran a pass at exit 0.
      Nothing anywhere said the single-instance lock was a pipe.
    * a **symlink to a regular file outside the root** was accepted, and that
      file's mode was changed ``0o644 → 0o600``.
    * a **dangling symlink** *created a new file outside the lab-data root*
      (absent before, ``0o600`` and empty after).
    * a **symlink to a directory outside the root** was refused exit 2 — but
      only after chmodding that directory to ``drw-------``, breaking it for
      its owner.
    * a **symlink to /dev/null** was accepted and *the device node's mode was
      changed* ``0o666 → 0o600``; a symlink to a ``0o400`` file had its mode
      **widened** to ``0o600``.

    And one defect nobody had filed: with a **directory** at the lock path,
    ``touch(exist_ok=True)`` *succeeds* — it merely ``utime``s it — so the
    ``chmod`` then left the lock *directory* at ``0o600`` (measured ``0o700 →
    0o600``) before the ``open`` failed. A refused startup left the directory
    non-traversable. One ``os.open`` cannot get that far.

    So the open is a single syscall carrying :data:`_OPEN_FLAGS`, and the type
    is checked on the **descriptor**. ``os.fstat`` resolves no path — it asks
    about the open file description ``os.open`` returned — so the thing
    inspected and the thing locked are the same inode *by construction*. A
    ``path.is_fifo()`` guard before the open would not be: measured, a
    ``rename`` between the check and the open returns a descriptor on a
    different inode, with nothing raised, which would leave the hang in place
    behind a FIFO check that visibly ran and passed.

    ``S_ISREG`` is an allow-list and deliberately not ``not S_ISFIFO``: a
    socket, a character device and a block device all open happily, and a
    deny-list would also leave ``close()``'s flush able to raise
    ``BlockingIOError`` from ``__exit__`` — outside the caller's startup
    ``try``, so a traceback at exit 1.

    **The open asks for the least it can, and that is a fix and not a nicety.**
    The first version of this used ``O_WRONLY | O_APPEND``, mirroring the
    ``Path.open("a")`` it replaced. Review found the cost and measurement
    confirmed it: a pre-existing lock file at mode ``0o400`` — owner-readable,
    not writable — made ``os.open`` fail ``EACCES`` *before* the ``os.fchmod``
    that would have widened it, so all four scheduled CLIs refused to start
    until a human intervened. The sequence this replaced recovered that file,
    because ``chmod`` needs ownership rather than write permission. Measured as
    the file's owner, unprivileged::

        lock mode   O_WRONLY (before)   O_RDONLY (now)
        0o600       ok                  ok
        0o400       EACCES              ok, narrowed to 0o600
        0o200       ok                  EACCES
        0o000       EACCES              EACCES
        0o666       ok, narrowed        ok, narrowed

    So it is a trade, and the ``0o200`` row is its price: a write-only lock file
    now refuses where it used to work. It is the right side of the trade because
    ``0o400`` is a mode this platform uses *deliberately* —
    ``agents/tools/containment.py`` chmods a quarantined payload to ``0o400``
    for forensic preservation — and the mode any "harden the data directory"
    script produces, while nothing produces ``0o200``. Neither is put at a lock
    path by this repository: both need an operator or an external script, and
    both refuse loudly at exit 2 naming the path, which is the fail-closed side.

    **``O_NONBLOCK`` is no longer cleared afterwards**, which is a consequence of
    ``O_RDONLY`` and not a separate decision. It was cleared because the
    descriptor outlives this function and a future writer would inherit a latent
    partial-write bug — but a read-only descriptor has no future writer, and
    ``O_NONBLOCK`` is a no-op on a regular file regardless (measured: ``read()``
    returns ``b''``, never ``EAGAIN``). Two ``fcntl`` calls leave the
    error-handling critical section with it.

    **What this costs, named.** ``O_NOFOLLOW`` applies to the final component
    only (an ancestor symlink still opens, measured), which is exactly
    AGENTS.md §5's posture for ``collect/`` — "No symlink at the log file ...
    Ancestor components are not walked, deliberately" — and stricter, because
    the check and the open are one syscall rather than two. The operator it
    breaks is a real one: anybody who relocates volatile locks onto tmpfs with
    ``ln -s /run/ianua/cycle.lock .../data/pipeline/cycle.lock`` now gets
    ``ELOOP`` and exit 2. That is a deliberate trade, not an oversight — the
    alternative is appending to, and chmodding, a file at a path the lock
    directory's own ``0o700`` does not govern.

    **``st_nlink`` was considered and declined**, with measurement. ``flock``
    is per-*inode*, so a hard link does not split the lock — locking through
    one name and attempting the other returned ``EAGAIN``. Refusing
    ``st_nlink != 1`` would therefore buy no exclusion, and would break
    ``rsync --link-dest``, ``cp -al`` and rsnapshot-style hardlink-farm backups
    of ``data/``, failing every timer-driven pass at exit 2 on a correct
    deployment. The residual it leaves is stated below.

    **Residuals, measured and not closed.** A **bind mount** at the lock file
    defeats this: nothing is followed, so ``O_NOFOLLOW`` does not apply, and
    ``st_nlink`` is 1. ``S_ISREG`` means "not a FIFO, socket, device or
    directory" and *not* "a real file on the lab-data volume" — procfs and
    sysfs attributes satisfy it. ``chattr +i``/``+a`` are regular files, so the
    guard is silent. A hard link remains an equal name, so ``os.fchmod`` can
    still reach an inode that lives elsewhere, exactly as ``path.chmod`` did.

    :param directory: the lock directory, created owner-only if absent and
        narrowed to :data:`DIR_MODE` if it already exists.
    :param filename: the CLI's own lock file name, so each CLI keeps its own
        ``LOCK_FILE`` constant and this function reads no caller's globals.
    :returns: the open handle, to be passed to :func:`single_instance`.
    :raises OSError: for every refusal, which is what each caller's startup
        ``except`` already catches — all four print and return 2.
    """
    directory.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    directory.chmod(DIR_MODE)
    path = directory / filename
    try:
        descriptor = os.open(path, _OPEN_FLAGS, FILE_MODE)
    except OSError as exc:
        # Only replace the message when the object can be named. ``EISDIR``,
        # ``EACCES``, ``EROFS`` and the rest already say what they mean, and
        # ``_describe`` returns ``None`` for all of them.
        if _describe(path) is None:
            raise
        raise _refuse(path, exc.errno or errno.EINVAL) from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise _refuse(path, errno.EINVAL)
        # Narrows a pre-existing lock file, as ``path.chmod`` did before it.
        # ``fchmod`` needs ownership and *not* write permission, which is what
        # lets a ``0o400`` lock file be recovered through a read-only descriptor.
        os.fchmod(descriptor, FILE_MODE)
    except BaseException:
        os.close(descriptor)
        raise
    # Deliberately outside the guard, and correct only because ``mode`` and
    # ``encoding`` are literals that cannot fail validation: ``open`` adopts the
    # descriptor when it constructs the underlying ``FileIO``, so a failure
    # *before* that leaks the descriptor while one *after* it closes it — and
    # wrapping this in the ``except`` above would double-close the second case.
    # Anyone parameterising either argument must revisit this.
    #
    # ``"r"`` and not ``"a"``: the descriptor is ``O_RDONLY``, and ``fdopen``
    # must agree with it. Nothing reads the handle either — ``single_instance``
    # takes only ``fileno()`` and the ``with`` that closes it.
    return os.fdopen(descriptor, "r", encoding="utf-8")


@contextlib.contextmanager
def single_instance(handle: TextIO) -> Iterator[bool]:
    """Hold an exclusive lock for one pass; yield ``False`` if another holds it.

    A declined lock is **not an error and must not exit non-zero**: a scheduled
    pass overlapping a slow one is expected, and failing would mail the
    operator until they learned to ignore it. The caller decides what to do
    with ``False``; this function only reports it.

    **Only contention yields ``False``, and the previous version of this
    docstring claimed the opposite was impossible.** It said "nothing here can
    fail for a reason the caller would have to translate", and on that basis
    caught bare ``OSError`` and reported every failure as a benign skip. That
    was wrong, and measurably so: ``flock`` fails with ``EBADF`` on a closed
    descriptor (measured, errno 9), and with ``ENOLCK`` when the kernel's lock
    table is exhausted or ``EOPNOTSUPP`` on a filesystem that does not
    implement it. On such a filesystem **every** scheduled pass of all four
    CLIs printed "skipped: another pass holds the lock; this invocation did
    nothing." and exited 0 — forever, with no contention anywhere and no work
    ever done. That is worse than a hang: a hang shows up as a timeout, while
    this reports success on the documented contract, so a scheduler, a log
    shipper and the SLI layer all read healthy. It is the failure class
    ``AGENTS.md`` names — every signal healthy while the SOC sees nothing.

    So the catch is an **allow-list of one**: ``BlockingIOError``, which is
    exactly how Python surfaces ``EAGAIN``/``EWOULDBLOCK``. Measured on this
    build, a second holder of a held lock raises
    ``BlockingIOError(11, 'Resource temporarily unavailable')``, and *not*
    ``EACCES`` — that caveat belongs to ``fcntl``-style ``F_SETLK`` locks,
    which this is not.

    **Catching the class rather than comparing errnos is right here for the
    opposite reason it was wrong in** ``scripts/_exit_codes.py``. There, the
    ``sqlite3`` hierarchy does *not* carry the distinction, so the predicate
    had to read the result code. Here Python's ``OSError`` hierarchy carries it
    precisely: ``BlockingIOError`` is ``EAGAIN``/``EWOULDBLOCK`` (plus two
    socket errnos ``flock`` cannot raise), while ``EBADF``, ``ENOLCK`` and
    ``EOPNOTSUPP`` arrive as plain ``OSError`` and ``EACCES`` as
    ``PermissionError`` — all measured. The lesson from the other module is to
    test the thing that actually carries the distinction, not to prefer errnos.

    Anything else becomes :class:`LockUnavailableError`, which each caller
    turns into a message and exit **2**.

    **Why 2, and not ``4`` or a fifth code.** The reason first given here was
    precedent — an unusable lock *path* already exits 2 — and precedent is the
    weak form of the argument. Sorted by what a human then does, the errnos
    behind this one code are not one condition: ``EBADF`` and ``EDEADLK`` mean
    *this code has a bug*, ``EOPNOTSUPP`` and ``EACCES`` mean *this deployment
    is wrong*, and ``ENOLCK`` can mean either. Three answers behind one code,
    which is the shape of the defect ``scripts/_exit_codes.py`` exists to fix.

    It is nonetheless right, because **an exit code's resolution should match
    the decisions its consumer can make**, and the consumer is a scheduler with
    two: retry, or page a human. "File a bug" and "fix the deployment" are both
    *page*; they differ in what the human does next, and the human reads the
    message, which carries the errno's own ``strerror`` and the path. What
    ``1`` conflated was *retry* against *page* — the one distinction the
    scheduler itself has to act on. This conflates two reasons to page, which
    it does not.

    **``ENOLCK`` was the one candidate for ``4``, and is refused fail-closed.**
    It is the only errno here that can mean "not now": a kernel short of lock
    records recovers on its own. But it is also what a lock service that cannot
    lock *at all* reports, and the errno does not say which — where SQLite's
    ``SQLITE_BUSY`` means "another connection holds it" and nothing else, so
    there the reason *is* the code. The kernel's own strings decline the
    distinction, measured: ``os.strerror(errno.EAGAIN)`` is "Resource
    temporarily unavailable" while ``os.strerror(errno.ENOLCK)`` is "No locks
    available", which does not call itself temporary. Admitting it to ``4``
    would mean that on the permanent variant a scheduler retries forever and
    nothing pages — *this defect exactly*, one layer up, with a non-zero code
    instead of a zero one. A transient condition wrongly paged costs one page;
    a permanent one wrongly retried costs the platform its single-instance
    control, silently.

    **``EINTR`` is unreachable from here, and that is measured rather than
    cited.** Six ``SIGALRM``s delivered during a *blocking* ``flock`` left the
    call to return normally at 2.00 s when the holder released it, so CPython
    retries the interrupt itself (PEP 475) and never surfaces it; the
    production call is ``LOCK_NB`` besides, which does not wait. It stays in
    the refused set and in the test table anyway: an unreachable errno costs
    nothing on the side that pages, and would cost silence on the side that
    retries.
    """
    with handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            # The one benign case: another pass holds it.
            yield False
            return
        except OSError as exc:
            raise LockUnavailableError(
                exc.errno,
                f"{LOCK_UNAVAILABLE_MESSAGE}: {exc.strerror}",
            ) from exc
        try:
            yield True
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
