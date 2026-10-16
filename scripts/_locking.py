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

#: How the lock file is opened. Every flag is load-bearing; see
#: :func:`prepare_lock` for what each one refuses and what it costs.
#:
#: * ``O_WRONLY | O_CREAT | O_APPEND`` — what ``Path.open("a")`` did.
#: * ``O_NONBLOCK`` — a FIFO with no reader fails ``ENXIO`` instead of blocking
#:   forever. It is what makes the type guard *reachable*: without it the
#:   process never returns from ``os.open`` to run any guard at all.
#: * ``O_NOFOLLOW`` — a symlink at the final component fails ``ELOOP``, before
#:   anything follows it and chmods whatever it points at.
_OPEN_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NONBLOCK | os.O_NOFOLLOW

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

    Appends, never truncates: the handle carries the lock, not the contents.

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
        os.fchmod(descriptor, FILE_MODE)
        # ``O_NONBLOCK`` was wanted for the duration of the open and no longer.
        # The descriptor outlives this function — ``single_instance`` holds it
        # for the whole pass — so leaving it set hands the next writer a latent
        # partial-write bug that would never reproduce on a local filesystem.
        # Mask-preserving, because clobbering ``O_APPEND`` here would be silent.
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        fcntl.fcntl(descriptor, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
    except BaseException:
        os.close(descriptor)
        raise
    # Deliberately outside the guard, and correct only because ``mode`` and
    # ``encoding`` are literals that cannot fail validation: ``open`` adopts the
    # descriptor when it constructs the underlying ``FileIO``, so a failure
    # *before* that leaks the descriptor while one *after* it closes it — and
    # wrapping this in the ``except`` above would double-close the second case.
    # Anyone parameterising either argument must revisit this.
    return os.fdopen(descriptor, "a", encoding="utf-8")


@contextlib.contextmanager
def single_instance(handle: TextIO) -> Iterator[bool]:
    """Hold an exclusive lock for one pass; yield ``False`` if another holds it.

    A declined lock is **not an error and must not exit non-zero**: a scheduled
    pass overlapping a slow one is expected, and failing would mail the
    operator until they learned to ignore it. The caller decides what to do
    with ``False``; this function only reports it.

    Takes a handle already opened by :func:`prepare_lock`, so nothing here can
    fail for a reason the caller would have to translate.
    """
    with handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
