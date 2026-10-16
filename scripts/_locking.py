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

Two fixes, each applied to a subset. A third is pending (a FIFO at the lock
path blocks the ``open`` forever, in all four), and writing it four times is
what this module exists to prevent.

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
``data/collect/``, ``data/pipeline/`` and ``data/retention/`` under the
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
import fcntl
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

    :param directory: the lock directory, created owner-only if absent and
        narrowed to :data:`DIR_MODE` if it already exists.
    :param filename: the CLI's own lock file name, so each CLI keeps its own
        ``LOCK_FILE`` constant and this function reads no caller's globals.
    :returns: the open handle, to be passed to :func:`single_instance`.
    """
    directory.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    directory.chmod(DIR_MODE)
    path = directory / filename
    path.touch(mode=FILE_MODE, exist_ok=True)
    path.chmod(FILE_MODE)
    return path.open("a", encoding="utf-8")


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
