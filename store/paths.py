# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Confining a path to the lab-data root, once, for everything that writes there.

Three packages now keep state under the gitignored lab-data root — ``store/``
(the event database), ``pipeline/`` (the cursor) and ``collect/`` (read
offsets) — and each had grown its own copy of the same check. The copies were
not merely duplicated, they were *wrong in the same way twice*: both examined
only the leaf directory and the file, so a symlink planted at ``data`` was
never looked at while ``mkdir(parents=True)`` created the leaf straight
through it; and both gated the check on ``exists()``, which is ``False`` for a
link whose target does not exist yet — precisely the case ``mkdir`` then goes
on to create. Fixing one copy and not the others is how that recurs, so there
is one implementation here and the security suite asserts every caller behaves
identically.

It lives in ``store/`` rather than a package of its own because ``store/`` is
the lowest layer that owns the lab-data root, and both other callers already
import it — ``pipeline/`` for ``EventStore``, ``collect/`` to write events. A
new top-level package for twelve lines would add a gate surface, a README and
an ``__init__`` to carry no additional meaning.

Security considerations (AGENTS.md §3, §5):

* **Every component is walked**, not just the leaf. A subdirectory two deep
  (``data/pipeline``) has an intermediate that a leaf-only check never sees.
* **``is_symlink`` rather than ``exists() and resolve() != path``.** The latter
  skips a dangling link, and a dangling link is exactly what a planted attack
  looks like before ``mkdir`` materializes its target.
* **The root is resolved once, then appended to.** Resolving the candidate
  first would follow a planted link and then cheerfully confirm the file sits
  inside its own target.
* **The caller's error type is raised**, so each package keeps its own
  taxonomy and a caller catching ``CursorPathError`` does not have to know
  this module exists.

The SQLite sidecar check (:func:`sidecar_problem`) lives here for the same
reason, one layer down: it is a check on *names beside a path*, it imports
nothing first-party, and it had one copy in ``scripts/run_backup.py`` while
the four scheduled entry points that open the live store ran with none.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

#: One path component: no separator, no traversal, no leading dot. Shared by
#: every caller so a filename safe for one is safe for all.
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

#: The files SQLite opens beside a database, and reads or writes through.
SIDECARS = ("-wal", "-journal", "-shm")

#: How a file that is not a regular one is named in a finding.
_KINDS = (
    (stat.S_ISLNK, "a symlink"),
    (stat.S_ISDIR, "a directory"),
    (stat.S_ISFIFO, "a FIFO"),
    (stat.S_ISSOCK, "a socket"),
    (stat.S_ISCHR, "a character device"),
    (stat.S_ISBLK, "a block device"),
)


def confine(
    root: Path,
    subdir: Path,
    filename: str,
    *,
    error: type[Exception],
    what: str = "file",
) -> Path:
    """Return ``root/subdir/filename``, or raise ``error`` if it could escape.

    Validates the filename against :data:`SAFE_FILENAME`, then walks every
    component from the resolved root down to the file, refusing any that is a
    symlink. The returned path is *not* created — the caller decides when, and
    a refusal therefore happens before anything exists to clean up.

    Args:
        root: The lab-data root. Resolved once; never followed afterwards.
        subdir: Where under the root this state belongs, e.g.
            ``Path("data") / "pipeline"``.
        filename: A single component. Separators and traversal are refused
            rather than normalized.
        error: The exception type to raise, so each package keeps its taxonomy.
        what: A noun for the message ("event store", "cursor", "offsets").

    Raises:
        error: On a filename that is not a single safe component, or on any
            symlinked component between the root and the file.
    """
    if filename in {".", ".."} or not SAFE_FILENAME.fullmatch(filename):
        raise error(f"{what} filename must match {SAFE_FILENAME.pattern!r}, got {filename!r}")
    base = root.resolve()
    directory = base / subdir
    candidate = directory / filename
    walked = base
    for part in (*subdir.parts, filename):
        walked = walked / part
        if walked.is_symlink():
            raise error(
                f"{walked} is a symlink (-> {walked.readlink()}); refusing to follow it "
                f"out of the lab-data root. Relocating the {what} is a deployment "
                "decision, not something a planted link should accomplish silently."
            )
    if not candidate.is_relative_to(directory):  # pragma: no cover
        # Unreachable while SAFE_FILENAME holds: a name with no separator
        # cannot escape its parent lexically, and the symlink walk above covers
        # the resolve-based escapes. Kept as a structural backstop so that
        # loosening that pattern does not silently open a traversal.
        raise error(f"{what} path {candidate} escapes {directory}")
    return candidate


def validated_root(root: Path, *, error: type[Exception], what: str = "lab-data root") -> Path:
    """Return ``root`` resolved, or raise ``error`` if it is not a usable root.

    Every scheduled entry point takes a ``--root`` and creates ``data/``
    beneath it, never the root itself — so a root that does not already exist
    is a typo or an unmounted volume, not a fresh deployment. Three of the
    four CLIs each carried their own copy of that check, one carried none, and
    **all four shared a hole**: ``Path("") == Path(".")`` and
    ``Path(".").is_dir()`` is ``True``, so an unset shell variable in the
    documented scheduler line — ``--root "$IANUA_ROOT"`` with nothing in it —
    passed the check and built a complete shadow ``data/`` tree in whatever
    the working directory happened to be.

    Measured on all four CLIs: exit 0 every time, and the collector silently
    wrote an ``events.sqlite3`` into the shadow tree. That is the failure
    ``docs/PRODUCTION_SOC_PLAN.md`` names as the catastrophic one — "every
    signal reading healthy while the SOC sees nothing" — reached by the
    likeliest misconfiguration there is.

    **Two rules, and the order of the second one is the whole control.**

    *Absolute only*, which is the rule ``collect/`` already applies to log
    sources for this exact reason (AGENTS.md §5: "a relative path means
    whatever the scheduler's working directory happens to be"). It refuses
    ``""`` and ``"."`` as instances rather than as special cases, and it
    refuses every other relative spelling with them.

    *Existence tested on the path as supplied, before ``resolve()``* — because
    ``resolve()`` does not merely normalize a path, it **invents a real one**.
    With ``strict=False`` (the default) it collapses ``..`` lexically against
    components that do not exist, so an absolute ``/srv/absent/..`` resolves to
    an existing ``/srv`` and sails through any check made afterwards. Measured,
    on the first version of this function: ``--root missing/..`` gave
    ``Path.resolve().is_dir() == True``, and ``scripts/run_pipeline.py`` exited
    ``0`` with "idle: no new events" after writing a complete shadow tree —
    ``data/events/events.sqlite3`` included — into the working directory. That
    version had **regressed** the per-CLI guards it replaced: their
    ``args.root.is_dir()`` stated the *unresolved* path, and the kernel refuses
    to walk ``..`` out of a component that is not there, so they rejected the
    spelling this one accepted. Found by the automated reviewer on the pull
    request that introduced it, against the enumeration of spellings that
    pull request asked it to break.

    ``..`` is not refused separately: with both rules above, a surviving ``..``
    means every component on the way to it exists, so nothing has been invented
    and the operator has named a real directory the long way round.

    *The filesystem root is refused*, and it is the only absolute path given a
    rule of its own, because it is the only one a misconfigured scheduler
    produces **by accident**. Measured: with the variable unset,
    ``--root "$IANUA_ROOT"`` is ``""`` and refused by the first rule, but
    ``--root "$IANUA_ROOT/"`` — the same line with an ordinary trailing slash —
    is exactly ``"/"``, which is absolute, is a directory, and was accepted.
    That puts the event store at ``/data`` with every signal reading healthy:
    one character from the hole this function was written to close, and in the
    same catastrophic class. ``//``, ``/.``, ``/..``, ``/../../..`` and
    ``/proc/self/root`` all resolve there too, so the test is on the resolved
    path — a path that is its own parent.

    **The limit of the absolute rule, stated rather than implied.** "Absolute"
    removes the *accidental* dependence on the working directory, not every
    possible one. ``/proc/self/cwd`` is absolute, is a directory, and resolves
    to the process's working directory; measured, it is accepted and the tree
    lands there, as it is for ``/proc/thread-self/cwd`` and ``/dev/fd/N``
    entries. Those are **not** refused, deliberately: no scheduler
    misconfiguration produces them — an unset variable yields ``""`` or ``"/"``,
    both now refused — and banning ``/proc`` would refuse paths that are
    legitimate on Linux. An operator who writes one has named that directory on
    purpose, which is the line this function draws. It also cannot catch
    ``--root "$IANUA_ROOT/data"`` with the variable unset, which yields
    ``/data``: that is an absolute path to a plausible lab-data root, and
    nothing here can distinguish it from an operator who meant it.

    One implementation, because four copies of a guard is how three of them
    stay fixed and one does not — which is the shape this very defect took.

    Args:
        root: The ``--root`` argument, exactly as the operator supplied it.
        error: The exception type to raise, so each caller keeps its taxonomy.
        what: A noun for the message.

    Returns:
        ``root`` resolved, so every later join is unambiguous.

    Raises:
        error: If ``root`` is relative (including ``""`` and ``"."``), does not
            already exist as a directory when stated as supplied, cannot be
            stated at all, or resolves to the filesystem root.
    """
    if not root.is_absolute():
        raise error(
            f"{what} must be an absolute path, got {str(root)!r}; a relative root means "
            "whatever the scheduler's working directory happens to be, which is how an "
            "unset shell variable becomes a shadow data tree that reports success"
        )
    # Stated as supplied. Resolving first is what let `/srv/absent/..` through.
    try:
        is_directory = root.is_dir()
    except OSError as exc:
        # `Path.is_dir()` swallows ENOENT, ENOTDIR, EBADF and ELOOP and returns
        # False, but *not* ENAMETOOLONG, which propagated as a bare `OSError`
        # and broke the `error` contract above. Measured: a 256-byte component
        # raised `[Errno 36] File name too long` straight through. The four
        # CLIs happen to catch `OSError` as well, so the exit code was right by
        # accident, which is not the same as the contract holding.
        raise error(f"{what} {root} cannot be stated: {exc}") from exc
    if not is_directory:
        raise error(
            f"{what} {root} is not an existing directory; data/ is created beneath the "
            "root but never the root itself, so this is a typo or an unmounted volume "
            "rather than a fresh deployment"
        )
    # Not wrapped: the path was just stat-ed successfully, so a failure here
    # would be a race rather than a reachable argument.
    resolved = root.resolve()
    # The path validated and the path returned are different paths whenever a
    # symlink is involved, and callers create `data/` beneath the *returned*
    # one. An atomic deployment symlink swap — `/srv/ianua` repointed from one
    # release to the next between these two calls — would otherwise hand back
    # a target nothing had checked, including one that does not exist, which
    # `mkdir(parents=True)` would then create. Re-stating it closes that
    # ordinary-operations case. It does **not** close an adversary racing the
    # two calls deliberately; §5 of the charter already records why that race
    # is unwinnable, and this is two syscalls apart like any other.
    if resolved != root and not resolved.is_dir():
        raise error(
            f"{what} {root} resolved to {resolved}, which is not a directory; a symlinked "
            "root that moved between the check and the return is the deployment case, and "
            "data/ must not be created under a path nothing validated"
        )
    if resolved.parent == resolved:
        raise error(
            f"{what} must not be the filesystem root, got {str(root)!r} (resolves to "
            f"{resolved}); data/ is created beneath the root, so this would put the "
            "event store at /data. It is the one absolute path a misconfigured "
            'scheduler writes by accident: --root "$IANUA_ROOT/" with the variable '
            'unset is exactly "/"'
        )
    return resolved


def kind_of(mode: int) -> str:
    """How a file of ``mode`` that is not a regular file is named in a finding.

    ``"a FIFO"``, ``"a symlink"`` and so on, or ``"unrecognised"`` for a type
    the table does not name. One table, shared by :func:`sidecar_problem` and
    by ``EventStore.open``'s check of the database file itself, so the two
    cannot describe one file type two ways.
    """
    return next((name for test, name in _KINDS if test(mode)), "unrecognised")


def sidecar_problem(db: Path, *, what: str) -> str | None:
    """Why a file beside ``db`` makes it unsafe to hand to SQLite, or ``None``.

    SQLite opens every sidecar with the database: it checkpoints a ``-wal``,
    replays a ``-journal``, and truncates and rewrites a ``-shm`` as its WAL
    index. Each must therefore be absent or a regular file with a single link.
    Measured in ``scripts/run_backup.py``, found by independent review:

    - a FIFO ``-journal`` hung both verifiers, and a plain take, inside the
      open while they held the backup lock, so every later pass skipped at
      exit 0; a FIFO ``-wal`` was deleted;
    - a symlinked, FIFO or directory ``-shm`` replaced the report with a bare
      SQLite error and left a new ``-wal`` in the tree under inspection;
    - a ``-shm`` **hard-linked** to another file had that file overwritten
      with 32 KiB of WAL index: the backup's own manifest, and the live
      store, were each destroyed under a run that exited 0 "verified".

    And measured through ``EventStore.open`` on the live store, which had no
    check at all, so every scheduled entry point that opens it — the
    collector, the pipeline, retention and ``scripts/report_sli.py`` — carried
    each of these (uid 0, Python 3.11.17, SQLite 3.45.1):

    - a FIFO ``-journal`` blocked the open in ``open(2)`` for good, and three
      of the four hold their single-instance lock across it, so every later
      scheduled pass printed "skipped" at exit 0 for as long as the FIFO
      stayed — a collector that never collects again, reading as idle;
    - a ``-shm`` hard-linked to a file outside the root left that file
      65536 -> 32768 bytes of WAL index, a new sha256 and mode 0o644 -> 0o600,
      at exit 0 — and SQLite unlinked the ``-shm`` name on close, so nothing
      was left in the tree to show it had happened. A hard-linked ``-wal`` was
      chmodded the same way through an open alone, and the collector, which
      writes, overwrote it with WAL frames;
    - a symlinked or directory ``-wal``, ``-journal`` or ``-shm`` mostly raised
      a bare ``OperationalError`` ("unable to open database file", "disk I/O
      error"), which the collector reported *against the log source* it
      happened to be reading. Two did not, and opened without a word (found by
      review): a dangling-symlink ``-journal``, and a directory ``-shm`` for a
      reader, which left a new ``-wal`` behind.

    A hard link is a regular file, which is why the link count is checked
    with the type, and why this is one ``lstat`` per name. It is a check on
    the path, so a sidecar swapped in between it and the open is not caught:
    that needs write access to the directory holding the database, which the
    store keeps at 0o700.

    Every offending sidecar is named, with what is wrong with it, because the
    remedies differ: a FIFO or a symlink is never benign, while a second link
    can come from a hard-link copy of the tree (``cp -al``, ``rsync
    --link-dest``) and the size says whether a ``-wal`` holds frames (found by
    review: the first version named only the first sidecar, and only as "not a
    regular file with a single link").

    Args:
        db: The database path. Only the names beside it are examined; the
            file itself is the caller's to check, because what is safe there
            differs — a second link to a database is a snapshot farm, not a
            hazard, while a second link to a ``-shm`` is a file SQLite will
            overwrite.
        what: How the database is named in the reason, e.g.
            ``"the event store /srv/ianua/data/events/events.sqlite3"``.

    Returns:
        ``None`` when every sidecar is absent or a regular file with one link,
        otherwise one sentence naming each one that is not. A reason, not a
        raise, so a caller that reports rather than refuses (``--verify``) can
        keep the rest of its report.
    """
    reasons: list[str] = []
    for suffix in SIDECARS:
        side = db.with_name(db.name + suffix)
        try:
            found = os.lstat(side)
        except FileNotFoundError:
            continue
        except OSError as exc:
            # Not walkable is not safe: an error other than "absent" is a
            # sidecar nothing here could look at, and treating it as absent
            # would hand SQLite a name this check never saw.
            reasons.append(f"its {suffix} cannot be checked ({type(exc).__name__})")
            continue
        if not stat.S_ISREG(found.st_mode):
            reasons.append(f"its {suffix} is {kind_of(found.st_mode)}, not a regular file")
        elif found.st_nlink != 1:
            reasons.append(
                f"its {suffix} ({found.st_size} bytes) has {found.st_nlink} links: another "
                "name shares the file, and SQLite would write through both"
            )
    if not reasons:
        return None
    return (
        f"{what} cannot be opened safely: {'; '.join(reasons)}. SQLite opens every "
        "sidecar with the store, so the store was not opened"
    )
