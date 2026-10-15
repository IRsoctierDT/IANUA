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
"""

from __future__ import annotations

import re
from pathlib import Path

#: One path component: no separator, no traversal, no leading dot. Shared by
#: every caller so a filename safe for one is safe for all.
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


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

    One implementation, because four copies of a guard is how three of them
    stay fixed and one does not — which is the shape this very defect took.

    Args:
        root: The ``--root`` argument, exactly as the operator supplied it.
        error: The exception type to raise, so each caller keeps its taxonomy.
        what: A noun for the message.

    Returns:
        ``root`` resolved, so every later join is unambiguous.

    Raises:
        error: If ``root`` is relative (including ``""`` and ``"."``), or does
            not already exist as a directory when stated as supplied.
    """
    if not root.is_absolute():
        raise error(
            f"{what} must be an absolute path, got {str(root)!r}; a relative root means "
            "whatever the scheduler's working directory happens to be, which is how an "
            "unset shell variable becomes a shadow data tree that reports success"
        )
    # Stated as supplied. Resolving first is what let `/srv/absent/..` through.
    if not root.is_dir():
        raise error(
            f"{what} {root} is not an existing directory; data/ is created beneath the "
            "root but never the root itself, so this is a typo or an unmounted volume "
            "rather than a fresh deployment"
        )
    return root.resolve()
