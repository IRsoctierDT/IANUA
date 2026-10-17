#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Perform the controlled repository-wide rename to IANUA.

The migration updates active text files while preserving captured historical
GitHub Actions logs under ``sample-logs/``. It is deterministic and safe to run
more than once.

Security considerations: every read and write goes through a descriptor
opened beneath the repository root without following a symlink at any
component, and a write goes only to the inode that was read and only when it
has exactly one name (see :func:`_open_beneath` and :func:`_rewrite`); a
refusal exits 2. A hard link is still *read*: its bytes may be shared with a
name outside the root, and a scan reports only which legacy identifier it
found. The scan is read-only unless ``--apply`` is passed, and this file
excludes itself (by inode) from rewriting — its ``REPLACEMENTS`` table
intentionally contains the legacy identifiers, so rewriting or scanning it
would corrupt the migration (the table would collapse to identity mappings and
``--check`` would then flag every occurrence of the *new* name as a leftover).
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SELF = Path(__file__).resolve()
EXCLUDED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
    "sample-logs",
}

#: Directory prefixes excluded as whole subtrees, matched on the path relative
#: to :data:`ROOT`. Distinct from :data:`EXCLUDED_PARTS`, which matches a single
#: component anywhere in a path and so cannot express "this directory only".
#:
#: ``.claude/worktrees`` holds the transient git worktrees an isolated agent
#: runs in, and a worktree contains a *copy* of this script. The real one is
#: skipped by resolved-path equality in :func:`eligible`; a copy at another
#: path is not, and it necessarily contains every legacy identifier because it
#: *is* :data:`REPLACEMENTS`. So walking into it fails the gate on its own
#: source — and CI never has a worktree there, so the failure is local-only,
#: which is the worse shape: an agent running the gate per AGENTS.md §7 sees a
#: red required check it did not cause.
#:
#: Scoped to ``.claude/worktrees`` and **not** to ``.claude``, because
#: ``.gitignore`` ignores selected ``.claude`` entries rather than the
#: directory wholesale, so content there can be tracked. Excluding the whole
#: directory would let a tracked ``.claude`` file carry a legacy identifier
#: past this gate. Found by review; ``tests/unit`` pins both halves.
EXCLUDED_PREFIXES: tuple[tuple[str, ...], ...] = ((".claude", "worktrees"),)

#: Top-level directories excluded as whole subtrees. ``data/`` is the
#: gitignored lab-data root (``.gitignore`` lists ``/data/``, top-level only):
#: it holds telemetry, evidence reports and staged third-party bundles, none
#: of which is a repository identifier this gate exists to migrate. Measured
#: on the unpatched gate: a probe report under ``data/reports/`` carrying a
#: legacy identifier turned ``--check`` red — a required check (AGENTS.md §7)
#: failing on content that is never committed, the same local-only false red
#: ``.claude/worktrees`` produced — and ``--apply`` rewrote it, which is
#: evidence mutated by a repository-hygiene tool. Matched on the first
#: component of the path relative to :data:`ROOT` only, so ``attack/data/``
#: (committed shards) stays in scope; :data:`EXCLUDED_PARTS` cannot express
#: that, since it matches a component anywhere.
EXCLUDED_TOP_LEVEL: frozenset[str] = frozenset({"data"})
TEXT_SUFFIXES = {
    ".cjs",
    ".css",
    ".env",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".lock",
    ".md",
    ".mjs",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

REPLACEMENTS: tuple[tuple[str, str], ...] = (
    ("AI_Operator_Cyber_Command_Center_Master_v1_STICHES", "IANUA"),
    ("ai-operator-cyber-command-center-master-v1-stiches", "ianua"),
    ("AI Operator Cyber Command Center", "IANUA"),
    ("ai-operator-cyber-command-center", "ianua"),
    ("AI-Command-Center", "IANUA"),
    ("AI_Command_Center", "IANUA"),
    ("ai_command_center", "ianua"),
    ("AI_COMMAND_CENTER", "IANUA"),
)


def eligible(path: Path) -> bool:
    """Return whether a repository file may be safely rewritten.

    A symlink is refused on the declared path, before anything follows it.
    ``rglob`` keeps every *declared* path under :data:`ROOT`, but it yields a
    link inside the tree, and ``is_file()``, ``read_text`` and ``write_text``
    all follow that link to wherever it points. Measured on the unpatched
    gate: a ``docs/*.md`` link to a file outside the checkout was reported by
    ``--check`` and the outside file was rewritten by ``--apply``. AGENTS.md
    §5 scopes filesystem reach to the project, and ``collect/`` refuses a
    symlink at a declared source for the same reason. A path that resolves
    outside the root is refused outright rather than judged on its unresolved
    parts, which was the previous fallback.

    This judges a *path*, which can change before it is opened, so it does not
    bound reach on its own: :func:`_open_beneath` decides again on the
    descriptor. A hard link is eligible to scan, since every file in a
    ``cp -al`` copy of a checkout has two names (measured: 495 of 495), and
    refusing them would scan nothing and report it clean; :func:`_rewrite`
    refuses to write one. The script is excluded by inode (``samefile``), so
    a second name for it is not scanned either.
    """
    if path.is_symlink():
        return False
    try:
        relative = path.resolve().relative_to(ROOT).parts
    except ValueError:
        return False
    if any(relative[: len(prefix)] == prefix for prefix in EXCLUDED_PREFIXES):
        return False
    if relative and relative[0] in EXCLUDED_TOP_LEVEL:
        return False
    if not path.is_file() or any(part in EXCLUDED_PARTS for part in path.parts):
        return False
    if path.samefile(SELF):
        return False
    # ``.env.example`` is named because ``Path(".env.example").suffix`` is
    # ``.example`` and ``Path(".env").suffix`` is ``""``: the ``.env`` suffix
    # entry above reaches neither, which kept the documented config out of
    # the gate (measured) and keeps the operator's gitignored ``.env`` out of
    # it, which is the half that must stay so.
    return path.suffix.lower() in TEXT_SUFFIXES or path.name in {
        "Dockerfile",
        "Makefile",
        "Procfile",
        ".pre-commit-config.yaml",
        ".env.example",
    }


class RefusedPath(OSError):
    """A scanned path the descriptor checks refused; :func:`main` exits 2."""


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _open_beneath(path: Path, flags: int) -> int:
    """Open ``path`` from :data:`ROOT` one component at a time, following no link.

    Each directory is opened ``O_NOFOLLOW`` relative to its parent's
    descriptor, and the file ``O_NOFOLLOW | O_NONBLOCK`` and then ``fstat``-ed.
    So a symlink swapped in at *any* component after :func:`eligible` approved
    the path fails instead of being followed, and a FIFO fails the
    regular-file check instead of blocking the gate. Measured on the previous
    gate: a file or an ancestor directory swapped for a link after the check
    was followed and its outside target rewritten, and a FIFO hung it. Unlike
    ``collect/``, ancestors are walked: ``rglob`` never descends a link, so no
    legitimate path beneath ROOT goes through one.
    """
    try:
        parts = path.relative_to(ROOT).parts
    except ValueError:
        parts = ()
    if not parts or ".." in parts:
        raise RefusedPath(f"{path}: not a path beneath the repository root")
    parent = os.open(ROOT, _DIR_FLAGS)
    try:
        for part in parts[:-1]:
            child = os.open(part, _DIR_FLAGS, dir_fd=parent)
            os.close(parent)
            parent = child
        leaf = flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        descriptor = os.open(parts[-1], leaf, dir_fd=parent)
    except OSError as exc:
        raise RefusedPath(f"{path}: {exc.strerror} on open beneath the root") from exc
    finally:
        os.close(parent)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise RefusedPath(f"{path}: not a regular file when opened")
    return descriptor


def _rewrite(path: Path, text: str, read: os.stat_result) -> None:
    """Write ``text`` to the inode ``read`` describes, and to nothing else.

    The path is reopened, so the descriptor must be that inode: anything
    renamed, linked or created in its place in between is refused. That holds
    only while the caller keeps the read descriptor open (measured: with it
    closed, a file unlinked and recreated in between got the same inode number
    and was written). And it must have exactly one name, because a write
    through a hard link rewrites every name of the inode, including one
    outside the root (measured on the previous gate: ``--apply`` rewrote an
    outside file through a ``docs/*.md`` hard link, and this script through a
    hard link to it). No ``O_TRUNC``: nothing is truncated until both
    checks pass. A write that fails after the truncate leaves the file short,
    as ``write_text`` did.
    """
    descriptor = _open_beneath(path, os.O_WRONLY)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        status = os.fstat(descriptor)
        if (status.st_dev, status.st_ino) != (read.st_dev, read.st_ino):
            raise RefusedPath(f"{path}: replaced between read and write")
        if status.st_nlink != 1:
            raise RefusedPath(f"{path}: has {status.st_nlink} names; a write rewrites all")
        handle.truncate(0)
        handle.write(text)


def migrate(*, apply: bool) -> tuple[list[Path], list[tuple[Path, str]]]:
    """Find and optionally replace legacy identifiers.

    :raises RefusedPath: when a descriptor check refuses a path. The pass stops
        there; files already rewritten stay so, which a rerun tolerates since
        the migration is idempotent.
    """
    changed: list[Path] = []
    remaining: list[tuple[Path, str]] = []

    for path in sorted(ROOT.rglob("*")):
        if not eligible(path):
            continue
        # Held open until the write, so the inode it read cannot be freed and
        # its number reused by a file created in its place (see _rewrite).
        with os.fdopen(_open_beneath(path, os.O_RDONLY), encoding="utf-8") as source:
            try:
                original = source.read()
            except UnicodeDecodeError:
                continue

            updated = original
            for old, new in REPLACEMENTS:
                updated = updated.replace(old, new)

            if updated != original:
                changed.append(path.relative_to(ROOT))
                if apply:
                    _rewrite(path, updated, os.fstat(source.fileno()))

        inspected = updated if apply else original
        for old, _ in REPLACEMENTS:
            if old in inspected:
                remaining.append((path.relative_to(ROOT), old))

    return changed, remaining


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Write replacements to disk.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when active legacy references remain after processing.",
    )
    args = parser.parse_args()

    try:
        changed, remaining = migrate(apply=args.apply)
    except OSError as exc:
        print(f"rename gate refused: {exc}", file=sys.stderr)
        return 2
    for path in changed:
        print(f"{'updated' if args.apply else 'would update'}: {path}")

    if remaining:
        for path, value in remaining:
            print(f"remaining: {path}: {value}")
        return 1 if args.check else 0

    print("IANUA rename scan clean; historical sample logs were preserved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
