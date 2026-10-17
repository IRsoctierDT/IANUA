#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Perform the controlled repository-wide rename to IANUA.

The migration updates active text files while preserving captured historical
GitHub Actions logs under ``sample-logs/``. It is deterministic and safe to run
more than once.

Security considerations: paths are constrained to the repository root — on
the *resolved* file, not only the declared one, since a symlink at a scanned
path is refused rather than followed (see :func:`eligible`) — the scan is
read-only unless ``--apply`` is passed, and this file excludes itself
from rewriting — its ``REPLACEMENTS`` table intentionally contains the legacy
identifiers, so rewriting or scanning it would corrupt the migration (the
table would collapse to identity mappings and ``--check`` would then flag
every occurrence of the *new* name as a leftover).
"""

from __future__ import annotations

import argparse
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
    if path.resolve() == SELF:
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


def migrate(*, apply: bool) -> tuple[list[Path], list[tuple[Path, str]]]:
    """Find and optionally replace legacy identifiers."""
    changed: list[Path] = []
    remaining: list[tuple[Path, str]] = []

    for path in sorted(ROOT.rglob("*")):
        if not eligible(path):
            continue
        try:
            original = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        updated = original
        for old, new in REPLACEMENTS:
            updated = updated.replace(old, new)

        if updated != original:
            changed.append(path.relative_to(ROOT))
            if apply:
                path.write_text(updated, encoding="utf-8")

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

    changed, remaining = migrate(apply=args.apply)
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
