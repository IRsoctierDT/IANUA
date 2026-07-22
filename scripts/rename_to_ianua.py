#!/usr/bin/env python3
"""Perform the controlled repository-wide rename to IANUA.

The migration updates active text files while preserving captured historical
GitHub Actions logs under ``sample-logs/``. It is deterministic and safe to run
more than once.

Security considerations: paths are constrained to the repository root, the
scan is read-only unless ``--apply`` is passed, and this file excludes itself
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
    """Return whether a repository file may be safely rewritten."""
    if not path.is_file() or any(part in EXCLUDED_PARTS for part in path.parts):
        return False
    if path.resolve() == SELF:
        return False
    return path.suffix.lower() in TEXT_SUFFIXES or path.name in {
        "Dockerfile",
        "Makefile",
        "Procfile",
        ".pre-commit-config.yaml",
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
