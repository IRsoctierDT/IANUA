# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""CLI helpers for backup tests."""

from __future__ import annotations

import shutil
import stat
from pathlib import Path

from scripts.run_backup import main as _main


def _preserve_source_chain(source_root: Path) -> Path:
    """Keep an independent copy of the source chain family beside a test root."""
    source_directory = source_root / "data" / "events"
    preserved = source_root.parent / f"{source_root.name}-preserved-events"
    preserved.mkdir(mode=0o700, exist_ok=True)
    current: set[str] = set()
    for child in source_directory.iterdir():
        if child.name.startswith("audit.log") and not child.name.endswith(".lock"):
            info = child.lstat()
            if stat.S_ISREG(info.st_mode):
                current.add(child.name)
                shutil.copy2(child, preserved / child.name)
    for child in preserved.iterdir():
        if child.name.startswith("audit.log") and child.name not in current:
            child.unlink()
    return preserved / "audit.log"


def _existing_anchor(root: Path | None, backup: Path) -> Path | None:
    """Find the source chain captured when the test backup was taken."""
    candidates: list[Path] = []
    if root is not None:
        candidates.append(root.parent / f"{root.name}-preserved-events" / "audit.log")
    if backup.parent.name == "backups" and backup.parent.parent.name == "data":
        source_root = backup.parents[2]
        candidates.append(source_root.parent / f"{source_root.name}-preserved-events" / "audit.log")
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def with_audit_anchor(argv: list[str]) -> list[str]:
    """Add an already-preserved chain for a restore or a lost-root verification."""
    result = list(argv)
    try:
        mode = next(flag for flag in ("--verify-restore", "--verify") if flag in result)
    except StopIteration:
        return result
    if "--audit-anchor" in result:
        return result
    backup = Path(result[result.index(mode) + 1])
    root = Path(result[result.index("--root") + 1]) if "--root" in result else None
    if (
        mode == "--verify"
        and root is not None
        and (root / "data" / "events" / "audit.log").is_file()
    ):
        return result
    anchor = _existing_anchor(root, backup)
    return [*result, "--audit-anchor", str(anchor)] if anchor is not None else result


def backup_main(argv: list[str]) -> int:
    """Run the CLI and preserve each successful take's source-chain family for restores."""
    result = _main(with_audit_anchor(argv))
    if (
        result == 0
        and "--verify" not in argv
        and "--verify-restore" not in argv
        and "--root" in argv
    ):
        _preserve_source_chain(Path(argv[argv.index("--root") + 1]))
    return result
