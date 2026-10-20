# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""CLI helpers for backup tests."""

from __future__ import annotations

import shutil
import stat
from pathlib import Path

from scripts.run_backup import main as _main


def _preserve_source_chain(backup: Path) -> Path:
    """Copy the source events chain family as restore step 4a does, without locks."""
    source_root = backup.parents[2]
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


def with_audit_anchor(argv: list[str]) -> list[str]:
    """Add a step-4a-style independent source-chain copy for test restores."""
    result = list(argv)
    try:
        restore_index = result.index("--verify-restore")
    except ValueError:
        return result
    if "--audit-anchor" in result:
        return result
    backup = Path(result[restore_index + 1])
    return [*result, "--audit-anchor", str(_preserve_source_chain(backup))]


def backup_main(argv: list[str]) -> int:
    """Run the backup CLI with the explicit independent anchor expected by new code."""
    return _main(with_audit_anchor(argv))
