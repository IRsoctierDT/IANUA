# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Local authorized snapshot ingestion for IANUA analytics.

No network access. Only declared filenames under gitignored data/imports/ are
accepted. Validate the complete source before atomically publishing it under
data/analytics/. The caller is responsible for lawful collection and export.
"""
from __future__ import annotations

import argparse
import csv
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from dashboard.analytics_governance import REQUIRED, quality_report
from dashboard.live_analytics import DATASETS, MAX_ROWS

MAX_BYTES = 2_000_000
IMPORT_DIR = Path("data/imports")
OUTPUT_DIR = Path("data/analytics")


def _regular(path: Path) -> bool:
    """Reject symlinks, special files, and multiply linked source files."""
    try:
        meta = path.lstat()
        return stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1
    except OSError:
        return False


def publish(root: Path, dataset: str, *, now: datetime | None = None) -> int:
    """Validate a declared local export and atomically publish a bounded snapshot.

    No existing snapshot is modified on validation failure. No arbitrary path
    argument is accepted. The output directory must be private and unsymlinked.
    """
    if dataset not in DATASETS:
        raise ValueError("undeclared dataset")
    root = root.resolve(strict=True)
    source_dir = root / IMPORT_DIR
    target_dir = root / OUTPUT_DIR
    source = source_dir / DATASETS[dataset]
    target = target_dir / DATASETS[dataset]
    if source_dir.is_symlink() or target_dir.is_symlink() or not _regular(source):
        raise ValueError("unsafe or missing declared import")
    if source.stat().st_size > MAX_BYTES:
        raise ValueError("import exceeds size limit")
    with source.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = reader.fieldnames
        if not fields or len(fields) > 40 or len(fields) != len(set(fields)):
            raise ValueError("invalid or duplicate header")
        if not REQUIRED[dataset].issubset(fields):
            raise ValueError("missing required columns")
        rows: list[dict[str, str]] = []
        for row in reader:
            if len(rows) >= MAX_ROWS or None in row or any(v is None for v in row.values()):
                raise ValueError("invalid or oversized import")
            rows.append(row)
    errors = quality_report(dataset, rows, now=now or datetime.now(timezone.utc))
    if errors:
        raise ValueError("quality gate rejected import: " + "; ".join(errors[:5]))
    target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target_dir.is_symlink() or (target.exists() and not _regular(target)):
        raise ValueError("unsafe destination")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", dir=target_dir,
            prefix=".analytics-", suffix=".tmp", delete=False
        ) as stream:
            temporary = Path(stream.name)
            os.chmod(temporary, 0o600)
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return len(rows)


def main() -> None:
    """CLI entry point; no implicit source discovery or network collection."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", choices=sorted(DATASETS))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    count = publish(args.root, args.dataset)
    print(f"Published {count} validated {args.dataset} rows")


if __name__ == "__main__":
    main()
