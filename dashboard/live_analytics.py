# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Read-only dashboard projections; no source mutation or network calls.

The event-store reader is bounded and refuses to create an absent database.
Optional CSV snapshots are restricted to the local gitignored analytics folder.
"""
from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path
from typing import Any

from store.events import EventStore, Query

MAX_EVENTS = 500
MAX_ROWS = 2000
ANALYTICS_DIR = Path("data") / "analytics"
DATASETS = {
    "phishing": "phishing.csv",
    "vulnerabilities": "vulnerabilities.csv",
    "pci": "pci_evidence.csv",
}


def load_events(root: Path) -> tuple[list[dict[str, Any]], str]:
    """Read a bounded recent event sample, preserving ingestion provenance.

    Never initializes an absent store. The existing store validates row integrity.
    """
    db = root / "data" / "events" / "events.sqlite3"
    if not db.is_file():
        return [], "unavailable: event store not initialized"
    try:
        with EventStore.open(root) as store:
            events = store.query(Query(limit=MAX_EVENTS))
        return [
            {
                "event_id": item.event_id,
                "ingested_at": item.ingested_at,
                "occurred_at": item.event.timestamp,
                "domain": item.event.source_type,
                "vendor": item.event.vendor,
                "parse_status": item.event.parse_status,
            }
            for item in events
        ], "connected"
    except (OSError, ValueError, RuntimeError) as exc:
        return [], f"unavailable: {type(exc).__name__}"


def load_snapshot(root: Path, dataset: str) -> tuple[list[dict[str, str]], str]:
    """Read only a declared CSV in the local analytics directory.

    Missing, oversized or malformed input is explicitly unavailable, never zero.
    """
    if dataset not in DATASETS:
        raise ValueError("unknown dataset")
    folder = root / ANALYTICS_DIR
    path = folder / DATASETS[dataset]
    if folder.is_symlink() or path.is_symlink():
        return [], "unavailable: symlink refused"
    try:
        if not path.is_file():
            return [], "unavailable: no authorized data source configured"
        if path.stat().st_size > 2_000_000:
            return [], "unavailable: snapshot exceeds size limit"
        with path.open(encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            if not reader.fieldnames or len(reader.fieldnames) > 40:
                return [], "unavailable: invalid columns"
            rows = []
            for index, row in enumerate(reader):
                if index >= MAX_ROWS:
                    return [], "unavailable: snapshot exceeds row limit"
                if None in row or any(value is None for value in row.values()):
                    return [], "unavailable: malformed CSV row"
                rows.append(row)
        return rows, "snapshot (not live)"
    except (OSError, UnicodeError, csv.Error):
        return [], "unavailable: unreadable snapshot"


def domain_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    """Count canonical domains without inferring missing telemetry."""
    return dict(sorted(Counter(str(event["domain"]) for event in events).items()))


def numeric_counts(rows: list[dict[str, str]], key: str) -> dict[str, int]:
    """Count values of an explicitly present classification column."""
    return dict(sorted(Counter(row[key] for row in rows if key in row).items()))
