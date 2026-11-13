# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Bounded, aggregate SOC telemetry and incident views for a local operator."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from correlation import Incident, assemble
from store import EventStore, Query

MAX_EVENTS = 500


@dataclass(frozen=True)
class SocSnapshot:
    """Aggregate activity and freshness for the requested source-time window."""

    counts: dict[str, int]
    incidents: tuple[Incident, ...]
    last_ingested: float | None
    limited: bool


def soc_snapshot(root: Path, start: float, end: float) -> SocSnapshot:
    """Read existing telemetry using IANUA's store and correlation engine."""
    with EventStore.open_read_only(root) as events:
        latest = events.query(Query(limit=1))
        rows = events.query(Query(since=start, until=end, limit=MAX_EVENTS + 1))
    window = rows[:MAX_EVENTS]
    return SocSnapshot(
        dict(Counter(f"{r.event.source_type} / {r.event.vendor}" for r in window)),
        assemble(window),
        latest[0].ingested_at if latest else None,
        len(rows) > MAX_EVENTS,
    )
