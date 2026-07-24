"""Posture trend history — score over time from the recorded evidence trail.

Reads the local evidence JSONL (via :func:`compliance.evidence.load_recent`,
which already validates record shape fail-closed) and groups records into one
point per recorded run. Pure aggregation — no additional I/O paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from compliance.controls import ControlStatus
from compliance.evidence import load_recent

_AUTOMATED_STATUSES = {
    ControlStatus.PASS.value,
    ControlStatus.FAIL.value,
    ControlStatus.ERROR.value,
}


@dataclass(frozen=True)
class TrendPoint:
    """One recorded run: automated pass count, total, and derived score."""

    recorded_at: str
    passing: int
    automated_total: int

    @property
    def score(self) -> int:
        if self.automated_total == 0:
            return 0
        return round(100 * self.passing / self.automated_total)


def score_history(root: Path, limit: int = 1000) -> tuple[TrendPoint, ...]:
    """Chronological trend points from the evidence trail (oldest first).

    Only automated statuses count toward the score, mirroring
    :attr:`compliance.engine.ComplianceReport.score`.
    """
    grouped: dict[str, tuple[int, int]] = {}
    for record in load_recent(root, limit=limit):
        if record.status not in _AUTOMATED_STATUSES:
            continue
        passing, total = grouped.get(record.recorded_at, (0, 0))
        grouped[record.recorded_at] = (
            passing + (1 if record.status == ControlStatus.PASS.value else 0),
            total + 1,
        )
    return tuple(
        TrendPoint(recorded_at=stamp, passing=passing, automated_total=total)
        for stamp, (passing, total) in sorted(grouped.items())
    )
