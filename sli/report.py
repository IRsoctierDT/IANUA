# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Assemble one measurement per objective into a report, grading each once.

The grading happens here and nowhere else: each indicator function returns a
number or ``None``, and :meth:`Objective.evaluate` turns that into a status.
Seven indicators grading themselves would be seven chances to compare a
target the wrong way round, which is the same argument ``ingest/_coerce.py``
makes for applying the field bound in one place rather than in ten parsers.

Security considerations: read-only over the lab-data root, and ``now`` is a
parameter so nothing here reads the clock. ``healthy`` is a conjunction over
``Status.healthy``, so an unmeasurable indicator can never lift the verdict —
see :class:`sli.objectives.Status`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sli.indicators import MEASURERS
from sli.objectives import OBJECTIVES, Objective, Status


@dataclass(frozen=True, slots=True)
class Indicator:
    """One objective, its measurement, and the grade."""

    objective: Objective
    status: Status
    value: float | None
    detail: str

    def summary(self) -> str:
        """One line, for a CLI or a compliance detail."""
        measured = "unmeasured" if self.value is None else f"{self.value:g} {self.objective.unit}"
        return (
            f"{self.objective.id}: {self.status.value} "
            f"({measured}, target {self.objective.direction.value} "
            f"{self.objective.target:g}) — {self.detail}"
        )

    def to_dict(self) -> dict[str, object]:
        """A JSON-ready mapping, for ``--json`` and for compliance evidence."""
        return {
            "id": self.objective.id,
            "title": self.objective.title,
            "status": self.status.value,
            "value": self.value,
            "unit": self.objective.unit,
            "direction": self.objective.direction.value,
            "target": self.objective.target,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class SliReport:
    """Every objective's current standing, measured at one instant."""

    measured_at: float
    indicators: tuple[Indicator, ...]

    @property
    def breached(self) -> tuple[Indicator, ...]:
        """Indicators measured and found wanting."""
        return tuple(item for item in self.indicators if item.status is Status.BREACHED)

    @property
    def unknown(self) -> tuple[Indicator, ...]:
        """Indicators that could not be measured at all."""
        return tuple(item for item in self.indicators if item.status is Status.UNKNOWN)

    @property
    def met(self) -> tuple[Indicator, ...]:
        """Indicators meeting their objective."""
        return tuple(item for item in self.indicators if item.status is Status.MET)

    @property
    def healthy(self) -> bool:
        """True only when there is at least one objective and every one is met.

        Two fail-open spellings are avoided here, and both are the spelling a
        reader reaches for first:

        * "none is breached" — a report of all-``UNKNOWN`` has nothing
          breached, so the conjunction is over :attr:`Status.healthy` instead;
        * ``all(...)`` alone — which is ``True`` over an empty sequence, so a
          report with no indicators at all would be healthy. That is not
          hypothetical housekeeping: it is the "assertion true of the empty
          set" shape that this repository has found in its own tests more than
          once, and an emptied objective table is exactly how a monitor goes
          silently green.
        """
        return bool(self.indicators) and all(item.status.healthy for item in self.indicators)

    def to_dict(self) -> dict[str, object]:
        """A JSON-ready mapping of the whole report."""
        return {
            "measured_at": self.measured_at,
            "healthy": self.healthy,
            "met": len(self.met),
            "breached": len(self.breached),
            "unknown": len(self.unknown),
            "indicators": [item.to_dict() for item in self.indicators],
        }

    def headline(self) -> str:
        """One sentence naming what is wrong, or that nothing is."""
        if self.healthy:
            return f"all {len(self.indicators)} objective(s) met"
        parts = []
        if self.breached:
            parts.append(
                f"{len(self.breached)} breached ({', '.join(i.objective.id for i in self.breached)})"
            )
        if self.unknown:
            parts.append(
                f"{len(self.unknown)} unmeasurable ({', '.join(i.objective.id for i in self.unknown)})"
            )
        return "; ".join(parts)


def measure(root: Path, *, now: float) -> SliReport:
    """Measure every objective against the state under ``root``.

    One indicator's failure to measure never stops the others: each measurer
    is already total over an unreadable artifact (it returns ``None`` with a
    reason), and an unexpected raise is caught here and graded ``UNKNOWN``
    rather than discarding the whole report. That is the same two-layer shape
    ``ingest.normalize_many`` uses and for the same reason — a monitor that
    returns nothing when one probe breaks is a monitor that goes dark exactly
    when something is wrong.
    """
    indicators: list[Indicator] = []
    for objective in OBJECTIVES:
        measurer = MEASURERS[objective.id]
        try:
            measurement = measurer(root, now)
        except Exception as exc:
            # The outer layer. Named broadly on purpose: the measurers are
            # written to be total, and if one is not, the report must still
            # arrive saying which probe failed and how.
            indicators.append(
                Indicator(
                    objective=objective,
                    status=Status.UNKNOWN,
                    value=None,
                    detail=f"the probe raised {type(exc).__name__}",
                )
            )
            continue
        indicators.append(
            Indicator(
                objective=objective,
                status=objective.evaluate(measurement.value),
                value=measurement.value,
                detail=measurement.detail,
            )
        )
    return SliReport(measured_at=now, indicators=tuple(indicators))
