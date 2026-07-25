"""Framework catalog and rollups for the compliance layer.

Maps IANUA controls to public security frameworks so the dashboard and trust
page can show per-framework coverage. The mappings are **indicative** — they
document which framework expectations a control speaks to; they are not an
audit, a certification, or legal advice, and the UI labels them accordingly.

Security consideration: this module is pure data + arithmetic — no I/O.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum


class Framework(Enum):
    """Public frameworks that controls can map to."""

    NIST_CSF = "NIST CSF 2.0"
    SOC_2 = "SOC 2 (Trust Services Criteria)"
    ISO_27001 = "ISO/IEC 27001:2022"


@dataclass(frozen=True)
class FrameworkRef:
    """A single control-to-framework mapping (e.g. NIST CSF ``PR.AA-05``)."""

    framework: Framework
    reference: str


@dataclass(frozen=True)
class FrameworkRollup:
    """Coverage of one framework by the current control results."""

    framework: Framework
    passing: int
    total: int

    @property
    def percent(self) -> int:
        """Whole-number passing percentage (0 when nothing is mapped)."""
        if self.total == 0:
            return 0
        return round(100 * self.passing / self.total)


def rollup(
    results: Iterable[tuple[frozenset[FrameworkRef], bool]],
) -> tuple[FrameworkRollup, ...]:
    """Aggregate ``(framework_refs, passed)`` pairs into per-framework rollups.

    A control counts once per framework it maps to, regardless of how many
    individual references it carries within that framework.
    """
    passing: dict[Framework, int] = dict.fromkeys(Framework, 0)
    total: dict[Framework, int] = dict.fromkeys(Framework, 0)
    for refs, passed in results:
        for fw in {ref.framework for ref in refs}:
            total[fw] += 1
            if passed:
                passing[fw] += 1
    return tuple(
        FrameworkRollup(framework=fw, passing=passing[fw], total=total[fw])
        for fw in Framework
        if total[fw] > 0
    )
