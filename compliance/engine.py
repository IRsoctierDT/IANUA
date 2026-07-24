"""Compliance engine — evaluate the control registry into a typed report.

Deterministic and offline: results depend only on the repository contents and
the injected clock, so identical inputs reproduce identical reports (which the
trust-page drift gate relies on).

Security consideration: a check that raises is captured as
``ControlStatus.ERROR`` — surfaced as non-passing (fail closed), never as a
silent pass — and the exception detail is reduced to the exception class name
so stack contents cannot leak file contents into evidence.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from compliance.controls import CheckResult, Control, ControlStatus, registry
from compliance.frameworks import FrameworkRollup, rollup

if TYPE_CHECKING:  # import cycle guard: attestations imports controls only
    from compliance.attestations import Attestation


@dataclass(frozen=True)
class ControlResult:
    """One control together with its evaluated outcome."""

    control: Control
    status: ControlStatus
    detail: str

    @property
    def passed(self) -> bool:
        """Passing means a green automated check or a current human attestation."""
        return self.status in (ControlStatus.PASS, ControlStatus.ATTESTED)


@dataclass(frozen=True)
class ComplianceReport:
    """Outcome of one full control-registry evaluation."""

    generated_at: str
    results: tuple[ControlResult, ...]

    @property
    def automated(self) -> tuple[ControlResult, ...]:
        return tuple(r for r in self.results if r.control.automated)

    @property
    def manual(self) -> tuple[ControlResult, ...]:
        return tuple(r for r in self.results if not r.control.automated)

    @property
    def passing(self) -> int:
        return sum(1 for r in self.automated if r.passed)

    @property
    def failing(self) -> tuple[ControlResult, ...]:
        return tuple(r for r in self.automated if not r.passed)

    @property
    def score(self) -> int:
        """Whole-number percentage of automated controls passing."""
        total = len(self.automated)
        if total == 0:
            return 0
        return round(100 * self.passing / total)

    def framework_rollups(self) -> tuple[FrameworkRollup, ...]:
        """Per-framework coverage. Manual controls count toward totals but
        never toward passing until they are automated — unverified claims do
        not inflate coverage."""
        return rollup((r.control.framework_refs, r.passed) for r in self.results)


def run_controls(
    root: Path,
    *,
    clock: Callable[[], str] | None = None,
    controls: tuple[Control, ...] | None = None,
    attestations: Mapping[str, Attestation] | None = None,
) -> ComplianceReport:
    """Evaluate every control against ``root`` and return the report.

    ``clock`` is injectable for deterministic tests; it must return an ISO-8601
    UTC timestamp string. ``attestations`` (keyed by control id) upgrades a
    manual control to ``ATTESTED`` while the attestation is current; expired or
    absent attestations leave it ``MANUAL`` (never a silent pass).
    """
    if not root.is_dir():
        raise ValueError(f"repository root does not exist: {root}")
    stamp = clock() if clock is not None else _utc_now()
    today = stamp[:10]
    results = []
    for control in controls if controls is not None else registry():
        if control.check is None:
            attestation = (attestations or {}).get(control.id)
            if attestation is not None and attestation.valid_on(today):
                outcome = CheckResult(
                    ControlStatus.ATTESTED,
                    f"attested by {attestation.attested_by} on {attestation.date}; "
                    f"expires {attestation.expires}",
                )
            elif attestation is not None:
                outcome = CheckResult(
                    ControlStatus.MANUAL,
                    f"attestation expired {attestation.expires} — re-attest. "
                    + (control.attestation_hint or ""),
                )
            else:
                outcome = CheckResult(
                    ControlStatus.MANUAL,
                    control.attestation_hint or "requires human attestation",
                )
        else:
            try:
                outcome = control.check(root)
            except Exception as exc:  # fail closed, leak nothing but the class
                outcome = CheckResult(ControlStatus.ERROR, f"check raised {type(exc).__name__}")
        results.append(ControlResult(control=control, status=outcome.status, detail=outcome.detail))
    return ComplianceReport(generated_at=stamp, results=tuple(results))


def _utc_now() -> str:
    from datetime import UTC, datetime

    return datetime.now(tz=UTC).isoformat(timespec="seconds")
