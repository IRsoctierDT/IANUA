"""Presentation helpers for the dashboard's Compliance tab.

Pure functions from compliance-engine types to render-ready rows, kept free of
any Streamlit import so they are unit-testable and reusable (the same rows
feed the trust-page snapshot).

Security consideration: helpers only reshape data already sanitized by the
compliance layer; they add no file or network access.
"""

from __future__ import annotations

from compliance.controls import Category, ControlStatus
from compliance.engine import ComplianceReport
from compliance.evidence import EvidenceRecord

#: Compact badge per status for tables (text-first: also readable without color).
STATUS_BADGES: dict[ControlStatus, str] = {
    ControlStatus.PASS: "✅ pass",
    ControlStatus.ATTESTED: "🖋️ attested",
    ControlStatus.FAIL: "❌ fail",
    ControlStatus.ERROR: "⚠️ error",
    ControlStatus.MANUAL: "📝 manual",
}

#: Indicative-mapping disclaimer shown wherever framework numbers appear.
FRAMEWORK_DISCLAIMER = (
    "Framework mappings are indicative — they document which expectations a "
    "control speaks to. This is not an audit, certification, or legal advice."
)


def control_rows(report: ComplianceReport) -> list[dict[str, str]]:
    """One table row per control, in registry order."""
    return [
        {
            "ID": r.control.id,
            "Control": r.control.title,
            "Category": r.control.category.value,
            "Severity": r.control.severity.value,
            "Status": STATUS_BADGES[r.status],
            "Detail": r.detail,
        }
        for r in report.results
    ]


def category_summary(report: ComplianceReport) -> list[dict[str, str]]:
    """Automated pass counts per category (manual controls listed separately)."""
    rows = []
    for category in Category:
        in_cat = [r for r in report.automated if r.control.category is category]
        if not in_cat:
            continue
        passing = sum(1 for r in in_cat if r.passed)
        rows.append(
            {
                "Category": category.value,
                "Passing": f"{passing}/{len(in_cat)}",
                "Status": STATUS_BADGES[
                    ControlStatus.PASS if passing == len(in_cat) else ControlStatus.FAIL
                ],
            }
        )
    return rows


def framework_rows(report: ComplianceReport) -> list[dict[str, object]]:
    """Per-framework coverage rows with a 0-100 percent for progress bars."""
    return [
        {
            "Framework": ru.framework.value,
            "Coverage": f"{ru.passing}/{ru.total}",
            "Percent": ru.percent,
        }
        for ru in report.framework_rollups()
    ]


def framework_refs_line(report: ComplianceReport, control_id: str) -> str:
    """Human-readable framework references for one control (or empty)."""
    for r in report.results:
        if r.control.id == control_id:
            return " · ".join(
                sorted(f"{ref.framework.value} {ref.reference}" for ref in r.control.framework_refs)
            )
    return ""


def evidence_rows(records: tuple[EvidenceRecord, ...]) -> list[dict[str, str]]:
    """Newest-first table rows for the evidence trail."""
    return [
        {
            "Recorded": rec.recorded_at,
            "Control": rec.control_id,
            "Status": rec.status,
            "Detail": rec.detail,
        }
        for rec in reversed(records)
    ]
