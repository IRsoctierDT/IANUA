"""Session-only scan-report review; uploaded text is never executed or rendered as HTML.

The UI is injected so bounded upload handling and presentation can be tested
without installing Streamlit. Reports are not cached globally or saved to disk.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import MutableMapping, Sequence
from typing import Any, Protocol

from dashboard.scan_reports import (
    MAX_REPORT_BYTES,
    Finding,
    FindingChange,
    ReportImportError,
    ScanReport,
    compare_reports,
    filter_findings,
    finding_rows,
    parse_report,
)

_CURRENT_KEY = "scan_report_current"
_BASELINE_KEY = "scan_report_baseline"
_FINDING_FILTER_KEYS = ("scan_report_severity", "scan_report_server", "scan_report_query")
_UPLOAD_ERROR = "Report not accepted. Use a supported, redacted IANUA-Broker JSON report."


class ReportUpload(Protocol):
    """Minimal uploader interface; size is checked before any bytes are read."""

    size: int

    def seek(self, offset: int) -> object:
        """Move to the start so widget reruns can read the same bounded input."""
        ...

    def read(self, size: int) -> bytes:
        """Read no more than the requested bound from memory."""
        ...


def load_upload(
    upload: ReportUpload | None, state: MutableMapping[str, Any], key: str
) -> tuple[ScanReport | None, str | None]:
    """Replace session data only after validation; clear stale data on any rejection.

    Empty, oversized, malformed and unreadable uploads return a fixed message;
    input content, filenames and parser exceptions never enter UI errors.
    """
    state.pop(key, None)
    if upload is None:
        return None, None
    if type(upload.size) is not int or not 0 < upload.size <= MAX_REPORT_BYTES:
        return None, _UPLOAD_ERROR
    try:
        upload.seek(0)
        data = upload.read(MAX_REPORT_BYTES + 1)
        if not isinstance(data, bytes) or len(data) != upload.size:
            return None, _UPLOAD_ERROR
        report = parse_report(data)
    except (ReportImportError, OSError, ValueError):
        return None, _UPLOAD_ERROR
    state[key] = report
    return report, None


def select_findings(
    report: ScanReport,
    *,
    severities: Sequence[str] = (),
    servers: Sequence[str] = (),
    query: str = "",
) -> tuple[Finding, ...]:
    """Return findings matching severity, server and literal text filters."""
    return tuple(
        finding
        for finding in filter_findings(report, severities=severities, query=query)
        if not servers or finding.server_id in servers
    )


def change_rows(changes: Sequence[FindingChange]) -> list[dict[str, str | int | None]]:
    """Project comparison into plain-text rows, retaining earlier severity and fixes."""
    rows = []
    for change in changes:
        row = finding_rows((change.finding,))[0]
        row["Change"] = change.status
        row["Previous severity"] = change.previous.severity if change.previous else ""
        row["Previous remediation"] = change.previous.remediation if change.previous else ""
        rows.append(row)
    return rows


def _render_findings(ui: Any, report: ScanReport) -> None:
    severity_counts = Counter(finding.severity for finding in report.findings)
    ui.dataframe(
        [{"Severity": severity, "Findings": count} for severity, count in severity_counts.items()],
        width="stretch",
    )
    # All options originate in the validated report, and only plain text is rendered.
    severities = ui.multiselect("Severity", sorted(severity_counts), key="scan_report_severity")
    servers = ui.multiselect("Server", list(report.server_ids), key="scan_report_server")
    query = ui.text_input("Search findings and remediation", key="scan_report_query")
    visible = select_findings(report, severities=severities, servers=servers, query=query)
    ui.caption(f"Showing {len(visible)} of {len(report.findings)} findings.")
    if visible:
        ui.dataframe(finding_rows(visible), width="stretch")
    else:
        ui.info("No findings match these filters. This does not establish scan completeness.")


def render_scan_reports(ui: Any) -> None:
    """Render consent, bounded uploads, findings and baseline comparison locally.

    ``ui`` is the Streamlit module; validated models live only in that session.
    No scan execution, URL fetching, persistence or shared caching occurs here.
    """
    ui.subheader("Scan Reports")
    ui.caption(
        "Review existing IANUA-Broker JSON reports. This tab does not run scans. "
        "Uploads stay in this dashboard session's memory and are not saved to disk."
    )
    ui.warning(
        "Use only reports you are authorized to review. Check redaction before uploading: "
        "validation does not guarantee removal of private paths, hostnames or other sensitive text. "
        "Keep the dashboard local; an upload is sent to the machine running it."
    )
    consent = ui.checkbox(
        "I checked these reports for sensitive information and consent to review them locally.",
        key="scan_report_consent",
    )
    if not consent:
        for key in (
            _CURRENT_KEY,
            _BASELINE_KEY,
            "scan_current_upload",
            "scan_baseline_upload",
            *_FINDING_FILTER_KEYS,
            "scan_report_changes",
        ):
            ui.session_state.pop(key, None)
        ui.info("Confirm before uploading a redacted report.")
        return

    current_upload = ui.file_uploader(
        "Current redacted report (JSON)", type=["json"], key="scan_current_upload"
    )
    baseline_upload = ui.file_uploader(
        "Optional baseline redacted report (JSON)", type=["json"], key="scan_baseline_upload"
    )
    current, current_error = load_upload(current_upload, ui.session_state, _CURRENT_KEY)
    baseline, baseline_error = load_upload(baseline_upload, ui.session_state, _BASELINE_KEY)
    for label, error in (("Current", current_error), ("Baseline", baseline_error)):
        if error:
            ui.error(f"{label}: {error}")
    if current is None:
        for key in _FINDING_FILTER_KEYS:
            ui.session_state.pop(key, None)
        ui.session_state.pop("scan_report_changes", None)
        return
    ui.text(f"Reported overall grade: {current.overall_grade}")
    ui.caption("Grades are supplied by the report, not independently verified by the dashboard.")
    if current.inspection_incomplete:
        ui.warning("Current inspection is incomplete. No findings does not mean no risk.")
        ui.dataframe(
            [{"Incomplete server": server} for server in current.incomplete_server_ids],
            width="stretch",
        )
    _render_findings(ui, current)
    if baseline is None:
        ui.session_state.pop("scan_report_changes", None)
        return
    ui.subheader("Changes from baseline")
    ui.caption(
        "Comparison uses server, rule and location. A changed location can appear as a new "
        "and resolved finding. Resolved means absent from comparable report coverage, "
        "not proof that remediation succeeded."
    )
    if baseline.inspection_incomplete or current.inspection_incomplete:
        ui.warning(
            "One or both inspections are incomplete. Missing or incomplete server coverage "
            "is labelled not observed rather than new or resolved."
        )
    changes = compare_reports(baseline, current)
    counts = Counter(change.status for change in changes)
    ui.dataframe(
        [{"Change": status, "Findings": count} for status, count in counts.items()],
        width="stretch",
    )
    statuses = ui.multiselect("Change type", sorted(counts), key="scan_report_changes")
    visible_changes = tuple(
        change for change in changes if not statuses or change.status in statuses
    )
    if visible_changes:
        ui.dataframe(change_rows(visible_changes), width="stretch")
    else:
        ui.info("No finding differences match these filters.")
