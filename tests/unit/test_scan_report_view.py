"""Upload-boundary and plain-text presentation contracts without Streamlit imports."""

from __future__ import annotations

import io
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from dashboard import scan_report_view as view
from dashboard.scan_reports import MAX_REPORT_BYTES, FindingChange, parse_report

pytestmark = pytest.mark.unit
_SAMPLE = Path(__file__).resolve().parents[2] / "docs/dashboard/sample-scan-before.json"


class Upload(io.BytesIO):
    """Memory upload recording the read limit and claimed size."""

    def __init__(self, data: bytes, size: int | None = None) -> None:
        super().__init__(data)
        self.size = len(data) if size is None else size
        self.read_limits: list[int | None] = []

    def read(self, size: int | None = -1) -> bytes:
        self.read_limits.append(size)
        return super().read(size)


class FakeUI:
    """UI recorder with no rich-text APIs, so unsafe rendering fails tests."""

    def __init__(
        self, consent: bool = True, current: Upload | None = None, baseline: Upload | None = None
    ) -> None:
        self.consent = consent
        self.uploads = [current, baseline]
        self.session_state: dict[str, Any] = {}
        self.texts: list[str] = []
        self.tables: list[list[dict[str, Any]]] = []
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.upload_calls = 0

    def subheader(self, text: str) -> None:
        self.texts.append(text)

    def caption(self, text: str) -> None:
        self.texts.append(text)

    def text(self, text: str) -> None:
        self.texts.append(text)

    def info(self, text: str) -> None:
        self.texts.append(text)

    def warning(self, text: str) -> None:
        self.warnings.append(text)

    def error(self, text: str) -> None:
        self.errors.append(text)

    def checkbox(self, _label: str, **_kwargs: Any) -> bool:
        return self.consent

    def file_uploader(self, _label: str, **_kwargs: Any) -> Upload | None:
        result = self.uploads[self.upload_calls]
        self.upload_calls += 1
        return result

    def dataframe(self, rows: list[dict[str, Any]], **_kwargs: Any) -> None:
        self.tables.append(rows)

    def multiselect(self, _label: str, _options: list[str], **_kwargs: Any) -> list[str]:
        return []

    def text_input(self, _label: str, **_kwargs: Any) -> str:
        return ""


def test_upload_bound_before_read_and_clears_previous_report() -> None:
    upload = Upload(b"small", size=MAX_REPORT_BYTES + 1)
    state: dict[str, Any] = {"current": object()}
    report, error = view.load_upload(upload, state, "current")
    assert report is None and error
    assert upload.read_limits == []
    assert "current" not in state


@pytest.mark.parametrize("data", [b"", b"secret is invalid", b"{bad json}"])
def test_invalid_upload_errors_never_echo_content(data: bytes) -> None:
    state: dict[str, Any] = {"current": object()}
    report, error = view.load_upload(Upload(data), state, "current")
    assert report is None and error == view._UPLOAD_ERROR
    assert "current" not in state


def test_upload_cleared_forgets_previous_report() -> None:
    state: dict[str, Any] = {"current": object()}
    assert view.load_upload(None, state, "current") == (None, None)
    assert not state


def test_valid_upload_has_bounded_read_and_supports_rerun() -> None:
    upload = Upload(_SAMPLE.read_bytes())
    state: dict[str, Any] = {}
    report, error = view.load_upload(upload, state, "current")
    assert report is not None and error is None
    assert state["current"] == report
    assert upload.read_limits == [MAX_REPORT_BYTES + 1]
    assert view.load_upload(upload, state, "current") == (report, None)


def test_lying_upload_size_is_rejected() -> None:
    upload = Upload(_SAMPLE.read_bytes(), size=1)
    report, error = view.load_upload(upload, {}, "current")
    assert report is None and error


def test_consent_required_before_upload_and_removes_stale_session() -> None:
    ui = FakeUI(consent=False)
    ui.session_state.update(
        scan_report_current=object(), scan_report_baseline=object(), scan_current_upload=object()
    )
    view.render_scan_reports(ui)
    assert ui.upload_calls == 0
    assert not ui.session_state
    assert any("does not guarantee" in text for text in ui.warnings)


def test_filters_server_severity_and_literal_search() -> None:
    report = parse_report(_SAMPLE.read_bytes())
    assert len(view.select_findings(report, severities=["critical"])) == 1
    assert len(view.select_findings(report, query="rotate")) == 1
    assert not view.select_findings(report, servers=["missing"])
    assert not view.select_findings(report, query=".*")


def test_changed_rows_retain_old_severity_and_remediation() -> None:
    finding = parse_report(_SAMPLE.read_bytes()).findings[0]
    current = replace(finding, severity="low", remediation="Review the updated fix.")
    rows = view.change_rows([FindingChange("changed", current, finding)])
    assert rows[0]["Change"] == "changed"
    assert rows[0]["Previous severity"] == "critical"
    assert rows[0]["Previous remediation"] == finding.remediation


def test_render_shows_findings_and_remediation_in_plain_tables() -> None:
    ui = FakeUI(current=Upload(_SAMPLE.read_bytes()), baseline=Upload(_SAMPLE.read_bytes()))
    view.render_scan_reports(ui)
    assert not ui.errors
    rows = [row for table in ui.tables for row in table]
    assert any("Rotate" in str(row) or "rotate" in str(row) for row in rows)
    assert any(row.get("Change") == "unchanged" for row in rows)


def test_invalid_replacement_clears_current_and_prevents_comparison() -> None:
    ui = FakeUI(current=Upload(b"malformed"), baseline=Upload(_SAMPLE.read_bytes()))
    ui.session_state["scan_report_current"] = object()
    ui.session_state["scan_report_query"] = "stale search"
    ui.session_state["scan_report_changes"] = ["resolved"]
    view.render_scan_reports(ui)
    assert "scan_report_current" not in ui.session_state
    assert "scan_report_query" not in ui.session_state
    assert "scan_report_changes" not in ui.session_state
    assert ui.errors
    assert "Changes from baseline" not in ui.texts


def test_untrusted_markup_is_not_interpreted(monkeypatch: pytest.MonkeyPatch) -> None:
    report = parse_report(_SAMPLE.read_bytes())
    payload = '<script>alert("example")</script> **not markdown**'
    finding = replace(report.findings[0], title=payload, remediation=payload)
    changed_report = replace(report, findings=(finding,))
    monkeypatch.setattr(view, "parse_report", lambda _data: changed_report)
    ui = FakeUI(current=Upload(_SAMPLE.read_bytes()))
    view.render_scan_reports(ui)
    assert any(payload in str(row) for table in ui.tables for row in table)
    assert all(payload not in text for text in ui.texts)


def test_incomplete_scan_is_visible_and_not_claimed_healthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = parse_report(_SAMPLE.read_bytes())
    incomplete = replace(report, incomplete_server_ids=report.server_ids, findings=())
    monkeypatch.setattr(view, "parse_report", lambda _data: incomplete)
    ui = FakeUI(current=Upload(_SAMPLE.read_bytes()), baseline=Upload(_SAMPLE.read_bytes()))
    view.render_scan_reports(ui)
    assert any("inspection is incomplete" in message for message in ui.warnings)
    assert any("One or both inspections are incomplete" in message for message in ui.warnings)


def test_current_only_finding_with_incomplete_baseline_is_not_observed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = parse_report(_SAMPLE.read_bytes())
    baseline = replace(report, incomplete_server_ids=report.server_ids, findings=())
    monkeypatch.setattr(
        view, "parse_report", lambda data: baseline if data == b"baseline" else report
    )
    ui = FakeUI(current=Upload(_SAMPLE.read_bytes()), baseline=Upload(b"baseline"))
    view.render_scan_reports(ui)
    changes = [row["Change"] for table in ui.tables for row in table if "Change" in row]
    assert changes and set(changes) == {"not observed"}
    assert any("One or both inspections are incomplete" in message for message in ui.warnings)
