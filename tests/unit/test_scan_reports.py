"""Offline Broker import, filtering, and scope-conscious comparison tests."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest
from dashboard.scan_reports import (
    ReportImportError,
    compare_reports,
    filter_findings,
    finding_rows,
    parse_report,
)


def payload() -> dict[str, Any]:
    """Return synthetic, non-sensitive Broker-renderer-shaped fixture data."""
    return {
        "tool": "ianua-broker",
        "schema_version": "1.1",
        "generated_with_online": False,
        "overall_grade": "C",
        "dimension_grades": dict.fromkeys(("exposure", "credential", "tool_scope", "pinning"), "A"),
        "servers": [
            {
                "id": "demo",
                "state": "declared",
                "running": False,
                "bind_addr": None,
                "port": None,
                "inspection_incomplete": False,
                "grade": "C",
                "findings": [
                    {
                        "id": "PIN-001",
                        "dimension": "pinning",
                        "severity": "medium",
                        "title": "Unpinned package",
                        "location": {"path": "config.json", "line": 3},
                        "rationale": "Version may change",
                        "remediation": "Pin a reviewed version",
                    }
                ],
            }
        ],
    }


def encoded(value: dict[str, Any]) -> bytes:
    """Encode a synthetic report."""
    return json.dumps(value).encode()


@pytest.mark.parametrize("schema", ["1.0", "1.1"])
def test_renderer_schema_projection(schema: str) -> None:
    data = payload()
    data["schema_version"] = schema
    data["unknown"] = "NOT DISPLAYED"
    data["servers"][0]["findings"][0]["secret"] = {"sha256_8": "abcdef12", "length": 8}
    report = parse_report(encoded(data))
    assert report.schema_version == schema
    assert report.overall_grade == "C"
    assert report.server_ids == ("demo",)
    assert report.findings[0].identity == ("demo", "PIN-001", "config.json", 3)
    assert "NOT DISPLAYED" not in repr(report)
    assert "sha256_8" not in repr(report)
    assert not report.inspection_incomplete


def test_compare_all_statuses() -> None:
    before = payload()
    current = deepcopy(before)
    original = current["servers"][0]["findings"][0]
    original["severity"] = "high"
    added = deepcopy(original)
    added["id"] = "PIN-002"
    current["servers"][0]["findings"].append(added)
    baseline = parse_report(encoded(before))
    result = compare_reports(baseline, parse_report(encoded(current)))
    assert [entry.status for entry in result] == ["changed", "new"]
    assert compare_reports(baseline, baseline)[0].status == "unchanged"
    current["servers"][0]["findings"] = []
    assert compare_reports(baseline, parse_report(encoded(current)))[0].status == "resolved"


@pytest.mark.parametrize("gap", ["incomplete", "missing", "other-incomplete"])
def test_missing_findings_do_not_claim_resolution_across_gaps(gap: str) -> None:
    before = payload()
    current = deepcopy(before)
    current["servers"][0]["findings"] = []
    if gap == "incomplete":
        current["servers"][0]["inspection_incomplete"] = True
    elif gap == "missing":
        current["servers"] = []
    else:
        other = deepcopy(current["servers"][0])
        other.update(id="other", inspection_incomplete=True)
        current["servers"].append(other)
    changes = compare_reports(parse_report(encoded(before)), parse_report(encoded(current)))
    assert changes[0].status == "not observed"


def test_location_and_server_participate_in_identity() -> None:
    data = payload()
    finding = deepcopy(data["servers"][0]["findings"][0])
    finding["location"]["line"] = None
    data["servers"][0]["findings"].append(finding)
    other = deepcopy(data["servers"][0])
    other["id"] = "other"
    data["servers"].append(other)
    report = parse_report(encoded(data))
    assert len({f.identity for f in report.findings}) == 4


def test_filters_are_literal_and_rows_only_display_fields() -> None:
    report = parse_report(encoded(payload()))
    assert len(filter_findings(report, severities=["medium"], query="UNPINNED")) == 1
    assert not filter_findings(report, severities=["critical"])
    assert not filter_findings(report, dimensions=["exposure"])
    assert not filter_findings(report, query=".*")
    rows = finding_rows(report.findings)
    assert rows[0]["Line"] == 3
    assert rows[0]["Remediation"] == "Pin a reviewed version"
    assert "secret" not in rows[0]


def test_acceptance_11_validated_but_never_displayed() -> None:
    data = payload()
    data["servers"][0]["findings"][0]["acceptance"] = {
        "owner": "Synthetic owner",
        "accepted": "2026-01-01",
        "expires": "2026-12-01",
        "reason": "Synthetic reason",
        "expired": False,
    }
    assert "Synthetic owner" not in repr(parse_report(encoded(data)))
    data["schema_version"] = "1.0"
    with pytest.raises(ReportImportError):
        parse_report(encoded(data))


def test_empty_explanatory_text_is_valid() -> None:
    data = payload()
    data["servers"][0]["findings"][0].update(rationale="", remediation="")
    finding = parse_report(encoded(data)).findings[0]
    assert finding.rationale == finding.remediation == ""


@pytest.mark.parametrize("gap", ["incomplete", "missing", "other-incomplete"])
def test_current_only_findings_do_not_claim_newness_across_baseline_gaps(gap: str) -> None:
    current = payload()
    before = deepcopy(current)
    before["servers"][0]["findings"] = []
    if gap == "incomplete":
        before["servers"][0]["inspection_incomplete"] = True
    elif gap == "missing":
        before["servers"] = []
    else:
        other = deepcopy(before["servers"][0])
        other.update(id="other", inspection_incomplete=True)
        before["servers"].append(other)
    changes = compare_reports(parse_report(encoded(before)), parse_report(encoded(current)))
    assert changes[0].status == "not observed"
    assert changes[0].previous is None
