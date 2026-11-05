# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Hostile report inputs never become code, paths, leaked errors, or ambiguous diffs."""

from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path

import pytest

import dashboard.scan_reports as reports
from tests.unit.test_scan_reports import encoded, payload


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\xff",
        b"{}",
        b"[]",
        b"null",
        b'{"tool":"one","tool":"two"}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":1e999}',
        b"[" * (reports.MAX_DEPTH + 1) + b"]" * (reports.MAX_DEPTH + 1),
        b" " * (reports.MAX_REPORT_BYTES + 1),
    ],
)
def test_hostile_json_rejected_with_generic_error(data: bytes) -> None:
    with pytest.raises(reports.ReportImportError) as raised:
        reports.parse_report(data)
    assert str(raised.value) == "Report format or limits are invalid."
    assert raised.value.__cause__ is None


@pytest.mark.parametrize(
    "case",
    [
        "masked",
        "duplicate-finding",
        "duplicate-server",
        "unsupported-schema",
        "bool-line",
        "negative-line",
        "bad-severity",
        "bad-dimension",
        "not-bool",
        "oversized-string",
        "oversized-list",
        "surrogate",
        "control",
        "bad-secret",
        "bad-port",
        "bad-tool",
    ],
)
def test_hostile_schema_rejected(case: str) -> None:
    data = payload()
    server = data["servers"][0]
    finding = server["findings"][0]
    if case == "masked":
        finding["secret"] = {"masked": "SYNTHETIC-SENSITIVE", "sha256_8": "abcdef12", "length": 8}
    elif case == "duplicate-finding":
        server["findings"].append(deepcopy(finding))
    elif case == "duplicate-server":
        data["servers"].append(deepcopy(server))
    elif case == "unsupported-schema":
        data["schema_version"] = "9.9"
    elif case == "bool-line":
        finding["location"]["line"] = True
    elif case == "negative-line":
        finding["location"]["line"] = -1
    elif case == "bad-severity":
        finding["severity"] = "urgent"
    elif case == "bad-dimension":
        finding["dimension"] = ["pinning"]
    elif case == "not-bool":
        server["inspection_incomplete"] = "false"
    elif case == "oversized-string":
        data["unknown"] = "x" * (reports.MAX_STRING_LENGTH + 1)
    elif case == "oversized-list":
        data["unknown"] = [None] * (reports.MAX_COLLECTION_ITEMS + 1)
    elif case == "surrogate":
        finding["title"] = "\ud800"
    elif case == "control":
        finding["title"] = "\x1bhidden"
    elif case == "bad-secret":
        finding["secret"] = {"sha256_8": "bad", "length": -1}
    elif case == "bad-port":
        server["port"] = True
    elif case == "bad-tool":
        data["tool"] = "other"
    with pytest.raises(reports.ReportImportError) as raised:
        reports.parse_report(encoded(data))
    assert "SYNTHETIC-SENSITIVE" not in str(raised.value)


def test_duplicate_nested_keys_are_rejected() -> None:
    data = encoded(payload()).replace(b'"line": 3', b'"line": 3, "line": 4')
    with pytest.raises(reports.ReportImportError):
        reports.parse_report(data)


def test_markup_and_paths_are_literal_labels_not_executed() -> None:
    data = payload()
    finding = data["servers"][0]["findings"][0]
    finding["title"] = '<script>alert("synthetic")</script>'
    finding["location"]["path"] = "https://example.invalid/../../config.json"
    finding["remediation"] = "$(do-not-execute) **plain text**"
    report = reports.parse_report(encoded(data))
    rows = reports.finding_rows(report.findings)
    assert rows[0]["Title"] == finding["title"]
    assert rows[0]["Path"] == finding["location"]["path"]
    assert rows[0]["Remediation"] == finding["remediation"]


def test_parser_has_no_io_or_dynamic_execution_surface() -> None:
    tree = ast.parse(Path(reports.__file__).read_text())
    imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)} | {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert imported <= {"__future__", "json", "math", "collections.abc", "dataclasses", "typing"}
    forbidden = {"open", "eval", "exec", "compile", "__import__"}
    assert not any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in forbidden
        for node in ast.walk(tree)
    )


def test_global_node_and_total_finding_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reports, "MAX_NODES", 2)
    with pytest.raises(reports.ReportImportError):
        reports.parse_report(encoded(payload()))
    monkeypatch.setattr(reports, "MAX_NODES", 100000)
    monkeypatch.setattr(reports, "MAX_FINDINGS", 1)
    data = payload()
    other = deepcopy(data["servers"][0])
    other["id"] = "other"
    data["servers"].append(other)
    with pytest.raises(reports.ReportImportError):
        reports.parse_report(encoded(data))


# --- schema-version and dimension forward compatibility (defect D-2) ---------
#
# A producer bumping its minor or adding a dimension used to reject the WHOLE
# upload with the generic message, so an operator saw a broken uploader rather
# than a version mismatch (`docs/EVIDENCE_CONTRACT.md` §6.2, §10 D-2). An
# unknown minor is now read with the newest known minor's field rules and an
# extra dimension is ignored, while an unknown MAJOR and a MISSING dimension
# still fail closed.
_NEWEST_KNOWN = reports.KNOWN_SCHEMA_VERSIONS[-1]
_UNKNOWN_MINOR = f"{reports.SCHEMA_MAJOR}.{int(_NEWEST_KNOWN.split('.')[1]) + 1}"


def test_d2_matrix_producer_may_bump_a_minor_and_add_a_dimension() -> None:
    """The exact four cases measured as broken when D-2 was recorded."""
    for version in (_NEWEST_KNOWN, _UNKNOWN_MINOR):
        for extra in ({}, {"governance": "B"}):
            data = payload()
            data["schema_version"] = version
            data["dimension_grades"].update(extra)
            report = reports.parse_report(encoded(data))
            # The REPORTED version is displayed, not the one its rules came from.
            assert report.schema_version == version, (version, extra)
            assert {dim for dim, _ in report.dimension_grades} == set(reports.DIMENSIONS)


def test_an_extra_dimension_is_ignored_and_never_retained() -> None:
    data = payload()
    data["dimension_grades"]["governance"] = "SYNTHETIC-EXTRA"
    report = reports.parse_report(encoded(data))
    assert "governance" not in {dim for dim, _ in report.dimension_grades}
    assert "SYNTHETIC-EXTRA" not in repr(report)


def test_an_unknown_minor_is_read_with_the_newest_known_field_rules() -> None:
    """`acceptance` is a 1.1 field, so a 1.2 report may carry it; 1.0 may not."""
    accepted = {
        "owner": "Synthetic owner",
        "accepted": "2026-01-01",
        "expires": "2026-12-01",
        "reason": "Synthetic reason",
        "expired": False,
    }
    data = payload()
    data["schema_version"] = _UNKNOWN_MINOR
    data["servers"][0]["findings"][0]["acceptance"] = deepcopy(accepted)
    assert reports.parse_report(encoded(data)).schema_version == _UNKNOWN_MINOR

    data["schema_version"] = reports.KNOWN_SCHEMA_VERSIONS[0]
    with pytest.raises(reports.ReportImportError):
        reports.parse_report(encoded(data))


def test_a_missing_dimension_is_still_fatal_and_named() -> None:
    data = payload()
    del data["dimension_grades"][reports.DIMENSIONS[0]]
    with pytest.raises(reports.ReportImportError) as raised:
        reports.parse_report(encoded(data))
    assert "missing a required dimension" in str(raised.value)


def test_an_unknown_major_fails_closed_and_names_the_supported_major() -> None:
    for version in ("2.0", "0.9", "9.9", "10.0"):
        data = payload()
        data["schema_version"] = version
        with pytest.raises(reports.ReportImportError) as raised:
            reports.parse_report(encoded(data))
        message = str(raised.value)
        assert "major version is not supported" in message, version
        assert version not in message  # never quotes the uploaded value


@pytest.mark.parametrize(
    "version",
    [
        "",
        "1",
        "1.",
        ".1",
        "1.2.3",
        "a.b",
        "1.-1",
        "+1.2",
        "01.2",
        "1.02",
        " 1.2",
        "1.2 ",
        "1,2",
        # ARABIC-INDIC ONE and SUPERSCRIPT ONE: str.isdigit() is True for both and
        # int() parses them, so a property-based check would read these as 1.1 and
        # 1.2. Composed from chr() so this source file stays ASCII.
        "1." + chr(0x0661),
        chr(0x00B9) + ".2",
        "1.2\u0000",
        "x" * (reports.MAX_SCHEMA_VERSION_LENGTH + 1),
    ],
)
def test_malformed_schema_versions_are_refused(version: str) -> None:
    data = payload()
    data["schema_version"] = version
    with pytest.raises(reports.ReportImportError) as raised:
        reports.parse_report(encoded(data))
    assert version.strip() not in str(raised.value) or not version.strip()


@pytest.mark.parametrize("version", [None, 1.1, 11, True, ["1.1"], {"v": "1.1"}])
def test_non_string_schema_versions_are_refused(version: object) -> None:
    data = payload()
    data["schema_version"] = version
    with pytest.raises(reports.ReportImportError):
        reports.parse_report(encoded(data))
