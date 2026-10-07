"""Hostile report inputs never become code, paths, leaked errors, or ambiguous diffs."""

from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path

import dashboard.scan_reports as reports
import pytest

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
