"""Unit tests for scripts/build_status_page.py."""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from scripts.build_status_page import (
    Component,
    Section,
    Status,
    StatusDataError,
    StatusReport,
    build,
    check,
    load_report,
    main,
    parse_report,
    project_version,
    render_html,
    render_json,
)

_VALID_DATA = {
    "title": "Test Center",
    "tagline": "A tagline.",
    "as_of": "2026-07-10",
    "sections": [
        {
            "title": "Infra",
            "components": [
                {"name": "CI", "status": "operational", "detail": "green"},
                {"name": "Console", "status": "planned", "detail": "later"},
            ],
        }
    ],
}


def _write(path: Path, obj: object) -> Path:
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


@pytest.mark.unit
def test_parse_report_happy_path() -> None:
    report = parse_report(_VALID_DATA, version="9.9.9")
    assert report.title == "Test Center"
    assert report.version == "9.9.9"
    assert report.sections[0].components[0].status is Status.OPERATIONAL


@pytest.mark.unit
def test_tally_counts_all_statuses() -> None:
    report = parse_report(_VALID_DATA, version="1.0.0")
    tally = report.tally()
    assert tally[Status.OPERATIONAL] == 1
    assert tally[Status.PLANNED] == 1
    assert tally[Status.DEGRADED] == 0
    assert tally[Status.OFFLINE] == 0


@pytest.mark.unit
@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda d: d.pop("title"), "missing required field 'title'"),
        (lambda d: d["sections"][0]["components"][0].update(status="haywire"), "unknown status"),
        (lambda d: d.update(sections=[]), "non-empty array"),
        (lambda d: d["sections"][0].update(components=[]), "non-empty array"),
        (lambda d: d.update(title=123), "expected a string"),
    ],
)
def test_parse_report_fails_closed(mutate: Callable[[dict[str, Any]], object], needle: str) -> None:
    data = json.loads(json.dumps(_VALID_DATA))  # deep copy
    mutate(data)
    with pytest.raises(StatusDataError) as exc:
        parse_report(data, version="1.0.0")
    assert needle in str(exc.value)


@pytest.mark.unit
def test_parse_report_rejects_non_object_root() -> None:
    with pytest.raises(StatusDataError):
        parse_report(["not", "an", "object"], version="1.0.0")


@pytest.mark.unit
def test_render_json_is_canonical_and_has_summary() -> None:
    report = parse_report(_VALID_DATA, version="2.0.0")
    out = render_json(report)
    assert out.endswith("\n")
    payload = json.loads(out)
    assert payload["summary"] == {
        "operational": 1,
        "planned": 1,
        "degraded": 0,
        "offline": 0,
    }
    # Canonical: sorted keys, stable across runs.
    assert render_json(report) == out


@pytest.mark.unit
def test_render_html_contains_component_and_version() -> None:
    report = parse_report(_VALID_DATA, version="3.1.4")
    page = render_html(report)
    assert page.startswith("<!DOCTYPE html>")
    assert "Version 3.1.4" in page
    assert "CI" in page and "Console" in page


@pytest.mark.unit
def test_project_version_reads_pyproject(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nversion = "7.7.7"\n', encoding="utf-8")
    assert project_version(pyproject) == "7.7.7"


@pytest.mark.unit
def test_project_version_fails_closed_when_absent(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'x'\n", encoding="utf-8")
    with pytest.raises(StatusDataError):
        project_version(pyproject)


@pytest.mark.unit
def test_load_report_rejects_invalid_json(tmp_path: Path) -> None:
    data_path = tmp_path / "status.data.json"
    data_path.write_text("{ not json", encoding="utf-8")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nversion = "1.0.0"\n', encoding="utf-8")
    with pytest.raises(StatusDataError) as exc:
        load_report(data_path, pyproject=pyproject)
    assert "invalid JSON" in str(exc.value)


@pytest.mark.unit
def test_build_then_check_is_in_sync(tmp_path: Path) -> None:
    data_path = _write(tmp_path / "status.data.json", _VALID_DATA)
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nversion = "1.0.0"\n', encoding="utf-8")
    html_path = tmp_path / "status.html"
    json_path = tmp_path / "status.json"

    build(data_path=data_path, html_path=html_path, json_path=json_path, pyproject=pyproject)
    assert (
        check(data_path=data_path, html_path=html_path, json_path=json_path, pyproject=pyproject)
        == []
    )


@pytest.mark.unit
def test_check_detects_drift(tmp_path: Path) -> None:
    data_path = _write(tmp_path / "status.data.json", _VALID_DATA)
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nversion = "1.0.0"\n', encoding="utf-8")
    html_path = tmp_path / "status.html"
    json_path = tmp_path / "status.json"

    build(data_path=data_path, html_path=html_path, json_path=json_path, pyproject=pyproject)
    html_path.write_text("stale", encoding="utf-8")
    problems = check(
        data_path=data_path, html_path=html_path, json_path=json_path, pyproject=pyproject
    )
    assert any("status.html" in p for p in problems)


@pytest.mark.unit
def test_check_reports_missing_output(tmp_path: Path) -> None:
    data_path = _write(tmp_path / "status.data.json", _VALID_DATA)
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nversion = "1.0.0"\n', encoding="utf-8")
    problems = check(
        data_path=data_path,
        html_path=tmp_path / "missing.html",
        json_path=tmp_path / "missing.json",
        pyproject=pyproject,
    )
    assert len(problems) == 2


@pytest.mark.unit
def test_main_check_ok_on_committed_repo() -> None:
    # The committed docs/status.* must stay in sync with docs/status.data.json.
    assert main(["--check"]) == 0


@pytest.mark.unit
def test_main_build_writes_outputs(tmp_path: Path) -> None:
    data_path = _write(tmp_path / "status.data.json", _VALID_DATA)
    html_path = tmp_path / "out.html"
    json_path = tmp_path / "out.json"
    # Uses the repo pyproject for the version (default); just needs to succeed.
    rc = main(
        ["--data", str(data_path), "--out-html", str(html_path), "--out-json", str(json_path)]
    )
    assert rc == 0
    assert html_path.is_file() and json_path.is_file()


@pytest.mark.unit
def test_main_bad_data_returns_2(tmp_path: Path) -> None:
    bad = _write(tmp_path / "bad.json", {"title": "x"})
    assert main(["--data", str(bad)]) == 2


@pytest.mark.unit
def test_status_label_covers_every_member() -> None:
    # Guards the label map against a newly added Status without a label.
    for status in Status:
        assert status.label


@pytest.mark.unit
def test_dataclasses_are_frozen() -> None:
    comp = Component(name="x", status=Status.OFFLINE, detail="d")
    section = Section(title="s", components=(comp,))
    report = StatusReport(title="t", tagline="g", version="1", as_of="d", sections=(section,))
    with pytest.raises(AttributeError):
        comp.name = "y"  # type: ignore[misc]
    assert report.sections[0].components[0] is comp
