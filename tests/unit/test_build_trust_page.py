"""Unit tests for scripts/build_trust_page.py — parse, build, drift gate."""

import json
from pathlib import Path

import pytest
from scripts.build_trust_page import (
    TrustDataError,
    build,
    check,
    main,
    parse_report,
    render_html,
    render_json,
    snapshot,
)

_VALID = {
    "as_of": "2026-07-24",
    "score": 92,
    "controls": [
        {"id": "POL-01", "title": "Default deny", "category": "Policy", "status": "pass"},
        {"id": "MAN-01", "title": "Branch protection", "category": "CI/CD", "status": "manual"},
    ],
    "frameworks": [{"name": "SOC 2", "passing": 11, "total": 12}],
}


def _paths(tmp_path: Path) -> dict[str, Path]:
    data = tmp_path / "trust.data.json"
    data.write_text(json.dumps(_VALID), encoding="utf-8")
    return {
        "data_path": data,
        "html_path": tmp_path / "trust.html",
        "json_path": tmp_path / "trust.json",
    }


def test_parse_valid_report() -> None:
    report = parse_report(_VALID)
    assert report.score == 92
    assert report.tally()["pass"] == 1
    assert report.frameworks[0].percent == 92


@pytest.mark.parametrize(
    "mutation",
    [
        {"score": "high"},
        {"score": 101},
        {"controls": []},
        {"controls": [{"id": "X", "title": "t", "category": "c", "status": "green"}]},
        {"frameworks": [{"name": "F", "passing": 3, "total": 2}]},
    ],
)
def test_bad_snapshot_fails_closed(mutation: dict[str, object]) -> None:
    with pytest.raises(TrustDataError):
        parse_report({**_VALID, **mutation})


def test_build_then_check_is_in_sync(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    build(**paths)
    assert check(**paths) == []


def test_check_detects_drift(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    build(**paths)
    paths["html_path"].write_text("tampered", encoding="utf-8")
    problems = check(**paths)
    assert problems and "trust.html" in problems[0]


def test_render_json_carries_disclaimer_and_summary() -> None:
    payload = json.loads(render_json(parse_report(_VALID)))
    assert "not an audit" in payload["disclaimer"]
    assert payload["summary"]["manual"] == 1


def test_render_html_contains_score_and_controls() -> None:
    page = render_html(parse_report(_VALID))
    assert "92%" in page
    assert "Default deny" in page


def test_snapshot_carries_no_detail_fields(tmp_path: Path) -> None:
    """The public snapshot schema must not leak check details."""
    data_path = tmp_path / "trust.data.json"
    repo_root = Path(__file__).resolve().parents[2]
    report = snapshot(data_path, root=repo_root)
    written = json.loads(data_path.read_text(encoding="utf-8"))
    assert report.controls  # engine ran
    assert all("detail" not in control for control in written["controls"])


def test_main_check_exit_codes(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    argv_common = [
        "--data",
        str(paths["data_path"]),
        "--out-html",
        str(paths["html_path"]),
        "--out-json",
        str(paths["json_path"]),
    ]
    assert main(argv_common) == 0
    assert main([*argv_common, "--check"]) == 0
    paths["json_path"].write_text("stale", encoding="utf-8")
    assert main([*argv_common, "--check"]) == 1


def test_main_bad_input_exit_code(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert main(["--data", str(bad)]) == 2
