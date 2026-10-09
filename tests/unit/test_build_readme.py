"""Tests for scripts/build_readme.py — the README drift gate (AGENTS.md §7)."""

from __future__ import annotations

from pathlib import Path

import pytest
from scripts import build_readme


def test_committed_readme_is_in_sync() -> None:
    _new, changed = build_readme.regenerate(build_readme.README.read_text(encoding="utf-8"))
    assert changed == [], f"README.md stale in {changed}; run python scripts/build_readme.py"


def test_every_indexed_case_study_is_linked_from_the_readme() -> None:
    readme = build_readme.README.read_text(encoding="utf-8")
    index = build_readme.CASE_STUDY_INDEX.read_text(encoding="utf-8")
    files = [m["file"] for m in build_readme._CASE_ROW.finditer(index)]
    assert files
    for name in files:
        assert f"./docs/case-studies/{name}" in readme, name


def test_quality_gate_block_matches_the_charter_verbatim() -> None:
    readme = build_readme.README.read_text(encoding="utf-8")
    assert build_readme.render_quality_gates() in readme
    assert "scripts/build_readme.py --check" in build_readme.render_quality_gates()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t.replace("<!-- BEGIN GENERATED: release -->", ""),
        lambda t: t + "\n<!-- BEGIN GENERATED: bogus -->\nx\n<!-- END GENERATED: bogus -->\n",
        lambda t: t + "\n<!-- BEGIN GENERATED: release -->\nx\n<!-- END GENERATED: release -->\n",
    ],
    ids=["missing", "unknown", "duplicated"],
)
def test_invalid_markers_fail_closed(mutate: object) -> None:
    text = build_readme.README.read_text(encoding="utf-8")
    with pytest.raises(build_readme.ReadmeError):
        build_readme.regenerate(mutate(text))  # type: ignore[operator]


def test_empty_case_study_index_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = tmp_path / "README.md"
    empty.write_text("# Case Studies\n\nno table\n", encoding="utf-8")
    monkeypatch.setattr(build_readme, "CASE_STUDY_INDEX", empty)
    with pytest.raises(build_readme.ReadmeError):
        build_readme.render_case_studies()


def test_check_mode_detects_drift_without_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stale = tmp_path / "README.md"
    original = build_readme.README.read_text(encoding="utf-8")
    stale.write_text(original.replace("**Current release: v", "**Current release: v0"), "utf-8")
    monkeypatch.setattr(build_readme, "README", stale)
    before = stale.read_text(encoding="utf-8")
    assert build_readme.main(["--check"]) == 1
    assert stale.read_text(encoding="utf-8") == before
    assert "release" in capsys.readouterr().err
    assert build_readme.main([]) == 0
    assert build_readme.main(["--check"]) == 0


def test_bad_input_exits_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    broken = tmp_path / "README.md"
    broken.write_text("no markers at all\n", encoding="utf-8")
    monkeypatch.setattr(build_readme, "README", broken)
    assert build_readme.main(["--check"]) == 2
