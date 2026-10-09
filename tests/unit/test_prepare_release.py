"""Tests for scripts/prepare_release.py — atomic, fail-closed release preparation."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from scripts import check_version_sync, prepare_release

_SURFACES = (
    "pyproject.toml",
    "uv.lock",
    "package.json",
    "package-lock.json",
    "security/sbom/npm.cdx.json",
    "security/sbom/sbom.cdx.json",
    "docs/status.data.json",
    "docs/status.json",
    "docs/Changelog.md",
    "docs/PROJECT_STATUS.md",
    "SECURITY.md",
    "tests/unit/test_version_sync.py",
)


@pytest.fixture
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A copy of every release surface; both scripts are pointed at it."""
    for rel in _SURFACES:
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(prepare_release.ROOT / rel, target)
    monkeypatch.setattr(prepare_release, "ROOT", tmp_path)
    monkeypatch.setattr(check_version_sync, "ROOT", tmp_path)
    return tmp_path


def _snapshot(root: Path) -> dict[str, bytes]:
    return {rel: (root / rel).read_bytes() for rel in _SURFACES}


def _next_minor() -> str:
    major, minor, _patch = prepare_release.parse_version(prepare_release.current_version())
    return f"{major}.{minor + 1}.0"


def _stub_regenerate(root: Path, version: str) -> dict[Path, str]:
    """Stand-in for the status-page build: only the version field matters here."""
    status = root / "docs" / "status.json"
    data = json.loads(status.read_text(encoding="utf-8"))
    data["version"] = version
    status.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return {}


@pytest.mark.unit
def test_plan_covers_every_surface_and_writes_nothing(sandbox: Path) -> None:
    before = _snapshot(sandbox)
    changes = prepare_release.plan(_next_minor(), "Live Tool Inspection", "2026-11-02")
    assert {p.relative_to(sandbox).as_posix() for p in changes} == set(_SURFACES) - {
        "docs/status.json"  # regenerated, not planned
    }
    assert _snapshot(sandbox) == before


@pytest.mark.unit
def test_apply_bumps_all_surfaces_in_sync(sandbox: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    version = _next_minor()
    monkeypatch.setattr(prepare_release, "_regenerate", lambda: _stub_regenerate(sandbox, version))
    changes = prepare_release.plan(version, "Live Tool Inspection", "2026-11-02")
    prepare_release.apply(changes, version)
    assert check_version_sync.check(f"v{version}") == version
    changelog = (sandbox / "docs/Changelog.md").read_text(encoding="utf-8")
    assert f"## Unreleased\n\n## v{version} — Live Tool Inspection — 2026-11-02\n" in changelog
    security = (sandbox / "SECURITY.md").read_text(encoding="utf-8")
    assert "(current — Live Tool Inspection)" in security
    assert security.count("(current —") == 1


@pytest.mark.unit
def test_failure_restores_every_file(sandbox: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    before = _snapshot(sandbox)

    def boom() -> dict[Path, str]:
        raise prepare_release.ReleaseError("regeneration failed")

    monkeypatch.setattr(prepare_release, "_regenerate", boom)
    version = _next_minor()
    changes = prepare_release.plan(version, "Live Tool Inspection", "2026-11-02")
    with pytest.raises(prepare_release.ReleaseError):
        prepare_release.apply(changes, version)
    assert _snapshot(sandbox) == before


@pytest.mark.unit
def test_failed_verification_restores_every_file(
    sandbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without the status regeneration the sync check fails — and nothing sticks."""
    before = _snapshot(sandbox)
    monkeypatch.setattr(prepare_release, "_regenerate", dict)
    version = _next_minor()
    changes = prepare_release.plan(version, "Live Tool Inspection", "2026-11-02")
    with pytest.raises(check_version_sync.VersionSyncError):
        prepare_release.apply(changes, version)
    assert _snapshot(sandbox) == before


@pytest.mark.unit
@pytest.mark.parametrize(
    ("version", "title", "date"),
    [
        ("v9.0.0", "Valid Title", "2026-11-02"),  # not canonical
        ("9.0", "Valid Title", "2026-11-02"),
        ("09.0.0", "Valid Title", "2026-11-02"),
        ("0.0.1", "Valid Title", "2026-11-02"),  # not greater than current
        ("9.0.0", "Bad | pipe", "2026-11-02"),  # breaks Markdown tables
        ("9.0.0", "Bad (paren)", "2026-11-02"),  # breaks the SECURITY.md row
        ("9.0.0", "Bad **bold**", "2026-11-02"),
        ("9.0.0", "Line\nbreak", "2026-11-02"),
        ("9.0.0", "<script>", "2026-11-02"),
        ("9.0.0", "x", "2026-11-02"),  # too short
        ("9.0.0", "Valid Title", "02/11/2026"),
    ],
)
def test_invalid_input_is_rejected(sandbox: Path, version: str, title: str, date: str) -> None:
    with pytest.raises(prepare_release.ReleaseError):
        prepare_release.plan(version, title, date)


@pytest.mark.unit
def test_empty_unreleased_section_fails_closed() -> None:
    text = "# Changelog\n\n## Unreleased\n\n## v1.0.0 — First — 2026-01-01\n"
    with pytest.raises(prepare_release.ReleaseError, match="empty"):
        prepare_release.promote_changelog(text, "1.1.0", "Next", "2026-02-01")


@pytest.mark.unit
def test_existing_release_heading_fails_closed() -> None:
    text = "## Unreleased\n\n- change\n\n## v1.1.0 — Next — 2026-02-01\n"
    with pytest.raises(prepare_release.ReleaseError, match="already"):
        prepare_release.promote_changelog(text, "1.1.0", "Next", "2026-02-01")


@pytest.mark.unit
def test_patch_release_keeps_supported_versions_table() -> None:
    text = "| 2.1.x (current — Title) | Supported — security fixes applied |\n"
    assert prepare_release.update_security(text, "2.1.0", "2.1.1", "Other") == text


@pytest.mark.unit
def test_shape_mismatch_fails_closed(sandbox: Path) -> None:
    lock = sandbox / "package-lock.json"
    data = json.loads(lock.read_text(encoding="utf-8"))
    data["packages"][""]["version"] = "0.0.0"
    lock.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(prepare_release.ReleaseError, match=r"package-lock\.json"):
        prepare_release.plan(_next_minor(), "Live Tool Inspection", "2026-11-02")


@pytest.mark.unit
def test_cli_dry_run_and_bad_input_exit_codes(
    sandbox: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _snapshot(sandbox)
    assert prepare_release.main([_next_minor(), "--title", "Valid Title", "--dry-run"]) == 0
    assert "would update pyproject.toml" in capsys.readouterr().out
    assert prepare_release.main(["not-a-version", "--title", "Valid Title"]) == 2
    assert _snapshot(sandbox) == before


@pytest.mark.unit
def test_regenerate_runs_generators_and_returns_originals(
    sandbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import build_status_page

    calls: list[list[str]] = []

    def record(argv: list[str]) -> int:
        calls.append(argv)
        return 0

    monkeypatch.setattr(build_status_page, "main", record)
    (sandbox / "docs" / "status.html").write_text("<html></html>\n", encoding="utf-8")
    originals = prepare_release._regenerate()
    assert calls == [[]]
    assert sandbox / "docs" / "status.html" in originals
    assert sandbox / "docs" / "status.json" in originals


@pytest.mark.unit
def test_regenerate_failure_raises(sandbox: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts import build_status_page

    monkeypatch.setattr(build_status_page, "main", lambda argv: 2)
    (sandbox / "docs" / "status.html").write_text("<html></html>\n", encoding="utf-8")
    with pytest.raises(prepare_release.ReleaseError, match="regenerating"):
        prepare_release._regenerate()


@pytest.mark.unit
def test_cli_success_reports_updated_files(
    sandbox: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    version = _next_minor()
    monkeypatch.setattr(prepare_release, "_regenerate", lambda: _stub_regenerate(sandbox, version))
    args = [version, "--title", "Live Tool Inspection", "--date", "2026-11-02"]
    assert prepare_release.main(args) == 0
    assert f"prepare-release: OK: v{version}" in capsys.readouterr().out
    assert check_version_sync.check() == version
