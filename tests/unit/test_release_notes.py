"""Contracts for scripts/release_notes.py — curated release bodies, fail closed.

The release body is externally visible and immutable in practice: once a
release is published, its notes are what consumers read. So the failure modes
that matter are the quiet ones — a blank body, a body that bleeds into the
previous release, or a compare link pointing at the wrong tag — and each gets
a test rather than a comment.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
from scripts import release_notes

_REPO_ROOT = Path(__file__).resolve().parents[2]
_REPO = "owner/name"

# A synthetic changelog in exactly the shape prepare_release.py produces,
# including the em-dash separators. Fixed forever, so these assertions are
# arithmetic on the fixture rather than on the live file.
_CHANGELOG = """# Changelog

All notable changes to this project. Versions correspond to git tags.

## Unreleased

## v2.2.0 — Second Release — 2026-10-13

### Added
- A thing that was added.

### Fixed
- A thing that was fixed.

## v2.1.0 — First Release — 2026-10-05

### Added
- The original thing.
"""


@pytest.mark.unit
def test_composes_the_curated_section_with_a_compare_link() -> None:
    notes = release_notes.compose(_CHANGELOG, "v2.2.0", _REPO)
    assert "### Added\n- A thing that was added." in notes
    assert "### Fixed\n- A thing that was fixed." in notes
    assert notes.endswith(
        "**Full Changelog**: https://github.com/owner/name/compare/v2.1.0...v2.2.0\n"
    )


@pytest.mark.unit
def test_section_stops_at_the_previous_release() -> None:
    """The body must not bleed into the release below it."""
    notes = release_notes.compose(_CHANGELOG, "v2.2.0", _REPO)
    assert "The original thing" not in notes, "v2.1.0 content leaked into v2.2.0's notes"
    assert "First Release" not in notes
    # Nor should it pick up the empty Unreleased section above it.
    assert "## Unreleased" not in notes


@pytest.mark.unit
def test_first_release_has_no_compare_link() -> None:
    """A compare link needs two tags; the oldest release gets notes without one."""
    notes = release_notes.compose(_CHANGELOG, "v2.1.0", _REPO)
    assert "The original thing" in notes
    assert "Full Changelog" not in notes


@pytest.mark.unit
def test_missing_heading_fails_closed() -> None:
    with pytest.raises(release_notes.ReleaseNotesError, match=re.escape("no '## v9.9.9")):
        release_notes.compose(_CHANGELOG, "v9.9.9", _REPO)


@pytest.mark.unit
def test_empty_section_refuses_to_publish_blank_notes() -> None:
    """The quiet failure this exists to prevent."""
    text = (
        "# Changelog\n\n## v1.0.0 — Empty — 2026-01-01\n\n## v0.9.0 — Prior — 2025-12-01\n\n- x\n"
    )
    with pytest.raises(release_notes.ReleaseNotesError, match="empty"):
        release_notes.compose(text, "v1.0.0", _REPO)


@pytest.mark.unit
def test_duplicate_heading_fails_closed() -> None:
    """Two headings for one version means the changelog is corrupt; don't guess."""
    text = (
        "# Changelog\n\n"
        "## v1.0.0 — One — 2026-01-01\n\n- a\n\n"
        "## v1.0.0 — Two — 2026-01-02\n\n- b\n"
    )
    with pytest.raises(release_notes.ReleaseNotesError, match="2 release headings"):
        release_notes.compose(text, "v1.0.0", _REPO)


@pytest.mark.unit
@pytest.mark.parametrize("tag", ["2.2.0", "v2.2", "v02.2.0", "v2.2.0-rc1", "", "v2.2.0 "])
def test_non_canonical_tags_are_rejected(tag: str) -> None:
    with pytest.raises(release_notes.ReleaseNotesError, match="canonical"):
        release_notes.compose(_CHANGELOG, tag, _REPO)


@pytest.mark.unit
@pytest.mark.parametrize(
    "repo",
    [
        "owner",  # no name
        "owner/name/extra",
        "owner name",
        "owner/name?x=1",  # would alter the published URL
        "../../etc",
        "https://evil.example/owner/name",
        "",
    ],
)
def test_repository_is_validated_before_it_lands_in_a_url(repo: str) -> None:
    """The repo is interpolated into a link published on the release page."""
    with pytest.raises(release_notes.ReleaseNotesError, match="owner/name"):
        release_notes.compose(_CHANGELOG, "v2.2.0", repo)


@pytest.mark.unit
def test_live_changelog_composes_for_the_current_version() -> None:
    """The coupling that actually drifts: the heading format.

    prepare_release.py writes the release heading and this script parses it.
    Nothing else notices if the two stop agreeing — a changed separator would
    silently make every future release body unbuildable. Reading the live file
    is deliberate here, and safe: check_version_sync already requires a
    ``## v<pyproject version>`` heading to exist, so this is stable across
    release state rather than dependent on it.
    """
    config = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = config["project"]["version"]
    text = (_REPO_ROOT / release_notes.CHANGELOG).read_text(encoding="utf-8")
    notes = release_notes.compose(text, f"v{version}", "IRsoctierDT/IANUA")
    assert notes.strip(), "the current release's notes came out empty"
    assert "## v" not in notes, "a release heading leaked into the body"


@pytest.mark.unit
def test_cli_writes_the_file_and_reports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "notes.md"
    code = release_notes.main(
        ["--tag", "v2.2.0", "--repo", _REPO, "--output", str(out)],
    )
    assert code == 0
    assert "release-notes: OK: v2.2.0" in capsys.readouterr().out
    # Composed from the LIVE changelog, so assert only the invariants.
    written = out.read_text(encoding="utf-8")
    assert written.strip()
    assert written.endswith("\n")


@pytest.mark.unit
def test_cli_bad_input_exits_nonzero_and_writes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "notes.md"
    assert release_notes.main(["--tag", "nope", "--repo", _REPO, "--output", str(out)]) == 1
    assert "release-notes: FAIL" in capsys.readouterr().err
    assert not out.exists(), "a failed run must not leave a partial notes file"


@pytest.mark.unit
def test_canonical_version_matches_prepare_release() -> None:
    """One definition of canonical, shared with the script that writes the tag.

    release_notes delegates to prepare_release.parse_version rather than
    hand-rolling a second pattern. Pinned directly because a looser reader
    would accept ``v02.2.0``, find no heading, and report the changelog as
    broken when the tag is what is malformed — and a stricter one would refuse
    a tag the release pipeline had already created.
    """
    from scripts import prepare_release

    for version in ("0.0.0", "1.2.3", "2.2.0", "10.20.30"):
        assert release_notes.parse_tag(f"v{version}") == version
        prepare_release.parse_version(version)  # the writer agrees

    for bad in ("02.2.0", "2.2", "2.2.0-rc1", "1.2.3.4"):
        with pytest.raises(release_notes.ReleaseNotesError):
            release_notes.parse_tag(f"v{bad}")
        with pytest.raises(prepare_release.ReleaseError):
            prepare_release.parse_version(bad)


@pytest.mark.unit
def test_runs_as_a_subprocess_from_a_foreign_cwd(tmp_path: Path) -> None:
    """``python scripts/release_notes.py`` puts scripts/ on sys.path, not the root.

    release.yml invokes this script by path, so a missing sys.path shim would
    surface only at publication time — the worst moment. The drift-gate list in
    test_scripts_import_from_foreign_cwd.py cannot cover it, because this
    script requires arguments and is not a ``--check`` gate, so it is pinned
    here instead.
    """
    import subprocess
    import sys

    result = subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [
            sys.executable,
            str(_REPO_ROOT / "scripts/release_notes.py"),
            "--tag",
            "v2.2.0",
            "--repo",
            "IRsoctierDT/IANUA",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=tmp_path,
        check=False,
    )
    assert result.returncode == 0, f"failed from foreign cwd:\n{result.stdout}\n{result.stderr}"
    assert result.stdout.strip()


@pytest.mark.unit
def test_release_workflow_guards_the_notes_step_for_older_tags() -> None:
    """The notes step must tolerate a tag cut before this script existed.

    release-on-merge.yml dispatches release.yml with ``--ref main``, so the
    RECIPE comes from main while release.yml detaches the CHECKOUT to the tag.
    A tag predating scripts/release_notes.py therefore has no such file, and an
    unguarded ``python scripts/release_notes.py`` fails the publish — which
    breaks the documented post-dispatch-failure recovery path for exactly those
    tags. v2.2.0 is one: this script landed in #193, after the tag.

    Pinned because the guard reads like defensive clutter and the failure it
    prevents only appears when republishing an old release, which is both rare
    and the worst moment to discover it.
    """
    workflow = (_REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "scripts/release_notes.py" in workflow, "release.yml no longer composes curated notes"
    assert "-f scripts/release_notes.py" in workflow, (
        "the notes step is no longer guarded on the script existing in the checked-out tree; "
        "republishing a tag cut before the script existed would fail the publish"
    )
    assert "--generate-notes" in workflow, (
        "the fallback for tags predating release_notes.py is gone; an older tag cannot be republished"
    )
    assert "--notes-file" in workflow, "the curated-notes path is gone"
