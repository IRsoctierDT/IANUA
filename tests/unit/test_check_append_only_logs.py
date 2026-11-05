# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The append-only-log gate: it catches a dropped entry and tolerates an edit.

Two properties carry the gate, and each is driven against a planted defect
rather than asserted, because a gate that fires on nothing teaches nobody
anything:

* a merge that resolves one of these logs' conflicts by keeping one side is
  **caught**, including the one-for-one same-date swap that a row count cannot
  see (``2b3f6b6c``'s shape, pinned below with the real row text); and
* an in-place correction -- which this repository makes constantly -- **passes**,
  because the gate keys on an entry's title and ignores its body.

The git-level cases run in throwaway repositories, so they neither read nor
depend on this repository's own history.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts.check_append_only_logs import (
    changelog_keys,
    decision_keys,
    load_declared_removals,
    lost_keys,
    main,
)

# --------------------------------------------------------------------------- #
# Fixtures: the smallest documents that carry the real structure.
# --------------------------------------------------------------------------- #

DESIGN_HEAD = """# Design

## 10. Something Else

| Date | Decision | Rationale |
|---|---|---|
| 2026-01-01 | A row in ANOTHER table that must never become a key | n/a |

## 11. Decision Log

| Date | Decision | Rationale |
|---|---|---|
| _initial_ | Local-first inference as default | Cost, privacy |
| 2026-10-24 | Third-party PR security review is SHA-pinned | It costs nothing |
| 2026-10-24 | The stage 7 listener gains connection-level bounds | One socket stalls it |
"""

DESIGN_APPENDED = DESIGN_HEAD + (
    "| 2026-10-30 | `ingest` fits every event under the ceiling | One record stalled a source |\n"
)

#: The #280 shape: the last row is REPLACED by a new one at the SAME date, so
#: the row count is unchanged. This is what review and a count both missed.
DESIGN_SWAPPED = DESIGN_HEAD.replace(
    "| 2026-10-24 | The stage 7 listener gains connection-level bounds | One socket stalls it |",
    "| 2026-10-24 | `report_sli.py` escapes every line it prints | The residual #276 left |",
)

CHANGELOG_HEAD = """# Changelog

## Unreleased

### Security
- **The stage 7 listener gains connection-level bounds.** The amendment's
  audit-write bound covers request floods, which is the path that carries a key.

### Known issues
- **An unclaimed record's `raw_excerpt` escapes non-ASCII characters.** It is
  serialized with `json.dumps`, whose default is `ensure_ascii=True`.
"""


def _write_logs(root: Path, design: str, changelog: str) -> None:
    (root / "DESIGN.md").write_text(design, encoding="utf-8")
    (root / "docs").mkdir(exist_ok=True)
    (root / "docs" / "Changelog.md").write_text(changelog, encoding="utf-8")


def _git(root: Path, *args: str) -> None:
    subprocess.run(  # noqa: S603 - fixed argv
        ["git", *args],  # noqa: S607 - git from PATH, test env
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway repository holding both logs on ``main``."""
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "T")
    _write_logs(root, DESIGN_HEAD, CHANGELOG_HEAD)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    return root


# --------------------------------------------------------------------------- #
# Key extraction
# --------------------------------------------------------------------------- #


def test_decision_keys_are_scoped_to_section_11() -> None:
    keys = decision_keys(DESIGN_HEAD)
    assert "A row in ANOTHER table that must never become a key" not in keys
    assert "Third-party PR security review is SHA-pinned" in keys


def test_decision_keys_include_the_initial_rows() -> None:
    assert "Local-first inference as default" in decision_keys(DESIGN_HEAD)


def test_decision_keys_are_empty_when_the_section_is_absent() -> None:
    assert decision_keys("# Design\n\n## 9. Other\n\ntext\n") == []


def test_changelog_keys_are_the_bold_lead_ins() -> None:
    keys = changelog_keys(CHANGELOG_HEAD)
    assert "The stage 7 listener gains connection-level bounds." in keys
    assert "An unclaimed record's `raw_excerpt` escapes non-ASCII characters." in keys


def test_keys_survive_reflowing_because_whitespace_is_normalised() -> None:
    reflowed = CHANGELOG_HEAD.replace(
        "- **The stage 7 listener gains connection-level bounds.**",
        "- **The stage 7 listener gains\n  connection-level bounds.**",
    )
    assert "The stage 7 listener gains connection-level bounds." in changelog_keys(reflowed)


# --------------------------------------------------------------------------- #
# The two load-bearing properties
# --------------------------------------------------------------------------- #


def test_an_appended_row_loses_nothing() -> None:
    assert lost_keys(DESIGN_HEAD, DESIGN_APPENDED, decision_keys) == []


def test_an_in_place_rationale_edit_loses_nothing() -> None:
    """The case that makes the gate usable: corrections must not fire it."""
    edited = DESIGN_HEAD.replace("One socket stalls it", "Measured on CPython 3.13.17")
    assert lost_keys(DESIGN_HEAD, edited, decision_keys) == []


def test_an_in_place_changelog_body_edit_loses_nothing() -> None:
    edited = CHANGELOG_HEAD.replace(
        "which is the path that carries a key", "which is the keyed path"
    )
    assert lost_keys(CHANGELOG_HEAD, edited, changelog_keys) == []


def test_a_same_date_one_for_one_swap_is_caught() -> None:
    """``2b3f6b6c``'s shape: a row overwritten by another at the same date."""
    lost = lost_keys(DESIGN_HEAD, DESIGN_SWAPPED, decision_keys)
    assert lost == ["The stage 7 listener gains connection-level bounds"]


def test_a_row_count_would_have_missed_that_swap() -> None:
    """Why this gate is not a count: the counts are equal across the swap.

    #306's merge dropped one row and added one, so both trees held 87, and
    ``2b3f6b6c`` did the same at the same date. This pins the reason a count
    was rejected, so nobody re-proposes one.
    """
    assert len(decision_keys(DESIGN_HEAD)) == len(decision_keys(DESIGN_SWAPPED))
    assert lost_keys(DESIGN_HEAD, DESIGN_SWAPPED, decision_keys) != []


def test_a_dropped_changelog_hunk_is_caught() -> None:
    kept_one_side = CHANGELOG_HEAD.replace(
        "- **The stage 7 listener gains connection-level bounds.** The amendment's\n"
        "  audit-write bound covers request floods, which is the path that carries a key.\n",
        "",
    )
    assert lost_keys(CHANGELOG_HEAD, kept_one_side, changelog_keys) == [
        "The stage 7 listener gains connection-level bounds."
    ]


def test_the_real_row_that_280_dropped_is_the_shape_this_catches() -> None:
    """A regression fixture carrying the real text, with no git dependency.

    ``2b3f6b6c`` overwrote this row; it is absent from ``DESIGN.md`` and from
    every tracked markdown file to this day.
    """
    real = (
        "| 2026-10-23 | Concurrent sessions are kept apart by a pre-flight overlap check,"
        " one owner per item, one job per lane and no stacked branches"
        " (`AGENTS.md` §2 step 8, §6.4, §8) | Several sessions can work this repo at once |\n"
    )
    base = DESIGN_HEAD + real
    overwritten = DESIGN_HEAD + (
        "| 2026-10-23 | `report_sli.py` escapes every line it prints | The residual #276 left |\n"
    )
    lost = lost_keys(base, overwritten, decision_keys)
    assert len(lost) == 1
    assert lost[0].startswith("Concurrent sessions are kept apart")


# --------------------------------------------------------------------------- #
# The declaration file: fail closed on anything malformed
# --------------------------------------------------------------------------- #


def test_an_absent_declaration_file_declares_nothing(tmp_path: Path) -> None:
    assert load_declared_removals(tmp_path) == {}


@pytest.mark.parametrize(
    "payload",
    [
        "not json at all",
        '["a bare list is the old shape"]',
        '{"version": 2, "removals": []}',
        '{"removals": []}',
        '{"version": 1, "removals": {}}',
        '{"version": 1, "removals": [{"file": "DESIGN.md", "key": "k"}]}',
        '{"version": 1, "removals": [{"file": "DESIGN.md", "key": "k", "reason": "  "}]}',
        '{"version": 1, "removals": [{"file": "README.md", "key": "k", "reason": "r"}]}',
        '{"version": 1, "removals": ["a string, not an object"]}',
    ],
)
def test_a_malformed_declaration_fails_closed(tmp_path: Path, payload: str) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "log_removals.json").write_text(payload, encoding="utf-8")
    with pytest.raises(ValueError):
        load_declared_removals(tmp_path)


def test_a_well_formed_declaration_loads(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "log_removals.json").write_text(
        json.dumps(
            {
                "version": 1,
                "removals": [
                    {
                        "file": "docs/Changelog.md",
                        "key": "An unclaimed record's `raw_excerpt` escapes non-ASCII characters.",
                        "reason": "fixed by #301; the entry records a resolved known issue",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    declared = load_declared_removals(tmp_path)
    assert declared["docs/Changelog.md"] == {
        "An unclaimed record's `raw_excerpt` escapes non-ASCII characters."
    }


# --------------------------------------------------------------------------- #
# End to end, through git, in a throwaway repository
# --------------------------------------------------------------------------- #


def test_a_clean_append_passes(repo: Path) -> None:
    _write_logs(repo, DESIGN_APPENDED, CHANGELOG_HEAD)
    assert main(["--base", "main", "--root", str(repo)]) == 0


def test_a_dropped_entry_fails(repo: Path) -> None:
    _write_logs(repo, DESIGN_SWAPPED, CHANGELOG_HEAD)
    assert main(["--base", "main", "--root", str(repo)]) == 1


def test_a_declared_removal_passes(repo: Path) -> None:
    _write_logs(repo, DESIGN_SWAPPED, CHANGELOG_HEAD)
    (repo / "docs" / "log_removals.json").write_text(
        json.dumps(
            {
                "version": 1,
                "removals": [
                    {
                        "file": "DESIGN.md",
                        "key": "The stage 7 listener gains connection-level bounds",
                        "reason": "superseded in this worked example",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert main(["--base", "main", "--root", str(repo)]) == 0


def test_a_branch_merely_behind_its_base_passes(repo: Path) -> None:
    """The false positive a base-tip comparison would produce, and this does not."""
    _git(repo, "checkout", "-qb", "feature")
    # main moves ahead with a new entry the branch has never seen.
    _git(repo, "checkout", "-q", "main")
    _write_logs(repo, DESIGN_APPENDED, CHANGELOG_HEAD)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "main adds a row")
    _git(repo, "checkout", "-q", "feature")
    _write_logs(repo, DESIGN_HEAD, CHANGELOG_HEAD)
    assert main(["--base", "main", "--root", str(repo)]) == 0


def test_a_bad_merge_resolution_fails(repo: Path) -> None:
    """The real hazard: the branch merges main and keeps only its own side."""
    _git(repo, "checkout", "-qb", "feature")
    branch_row = "| 2026-10-30 | A row only this branch has | its own rationale |\n"
    _write_logs(repo, DESIGN_HEAD + branch_row, CHANGELOG_HEAD)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "branch adds a row")
    _git(repo, "checkout", "-q", "main")
    _write_logs(repo, DESIGN_APPENDED, CHANGELOG_HEAD)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "main adds a different row")
    _git(repo, "checkout", "-q", "feature")
    subprocess.run(
        ["git", "merge", "main", "--no-commit"],  # noqa: S607 - git from PATH, test env
        cwd=repo,
        capture_output=True,
        text=True,
    )
    # Resolve by keeping only this branch's side -- the recorded failure.
    _write_logs(repo, DESIGN_HEAD + branch_row, CHANGELOG_HEAD)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "merge main (resolved badly)")
    assert main(["--base", "main", "--root", str(repo)]) == 1


@pytest.mark.parametrize(
    "ref",
    [
        # The `=` form is used deliberately: `--base --upload-pack=evil` is
        # consumed by argparse as an option before the validator sees it, so it
        # would prove argparse's behaviour rather than this gate's.
        "--upload-pack=evil",
        "-x",
        "main; rm -rf /",
        "main$(id)",
        "main\nmain",
        "a" * 400,
    ],
)
def test_an_unsafe_ref_is_refused(repo: Path, ref: str) -> None:
    """The validator refuses it, not argparse and not git."""
    assert main([f"--base={ref}", "--root", str(repo)]) == 2


def test_an_unknown_ref_reports_a_missing_input(repo: Path) -> None:
    assert main(["--base", "no-such-ref", "--root", str(repo)]) == 2


def test_this_repository_passes_its_own_gate() -> None:
    """A stale tree turns the suite red locally, before CI's copy does."""
    root = Path(__file__).resolve().parents[2]
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],  # noqa: S607 - git from PATH, test env
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if head.returncode != 0:  # pragma: no cover - not a git checkout
        pytest.skip("not a git checkout")
    assert main(["--base", "HEAD", "--root", str(root)]) == 0
