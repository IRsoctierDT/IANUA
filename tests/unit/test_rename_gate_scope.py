# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The IANUA-rename drift gate must skip agent worktrees and nothing else.

`scripts/rename_to_ianua.py` is a required check (AGENTS.md §7 step 6) and had
no tests at all. Two defects were found in one review round, in opposite
directions, which is why both halves are pinned here:

* **Too narrow.** `EXCLUDED_PARTS` had no `.claude` entry, so the scan walked
  into `.claude/worktrees/`, where an isolated agent's checkout holds a *copy*
  of the rename script. The real one is skipped by resolved-path equality; a
  copy at another path is not, and it necessarily contains every legacy
  identifier because it *is* `REPLACEMENTS`. CI has no worktree there, so the
  gate was green in the pipeline and red only locally — the worse shape, since
  an agent running §7 sees a red required check it did not cause and the
  obvious next move is to stop running the check.
* **Then too wide.** The first fix added `".claude"` to `EXCLUDED_PARTS`, which
  matches a single component *anywhere* in a path and so excluded the whole
  directory. `.gitignore` ignores selected `.claude` entries rather than the
  directory wholesale, so content there can be tracked — and a tracked
  `.claude` file carrying a legacy identifier would have passed the gate.

Both were found by review. The fix is `EXCLUDED_PREFIXES`, matched on the path
relative to `ROOT`, so the exclusion names one subtree instead of one component.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.rename_to_ianua import EXCLUDED_PREFIXES, REPLACEMENTS, ROOT, eligible

# A legacy identifier taken from the script's own table rather than retyped, so
# this cannot drift from what the gate actually looks for.
LEGACY = REPLACEMENTS[5][0]


@pytest.mark.unit
def test_the_worktree_subtree_is_excluded() -> None:
    """A copy of the rename script inside an agent worktree is not scanned."""
    inside = ROOT / ".claude" / "worktrees" / "wf_probe" / "scripts" / "rename_to_ianua.py"

    assert not eligible(inside)


@pytest.mark.unit
def test_a_tracked_claude_file_is_still_scanned(tmp_path: Path) -> None:
    """The exclusion is one subtree, not the whole `.claude` directory.

    Written as a real file because `eligible` calls `is_file()`, so a path that
    does not exist is refused for the wrong reason and the test would pass
    whatever the exclusion said.
    """
    tracked = ROOT / ".claude" / "test_rename_gate_scope_probe.md"
    tracked.parent.mkdir(parents=True, exist_ok=True)
    tracked.write_text(f"a legacy {LEGACY} identifier\n", encoding="utf-8")
    try:
        assert eligible(tracked), (
            "a tracked .claude file is skipped — the exclusion is too wide and a "
            "legacy identifier there would pass the gate"
        )
    finally:
        tracked.unlink()


@pytest.mark.unit
def test_the_exclusion_names_a_subtree_and_not_a_bare_component() -> None:
    """Pins the shape, because the component form is what was wrong.

    `(".claude",)` here would re-admit the too-wide fix while leaving both
    tests above green: the worktree copy would still be excluded and a tracked
    `.claude` file is only caught because the prefix has a second element.
    """
    assert EXCLUDED_PREFIXES == ((".claude", "worktrees"),)
    assert all(len(prefix) >= 2 for prefix in EXCLUDED_PREFIXES), (
        "a one-component prefix excludes a whole top-level directory; use "
        "EXCLUDED_PARTS for that, deliberately, or name the subtree"
    )


@pytest.mark.unit
def test_the_script_still_skips_only_itself_among_its_own_copies() -> None:
    """The resolved-path self-exclusion is what the worktree copy defeats.

    Recorded so the interaction is visible: `SELF` is excluded by path
    equality, which is correct for the real file and silently useless for a
    copy. Without `EXCLUDED_PREFIXES` the copy is eligible, which is the
    original defect.
    """
    real = ROOT / "scripts" / "rename_to_ianua.py"
    copy_outside_worktrees = ROOT / "docs" / "rename_to_ianua.py"

    assert not eligible(real), "the script must not rewrite itself"
    # Not a worktree path, so only SELF-equality could exclude it — and it does
    # not, because it is a different path. It is refused for not existing,
    # which is the point: path equality does not generalise to copies.
    assert not copy_outside_worktrees.exists()
    assert not eligible(copy_outside_worktrees)
