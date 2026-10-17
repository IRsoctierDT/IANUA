# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The IANUA-rename gate must not read or write outside the repository.

`scripts/rename_to_ianua.py` says "paths are constrained to the repository
root", and `ROOT.rglob("*")` does keep every *declared* path under ROOT. It did
not keep the *resolved* path there: `rglob` yields a symlink inside the tree,
and `is_file()`, `read_text` and `write_text` all follow it to wherever it
points. Measured on the unpatched gate: a `docs/*.md` link to a file outside
the checkout was reported by `--check`, and `--apply` rewrote the outside file
in place and left the link intact. The `except ValueError` fallback that
should have caught a path resolving outside ROOT instead judged the link on
its unresolved parts, so it was permissive where it needed to fail closed.

AGENTS.md §5 scopes filesystem reach to the project, and `collect/` already
refuses a symlink at a declared source for exactly this reason. These tests
pin the same rule here. Every probe is a real file carrying a real legacy
identifier, because `eligible` refuses a nonexistent path through its own
`is_file()` guard and a test against a missing path holds whatever the rule
does (the lesson `test_rename_gate_scope.py` records).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from scripts.rename_to_ianua import REPLACEMENTS, ROOT, eligible, migrate

LEGACY = REPLACEMENTS[5][0]
# Same tracked-eligible location `test_rename_gate_scope.py` already probes.
PROBE_DIR = ROOT / ".claude"


@contextmanager
def _probe(name: str) -> Iterator[Path]:
    """A path under the repository that is removed again whatever happens."""
    PROBE_DIR.mkdir(parents=True, exist_ok=True)
    path = PROBE_DIR / name
    try:
        yield path
    finally:
        path.unlink(missing_ok=True)


@pytest.mark.unit
def test_a_symlink_to_a_file_outside_the_repository_is_refused(tmp_path: Path) -> None:
    assert not tmp_path.resolve().is_relative_to(ROOT), "tmp_path must lie outside the repo"
    outside = tmp_path / "outside.md"
    outside.write_text(f"legacy {LEGACY} identifier\n", encoding="utf-8")
    with _probe("test_rename_gate_reach_outside_link.md") as link:
        link.symlink_to(outside)
        assert link.is_symlink() and LEGACY in link.read_text(encoding="utf-8"), (
            "the probe must be a live link to legacy content or this test is vacuous"
        )
        assert not eligible(link), "a symlink out of the repository is scanned — and rewritten"
        changed, remaining = migrate(apply=False)
        touched = {str(p) for p in changed} | {str(p) for p, _ in remaining}
        assert str(link.relative_to(ROOT)) not in touched
    assert LEGACY in outside.read_text(encoding="utf-8"), "the outside file must be untouched"


@pytest.mark.unit
def test_a_symlink_inside_the_repository_is_refused_on_the_link_itself() -> None:
    """The rule is on the link, not on where it points.

    The target is still scanned once, through its own path — so content is
    never read or rewritten twice, and a link is never the route to a file.
    """
    with (
        _probe("test_rename_gate_reach_target.md") as target,
        _probe("test_rename_gate_reach_inside_link.md") as link,
    ):
        target.write_text(f"legacy {LEGACY} identifier\n", encoding="utf-8")
        link.symlink_to(target)
        assert eligible(target), "the real file must still be scanned"
        assert not eligible(link), "a link to an eligible file is itself eligible"


@pytest.mark.unit
def test_a_path_that_resolves_outside_the_repository_is_refused(tmp_path: Path) -> None:
    """Pins the fail-closed branch that used to fall back to the unresolved parts."""
    assert not tmp_path.resolve().is_relative_to(ROOT)
    stray = tmp_path / "stray.md"
    stray.write_text(f"legacy {LEGACY} identifier\n", encoding="utf-8")
    assert stray.is_file()
    assert not eligible(stray)
