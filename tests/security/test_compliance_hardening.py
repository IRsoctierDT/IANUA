# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Boundary properties of the compliance control checks.

A control check is handed a repository root and grades it. Everything under
that root is **data** to the check — the module docstring of
``compliance/controls.py`` promises reads only, no writes, no network, no
shell — and that has to include the Python interpreter's own import path,
because a check that loads code from the tree it is grading has made the
tree's author a participant in the verdict.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from compliance.controls import ControlStatus, check_attack_corpus_integrity


@pytest.mark.security
def test_the_corpus_check_runs_no_code_from_the_root_under_evaluation(tmp_path: Path) -> None:
    """``root`` is data, never a code path.

    The check used to insert ``root`` at the front of ``sys.path`` and import
    ``attack`` lazily, so an ``attack/__init__.py`` under the root *executed*
    and the process kept both the planted module and the widened ``sys.path``.
    Measured before the fix: the marker below was written, ``sys.path[0]``
    became the temporary root, and ``sys.modules["attack"].__file__`` pointed
    into it. Three assertions, because each is a separate way to fail: the
    planted code must not run, the import path must not change, and the
    ``attack`` module the process holds afterwards must not live under the
    root it was grading.
    """
    marker = tmp_path / "MARKER"
    planted = tmp_path / "attack"
    planted.mkdir()
    (planted / "__init__.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('planted code ran')\n",
        encoding="utf-8",
    )
    path_before = list(sys.path)

    result = check_attack_corpus_integrity(tmp_path)

    assert result.status is ControlStatus.FAIL, result.detail  # no pin under this root
    assert not marker.exists(), "the check executed attack/__init__.py from the root it was grading"
    assert sys.path == path_before, "the check mutated sys.path"
    assert str(tmp_path) not in sys.path
    loaded = sys.modules["attack"].__file__
    assert loaded is not None
    assert not Path(loaded).resolve().is_relative_to(tmp_path.resolve()), (
        f"the process now holds the planted attack package: {loaded}"
    )
