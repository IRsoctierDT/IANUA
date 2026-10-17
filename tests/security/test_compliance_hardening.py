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

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from compliance.controls import ControlStatus, check_attack_corpus_integrity

_REPO = Path(__file__).resolve().parents[2]

# A complete forged ``attack`` package: it records that it ran, and it offers
# the two loader names SUP-03 imports, each answering as a healthy signed corpus.
_PLANTED = (
    "from types import SimpleNamespace\n"
    "from pathlib import Path\n"
    "Path(__file__).resolve().parent.parent.joinpath('MARKER').write_text('planted code ran')\n"
    "def load_pin(path=None):\n"
    "    return SimpleNamespace(signature=SimpleNamespace(algorithm='ed25519'))\n"
    "def load_corpus(*, pin=None, data_dir=None):\n"
    "    return SimpleNamespace(attack_version='99.9', techniques={'T0000': 1}, tombstones={})\n"
)

# Run from inside the graded tree. Reports where ``import attack`` *would* have
# bound (located, not executed), then what the check did about it.
_CWD_SHADOW = """\
import importlib.util, json, sys
from pathlib import Path
from compliance.controls import check_attack_corpus_integrity
spec = importlib.util.find_spec("attack")
result = check_attack_corpus_integrity(Path.cwd())
print(json.dumps({
    "path0": sys.path[0],
    "would_import": spec.origin if spec is not None else None,
    "status": result.status.value,
    "detail": result.detail,
    "held": sys.modules["attack"].__file__ if "attack" in sys.modules else None,
}))
"""


def _plant(root: Path) -> Path:
    """Plant the forged package under ``root``; return the marker it writes when run."""
    (root / "attack").mkdir()
    (root / "attack" / "__init__.py").write_text(_PLANTED, encoding="utf-8")
    return root / "MARKER"


@pytest.mark.security
def test_the_corpus_check_runs_no_code_from_the_root_under_evaluation(tmp_path: Path) -> None:
    """A root that is not on the import path: ``root`` is data, never a code path.

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
    marker = _plant(tmp_path)
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


@pytest.mark.security
def test_the_corpus_check_refuses_an_attack_package_that_shadows_its_own(tmp_path: Path) -> None:
    """The graded tree as cwd, under ``python -c`` with IANUA on ``PYTHONPATH``.

    This is the configuration the in-process test above cannot reach — pytest's
    cwd is the repository — and the one the previous fix left open: ``''`` is
    ``sys.path[0]`` for ``-c``, ``-m`` and the REPL, so ``import attack`` binds
    to the planted package under the root. Measured on 2973439: the marker was
    written, the status was ``pass`` with the forged detail, and
    ``sys.modules["attack"].__file__`` pointed into the graded tree. The
    precondition is asserted rather than assumed — the subprocess reports where
    the import system *would* have taken ``attack`` from, and that must be the
    planted root or this test proves nothing.
    """
    marker = _plant(tmp_path)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(_REPO),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    proc = subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, "-c", _CWD_SHADOW],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=tmp_path,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)

    assert report["path0"] == "", "precondition: the graded tree must be sys.path[0]"
    assert report["would_import"] is not None
    assert Path(report["would_import"]).resolve().is_relative_to(tmp_path.resolve()), (
        "precondition: the planted package must be what `import attack` would bind to"
    )
    assert not marker.exists(), "the check executed attack/__init__.py from the root it was grading"
    assert report["status"] == ControlStatus.ERROR.value, report
    assert report["held"] is None, f"the check imported the shadowing package: {report['held']}"
    assert str(tmp_path) not in report["detail"], "the refusal disclosed a path"


@pytest.mark.security
@pytest.mark.parametrize(
    "spec",
    [None, SimpleNamespace(origin=None)],
    ids=["no-spec", "namespace-package"],
)
def test_the_loader_guard_fails_closed_without_a_file_origin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, spec: object
) -> None:
    """No spec, or a spec with no file origin, is a refusal — not a pass-through."""
    monkeypatch.setattr("importlib.util.find_spec", lambda name: spec)
    result = check_attack_corpus_integrity(tmp_path)
    assert result.status is ControlStatus.ERROR, result.detail


@pytest.mark.security
def test_the_corpus_check_still_loads_its_own_installation() -> None:
    """``root`` equal to the installation is the licensed configuration, not a shadow.

    The shipped callers (``dashboard/app.py``, ``scripts/build_trust_page.py``)
    derive ``root`` from ``__file__``, so ``root / "attack"`` *is* the package
    beside ``compliance/`` — the one the guard admits. Without this assertion
    a guard that refused everything would read as secure.
    """
    result = check_attack_corpus_integrity(_REPO)
    assert result.status is ControlStatus.PASS, result.detail
