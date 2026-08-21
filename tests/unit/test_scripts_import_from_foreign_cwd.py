"""Every gate script must run as a subprocess from a foreign CWD.

``python scripts/x.py`` puts ``scripts/`` (not the repo root) on ``sys.path``,
and CI's status-page-sync job runs with a minimal install — a missing
``sys.path`` shim surfaces only at invocation time. This test pins the shim
for every drift-gate script by actually invoking each one from a different
working directory.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]

_GATES = [
    ["scripts/update_attack.py", "--check"],
    ["scripts/build_attack_navigator.py", "--check"],
    ["scripts/check_locks.py"],
    ["scripts/build_status_page.py", "--check"],
    ["scripts/build_trust_page.py", "--check"],
]


@pytest.mark.unit
@pytest.mark.parametrize("gate", _GATES, ids=lambda g: g[0].rsplit("/", 1)[-1])
def test_gate_runs_from_foreign_cwd(gate: list[str], tmp_path: Path) -> None:
    result = subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, str(_REPO / gate[0]), *gate[1:]],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=tmp_path,
        check=False,
    )
    assert result.returncode == 0, (
        f"{gate} failed from foreign cwd:\n{result.stdout}\n{result.stderr}"
    )
