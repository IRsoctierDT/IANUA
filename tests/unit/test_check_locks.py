"""Unit tests for scripts/check_locks.py (uv.lock <-> pip-lock consistency gate)."""

from pathlib import Path

import pytest
from scripts.check_locks import drift, main, uv_lock_versions

_UV_LOCK = """
version = 1

[[package]]
name = "numpy"
version = "2.5.0"

[[package]]
name = "Ruff"
version = "0.15.18"
"""


def _write(dirpath: Path, name: str, body: str) -> Path:
    path = dirpath / name
    path.write_text(body, encoding="utf-8")
    return path


@pytest.mark.unit
def test_parses_and_normalises_names(tmp_path: Path) -> None:
    versions = uv_lock_versions(_write(tmp_path, "uv.lock", _UV_LOCK))
    # PEP 503: "Ruff" is normalised to "ruff".
    assert versions == {"numpy": "2.5.0", "ruff": "0.15.18"}


@pytest.mark.unit
def test_consistent_lock_has_no_drift(tmp_path: Path) -> None:
    versions = uv_lock_versions(_write(tmp_path, "uv.lock", _UV_LOCK))
    lock = _write(
        tmp_path,
        "requirements.lock",
        "# header\nnumpy==2.5.0 \\\n    --hash=sha256:abc\nruff==0.15.18 ; sys_platform == 'linux'\n",
    )
    assert drift(lock, versions) == []


@pytest.mark.unit
def test_version_mismatch_and_missing_are_reported(tmp_path: Path) -> None:
    versions = uv_lock_versions(_write(tmp_path, "uv.lock", _UV_LOCK))
    lock = _write(tmp_path, "requirements.lock", "numpy==2.4.6\nmem0ai==0.1.27\n")
    problems = drift(lock, versions)
    assert any("numpy==2.4.6" in p and "2.5.0" in p for p in problems)
    assert any("mem0ai" in p and "MISSING" in p for p in problems)


@pytest.mark.unit
def test_main_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    uv = _write(tmp_path, "uv.lock", _UV_LOCK)
    good = _write(tmp_path, "good.lock", "numpy==2.5.0\n")
    bad = _write(tmp_path, "bad.lock", "numpy==9.9.9\n")
    assert main(["--uv-lock", str(uv), "--lock", str(good)]) == 0
    assert main(["--uv-lock", str(uv), "--lock", str(bad)]) == 1
    assert main(["--uv-lock", str(uv), "--lock", str(tmp_path / "nope.lock")]) == 2
