"""Unit tests for scripts/refresh_locks.py (pure functions only — no network,
no subprocesses). The uv/pip-compile integration is exercised by the sbom-sync
CI gate, which regenerates from the committed locks and diffs."""

from pathlib import Path

import pytest
from scripts.refresh_locks import _matches_target, lock_header, target_pins


def _write_uv_lock(tmp_path: Path, body: str) -> Path:
    lock = tmp_path / "uv.lock"
    lock.write_text(body, encoding="utf-8")
    return lock


class TestLockHeader:
    def test_extracts_leading_comment_block(self, tmp_path: Path) -> None:
        lock = tmp_path / "x.lock"
        lock.write_text("# line one\n# line two\nfoo==1.0\n# not a header\n")
        assert lock_header(lock) == "# line one\n# line two\n"

    def test_no_header_returns_empty(self, tmp_path: Path) -> None:
        lock = tmp_path / "x.lock"
        lock.write_text("foo==1.0\n")
        assert lock_header(lock) == ""

    def test_empty_file_returns_empty(self, tmp_path: Path) -> None:
        lock = tmp_path / "x.lock"
        lock.write_text("")
        assert lock_header(lock) == ""


class TestMatchesTarget:
    def test_no_markers_is_unconditional(self) -> None:
        assert _matches_target([])

    def test_python_312_fork_matches(self) -> None:
        assert _matches_target(["python_full_version >= '3.12'"])

    def test_python_311_fork_rejected(self) -> None:
        assert not _matches_target(["python_full_version < '3.12'"])

    def test_any_marker_suffices(self) -> None:
        assert _matches_target(["python_full_version < '3.12'", "sys_platform == 'linux'"])

    def test_non_linux_fork_rejected(self) -> None:
        assert not _matches_target(["sys_platform == 'win32'"])


class TestTargetPins:
    def test_selects_target_fork_of_duplicated_package(self, tmp_path: Path) -> None:
        lock = _write_uv_lock(
            tmp_path,
            """
[[package]]
name = "numpy"
version = "2.4.6"
resolution-markers = ["python_full_version < '3.12'"]

[[package]]
name = "numpy"
version = "2.5.0"
resolution-markers = ["python_full_version >= '3.12'"]

[[package]]
name = "requests"
version = "2.32.0"
""",
        )
        pins = target_pins(lock, "myproject")
        assert pins == {"numpy": "2.5.0", "requests": "2.32.0"}

    def test_excludes_the_project_itself(self, tmp_path: Path) -> None:
        lock = _write_uv_lock(
            tmp_path,
            """
[[package]]
name = "myproject"
version = "0.1.0"

[[package]]
name = "requests"
version = "2.32.0"
""",
        )
        assert target_pins(lock, "myproject") == {"requests": "2.32.0"}

    def test_ambiguous_forks_fail_closed(self, tmp_path: Path) -> None:
        lock = _write_uv_lock(
            tmp_path,
            """
[[package]]
name = "numpy"
version = "2.4.6"

[[package]]
name = "numpy"
version = "2.5.0"
""",
        )
        with pytest.raises(ValueError, match="numpy"):
            target_pins(lock, "myproject")

    def test_empty_lock_yields_no_pins(self, tmp_path: Path) -> None:
        lock = _write_uv_lock(tmp_path, "")
        assert target_pins(lock, "myproject") == {}
