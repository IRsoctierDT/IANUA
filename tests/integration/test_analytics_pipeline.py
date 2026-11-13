# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""End-to-end local export -> validated snapshot -> dashboard reader tests."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from dashboard.live_analytics import load_snapshot
from scripts.publish_analytics import publish

NOW = datetime(2026, 11, 13, 12, tzinfo=timezone.utc)
HEADER = (
    "department,month,clicks,source_timestamp,data_owner,"
    "reporting_period_start,reporting_period_end,source_system\n"
)
GOOD = (
    "IT,2026-11,3,2026-11-13T11:00:00Z,security,"
    "2026-11-01,2026-11-13,authorized-lab\n"
)


def _source(root: Path, text: str) -> Path:
    """Create an explicitly declared local export in a private lab directory."""
    directory = root / "data" / "imports"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "phishing.csv"
    path.write_text(text, encoding="utf-8")
    return path


def test_end_to_end_publish_and_dashboard_read(tmp_path: Path) -> None:
    """Validated source is published and read with source provenance intact."""
    _source(tmp_path, HEADER + GOOD)
    assert publish(tmp_path, "phishing", now=NOW) == 1
    rows, status = load_snapshot(tmp_path, "phishing")
    assert status.startswith("snapshot")
    assert rows[0]["clicks"] == "3"
    assert rows[0]["source_system"] == "authorized-lab"


def test_invalid_replacement_preserves_last_valid_snapshot(tmp_path: Path) -> None:
    """Bad source cannot overwrite previously verified evidence."""
    source = _source(tmp_path, HEADER + GOOD)
    publish(tmp_path, "phishing", now=NOW)
    source.write_text(HEADER + GOOD.replace(",3,", ",-4,"), encoding="utf-8")
    with pytest.raises(ValueError, match="quality gate"):
        publish(tmp_path, "phishing", now=NOW)
    rows, _ = load_snapshot(tmp_path, "phishing")
    assert rows[0]["clicks"] == "3"


def test_source_symlink_is_refused(tmp_path: Path) -> None:
    """The publisher must not follow symlinks outside declared imports."""
    source = _source(tmp_path, HEADER + GOOD)
    target = tmp_path / "outside.csv"
    target.write_text(HEADER + GOOD, encoding="utf-8")
    source.unlink()
    source.symlink_to(target)
    with pytest.raises(ValueError, match="unsafe"):
        publish(tmp_path, "phishing", now=NOW)


def test_stale_import_is_refused(tmp_path: Path) -> None:
    """An old source cannot masquerade as a current live feed."""
    _source(tmp_path, HEADER + GOOD.replace("2026-11-13T11:00:00Z", "2026-10-01T11:00:00Z"))
    with pytest.raises(ValueError, match="stale"):
        publish(tmp_path, "phishing", now=NOW)
