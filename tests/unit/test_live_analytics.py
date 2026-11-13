# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for bounded local security analytics projections."""
from __future__ import annotations

from pathlib import Path

import pytest

from dashboard.live_analytics import domain_counts, load_events, load_snapshot, numeric_counts


def test_missing_store_is_unavailable(tmp_path: Path) -> None:
    """A dashboard read must not initialize a shadow event store."""
    events, status = load_events(tmp_path)
    assert events == []
    assert "not initialized" in status
    assert not (tmp_path / "data").exists()


def test_missing_snapshot_is_not_zero(tmp_path: Path) -> None:
    """Missing telemetry must be marked unavailable."""
    rows, status = load_snapshot(tmp_path, "phishing")
    assert rows == []
    assert status.startswith("unavailable")


def test_reject_undeclared_dataset(tmp_path: Path) -> None:
    """Callers cannot use dataset names to traverse the filesystem."""
    with pytest.raises(ValueError):
        load_snapshot(tmp_path, "../secrets")


def test_snapshot_counts_and_provenance(tmp_path: Path) -> None:
    """A declared snapshot remains a snapshot, not a live feed."""
    folder = tmp_path / "data" / "analytics"
    folder.mkdir(parents=True)
    (folder / "phishing.csv").write_text(
        "department,month,clicks,source_timestamp,data_owner\n"
        "Finance,2026-10,4,2026-11-01T00:00:00Z,awareness\n"
        "IT,2026-10,1,2026-11-01T00:00:00Z,awareness\n",
        encoding="utf-8",
    )
    rows, status = load_snapshot(tmp_path, "phishing")
    assert len(rows) == 2
    assert status.startswith("snapshot")
    assert numeric_counts(rows, "department") == {"Finance": 1, "IT": 1}


def test_reject_symlink_snapshot(tmp_path: Path) -> None:
    """A symlink must not redirect dashboard reads to arbitrary files."""
    folder = tmp_path / "data" / "analytics"
    folder.mkdir(parents=True)
    secret = tmp_path / "secret.csv"
    secret.write_text("secret\nvalue\n", encoding="utf-8")
    (folder / "phishing.csv").symlink_to(secret)
    rows, status = load_snapshot(tmp_path, "phishing")
    assert rows == []
    assert "symlink refused" in status


def test_domain_counts() -> None:
    """Domain aggregation uses canonical classifications."""
    assert domain_counts([{"domain": "network"}, {"domain": "email"}, {"domain": "network"}]) == {
        "email": 1, "network": 2
    }
