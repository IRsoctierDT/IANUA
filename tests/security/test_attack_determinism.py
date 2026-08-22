"""Determinism contracts: same shards -> same corpus, pure freshness."""

from __future__ import annotations

from datetime import date

import pytest
from attack import freshness, load_corpus


@pytest.mark.security
def test_two_loads_are_identical() -> None:
    first = load_corpus()
    second = load_corpus()
    assert first == second


@pytest.mark.security
def test_freshness_is_pure_in_today() -> None:
    day = date(2026, 8, 21)
    a = freshness(today=day)
    b = freshness(today=day)
    assert a == b
    later = freshness(today=date(2027, 8, 21))
    assert later.pin_age_days == a.pin_age_days + 365
    assert later.version_distance == a.version_distance, "distance is version-based, not time"
