"""Contracts for the Detection Intelligence dashboard views.

Two properties matter more than the formatting: the views must be honest
about staleness (a stale corpus reports as needing attention, never as
quietly healthy), and they must fail soft without ever rendering an
unavailable layer as an empty-but-fine one.
"""

from __future__ import annotations

from datetime import date
from typing import Any

import pytest
from dashboard import intelligence_view as view

_TODAY = date(2026, 8, 21)


@pytest.mark.unit
def test_layer_rows_cover_every_layer() -> None:
    rows = view.layer_rows(as_of=_TODAY)
    layers = {row["Layer"] for row in rows}
    assert layers == {
        "Telemetry ingest",
        "ATT&CK corpus",
        "Mapping ruleset",
        "Threat-intel library",
        "Behavioral detections",
        "Response layer",
    }
    for row in rows:
        assert row["Status"] and row["Detail"], f"{row['Layer']}: empty status or detail"


@pytest.mark.unit
def test_corpus_status_reports_version_and_signing_posture() -> None:
    status = view.attack_corpus_status(as_of=_TODAY)
    assert "ATT&CK 19" in status.detail
    # The unsigned-pin posture must be stated, not implied away.
    assert "pin" in status.detail


@pytest.mark.unit
def test_corpus_status_flags_version_distance(monkeypatch: pytest.MonkeyPatch) -> None:
    """A corpus behind upstream must read as attention, never as current."""
    import attack

    real_freshness = attack.freshness

    def _behind(*args: Any, **kwargs: Any) -> Any:
        report = real_freshness(*args, **kwargs)
        return type(report)(
            pinned_version=report.pinned_version,
            latest_known_version="99.9",
            version_distance=3,
            latest_modified=report.latest_modified,
            pin_age_days=report.pin_age_days,
        )

    monkeypatch.setattr(attack, "freshness", _behind)
    status = view.attack_corpus_status(as_of=_TODAY)
    assert "attention" in status.status
    assert "3 release(s) behind" in status.detail


@pytest.mark.unit
def test_behavior_status_states_the_telemetry_split() -> None:
    status = view.behavior_status()
    assert "awaiting telemetry" in status.detail
    # Rules that cannot fire must never be presented as unqualified coverage.
    assert "live" in status.detail


@pytest.mark.unit
def test_response_status_is_always_plan_only() -> None:
    status = view.response_status()
    assert status.status == "📝 plan-only"
    assert "executes nothing" in status.detail
    assert "human" in status.detail


@pytest.mark.unit
def test_behavior_rows_sort_live_coverage_first() -> None:
    rows = view.behavior_rows()
    assert rows
    # Assert the grouping directly rather than via the badge glyphs — emoji
    # sort by codepoint, so "⏳" precedes "✅" and a naive sorted() comparison
    # would test the wrong thing.
    live_flags = [row["Telemetry"].endswith("live") for row in rows]
    assert live_flags == sorted(live_flags, reverse=True), (
        "live rules should group ahead of the ones awaiting telemetry"
    )
    assert live_flags[0], "at least one live rule should lead the table"
    for row in rows:
        assert row["Techniques"], f"{row['Rule']}: no techniques rendered"


@pytest.mark.unit
def test_review_debt_is_empty_today_and_populated_later() -> None:
    assert view.review_due_rows(as_of=_TODAY) == []
    later = view.review_due_rows(as_of=date(2028, 1, 1))
    assert later, "records past their review interval must surface as debt"
    assert all(row["Status"] for row in later)


@pytest.mark.unit
def test_response_plan_rows_flag_irreversibility() -> None:
    from agents.response import ResponsePlanner

    plan = ResponsePlanner().plan_for_techniques(["T1078"], ["web-01"])
    rows = view.response_plan_rows(plan.to_dict())
    assert rows
    assert any(row["Reversible"] == "⚠️ NO" for row in rows), (
        "an irreversible step must be visually distinct before it is performed"
    )
    for row in rows:
        assert row["Performed by"], "every action must name its human owner"
        assert row["Rollback"]
    assert view.response_plan_rows(None) == []


@pytest.mark.unit
def test_every_status_fails_soft_and_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unavailable layer reports unavailable — never empty-and-healthy."""
    import attack
    import intel

    def _boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("simulated outage")

    monkeypatch.setattr(attack, "load_corpus", _boom)
    monkeypatch.setattr(intel, "load_store", _boom)

    corpus = view.attack_corpus_status(as_of=_TODAY)
    assert "unavailable" in corpus.detail
    assert corpus.status == "❌ unavailable"

    library = view.intel_status(as_of=_TODAY)
    assert "unavailable" in library.detail

    # The headline table still renders every row rather than raising.
    rows = view.layer_rows(as_of=_TODAY)
    assert len(rows) == 6


@pytest.mark.unit
def test_views_are_deterministic_in_as_of() -> None:
    assert view.layer_rows(as_of=_TODAY) == view.layer_rows(as_of=_TODAY)
    assert view.behavior_rows() == view.behavior_rows()


@pytest.mark.unit
def test_ingest_status_reports_domain_coverage_not_parser_count() -> None:
    """A defender needs to know which domains are blind, not how much code exists."""
    status = view.ingest_status()
    assert "5/5 domains" in status.detail
    for domain in ("endpoint", "network", "cloud", "identity", "email"):
        assert domain in status.detail
    assert "never guessed" in status.detail
