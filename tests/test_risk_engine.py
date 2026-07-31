"""Contracts for the deterministic RBA risk engine."""

from __future__ import annotations

import pytest
from agents.risk_engine import (
    RiskContribution,
    RiskEngine,
    contributions_from_analyses,
)


@pytest.mark.unit
def test_single_low_event_does_not_cross_threshold() -> None:
    engine = RiskEngine(threshold=90)
    findings = engine.score([RiskContribution("10.0.0.5", "firewall block", 20)])
    assert findings == []


@pytest.mark.unit
def test_accumulated_events_cross_threshold() -> None:
    # Three mediums (45 each) on one entity exceed 90 even at weight < 1.
    engine = RiskEngine(threshold=90)
    contribs = [RiskContribution("10.0.0.5", "ids alert", 45) for _ in range(3)]
    findings = engine.score(contribs)
    assert len(findings) == 1
    assert findings[0].entity == "10.0.0.5"
    assert findings[0].contribution_count == 3
    assert findings[0].total_score >= 90


@pytest.mark.unit
def test_entities_are_scored_independently() -> None:
    engine = RiskEngine(threshold=90)
    contribs = [
        RiskContribution("10.0.0.5", "authentication failure", 70),
        RiskContribution("10.0.0.5", "successful login", 70),  # crosses
        RiskContribution("10.0.0.9", "firewall block", 20),  # does not
    ]
    findings = engine.score(contribs)
    assert [f.entity for f in findings] == ["10.0.0.5"]


@pytest.mark.unit
def test_weights_amplify_high_value_event_types() -> None:
    # log tampering (weight 1.5) reaches threshold faster than firewall block.
    engine = RiskEngine(threshold=90)
    tamper = engine.score([RiskContribution("h1", "log tampering", 70)] * 1)
    # 70 * 1.5 = 105 >= 90 from a single event
    assert len(tamper) == 1
    block = engine.score([RiskContribution("h2", "firewall block", 70)] * 1)
    # 70 * 0.6 = 42 < 90
    assert block == []


@pytest.mark.unit
def test_window_excludes_stale_contributions() -> None:
    engine = RiskEngine(threshold=90, window_seconds=600)
    contribs = [
        RiskContribution("10.0.0.5", "ids alert", 70, timestamp=0.0),  # stale
        RiskContribution("10.0.0.5", "ids alert", 70, timestamp=1000.0),  # anchor
    ]
    # Only the anchor is inside a 600s window ending at t=1000 → 70*0.7=49 < 90.
    assert engine.score(contribs) == []


@pytest.mark.unit
def test_findings_sorted_most_risky_first() -> None:
    engine = RiskEngine(threshold=50)
    contribs = [
        RiskContribution("low", "ids alert", 80),  # 56
        RiskContribution("high", "log tampering", 90),  # 135
    ]
    findings = engine.score(contribs)
    assert [f.entity for f in findings] == ["high", "low"]


@pytest.mark.unit
def test_dominant_event_type_is_reported() -> None:
    engine = RiskEngine(threshold=50)
    contribs = [
        RiskContribution("h1", "firewall block", 20),
        RiskContribution("h1", "log tampering", 80),
    ]
    finding = engine.score(contribs)[0]
    assert finding.dominant_event_type == "log tampering"


@pytest.mark.unit
def test_explainability_contributions_present() -> None:
    engine = RiskEngine(threshold=50)
    finding = engine.score([RiskContribution("h1", "log tampering", 90, detail="history -c")])[0]
    assert finding.contributions[0]["detail"] == "history -c"
    assert finding.contributions[0]["weighted_score"] == pytest.approx(135.0)


@pytest.mark.unit
@pytest.mark.parametrize(
    "bad",
    [
        [RiskContribution("", "ids alert", 10)],
        [RiskContribution("h1", "ids alert", -5)],
        ["not-a-contribution"],
    ],
)
def test_fail_closed_on_malformed_input(bad: object) -> None:
    with pytest.raises(ValueError):
        RiskEngine().score(bad)  # type: ignore[arg-type]


@pytest.mark.unit
@pytest.mark.parametrize("bad_kw", [{"threshold": 0}, {"window_seconds": -1}])
def test_fail_closed_on_bad_config(bad_kw: dict) -> None:
    with pytest.raises(ValueError):
        RiskEngine(**bad_kw)


@pytest.mark.unit
def test_contributions_from_soc_analyses() -> None:
    analyses = [
        {"event_type": "log tampering", "severity_score": 70, "source": "10.0.0.5"},
        {"event_type": "port scan", "severity_score": 45, "indicators": ["10.0.0.9"]},
        {"event_type": "unknown security event", "severity_score": 0},
    ]
    contribs = contributions_from_analyses(analyses)
    assert contribs[0].entity == "10.0.0.5"
    assert contribs[1].entity == "10.0.0.9"  # fell back to first indicator
    assert contribs[2].entity == "unknown"  # no source, no indicators
    assert contribs[0].score == 70


@pytest.mark.unit
def test_determinism_same_input_same_output() -> None:
    engine = RiskEngine(threshold=50)
    contribs = [
        RiskContribution("h1", "log tampering", 80),
        RiskContribution("h2", "ids alert", 90),
    ]
    assert engine.score_as_dicts(contribs) == engine.score_as_dicts(contribs)
