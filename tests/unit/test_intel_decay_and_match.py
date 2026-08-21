"""Unit contracts: decay arithmetic, corroboration, behavioral aging, agent enrichment."""

from __future__ import annotations

from datetime import date

import pytest
from attack import load_corpus
from intel import (
    HALF_LIFE_DAYS,
    decayed_score,
    default_as_of,
    load_store,
    lookup_indicator,
    match_behaviors,
    score_to_confidence,
)
from intel.model import AtomicIndicator


def _indicator(**overrides: object) -> AtomicIndicator:
    base: dict = {
        "indicator_type": "ipv4",
        "value": "203.0.113.10",
        "risk": "malicious",
        "confidence": "high",
        "source_id": "synthetic-feed-alpha",
        "first_seen": "2026-01-01",
        "retrieved": "2026-01-01",
        "expires": "2027-01-01",
        "tlp": "clear",
        "reference": "https://feed-alpha.example/x",
    }
    base.update(overrides)
    return AtomicIndicator(**base)


@pytest.mark.unit
def test_decay_halves_at_half_life() -> None:
    indicator = _indicator()
    day_zero = decayed_score(indicator, as_of=date(2026, 1, 1))
    half_life = HALF_LIFE_DAYS["ipv4"]
    later = decayed_score(indicator, as_of=date(2026, 1, 31))  # 30 days = ipv4 half-life
    assert day_zero == 1.0
    assert later == pytest.approx(0.5, abs=0.01)
    assert half_life == 30.0


@pytest.mark.unit
def test_expiry_is_a_hard_zero_and_future_retrieval_scores_zero() -> None:
    indicator = _indicator(expires="2026-02-01")
    assert decayed_score(indicator, as_of=date(2026, 2, 2)) == 0.0
    assert decayed_score(_indicator(retrieved="2026-06-01"), as_of=date(2026, 1, 1)) == 0.0


@pytest.mark.unit
def test_hash_decays_slower_than_url() -> None:
    on = date(2026, 3, 1)
    url = _indicator(indicator_type="url", value="https://c2.invalid/x")
    sha = _indicator(indicator_type="sha256", value="ab" * 32)
    assert decayed_score(sha, as_of=on) > decayed_score(url, as_of=on)


@pytest.mark.unit
def test_score_to_confidence_bands() -> None:
    assert score_to_confidence(0.9) == "high"
    assert score_to_confidence(0.5) == "medium"
    assert score_to_confidence(0.2) == "low"
    assert score_to_confidence(0.1) == "none"


@pytest.mark.unit
def test_corroborated_verdict_and_single_source_cap() -> None:
    store = load_store()
    as_of = date(2026, 8, 21)
    corroborated = lookup_indicator(store, "203.0.113.66", as_of=as_of)
    assert corroborated.risk == "malicious" and len(corroborated.sources) == 2
    single = lookup_indicator(store, "198.51.100.77", as_of=as_of)
    assert single.risk == "suspicious" and "capped" in single.notes[0]


@pytest.mark.unit
def test_lookup_is_deterministic_in_as_of() -> None:
    store = load_store()
    a = lookup_indicator(store, "203.0.113.66", as_of=date(2026, 8, 21))
    b = lookup_indicator(store, "203.0.113.66", as_of=date(2026, 8, 21))
    assert a == b
    far = lookup_indicator(store, "203.0.113.66", as_of=date(2027, 8, 21))
    assert far.risk == "expired"


@pytest.mark.unit
def test_default_as_of_is_store_derived_not_clock() -> None:
    store = load_store()
    assert default_as_of(store) == date(2026, 8, 21)  # newest committed retrieval


@pytest.mark.unit
def test_behavior_review_due_after_interval() -> None:
    store = load_store()
    corpus = load_corpus()
    fresh = match_behaviors(store, "authentication failure", corpus, as_of=date(2026, 9, 1))
    assert fresh and fresh[0].status == "active"
    overdue = match_behaviors(store, "authentication failure", corpus, as_of=date(2028, 1, 1))
    assert overdue and overdue[0].status == "review-due"


@pytest.mark.unit
def test_agent_enrichment_and_reserved_scopes() -> None:
    from agents.threat_intel_agent import ThreatIntelAgent

    agent = ThreatIntelAgent()
    hit = agent.analyze_indicator("203.0.113.66", as_of=date(2026, 8, 21))
    assert hit["risk_level"] == "malicious" and hit["intel"]["matched"]
    metadata = agent.analyze_indicator("169.254.169.254")
    assert metadata["indicator_type"] == "link_local_ip"
    assert "SSRF" in " ".join(metadata["recommended_actions"])
    loopback = agent.analyze_indicator("127.0.0.1")
    assert loopback["indicator_type"] == "loopback_ip"
    cgnat = agent.analyze_indicator("100.64.0.1")
    assert cgnat["indicator_type"] == "private_ip"
    malformed = agent.analyze_indicator("01.02.03.04")
    assert malformed["indicator_type"] != "public_ip"


@pytest.mark.unit
def test_agent_fails_soft_without_store() -> None:
    from agents.threat_intel_agent import ThreatIntelAgent

    agent = ThreatIntelAgent()
    agent._store = None  # simulate unavailable library
    result = agent.analyze_indicator("8.8.8.8")
    assert result["indicator_type"] == "public_ip"
    assert result["intel"] == {"available": False, "note": "local intel library unavailable"}
