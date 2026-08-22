"""Unit contracts for the data-driven mapping engine."""

from __future__ import annotations

import pytest
from agents.mapping import MappingEngine


@pytest.fixture(scope="module")
def engine() -> MappingEngine:
    return MappingEngine()


@pytest.mark.unit
def test_legacy_keys_and_shape_preserved(engine: MappingEngine) -> None:
    result = engine.map_as_dict("authentication failure", "Failed password for root")
    for key in (
        "event_type",
        "tactic",
        "technique",
        "technique_id",
        "confidence",
        "evidence",
        "recommended_investigation",
    ):
        assert key in result
    assert result["technique_id"] == "T1110"
    assert result["technique"] == "Brute Force"
    assert result["tactic"] == "Credential Access"
    assert isinstance(result["evidence"], list)


@pytest.mark.unit
def test_multi_technique_output_with_secondary(engine: MappingEngine) -> None:
    result = engine.map_as_dict("login event", "Accepted publickey for admin ssh2")
    ids = [t["technique_id"] for t in result["techniques"]]
    assert ids == ["T1078", "T1021.004"]
    assert result["technique_id"] == "T1078"  # primary drives the legacy scalars
    lateral = result["techniques"][1]
    assert lateral["tactic"] == "Lateral Movement"
    assert lateral["confidence"] == "low"


@pytest.mark.unit
def test_same_technique_merges_across_rules(engine: MappingEngine) -> None:
    # Both the ssh log rule and the successful-login event rule attribute
    # T1078; the merged view carries it once, first occurrence's evidence.
    result = engine.map_as_dict("successful login", "Accepted password for root ssh2")
    assert result["matched_rules"] == [
        "ssh-accepted-valid-accounts",
        "successful-login-valid-accounts",
    ]
    t1078 = [t for t in result["techniques"] if t["technique_id"] == "T1078"]
    assert len(t1078) == 1
    assert "SSH accepted-login pattern detected." in t1078[0]["evidence"]


@pytest.mark.unit
def test_names_and_tactics_come_from_the_pinned_corpus(engine: MappingEngine) -> None:
    result = engine.map_as_dict("arp spoofing", "gratuitous arp spoof detected")
    # Corpus truth, not the ladder's old compound label.
    assert result["technique"] == "Adversary-in-the-Middle"
    assert result["technique_id"] == "T1557"
    ids = [t["technique_id"] for t in result["techniques"]]
    assert "T1557.002" in ids
    tamper = engine.map_as_dict("log tampering", "history -c")
    # ATT&CK v19 split Defense Evasion; indicator removal now sits in Stealth.
    assert tamper["tactic"] == "Stealth"
    assert tamper["technique_id"] == "T1070.003"


@pytest.mark.unit
def test_attack_version_stamped(engine: MappingEngine) -> None:
    result = engine.map_as_dict("port scan", "nmap sweep")
    assert result["attack_version"] == engine.store.attack_version
    assert result["technique_id"] == "T1046"


@pytest.mark.unit
def test_sentinel_and_fallback_have_empty_attributions(engine: MappingEngine) -> None:
    sentinel = engine.map_as_dict("ids alert", "Suricata alert: policy violation")
    assert sentinel["technique_id"] == "UNKNOWN"
    assert sentinel["tactic"] == "Detection-dependent"
    assert sentinel["techniques"] == []
    fallback = engine.map_as_dict("unknown security event", "unclassified")
    assert fallback["technique_id"] == "UNKNOWN"
    assert fallback["tactic"] == "Unknown"
    assert fallback["matched_rules"] == []


@pytest.mark.unit
def test_input_validation_fail_closed(engine: MappingEngine) -> None:
    with pytest.raises(ValueError):
        engine.map_as_dict("", "log")
    with pytest.raises(ValueError):
        engine.map_as_dict("   ", "log")
    with pytest.raises(ValueError):
        engine.map_as_dict("event", None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        engine.map_as_dict(42, "log")  # type: ignore[arg-type]


@pytest.mark.unit
def test_matching_is_case_insensitive(engine: MappingEngine) -> None:
    upper = engine.map_as_dict("AUTHENTICATION FAILURE", "FAILED PASSWORD")
    assert upper["technique_id"] == "T1110"
