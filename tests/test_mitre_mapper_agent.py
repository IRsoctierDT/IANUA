from agents.mitre_mapper_agent import MitreMapperAgent


def test_authentication_failure_maps_to_brute_force():
    mapper = MitreMapperAgent()
    result = mapper.map_event(
        "authentication failure",
        "Failed password for root from 10.0.0.5 port 22 ssh2",
    )

    assert result["technique_id"] == "T1110"
    assert result["technique"] == "Brute Force"
    assert result["confidence"] == "medium"


def test_accepted_ssh_maps_to_valid_accounts():
    mapper = MitreMapperAgent()
    result = mapper.map_event(
        "login event",
        "Accepted password for ivan from 192.168.1.25 port 22 ssh2",
    )

    assert result["technique_id"] == "T1078"
    assert result["technique"] == "Valid Accounts"


def test_unknown_event_returns_unknown_mapping():
    mapper = MitreMapperAgent()
    result = mapper.map_event("unknown security event", "unclassified log")

    assert result["technique_id"] == "UNKNOWN"
    assert result["confidence"] == "low"


def test_arp_spoofing_maps_to_t1557():
    result = MitreMapperAgent().map_event("arp spoofing", "arp: 10.0.0.1 moved from a to b")
    assert result["technique_id"] == "T1557"
    assert result["tactic"] == "Credential Access"
    investigation = " ".join(result["recommended_investigation"]).lower()
    # The mapping must prompt the analyst to rule out benign rebinding first.
    assert "dhcp" in investigation
