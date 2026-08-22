"""Pinned expected outputs for every ladder-era branch, plus the deliberate changes.

The legacy scalar SHAPE is frozen; three string values changed deliberately
when names/tactics started coming from the pinned corpus instead of
hardcoded literals (recorded in DESIGN.md §11 2026-08-21):
* T1557's technique reads "Adversary-in-the-Middle" (the old compound label
  belonged to T1557.002),
* T1070.003's tactic reads "Stealth" (ATT&CK v19 split Defense Evasion),
* T1070.003's technique reads "Clear Command History" (corpus name).
The empty-attribution paths (review sentinel, fallback) are tested FIRST —
they are the ones a naive ``techniques[0]`` projection breaks on.
"""

from __future__ import annotations

import pytest
from agents.mitre_mapper_agent import MitreMapperAgent

_LEGACY_KEYS = {
    "event_type",
    "tactic",
    "technique",
    "technique_id",
    "confidence",
    "evidence",
    "recommended_investigation",
}

_CASES = [
    # (event_type, log_text, tactic, technique, technique_id, confidence)
    (
        "ids alert",
        "Suricata alert",
        "Detection-dependent",
        "Requires analyst review",
        "UNKNOWN",
        "low",
    ),
    ("unknown security event", "unclassified log", "Unknown", "Unknown", "UNKNOWN", "low"),
    (
        "authentication failure",
        "Failed password for root",
        "Credential Access",
        "Brute Force",
        "T1110",
        "medium",
    ),
    (
        "login event",
        "Accepted password ssh2",
        "Initial Access",
        "Valid Accounts",
        "T1078",
        "medium",
    ),
    (
        "arp spoofing",
        "arp moved from a to b",
        "Credential Access",
        "Adversary-in-the-Middle",
        "T1557",
        "medium",
    ),
    ("log tampering", "history -c", "Stealth", "Clear Command History", "T1070.003", "medium"),
    (
        "privileged group addition",
        "usermod added to sudo",
        "Privilege Escalation",
        "Account Manipulation",
        "T1098",
        "medium",
    ),
    ("account creation", "useradd new user", "Persistence", "Local Account", "T1136.001", "medium"),
    (
        "port scan",
        "nmap scan detected",
        "Discovery",
        "Network Service Discovery",
        "T1046",
        "medium",
    ),
]


@pytest.mark.unit
@pytest.mark.parametrize(
    ("event_type", "log_text", "tactic", "technique", "technique_id", "confidence"),
    _CASES,
    ids=[case[0] for case in _CASES],
)
def test_legacy_projection(
    event_type: str,
    log_text: str,
    tactic: str,
    technique: str,
    technique_id: str,
    confidence: str,
) -> None:
    result = MitreMapperAgent().map_event(event_type, log_text)
    assert set(result) >= _LEGACY_KEYS
    assert result["event_type"] == event_type
    assert result["tactic"] == tactic
    assert result["technique"] == technique
    assert result["technique_id"] == technique_id
    assert result["confidence"] == confidence
    assert result["evidence"] and result["recommended_investigation"]


@pytest.mark.unit
def test_dhcp_rule_out_survives_the_migration() -> None:
    # The ARP mapping must still prompt ruling out benign rebinding first.
    result = MitreMapperAgent().map_event("arp spoofing", "arp moved from a to b")
    investigation = " ".join(result["recommended_investigation"]).lower()
    assert "dhcp" in investigation
