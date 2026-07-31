"""End-to-end contracts for the widened detection + KB coverage.

Pins the four event types added to close the classifier<->Sigma gap
(log tampering, privileged group addition, account creation, port scan):
classification, severity, MITRE mapping, and Sigma-rule matching — plus the
retrievability of the new cited knowledge-base entries.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from agents.detection_matcher_agent import DetectionMatcherAgent
from agents.mitre_mapper_agent import MitreMapperAgent
from agents.soc_analyst_agent import SocAnalystAgent

_CASES = [
    # (log line, expected event type, expected severity, expected technique)
    (
        "root: history -c executed; .bash_history removed",
        "log tampering",
        "high",
        "T1070.003",
    ),
    (
        "usermod: added user 'svc-backup' to group 'sudo'",
        "privileged group addition",
        "high",
        "T1098",
    ),
    (
        "useradd: new user: name=svc-backup, UID=1007, home=/home/svc-backup",
        "account creation",
        "medium",
        "T1136.001",
    ),
    (
        "Suricata alert: ET SCAN nmap TCP port scan from 203.0.113.7",
        "port scan",
        "medium",
        "T1046",
    ),
]


@pytest.mark.unit
@pytest.mark.parametrize(("log", "event_type", "severity", "technique"), _CASES)
def test_new_event_types_classify_and_map(
    log: str, event_type: str, severity: str, technique: str
) -> None:
    soc = SocAnalystAgent().analyze_log(log)
    assert soc["event_type"] == event_type
    assert soc["severity"] == severity
    mitre = MitreMapperAgent().map_event(soc["event_type"], log)
    assert mitre["technique_id"] == technique


@pytest.mark.unit
@pytest.mark.parametrize(("log", "event_type", "severity", "technique"), _CASES)
def test_new_techniques_match_shipped_sigma_rules(
    log: str, event_type: str, severity: str, technique: str
) -> None:
    # Every new technique must land on at least one shipped Sigma rule —
    # the classifier<->detection-content gap this widening closes.
    matches = DetectionMatcherAgent().match_for_technique(technique)
    assert matches, f"no Sigma rule tagged for {technique}"


@pytest.mark.unit
def test_specific_types_win_over_generic_ids_alert() -> None:
    # An IDS alert *about* a scan gets the specific classification (same
    # precedence rationale as ARP spoofing before the generic alert rule).
    result = SocAnalystAgent().analyze_log("IDS alert: portscan detected from 198.51.100.9")
    assert result["event_type"] == "port scan"


@pytest.mark.unit
def test_benign_auditd_start_is_not_tampering() -> None:
    # auditd lifecycle noise must not classify as evidence destruction.
    result = SocAnalystAgent().analyze_log("auditd[812]: service started successfully")
    assert result["event_type"] != "log tampering"


_KB_ROOT = Path(__file__).resolve().parents[2] / "knowledge-base"
_NEW_KB_ENTRIES = [
    "nist/incident_response_800_61.md",
    "nist/log_management_800_92.md",
    "mitre/persistence_account_creation.md",
    "mitre/defense_evasion_indicator_removal.md",
    "mitre/discovery_network_service.md",
    "owasp/logging_monitoring_failures_a09.md",
    "cis/control_8_audit_log_management.md",
]


@pytest.mark.unit
@pytest.mark.parametrize("rel_path", _NEW_KB_ENTRIES)
def test_new_kb_entries_cite_an_authoritative_source(rel_path: str) -> None:
    # Every KB entry must carry a resolvable citation to its primary source
    # (NOTICE provenance contract: original summaries, sources cited).
    text = (_KB_ROOT / rel_path).read_text(encoding="utf-8")
    assert "Authoritative source" in text
    assert "https://" in text
    assert "original summary" in text
