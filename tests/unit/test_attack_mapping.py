"""Unit tests for the containment capabilities' MITRE ATT&CK mapping catalog."""

from __future__ import annotations

import json
import re

import pytest
from agents.tools import attack_mapping
from agents.tools.containment import ContainmentToolkit

_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_MITIGATION_ID = re.compile(r"^M\d{4}$")

#: Every public capability the toolkit exposes, primary and rollback alike.
_TOOLKIT_CAPABILITIES = (
    "quarantine_file",
    "release_file",
    "stop_process",
    "resume_process",
    "isolate_host",
    "restore_host",
    "block_indicator",
    "unblock_indicator",
    "disable_account",
    "enable_account",
)


@pytest.mark.unit
def test_every_mapping_is_complete_and_well_formed() -> None:
    mappings = attack_mapping.all_mappings()
    assert mappings, "catalog must not be empty"
    for mapping in mappings:
        assert mapping.action_class == "containment"
        assert mapping.description.strip(), f"{mapping.capability}: empty description"
        assert mapping.counters, f"{mapping.capability}: no techniques countered"
        for technique in mapping.counters:
            assert _TECHNIQUE_ID.fullmatch(technique.technique_id), technique.technique_id
            assert technique.name.strip()
            assert technique.tactic.strip()
            assert technique.description.strip(), f"{technique.technique_id}: no description"
            assert technique.url.startswith("https://attack.mitre.org/techniques/")
        assert _MITIGATION_ID.fullmatch(mapping.mitigation.mitigation_id)
        assert mapping.mitigation.description.strip()


@pytest.mark.unit
def test_every_toolkit_capability_has_a_mapping() -> None:
    """The 'tools portion' contract: no containment capability without ATT&CK context."""
    for capability in _TOOLKIT_CAPABILITIES:
        assert hasattr(ContainmentToolkit, capability), f"toolkit lacks {capability}"
        mapping = attack_mapping.get_mapping(capability)
        assert mapping.technique_ids(), capability


@pytest.mark.unit
def test_rollbacks_and_variants_share_their_primary_mapping() -> None:
    assert attack_mapping.get_mapping("release_file") is attack_mapping.get_mapping(
        "quarantine_file"
    )
    assert attack_mapping.get_mapping("resume_process") is attack_mapping.get_mapping(
        "stop_process"
    )
    assert attack_mapping.get_mapping("stop_process_force") is attack_mapping.get_mapping(
        "stop_process"
    )


@pytest.mark.unit
def test_t1098_lists_both_tactics() -> None:
    """ATT&CK v16 files Account Manipulation under Persistence AND Privilege Escalation."""
    mapping = attack_mapping.get_mapping("disable_account")
    t1098 = next(t for t in mapping.counters if t.technique_id == "T1098")
    assert "Persistence" in t1098.tactic
    assert "Privilege Escalation" in t1098.tactic


@pytest.mark.unit
def test_unknown_capability_fails_closed() -> None:
    with pytest.raises(ValueError, match="unknown containment capability"):
        attack_mapping.get_mapping("summon_airstrike")


@pytest.mark.unit
def test_ransomware_and_extortion_coverage() -> None:
    """The catalog must counter the techniques this control exists for."""
    covered = {t.technique_id for m in attack_mapping.all_mappings() for t in m.counters}
    for expected in ("T1486", "T1490", "T1657", "T1078", "T1071"):
        assert expected in covered, f"{expected} missing from containment coverage"


@pytest.mark.unit
def test_attack_coverage_is_json_serializable() -> None:
    coverage = attack_mapping.attack_coverage()
    payload = json.loads(json.dumps(coverage))
    assert payload["domain"] == "enterprise-attack"
    assert payload["attack_version"] == "16"
    capabilities = {c["capability"] for c in payload["capabilities"]}
    assert "quarantine_file" in capabilities
    for entry in payload["capabilities"]:
        assert entry["mitigation"]["url"].startswith("https://attack.mitre.org/mitigations/")


@pytest.mark.unit
def test_toolkit_exposes_the_coverage() -> None:
    assert ContainmentToolkit.attack_coverage() == attack_mapping.attack_coverage()
