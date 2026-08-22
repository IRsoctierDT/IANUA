"""The Detection Matcher surfaces behavioral coverage alongside Sigma coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from agents.detection_matcher_agent import DetectionMatcherAgent
from agents.mitre_mapper_agent import MitreMapperAgent


@pytest.fixture(scope="module")
def matcher() -> DetectionMatcherAgent:
    return DetectionMatcherAgent()


@pytest.mark.unit
def test_matches_behavioral_rules_by_technique(matcher: DetectionMatcherAgent) -> None:
    matches = matcher.match_behaviors_for_technique("T1685")
    assert matches, "T1685 must have behavioral coverage"
    names = {m["file"] for m in matches}
    assert "auditd_stopped.yml" in names
    # Most severe first.
    levels = [m["level"] for m in matches]
    assert levels == sorted(levels, key=lambda level: {"critical": 0, "high": 1}.get(level, 9))


@pytest.mark.unit
def test_validation_marker_is_reported(matcher: DetectionMatcherAgent) -> None:
    matches = matcher.match_behaviors_for_technique("T1685")
    by_file = {m["file"]: m for m in matches}
    assert by_file["auditd_stopped.yml"]["validation"] == "telemetry-available"
    assert by_file["security_tool_tamper_command.yml"]["validation"] == "telemetry-required"


@pytest.mark.unit
def test_unknown_and_malformed_techniques_yield_nothing(
    matcher: DetectionMatcherAgent,
) -> None:
    assert matcher.match_behaviors_for_technique("UNKNOWN") == []
    assert matcher.match_behaviors_for_technique("") == []
    assert matcher.match_behaviors_for_technique("T9999") == []


@pytest.mark.unit
def test_event_matching_spans_every_attributed_technique(
    matcher: DetectionMatcherAgent,
) -> None:
    # The audit-daemon log attributes T1070.003 (primary) and T1685
    # (secondary); behavioral coverage must follow the secondary attribution,
    # which a legacy technique_id-only lookup would miss entirely.
    mapping = MitreMapperAgent().map_event("log tampering", "auditd: the audit daemon is stopped")
    assert [t["technique_id"] for t in mapping["techniques"]] == ["T1070.003", "T1685"]
    matches = matcher.match_behaviors_for_event(mapping)
    assert {m["file"] for m in matches} >= {"auditd_stopped.yml"}


@pytest.mark.unit
def test_event_matching_falls_back_to_legacy_scalar(
    matcher: DetectionMatcherAgent,
) -> None:
    matches = matcher.match_behaviors_for_event({"technique_id": "T1685"})
    assert matches, "legacy-shaped mapping results must still resolve coverage"


@pytest.mark.unit
def test_deduplicates_across_techniques(matcher: DetectionMatcherAgent) -> None:
    mapping = {
        "techniques": [
            {"technique_id": "T1685"},
            {"technique_id": "T1685"},
        ]
    }
    matches = matcher.match_behaviors_for_event(mapping)
    ids = [m["rule_id"] for m in matches]
    assert len(ids) == len(set(ids))


@pytest.mark.unit
def test_missing_or_corrupt_index_fails_soft(tmp_path: Path) -> None:
    absent = DetectionMatcherAgent(behavior_index=tmp_path / "nope.json")
    assert absent.match_behaviors_for_technique("T1685") == []

    corrupt_path = tmp_path / "corrupt.json"
    corrupt_path.write_text("{not json", encoding="utf-8")
    corrupt = DetectionMatcherAgent(behavior_index=corrupt_path)
    assert corrupt.match_behaviors_for_technique("T1685") == []

    wrong_shape = tmp_path / "shape.json"
    wrong_shape.write_text(json.dumps({"behaviors": "not-a-list"}), encoding="utf-8")
    assert (
        DetectionMatcherAgent(behavior_index=wrong_shape).match_behaviors_for_technique("T1685")
        == []
    )


@pytest.mark.unit
def test_index_read_needs_no_yaml(monkeypatch: pytest.MonkeyPatch) -> None:
    """Behavioral coverage must resolve with PyYAML absent (runtime posture)."""
    import agents.detection_matcher_agent as module

    monkeypatch.setattr(module, "yaml", None)
    assert module.DetectionMatcherAgent().match_behaviors_for_technique("T1685")
