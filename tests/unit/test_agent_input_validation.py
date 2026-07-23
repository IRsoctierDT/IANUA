"""Input-validation contracts for agents that consume untrusted text.

Every agent validates its own inputs (AGENTS.md §4): malformed input raises
``ValueError`` before any work — never a raw ``AttributeError`` from an
untyped boundary.
"""

from __future__ import annotations

import pytest
from agents.incident_report_agent import IncidentReportAgent
from agents.mitre_mapper_agent import MitreMapperAgent


class TestMitreMapperValidation:
    def test_non_string_event_type_raises(self) -> None:
        with pytest.raises(ValueError, match="event_type"):
            MitreMapperAgent().map_event(None)  # type: ignore[arg-type]

    def test_empty_event_type_raises(self) -> None:
        with pytest.raises(ValueError, match="event_type"):
            MitreMapperAgent().map_event("   ")

    def test_non_string_log_text_raises(self) -> None:
        with pytest.raises(ValueError, match="log_text"):
            MitreMapperAgent().map_event("authentication failure", log_text=123)  # type: ignore[arg-type]

    def test_valid_input_still_maps(self) -> None:
        result = MitreMapperAgent().map_event(
            "authentication failure", "Failed password for root from 10.0.0.5"
        )
        assert result["technique_id"] == "T1110"


class TestIncidentReportValidation:
    def test_non_string_log_text_raises(self, tmp_path: object) -> None:
        with pytest.raises(ValueError, match="log_text"):
            IncidentReportAgent().generate_report(None, "out.md")  # type: ignore[arg-type]

    def test_empty_output_path_raises(self) -> None:
        with pytest.raises(ValueError, match="output_path"):
            IncidentReportAgent().generate_report("Failed password for root", "  ")
