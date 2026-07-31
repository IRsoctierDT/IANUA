"""Contracts for OCSF normalization and deterministic source labeling."""

from __future__ import annotations

import json
import typing

import pytest
from agents.orchestrator_agent import OrchestratorAgent
from agents.soc_analyst_agent import SocAnalystAgent
from agents.tools.ocsf import OCSF_SCHEMA_VERSION, classify, normalize
from agents.tools.scanner_labels import (
    canary_source,
    is_canary_event,
    is_darknet_destination,
    label_source,
)


class TestOcsf:
    @pytest.mark.unit
    @pytest.mark.parametrize(
        ("event_type", "class_uid", "class_name"),
        [
            ("authentication failure", 3002, "Authentication"),
            ("successful login", 3002, "Authentication"),
            ("account creation", 3001, "Account Change"),
            ("privileged group addition", 3001, "Account Change"),
            ("port scan", 4001, "Network Activity"),
            ("firewall block", 4001, "Network Activity"),
            ("arp spoofing", 4001, "Network Activity"),
            ("ids alert", 2004, "Detection Finding"),
            ("log tampering", 1008, "File System Activity"),
        ],
    )
    def test_known_event_types_map(self, event_type: str, class_uid: int, class_name: str) -> None:
        ocsf = classify(event_type)
        assert ocsf.class_uid == class_uid
        assert ocsf.class_name == class_name

    @pytest.mark.unit
    def test_unmapped_type_fails_closed_to_base_event(self) -> None:
        descriptor = normalize("some future event type")
        assert descriptor["class_uid"] == 0
        assert descriptor["mapped"] is False

    @pytest.mark.unit
    def test_descriptor_carries_schema_version(self) -> None:
        assert normalize("port scan")["schema_version"] == OCSF_SCHEMA_VERSION

    @pytest.mark.unit
    def test_soc_result_carries_ocsf(self) -> None:
        result = SocAnalystAgent().analyze_log("Failed password for root from 10.0.0.5")
        assert result["ocsf"]["class_uid"] == 3002
        assert result["ocsf"]["mapped"] is True


class TestScannerLabels:
    @pytest.mark.unit
    def test_benign_scanner_range(self) -> None:
        labeled = label_source("192.0.2.3")  # inside the bundled /29 example
        assert labeled["label"] == "benign-scanner"

    @pytest.mark.unit
    def test_unknown_source(self) -> None:
        assert label_source("198.51.100.77")["label"] == "unknown"

    @pytest.mark.unit
    def test_canary_hit_outranks_benign_range(self) -> None:
        labeled = label_source("192.0.2.3", canary_hit=True)
        assert labeled["label"] == "malicious"
        assert "canary" in labeled["rule"]

    @pytest.mark.unit
    def test_darknet_destination_is_suspicious(self) -> None:
        labeled = label_source("198.51.100.77", darknet_destination=True)
        assert labeled["label"] == "suspicious"

    @pytest.mark.unit
    def test_darknet_membership(self) -> None:
        assert is_darknet_destination("203.0.113.230")  # inside the bundled /27
        assert not is_darknet_destination("203.0.113.10")
        assert not is_darknet_destination("not-an-ip")

    @pytest.mark.unit
    def test_fail_closed_on_empty_source(self) -> None:
        with pytest.raises(ValueError):
            label_source("   ")

    @pytest.mark.unit
    def test_every_label_is_explainable(self) -> None:
        assert label_source("198.51.100.77")["rule"]


class TestCanaryEvents:
    _EVENT: typing.ClassVar[dict] = {
        "logtype": 4002,
        "src_host": "198.51.100.9",
        "dst_host": "10.0.0.250",
    }

    @pytest.mark.unit
    def test_dict_and_json_forms_recognized(self) -> None:
        import json

        assert is_canary_event(self._EVENT)
        assert is_canary_event(json.dumps(self._EVENT))
        assert canary_source(self._EVENT) == "198.51.100.9"

    @pytest.mark.unit
    def test_ordinary_logs_are_not_canary_events(self) -> None:
        assert not is_canary_event("Failed password for root from 10.0.0.5")
        assert not is_canary_event('{"message": "plain structured log"}')
        assert not is_canary_event("{broken json")
        assert canary_source("Failed password for root") is None


class TestOrchestratorLabeling:
    @pytest.mark.unit
    def test_sequence_result_carries_source_labels(self, tmp_path: object) -> None:
        events = ["Failed password for root from 198.51.100.9 port 22 ssh2"] * 3
        result = OrchestratorAgent().process_sequence(
            events,
            report_path=str(tmp_path / "r.md"),  # type: ignore[operator]
        )
        labels = {sl["source"]: sl["label"] for sl in result["source_labels"]}
        assert labels == {"198.51.100.9": "unknown"}

    @pytest.mark.unit
    def test_canary_event_source_is_labeled_malicious(self, tmp_path: object) -> None:
        """End-to-end wiring: a real OpenCanary-shaped event must surface as a
        malicious source label AND carry a per-event source (src_host), so it
        participates in correlation and risk scoring — the review finding was
        that intersecting differently-extracted source populations made this
        path unreachable."""
        canary_event = json.dumps(
            {
                "logtype": 4002,
                "src_host": "203.0.113.9",
                "dst_host": "10.0.0.1",
                "message": "canary ssh service login attempt",
            }
        )
        events = [
            "Failed password for root from 198.51.100.9 port 22 ssh2",
            canary_event,
        ]
        result = OrchestratorAgent().process_sequence(
            events,
            report_path=str(tmp_path / "r.md"),  # type: ignore[operator]
        )
        labels = {sl["source"]: sl for sl in result["source_labels"]}
        assert "203.0.113.9" in labels, "canary source missing from labels"
        assert labels["203.0.113.9"]["label"] == "malicious"
        assert "canary" in labels["203.0.113.9"]["rule"]
        # The canary event also carries a source at the event level now.
        canary_entries = [e for e in result["sequence"]["events"] if e["source"] == "203.0.113.9"]
        assert canary_entries, "canary event has no extracted source (src_host)"
