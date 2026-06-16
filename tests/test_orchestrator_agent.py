from pathlib import Path

import pytest
from agents.orchestrator_agent import OrchestratorAgent


@pytest.mark.unit
def test_process_log_returns_all_keys() -> None:
    agent = OrchestratorAgent()
    result = agent.process_log("Failed password for root from 10.0.0.5 port 22 ssh2")
    assert "soc" in result
    assert "mitre" in result
    assert "threat_intel" in result


@pytest.mark.unit
def test_process_log_soc_event_type() -> None:
    agent = OrchestratorAgent()
    result = agent.process_log("Failed password for root from 10.0.0.5 port 22 ssh2")
    assert result["soc"]["event_type"] == "authentication failure"
    assert result["soc"]["severity"] == "high"


@pytest.mark.unit
def test_process_log_threat_intel_populated(tmp_path: Path) -> None:
    agent = OrchestratorAgent()
    result = agent.process_log("Failed password for root from 10.0.0.5 port 22 ssh2")
    assert isinstance(result["threat_intel"], list)
    assert len(result["threat_intel"]) > 0


@pytest.mark.unit
def test_process_log_no_indicators_when_no_ip() -> None:
    agent = OrchestratorAgent()
    result = agent.process_log("Suricata alert: suspicious traffic detected")
    assert result["threat_intel"] == []


@pytest.mark.unit
def test_process_log_writes_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "reports" / "markdown").mkdir(parents=True)

    agent = OrchestratorAgent()
    agent.process_log("Failed password for root from 10.0.0.5 port 22 ssh2")

    assert (tmp_path / "reports" / "markdown" / "orchestrated_incident.md").exists()
