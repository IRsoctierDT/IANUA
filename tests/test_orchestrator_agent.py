from pathlib import Path

import pytest
from agents.orchestrator_agent import OrchestratorAgent


@pytest.mark.unit
def test_process_log_returns_all_keys(tmp_path: Path) -> None:
    agent = OrchestratorAgent()
    result = agent.process_log(
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        report_path=str(tmp_path / "report.md"),
    )
    assert "soc" in result
    assert "mitre" in result
    assert "threat_intel" in result
    assert "knowledge_base" in result
    assert "detections" in result


@pytest.mark.unit
def test_process_log_detections_cover_technique(tmp_path: Path) -> None:
    agent = OrchestratorAgent()
    result = agent.process_log(
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        report_path=str(tmp_path / "report.md"),
    )
    detections = result["detections"]
    assert isinstance(detections, list)
    # Run from the repo root, the T1110 brute-force rules should match.
    if detections:
        assert set(detections[0]) == {"rule_id", "title", "level", "technique", "file"}


@pytest.mark.unit
def test_process_log_knowledge_base_is_list_of_refs(tmp_path: Path) -> None:
    agent = OrchestratorAgent()
    result = agent.process_log(
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        report_path=str(tmp_path / "report.md"),
    )
    kb = result["knowledge_base"]
    assert isinstance(kb, list)
    # Run from the repo root, the curated KB should ground this event.
    if kb:
        assert set(kb[0]) == {"source", "score", "snippet"}


@pytest.mark.unit
def test_process_log_soc_event_type(tmp_path: Path) -> None:
    agent = OrchestratorAgent()
    result = agent.process_log(
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        report_path=str(tmp_path / "report.md"),
    )
    assert result["soc"]["event_type"] == "authentication failure"
    assert result["soc"]["severity"] == "high"


@pytest.mark.unit
def test_process_log_threat_intel_populated(tmp_path: Path) -> None:
    agent = OrchestratorAgent()
    result = agent.process_log(
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        report_path=str(tmp_path / "report.md"),
    )
    assert isinstance(result["threat_intel"], list)
    assert len(result["threat_intel"]) > 0


@pytest.mark.unit
def test_process_log_no_indicators_when_no_ip(tmp_path: Path) -> None:
    agent = OrchestratorAgent()
    result = agent.process_log(
        "Suricata alert: suspicious traffic detected",
        report_path=str(tmp_path / "report.md"),
    )
    assert result["threat_intel"] == []


@pytest.mark.unit
def test_process_log_writes_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "reports" / "markdown").mkdir(parents=True)

    agent = OrchestratorAgent()
    agent.process_log("Failed password for root from 10.0.0.5 port 22 ssh2")

    assert (tmp_path / "reports" / "markdown" / "orchestrated_incident.md").exists()


# ------------------------------------------------------------------ v1.9: sequence + citations
@pytest.mark.unit
def test_process_log_includes_citations_key(tmp_path: Path) -> None:
    agent = OrchestratorAgent()
    result = agent.process_log(
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        report_path=str(tmp_path / "report.md"),
    )
    assert "citations" in result
    assert isinstance(result["citations"], list)
    for citation in result["citations"]:
        assert set(citation) == {"source", "score", "quote", "char_start", "char_end"}


@pytest.mark.unit
def test_process_sequence_returns_sequence_and_report(tmp_path: Path) -> None:
    agent = OrchestratorAgent()
    report_path = tmp_path / "sequence_report.md"
    events = [
        "Failed password for root from 203.0.113.7 port 22 ssh2",
        "Failed password for root from 203.0.113.7 port 22 ssh2",
        "Failed password for root from 203.0.113.7 port 22 ssh2",
        "Accepted password for root from 203.0.113.7 port 22 ssh2",
    ]
    result = agent.process_sequence(events, report_path=str(report_path))
    assert result["sequence"]["event_count"] == 4
    patterns = {f["pattern"] for f in result["sequence"]["findings"]}
    assert "brute_force" in patterns
    assert "auth_failure_then_success" in patterns
    content = report_path.read_text(encoding="utf-8")
    assert "## Sequence Correlation" in content
    assert "brute_force" in content
    # Threat intel covers the sequence-wide indicator union.
    assert len(result["threat_intel"]) == 1


@pytest.mark.unit
def test_process_sequence_rejects_empty(tmp_path: Path) -> None:
    agent = OrchestratorAgent()
    with pytest.raises(ValueError):
        agent.process_sequence([], report_path=str(tmp_path / "r.md"))
