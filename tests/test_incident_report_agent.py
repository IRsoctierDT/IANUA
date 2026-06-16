from pathlib import Path

import pytest
from agents.incident_report_agent import IncidentReportAgent


@pytest.mark.unit
def test_generates_report_file(tmp_path: Path):
    agent = IncidentReportAgent()
    output = tmp_path / "report.md"
    result = agent.generate_report(
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        str(output),
    )
    assert result == output
    assert output.exists()


@pytest.mark.unit
def test_report_contains_severity(tmp_path: Path):
    agent = IncidentReportAgent()
    output = tmp_path / "report.md"
    agent.generate_report(
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        str(output),
    )
    content = output.read_text(encoding="utf-8")
    assert "high" in content
    assert "T1110" in content


@pytest.mark.unit
def test_creates_parent_directories(tmp_path: Path):
    agent = IncidentReportAgent()
    output = tmp_path / "nested" / "deep" / "report.md"
    agent.generate_report(
        "Failed password for invalid user admin from 192.168.1.50 port 22 ssh2",
        str(output),
    )
    assert output.exists()


@pytest.mark.unit
def test_uses_precomputed_results_not_reanalyze(tmp_path: Path):
    agent = IncidentReportAgent()
    output = tmp_path / "report.md"
    fake_soc = {
        "summary": "Custom summary",
        "severity": "critical",
        "event_type": "authentication failure",
        "indicators": ["1.2.3.4"],
        "recommended_actions": ["Act immediately"],
        "assumptions": ["No external enrichment"],
    }
    fake_mitre = {
        "tactic": "Custom Tactic",
        "technique": "Custom Technique",
        "technique_id": "T9999",
        "confidence": "high",
        "evidence": ["Custom evidence"],
        "recommended_investigation": ["Investigate X"],
    }
    agent.generate_report("ignored log", str(output), soc_result=fake_soc, mitre_result=fake_mitre)
    content = output.read_text(encoding="utf-8")
    assert "Custom summary" in content
    assert "T9999" in content
    assert "critical" in content


@pytest.mark.unit
def test_no_indicators_shows_none(tmp_path: Path):
    agent = IncidentReportAgent()
    output = tmp_path / "report.md"
    agent.generate_report(
        "Suricata alert: suspicious traffic detected",
        str(output),
    )
    content = output.read_text(encoding="utf-8")
    assert "None detected" in content
