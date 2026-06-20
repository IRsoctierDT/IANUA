from pathlib import Path

import pytest
from agents.incident_report_agent import IncidentReportAgent


@pytest.mark.unit
def test_generates_report_file(tmp_path: Path) -> None:
    agent = IncidentReportAgent()
    output = tmp_path / "report.md"
    result = agent.generate_report(
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        str(output),
    )
    assert result == output
    assert output.exists()


@pytest.mark.unit
def test_report_contains_severity(tmp_path: Path) -> None:
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
def test_creates_parent_directories(tmp_path: Path) -> None:
    agent = IncidentReportAgent()
    output = tmp_path / "nested" / "deep" / "report.md"
    agent.generate_report(
        "Failed password for invalid user admin from 192.168.1.50 port 22 ssh2",
        str(output),
    )
    assert output.exists()


@pytest.mark.unit
def test_uses_precomputed_results_not_reanalyze(tmp_path: Path) -> None:
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
def test_no_indicators_shows_none(tmp_path: Path) -> None:
    agent = IncidentReportAgent()
    output = tmp_path / "report.md"
    agent.generate_report(
        "Suricata alert: suspicious traffic detected",
        str(output),
    )
    content = output.read_text(encoding="utf-8")
    assert "None detected" in content


@pytest.mark.unit
def test_kb_references_render_when_supplied(tmp_path: Path) -> None:
    agent = IncidentReportAgent()
    output = tmp_path / "report.md"
    kb_refs = [
        {"source": "mitre.md", "score": 0.44, "snippet": "# MITRE ATT&CK Enterprise overview"},
    ]
    agent.generate_report(
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        str(output),
        kb_references=kb_refs,
    )
    content = output.read_text(encoding="utf-8")
    assert "## Knowledge Base References" in content
    assert "mitre.md" in content
    assert "0.44" in content


@pytest.mark.unit
def test_kb_references_absent_shows_none_captured(tmp_path: Path) -> None:
    agent = IncidentReportAgent()
    output = tmp_path / "report.md"
    agent.generate_report(
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        str(output),
    )
    content = output.read_text(encoding="utf-8")
    assert "## Knowledge Base References" in content
    assert "None captured" in content


@pytest.mark.unit
def test_detection_matches_render_when_supplied(tmp_path: Path) -> None:
    agent = IncidentReportAgent()
    output = tmp_path / "report.md"
    matches = [
        {
            "rule_id": "abc",
            "title": "SSH Brute Force",
            "level": "high",
            "technique": "T1110",
            "file": "ssh_brute_force.yml",
        },
    ]
    agent.generate_report(
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        str(output),
        detection_matches=matches,
    )
    content = output.read_text(encoding="utf-8")
    assert "## Detection Coverage" in content
    assert "SSH Brute Force" in content
    assert "ssh_brute_force.yml" in content


@pytest.mark.unit
def test_detection_matches_absent_shows_none(tmp_path: Path) -> None:
    agent = IncidentReportAgent()
    output = tmp_path / "report.md"
    agent.generate_report(
        "Suricata alert: suspicious traffic detected",
        str(output),
    )
    content = output.read_text(encoding="utf-8")
    assert "## Detection Coverage" in content
    assert "No Sigma rule covers this technique yet" in content


@pytest.mark.unit
def test_ai_narrative_disabled_by_default(tmp_path: Path) -> None:
    agent = IncidentReportAgent()
    output = tmp_path / "report.md"
    agent.generate_report("Failed password for root from 10.0.0.5 port 22 ssh2", str(output))
    content = output.read_text(encoding="utf-8")
    assert "## Analyst Narrative (AI-generated)" in content
    assert "not enabled" in content


@pytest.mark.unit
def test_ai_narrative_renders_with_generator(tmp_path: Path) -> None:
    class _FakeGen:
        def generate(self, prompt: str, *, system: str | None = None) -> str:
            return "Root SSH login after repeated failures; likely brute-force success."

    agent = IncidentReportAgent()
    output = tmp_path / "report.md"
    agent.generate_report(
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        str(output),
        generator=_FakeGen(),
    )
    content = output.read_text(encoding="utf-8")
    assert "## Analyst Narrative (AI-generated)" in content
    assert "brute-force success" in content


@pytest.mark.unit
def test_ai_narrative_structured_when_generator_supports_json(tmp_path: Path) -> None:
    """A grammar-capable backend yields a structured (bulleted) narrative."""

    class _JsonGen:
        def generate(self, prompt: str, *, system: str | None = None) -> str:
            return "free text fallback"

        def generate_json(self, prompt: str, *, system: str | None = None) -> dict:
            return {
                "summary": "Root SSH login after failures",
                "assessment": "Likely brute-force success",
                "recommended_next_step": "Isolate host and rotate creds",
            }

    agent = IncidentReportAgent()
    output = tmp_path / "report.md"
    agent.generate_report(
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        str(output),
        generator=_JsonGen(),
    )
    content = output.read_text(encoding="utf-8")
    assert "- **Summary:** Root SSH login after failures" in content
    assert "- **Recommended next step:** Isolate host and rotate creds" in content
    assert "free text fallback" not in content  # structured path preferred


@pytest.mark.unit
def test_ai_narrative_fails_soft_on_generator_error(tmp_path: Path) -> None:
    from agents.tools.validation import ValidationError

    class _DeadGen:
        def generate(self, prompt: str, *, system: str | None = None) -> str:
            raise ValidationError("ollama unreachable")

    agent = IncidentReportAgent()
    output = tmp_path / "report.md"
    # The report still writes; the narrative section records the failure.
    agent.generate_report(
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        str(output),
        generator=_DeadGen(),
    )
    content = output.read_text(encoding="utf-8")
    assert "AI narrative unavailable" in content
