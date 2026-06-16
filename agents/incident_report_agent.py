from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from agents.mitre_mapper_agent import MitreMapperAgent
from agents.soc_analyst_agent import SocAnalystAgent


class IncidentReportAgent:
    def __init__(self):
        self.soc_agent = SocAnalystAgent()
        self.mitre_mapper = MitreMapperAgent()

    def generate_report(
        self,
        log_text: str,
        output_path: str,
        *,
        soc_result: dict | None = None,
        mitre_result: dict | None = None,
    ) -> Path:
        """Write a markdown incident report.

        Pass pre-computed ``soc_result`` and ``mitre_result`` to avoid
        re-running analysis when the orchestrator has already done it.
        """
        if soc_result is None:
            soc_result = self.soc_agent.analyze_log(log_text)
        if mitre_result is None:
            mitre_result = self.mitre_mapper.map_event(
                soc_result["event_type"],
                log_text,
            )

        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        indicators = soc_result.get("indicators", [])

        report = f"""# Incident Report

## Generated
{datetime.now(UTC).isoformat()}

## Summary
{soc_result["summary"]}

## Severity
{soc_result["severity"]}

## Event Type
{soc_result["event_type"]}

## MITRE ATT&CK Mapping

- **Tactic:** {mitre_result["tactic"]}
- **Technique:** {mitre_result["technique"]}
- **Technique ID:** {mitre_result["technique_id"]}
- **Confidence:** {mitre_result["confidence"]}

### MITRE Evidence
{chr(10).join(f"- {e}" for e in mitre_result["evidence"])}

### MITRE Investigation Steps
{chr(10).join(f"- {s}" for s in mitre_result["recommended_investigation"])}

## Indicators
{chr(10).join(f"- `{i}`" for i in indicators) if indicators else "- None detected"}

## Recommended Actions
{chr(10).join(f"- {a}" for a in soc_result["recommended_actions"])}

## Assumptions
{chr(10).join(f"- {a}" for a in soc_result["assumptions"])}
"""

        target.write_text(report, encoding="utf-8")
        return target


if __name__ == "__main__":
    agent = IncidentReportAgent()
    agent.generate_report(
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        "reports/markdown/sample_incident_report.md",
    )
    print("Generated reports/markdown/sample_incident_report.md")
