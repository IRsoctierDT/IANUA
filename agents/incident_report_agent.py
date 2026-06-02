from pathlib import Path
from datetime import datetime, timezone

from agents.soc_analyst_agent import SocAnalystAgent
from agents.mitre_mapper_agent import MitreMapperAgent


class IncidentReportAgent:
    def __init__(self):
        self.soc_agent = SocAnalystAgent()
        self.mitre_mapper = MitreMapperAgent()

    def generate_report(self, log_text: str, output_path: str) -> Path:
        result = self.soc_agent.analyze_log(log_text)
        mitre = self.mitre_mapper.map_event(
            result["event_type"],
            log_text,
        )

        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        indicators = result.get("indicators", [])

        report = f"""# Incident Report

## Generated
{datetime.now(timezone.utc).isoformat()}

## Summary
{result["summary"]}

## Severity
{result["severity"]}

## Event Type
{result["event_type"]}

## MITRE ATT&CK Mapping

- **Tactic:** {mitre["tactic"]}
- **Technique:** {mitre["technique"]}
- **Technique ID:** {mitre["technique_id"]}
- **Confidence:** {mitre["confidence"]}

### MITRE Evidence
{chr(10).join(f"- {e}" for e in mitre["evidence"])}

### MITRE Investigation Steps
{chr(10).join(f"- {s}" for s in mitre["recommended_investigation"])}

## Indicators
{chr(10).join(f"- `{i}`" for i in indicators) if indicators else "- None detected"}

## Recommended Actions
{chr(10).join(f"- {a}" for a in result["recommended_actions"])}

## Assumptions
{chr(10).join(f"- {a}" for a in result["assumptions"])}
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
