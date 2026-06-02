from pathlib import Path
from datetime import datetime, timezone

from agents.soc_analyst_agent import SocAnalystAgent


class IncidentReportAgent:
    def __init__(self):
        self.soc_agent = SocAnalystAgent()

    def generate_report(self, log_text: str, output_path: str) -> Path:
        result = self.soc_agent.analyze_log(log_text)
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        report = f"""# Incident Report

## Generated
{datetime.now(timezone.utc).isoformat()}

## Summary
{result["summary"]}

## Severity
{result["severity"]}

## Event Type
{result["event_type"]}

## Indicators
{chr(10).join(f"- `{i}`" for i in result["indicators"]) or "- None detected"}

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
