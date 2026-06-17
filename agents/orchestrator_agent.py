from typing import Any

from agents.incident_report_agent import IncidentReportAgent
from agents.knowledge_base_agent import KnowledgeBaseAgent
from agents.mitre_mapper_agent import MitreMapperAgent
from agents.soc_analyst_agent import SocAnalystAgent
from agents.threat_intel_agent import ThreatIntelAgent


class OrchestratorAgent:
    def __init__(self) -> None:
        self.soc = SocAnalystAgent()
        self.mitre = MitreMapperAgent()
        self.threat = ThreatIntelAgent()
        self.knowledge_base = KnowledgeBaseAgent()
        self.report = IncidentReportAgent()

    def process_log(
        self,
        log_text: str,
        report_path: str = "reports/markdown/orchestrated_incident.md",
    ) -> dict[str, Any]:
        """Run the full agent pipeline over a single log line.

        Inputs:
            log_text: Raw log line to analyze.
            report_path: Destination for the generated Markdown incident
                report. Defaults to the tracked sample location; tests should
                override this to a temporary path to avoid mutating the working
                tree.

        Returns a dict with the SOC, MITRE, threat-intel, and knowledge-base
        results for the event.
        """
        soc_result = self.soc.analyze_log(log_text)

        mitre_result = self.mitre.map_event(
            soc_result["event_type"],
            log_text,
        )

        indicators = soc_result.get("indicators", [])

        intel_results = [self.threat.analyze_indicator(ind) for ind in indicators]

        kb_references = self.knowledge_base.reference_for_event(soc_result, mitre_result)

        self.report.generate_report(
            log_text,
            report_path,
            soc_result=soc_result,
            mitre_result=mitre_result,
            kb_references=kb_references,
        )

        return {
            "soc": soc_result,
            "mitre": mitre_result,
            "threat_intel": intel_results,
            "knowledge_base": kb_references,
        }


if __name__ == "__main__":
    log = "Failed password for root from 10.0.0.5 port 22 ssh2"
    agent = OrchestratorAgent()
    result = agent.process_log(log)
    print(result)
