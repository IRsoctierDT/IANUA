from agents.soc_analyst_agent import SocAnalystAgent
from agents.mitre_mapper_agent import MitreMapperAgent
from agents.threat_intel_agent import ThreatIntelAgent
from agents.incident_report_agent import IncidentReportAgent


class OrchestratorAgent:

    def __init__(self):
        self.soc = SocAnalystAgent()
        self.mitre = MitreMapperAgent()
        self.threat = ThreatIntelAgent()
        self.report = IncidentReportAgent()

    def process_log(self, log_text):

        soc_result = self.soc.analyze_log(log_text)

        mitre_result = self.mitre.map_event(
            soc_result["event_type"],
            log_text
        )

        indicators = soc_result.get("indicators", [])

        intel_results = []

        for indicator in indicators:
            intel_results.append(
                self.threat.analyze_indicator(indicator)
            )

        self.report.generate_report(
            log_text,
            "reports/markdown/orchestrated_incident.md"
        )

        return {
            "soc": soc_result,
            "mitre": mitre_result,
            "threat_intel": intel_results
        }


if __name__ == "__main__":

    log = "Failed password for root from 10.0.0.5 port 22 ssh2"

    agent = OrchestratorAgent()

    result = agent.process_log(log)

    print(result)