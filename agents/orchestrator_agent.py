import json
from collections.abc import Sequence
from dataclasses import asdict
from typing import Any

from agents.detection_matcher_agent import DetectionMatcherAgent
from agents.incident_report_agent import IncidentReportAgent
from agents.knowledge_base_agent import KnowledgeBaseAgent
from agents.mitre_mapper_agent import MitreMapperAgent
from agents.soc_analyst_agent import SocAnalystAgent
from agents.threat_intel_agent import ThreatIntelAgent
from agents.tools.llm import Generator, resolve_generator


class OrchestratorAgent:
    def __init__(self, *, generator: Generator | None = None) -> None:
        self.soc = SocAnalystAgent()
        self.mitre = MitreMapperAgent()
        self.threat = ThreatIntelAgent()
        self.knowledge_base = KnowledgeBaseAgent()
        self.detections = DetectionMatcherAgent()
        self.report = IncidentReportAgent()
        # On by default via env (LLM_NARRATIVE=auto): the report's AI narrative is
        # produced when a local model is reachable, and fails soft otherwise. Pass
        # an explicit generator to override, or set LLM_NARRATIVE=off to disable.
        self.generator = generator if generator is not None else resolve_generator()

    def _verified_citations(
        self, soc_result: dict[str, Any], mitre_result: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Passage-level citations for the event, attached only if they verify.

        Builds the same query the knowledge-base references use, cites the exact
        matching passages, then runs the anti-hallucination check
        (``verify_citations``). Fail-closed: citations that do not verify
        verbatim at their recorded offsets are dropped rather than reported.
        """
        parts = [
            value
            for key in ("event_type", "summary")
            if isinstance(value := soc_result.get(key), str)
        ]
        parts += [
            value
            for key in ("tactic", "technique")
            if isinstance(value := mitre_result.get(key), str)
        ]
        citations = self.knowledge_base.cite(" ".join(parts), k=3)
        if not citations or not self.knowledge_base.verify_citations(citations):
            return []
        return [asdict(c) for c in citations]

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

        Returns a dict with the SOC, MITRE, threat-intel, knowledge-base,
        detection, and verified-citation results for the event.
        """
        soc_result = self.soc.analyze_log(log_text)

        mitre_result = self.mitre.map_event(
            soc_result["event_type"],
            log_text,
        )

        indicators = soc_result.get("indicators", [])

        intel_results = [self.threat.analyze_indicator(ind) for ind in indicators]

        kb_references = self.knowledge_base.reference_for_event(soc_result, mitre_result)

        detection_matches = self.detections.match_for_event(mitre_result)

        citations = self._verified_citations(soc_result, mitre_result)

        self.report.generate_report(
            log_text,
            report_path,
            soc_result=soc_result,
            mitre_result=mitre_result,
            kb_references=kb_references,
            detection_matches=detection_matches,
            citations=citations,
            citations_verified=True,
            generator=self.generator,
        )

        return {
            "soc": soc_result,
            "mitre": mitre_result,
            "threat_intel": intel_results,
            "knowledge_base": kb_references,
            "detections": detection_matches,
            "citations": citations,
        }

    def process_sequence(
        self,
        events: Sequence[str | dict[str, Any]],
        report_path: str = "reports/markdown/orchestrated_sequence_incident.md",
    ) -> dict[str, Any]:
        """Run the pipeline over an ordered batch of log events.

        The SOC agent correlates the sequence (brute force, failure-then-success
        credential compromise — see ``analyze_sequence``); the standard
        single-event pipeline then runs on the batch's most severe event so the
        report keeps its familiar sections, with the sequence findings surfaced
        in a dedicated "Sequence Correlation" section. Threat intel covers the
        union of indicators across the whole sequence.

        Deterministic and network-free like ``process_log``; input validation is
        fail-closed (delegated to ``analyze_sequence``).
        """
        event_list: list[str | dict[str, Any]] = list(events)
        sequence_result = self.soc.analyze_sequence(event_list)

        # Anchor the standard report sections on the most severe event
        # (highest severity score; earliest event wins ties — deterministic).
        top_summary = max(
            sequence_result["events"],
            key=lambda e: (e["severity_score"], -e["index"]),
        )
        top_event = event_list[top_summary["index"]]
        log_text = (
            top_event if isinstance(top_event, str) else json.dumps(top_event, sort_keys=True)
        )

        soc_result = self.soc.analyze_log(top_event)
        mitre_result = self.mitre.map_event(soc_result["event_type"], log_text)

        # Union of indicators across the sequence, deterministic order.
        all_indicators = sorted(
            {ind for entry in sequence_result["events"] for ind in entry["indicators"]}
        )
        intel_results = [self.threat.analyze_indicator(ind) for ind in all_indicators]

        kb_references = self.knowledge_base.reference_for_event(soc_result, mitre_result)
        detection_matches = self.detections.match_for_event(mitre_result)
        sequence_detections = self.detections.match_for_sequence(sequence_result)
        citations = self._verified_citations(soc_result, mitre_result)

        self.report.generate_report(
            log_text,
            report_path,
            soc_result=soc_result,
            mitre_result=mitre_result,
            kb_references=kb_references,
            detection_matches=detection_matches,
            sequence_result=sequence_result,
            sequence_detections=sequence_detections,
            citations=citations,
            citations_verified=True,
            generator=self.generator,
        )

        return {
            "soc": soc_result,
            "sequence": sequence_result,
            "mitre": mitre_result,
            "threat_intel": intel_results,
            "knowledge_base": kb_references,
            "detections": detection_matches,
            "sequence_detections": sequence_detections,
            "citations": citations,
        }


if __name__ == "__main__":
    log = "Failed password for root from 10.0.0.5 port 22 ssh2"
    agent = OrchestratorAgent()
    result = agent.process_log(log)
    print(result)
