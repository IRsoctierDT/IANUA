"""SOC Analyst Agent.

Safe starter agent for classifying cybersecurity log text.
It does not perform network activity, scanning, exploitation, or external actions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

Severity = Literal["low", "medium", "high", "critical", "unknown"]


@dataclass(frozen=True)
class SocAnalysisResult:
    """Structured SOC analysis output."""

    agent: str
    summary: str
    severity: Severity
    event_type: str
    indicators: list[str]
    recommended_actions: list[str]
    assumptions: list[str]


class SocAnalystAgent:
    """Analyze supplied log text and return structured, human-reviewable findings."""

    def __init__(self, name: str = "SOC Analyst Agent") -> None:
        self.name = name

    def analyze_log(self, log_text: str) -> dict[str, object]:
        """Analyze a log entry or log block."""
        if not isinstance(log_text, str):
            raise ValueError("log_text must be a string.")

        cleaned_log = log_text.strip()
        if not cleaned_log:
            raise ValueError("log_text cannot be empty.")

        event_type = self._classify_event(cleaned_log)
        severity = self._estimate_severity(cleaned_log, event_type)
        indicators = self._extract_indicators(cleaned_log)

        result = SocAnalysisResult(
            agent=self.name,
            summary=f"Detected probable {event_type} activity.",
            severity=severity,
            event_type=event_type,
            indicators=indicators,
            recommended_actions=self._recommend_actions(event_type, severity),
            assumptions=[
                "Analysis is based only on the supplied log text.",
                "No external enrichment, threat intelligence, or packet inspection was performed.",
            ],
        )
        return asdict(result)

    @staticmethod
    def _classify_event(log_text: str) -> str:
        lowered = log_text.lower()
        if "failed password" in lowered or "invalid user" in lowered:
            return "authentication failure"
        if "suricata" in lowered or "alert" in lowered:
            return "ids alert"
        if "blocked" in lowered or "deny" in lowered:
            return "firewall block"
        return "unknown security event"

    @staticmethod
    def _estimate_severity(log_text: str, event_type: str) -> Severity:
        lowered = log_text.lower()
        if "root" in lowered and event_type == "authentication failure":
            return "high"
        if event_type == "ids alert":
            return "medium"
        if event_type == "firewall block":
            return "low"
        if event_type == "authentication failure":
            return "medium"
        return "unknown"

    @staticmethod
    def _extract_indicators(log_text: str) -> list[str]:
        tokens = log_text.replace(",", " ").split()
        indicators: list[str] = []

        for token in tokens:
            stripped = token.strip("[]():;")
            parts = stripped.split(".")
            if len(parts) == 4 and all(part.isdigit() for part in parts):
                indicators.append(stripped)

        return sorted(set(indicators))

    @staticmethod
    def _recommend_actions(event_type: str, severity: Severity) -> list[str]:
        actions = ["Preserve the original log evidence.", "Correlate with adjacent timestamps."]

        if event_type == "authentication failure":
            actions.extend(
                [
                    "Check whether the source IP appears repeatedly.",
                    "Review account lockout, MFA, and SSH exposure.",
                ]
            )

        if severity in {"high", "critical"}:
            actions.append("Escalate for immediate human review.")

        return actions


if __name__ == "__main__":
    agent = SocAnalystAgent()
    sample = "Failed password for invalid user admin from 192.168.1.50 port 22 ssh2"
    print(agent.analyze_log(sample))
