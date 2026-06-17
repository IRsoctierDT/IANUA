"""SOC Analyst Agent v0.2.

Accepts plain-text or structured JSON log input. Returns a richer result
that includes a numeric severity score, an evidence table, and all v0.1
fields. Does not perform network activity, scanning, or external actions.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Literal, cast

Severity = Literal["low", "medium", "high", "critical", "unknown"]

# Severity label -> base numeric score (0-100)
_SEVERITY_SCORES: dict[str, int] = {
    "critical": 90,
    "high": 70,
    "medium": 45,
    "low": 20,
    "unknown": 0,
}


@dataclass(frozen=True)
class EvidenceEntry:
    """A single observed field that contributed to the analysis."""

    field: str
    value: str
    significance: str


@dataclass(frozen=True)
class SocAnalysisResult:
    """Structured SOC analysis output."""

    agent: str
    summary: str
    severity: Severity
    severity_score: int
    event_type: str
    indicators: list[str]
    evidence: list[EvidenceEntry]
    recommended_actions: list[str]
    assumptions: list[str]


class SocAnalystAgent:
    """Analyze a log entry (plain text or JSON) and return structured findings."""

    def __init__(self, name: str = "SOC Analyst Agent v0.2") -> None:
        self.name = name

    def analyze_log(self, log_input: str | dict[str, Any]) -> dict[str, Any]:
        """Analyze a log entry or log block.

        Args:
            log_input: A plain-text log string or a structured dict/JSON string
                       with keys like ``message``, ``host``, ``user``, ``src_ip``,
                       ``timestamp``, ``severity``.
        """
        log_text, structured = self._normalize_input(log_input)

        event_type = self._classify_event(log_text)
        severity = self._estimate_severity(log_text, event_type, structured)
        severity_score = self._score_severity(severity, log_text, event_type, structured)
        indicators = self._extract_indicators(log_text, structured)
        evidence = self._build_evidence(log_text, structured, event_type)

        result = SocAnalysisResult(
            agent=self.name,
            summary=f"Detected probable {event_type} activity.",
            severity=severity,
            severity_score=severity_score,
            event_type=event_type,
            indicators=indicators,
            evidence=evidence,
            recommended_actions=self._recommend_actions(event_type, severity),
            assumptions=[
                "Analysis is based only on the supplied log input.",
                "No external enrichment, threat intelligence, or packet inspection was performed.",
            ],
        )
        return asdict(result)

    # ------------------------------------------------------------------
    # Input normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_input(
        log_input: str | dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        """Return (flat_text, structured_fields) from any supported input form."""
        if isinstance(log_input, dict):
            if not log_input:
                raise ValueError("log_input dict cannot be empty.")
            structured = {k: str(v) for k, v in log_input.items()}
            log_text = structured.get("message", " ".join(structured.values()))
            return log_text.strip(), structured

        if not isinstance(log_input, str):
            raise ValueError("log_input must be a string or dict.")

        text = log_input.strip()
        if not text:
            raise ValueError("log_input cannot be empty.")

        # Try to parse as JSON string
        if text.startswith("{"):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    structured = {k: str(v) for k, v in parsed.items()}
                    log_text = structured.get("message", " ".join(structured.values()))
                    return log_text.strip(), structured
            except json.JSONDecodeError:
                pass

        return text, {}

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_event(log_text: str) -> str:
        lowered = log_text.lower()
        if "failed password" in lowered or "invalid user" in lowered:
            return "authentication failure"
        if "suricata" in lowered or "alert" in lowered:
            return "ids alert"
        if "blocked" in lowered or "deny" in lowered:
            return "firewall block"
        if "accepted password" in lowered or "accepted publickey" in lowered:
            return "successful login"
        if "connection refused" in lowered or "timeout" in lowered:
            return "network anomaly"
        return "unknown security event"

    # ------------------------------------------------------------------
    # Severity
    # ------------------------------------------------------------------

    @staticmethod
    def _estimate_severity(
        log_text: str,
        event_type: str,
        structured: dict[str, Any],
    ) -> Severity:
        # Honour an explicit severity field from structured input
        explicit = structured.get("severity", "").lower()
        if explicit in _SEVERITY_SCORES:
            return cast(Severity, explicit)

        lowered = log_text.lower()
        # Check both flat log text and the structured user/account fields.
        user_val = structured.get("user", structured.get("account", "")).lower()
        is_privileged = (
            "root" in lowered
            or "administrator" in lowered
            or user_val in ("root", "administrator", "admin")
        )
        if event_type == "authentication failure":
            return "high" if is_privileged else "medium"
        if event_type == "successful login":
            return "high" if is_privileged else "low"
        if event_type == "ids alert":
            return "medium"
        if event_type == "firewall block":
            return "low"
        if event_type == "network anomaly":
            return "low"
        return "unknown"

    @staticmethod
    def _score_severity(
        severity: Severity,
        log_text: str,
        event_type: str,
        structured: dict[str, Any],
    ) -> int:
        """Return a 0-100 numeric score; apply modifiers for aggravating signals."""
        base = _SEVERITY_SCORES.get(severity, 0)
        lowered = log_text.lower()
        user_val = structured.get("user", structured.get("account", "")).lower()
        bonus = 0
        if (
            "root" in lowered
            or "administrator" in lowered
            or user_val in ("root", "administrator", "admin")
        ):
            bonus += 10
        if event_type == "authentication failure" and any(
            kw in lowered for kw in ("repeated", "multiple", "brute")
        ):
            bonus += 10
        if "critical" in lowered:
            bonus += 5
        return min(base + bonus, 100)

    # ------------------------------------------------------------------
    # Indicators
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_indicators(log_text: str, structured: dict[str, Any]) -> list[str]:
        indicators: list[str] = []

        # Pull src_ip / source_ip from structured fields first
        for key in ("src_ip", "source_ip", "ip", "remote_addr"):
            if key in structured:
                indicators.append(structured[key])

        # Fall back to token scanning for IPv4 addresses
        if not indicators:
            tokens = log_text.replace(",", " ").split()
            for token in tokens:
                stripped = token.strip("[]():;")
                parts = stripped.split(".")
                if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    indicators.append(stripped)

        return sorted(set(indicators))

    # ------------------------------------------------------------------
    # Evidence table
    # ------------------------------------------------------------------

    @staticmethod
    def _build_evidence(
        log_text: str,
        structured: dict[str, Any],
        event_type: str,
    ) -> list[EvidenceEntry]:
        entries: list[EvidenceEntry] = []
        lowered = log_text.lower()

        if structured:
            _FIELD_SIG: dict[str, str] = {
                "timestamp": "Establishes when the event occurred.",
                "host": "Identifies the affected system.",
                "user": "Identifies the targeted account.",
                "src_ip": "Primary network indicator of compromise.",
                "source_ip": "Primary network indicator of compromise.",
                "severity": "Reported severity from the originating system.",
                "message": "Raw event message used for classification.",
            }
            for field, sig in _FIELD_SIG.items():
                if field in structured:
                    entries.append(
                        EvidenceEntry(field=field, value=structured[field], significance=sig)
                    )
        else:
            # Extract evidence from plain text
            if "root" in lowered or "administrator" in lowered:
                entries.append(
                    EvidenceEntry(
                        field="privileged_account",
                        value="root/administrator",
                        significance="Privileged account targeted — elevates severity.",
                    )
                )
            if event_type == "authentication failure":
                entries.append(
                    EvidenceEntry(
                        field="event_signal",
                        value="failed password / invalid user",
                        significance="Direct keyword match for authentication failure pattern.",
                    )
                )
            if event_type == "ids alert":
                entries.append(
                    EvidenceEntry(
                        field="event_signal",
                        value="suricata / alert keyword",
                        significance="IDS signature triggered — requires rule and packet review.",
                    )
                )

        return entries

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------

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
        if event_type == "successful login":
            actions.extend(
                [
                    "Confirm whether the login was expected and authorised.",
                    "Review follow-on commands or session activity.",
                ]
            )
        if event_type == "ids alert":
            actions.extend(
                [
                    "Review IDS signature metadata and packet capture.",
                    "Correlate with destination asset exposure.",
                ]
            )
        if severity in {"high", "critical"}:
            actions.append("Escalate for immediate human review.")

        return actions


if __name__ == "__main__":
    agent = SocAnalystAgent()

    print("=== Plain text ===")
    print(agent.analyze_log("Failed password for root from 10.0.0.5 port 22 ssh2"))

    print("\n=== JSON string ===")
    print(
        agent.analyze_log(
            '{"timestamp":"2025-06-15T14:00:00Z","host":"web-01",'
            '"user":"root","src_ip":"10.0.0.5","message":"Failed password for root"}'
        )
    )

    print("\n=== Dict input ===")
    print(
        agent.analyze_log(
            {
                "timestamp": "2025-06-15T14:00:00Z",
                "host": "web-01",
                "user": "admin",
                "src_ip": "192.168.1.99",
                "message": "Failed password for invalid user admin from 192.168.1.99",
            }
        )
    )
