from dataclasses import dataclass, asdict
from typing import Literal


Confidence = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class MitreMappingResult:
    event_type: str
    tactic: str
    technique: str
    technique_id: str
    confidence: Confidence
    evidence: list[str]
    recommended_investigation: list[str]


class MitreMapperAgent:
    def map_event(self, event_type: str, log_text: str = "") -> dict:
        normalized_event = event_type.lower()
        normalized_log = log_text.lower()

        if "authentication failure" in normalized_event:
            return asdict(
                MitreMappingResult(
                    event_type=event_type,
                    tactic="Credential Access",
                    technique="Brute Force",
                    technique_id="T1110",
                    confidence="medium",
                    evidence=[
                        "Authentication failure event detected.",
                        "Repeated failed login activity may indicate brute force behavior.",
                    ],
                    recommended_investigation=[
                        "Check source IP frequency.",
                        "Review failed login count per account.",
                        "Verify whether MFA or account lockout controls were triggered.",
                    ],
                )
            )

        if "ssh" in normalized_log and "accepted" in normalized_log:
            return asdict(
                MitreMappingResult(
                    event_type=event_type,
                    tactic="Initial Access",
                    technique="Valid Accounts",
                    technique_id="T1078",
                    confidence="medium",
                    evidence=[
                        "SSH accepted-login pattern detected.",
                        "Valid account usage may require legitimacy review.",
                    ],
                    recommended_investigation=[
                        "Confirm whether the login was expected.",
                        "Review source IP reputation and geolocation.",
                        "Check for follow-on activity after login.",
                    ],
                )
            )

        if "ids alert" in normalized_event:
            return asdict(
                MitreMappingResult(
                    event_type=event_type,
                    tactic="Detection-dependent",
                    technique="Requires analyst review",
                    technique_id="UNKNOWN",
                    confidence="low",
                    evidence=[
                        "IDS alert requires signature and packet-context review.",
                    ],
                    recommended_investigation=[
                        "Review IDS signature metadata.",
                        "Correlate with destination asset exposure.",
                        "Inspect packet capture if available.",
                    ],
                )
            )

        return asdict(
            MitreMappingResult(
                event_type=event_type,
                tactic="Unknown",
                technique="Unknown",
                technique_id="UNKNOWN",
                confidence="low",
                evidence=["No supported mapping rule matched."],
                recommended_investigation=[
                    "Review raw log evidence.",
                    "Add a new mapping rule if pattern becomes repeatable.",
                ],
            )
        )


if __name__ == "__main__":
    mapper = MitreMapperAgent()
    result = mapper.map_event(
        "authentication failure",
        "Failed password for root from 10.0.0.5 port 22 ssh2",
    )
    print(result)
