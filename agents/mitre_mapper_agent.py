"""MITRE ATT&CK Mapper Agent — deterministic event-to-technique mapping.

Maps a classified event (from the SOC Analyst Agent) to a MITRE ATT&CK
tactic/technique with a confidence rating, supporting evidence, and
recommended investigation steps. Read-only, network-free, and deterministic:
unmatched events map to an explicit ``UNKNOWN`` result rather than a guess.

Security consideration: ``map_event`` validates both inputs are strings and
``event_type`` is non-empty (fail closed on malformed input) — callers may
pass untrusted, LLM-derived text safely.
"""

from dataclasses import asdict, dataclass
from typing import Any, Literal

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
    def map_event(self, event_type: str, log_text: str = "") -> dict[str, Any]:
        """Map ``event_type`` (+ optional raw ``log_text``) to an ATT&CK result dict.

        Validates its own inputs (AGENTS.md §4): both must be strings and
        ``event_type`` must be non-empty; raises ``ValueError`` otherwise.
        """
        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("event_type must be a non-empty string.")
        if not isinstance(log_text, str):
            raise ValueError("log_text must be a string.")
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

        if "arp spoofing" in normalized_event or (
            "arp" in normalized_log
            and any(m in normalized_log for m in ("moved from", "spoof", "poison"))
        ):
            return asdict(
                MitreMappingResult(
                    event_type=event_type,
                    tactic="Credential Access",
                    technique="Adversary-in-the-Middle: ARP Cache Poisoning",
                    technique_id="T1557",
                    confidence="medium",
                    evidence=[
                        "ARP cache-poisoning indicator detected "
                        "(IP-to-MAC binding changed unexpectedly).",
                        "ARP poisoning positions an attacker to intercept or relay "
                        "traffic on the local segment.",
                    ],
                    recommended_investigation=[
                        "Identify the MAC address claiming the disputed IP and locate "
                        "the physical port it is attached to.",
                        "Check whether DHCP lease churn or a virtual-IP failover "
                        "explains the rebinding before treating it as hostile.",
                        "Review traffic captured during the window for credential "
                        "or session data exposed in cleartext.",
                    ],
                )
            )

        if "log tampering" in normalized_event:
            return asdict(
                MitreMappingResult(
                    event_type=event_type,
                    tactic="Defense Evasion",
                    technique="Indicator Removal: Clear Command History",
                    technique_id="T1070.003",
                    confidence="medium",
                    evidence=[
                        "Audit-evidence destruction indicator detected "
                        "(history cleared, log removed, or audit daemon stopped).",
                        "Clearing evidence is post-compromise behavior — it presumes "
                        "there was activity worth hiding.",
                    ],
                    recommended_investigation=[
                        "Recover the audit trail from remote or forwarded log copies.",
                        "Establish what the account did before the evidence was cleared.",
                        "Treat the host as compromised until the review completes.",
                    ],
                )
            )

        if "privileged group addition" in normalized_event:
            return asdict(
                MitreMappingResult(
                    event_type=event_type,
                    tactic="Privilege Escalation",
                    technique="Account Manipulation",
                    technique_id="T1098",
                    confidence="medium",
                    evidence=[
                        "An account was added to a privileged group (sudo/wheel/admin).",
                        "Privileged-group membership grants durable elevated access "
                        "— a persistence and escalation primitive.",
                    ],
                    recommended_investigation=[
                        "Verify the change against change-management records.",
                        "Check when the target account was created — a fresh account "
                        "gaining privilege is the classic persistence chain.",
                        "Review the actor account that performed the change.",
                    ],
                )
            )

        if "account creation" in normalized_event:
            return asdict(
                MitreMappingResult(
                    event_type=event_type,
                    tactic="Persistence",
                    technique="Create Account: Local Account",
                    technique_id="T1136.001",
                    confidence="medium",
                    evidence=[
                        "A local account was created.",
                        "Adversaries create local accounts to maintain access that "
                        "survives credential rotation.",
                    ],
                    recommended_investigation=[
                        "Confirm the account maps to an approved provisioning request.",
                        "Watch for follow-on privilege changes on the same account.",
                        "Review the creating account's session for other changes.",
                    ],
                )
            )

        if "port scan" in normalized_event:
            return asdict(
                MitreMappingResult(
                    event_type=event_type,
                    tactic="Discovery",
                    technique="Network Service Discovery",
                    technique_id="T1046",
                    confidence="medium",
                    evidence=[
                        "Port-scanning activity detected (service discovery probes).",
                        "Service discovery commonly precedes exploitation of the "
                        "services it enumerates.",
                    ],
                    recommended_investigation=[
                        "Identify the scan source and whether it is an authorized "
                        "scanner (vulnerability management, asset inventory).",
                        "Review exposure of the probed ports and their services.",
                        "Correlate with follow-on connection attempts from the same source.",
                    ],
                )
            )

        if "ransomware" in normalized_event or any(
            m in normalized_log
            for m in ("ransom note", "ransom_note", "files encrypted", "vssadmin delete shadows")
        ):
            return asdict(
                MitreMappingResult(
                    event_type=event_type,
                    tactic="Impact",
                    technique="Data Encrypted for Impact",
                    technique_id="T1486",
                    confidence="high",
                    evidence=[
                        "Ransomware indicator detected (encryption activity, ransom "
                        "note, or shadow-copy deletion).",
                        "Encryption for impact is time-critical: unrecovered data "
                        "grows with every minute the payload keeps running.",
                    ],
                    recommended_investigation=[
                        "Contain first (agents/tools/containment.py): stop the "
                        "encrypting process, quarantine the payload, and isolate "
                        "the affected lab host.",
                        "Check for recovery inhibition (T1490): shadow copies and "
                        "backups deleted or disabled.",
                        "Identify the initial access vector and any staged "
                        "exfiltration preceding encryption (double extortion).",
                    ],
                )
            )

        if "extortion" in normalized_event or "double extortion" in normalized_log:
            return asdict(
                MitreMappingResult(
                    event_type=event_type,
                    tactic="Impact",
                    technique="Financial Theft",
                    technique_id="T1657",
                    confidence="medium",
                    evidence=[
                        "Extortion indicator detected (ransom/payment demand or data-leak threat).",
                        "Extortion leverage depends on continued access and staged "
                        "data — both are containable.",
                    ],
                    recommended_investigation=[
                        "Contain the leverage (agents/tools/containment.py): "
                        "isolate affected hosts, block exfiltration indicators, "
                        "and disable compromised accounts.",
                        "Establish what data was staged or exfiltrated and from which systems.",
                        "Preserve the demand and all attacker communication as "
                        "evidence; escalate to the human owner (AGENTS.md §6.3).",
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
