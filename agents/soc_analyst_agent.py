"""SOC Analyst Agent.

Accepts plain-text or structured JSON log input. Returns a structured result
with a numeric severity score, an evidence table, indicators, and recommended
actions. ``analyze_sequence`` additionally correlates an ordered batch of
events into multi-event findings (brute force, failure-then-success credential
compromise). Does not perform network activity, scanning, or external actions.

The agent's display name carries the platform version automatically (see
``agents.versioned_agent_name``), so it stays current with every release.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any, Literal, cast

from agents import versioned_agent_name
from agents.tools.ocsf import normalize as ocsf_normalize

Severity = Literal["low", "medium", "high", "critical", "unknown"]

# How the input was understood: fully structured (dict / valid JSON), plain
# text, or JSON-looking text that failed to parse and was downgraded to text.
ParseStatus = Literal["structured", "text", "malformed_json"]

# Severity label -> base numeric score (0-100)
_SEVERITY_SCORES: dict[str, int] = {
    "critical": 90,
    "high": 70,
    "medium": 45,
    "low": 20,
    "unknown": 0,
}

# Minimum authentication failures from one source to call it brute force.
_BRUTE_FORCE_THRESHOLD = 3
# One ARP anomaly can be DHCP churn or a flapping interface; a burst from a
# single source is an active adversary-in-the-middle attempt (T1557.002).
_ARP_SPOOF_BURST_THRESHOLD = 3


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
    # OCSF event-class descriptor for the event_type (category/class uid+name,
    # schema version, mapped flag) — vendor-neutral schema alignment.
    ocsf: dict[str, Any]
    indicators: list[str]
    evidence: list[EvidenceEntry]
    recommended_actions: list[str]
    assumptions: list[str]


@dataclass(frozen=True)
class EventSummary:
    """Compact per-event view inside a sequence analysis."""

    index: int
    event_type: str
    severity: Severity
    severity_score: int
    indicators: list[str]
    source: str | None


@dataclass(frozen=True)
class CorrelatedFinding:
    """A multi-event pattern detected across the supplied sequence."""

    pattern: Literal["brute_force", "auth_failure_then_success", "arp_spoof_burst"]
    source: str
    event_indices: list[int]
    severity: Severity
    description: str


@dataclass(frozen=True)
class SequenceAnalysisResult:
    """Structured output of a multi-event sequence analysis."""

    agent: str
    summary: str
    severity: Severity
    severity_score: int
    event_count: int
    # Events whose source could not be extracted and validated — they cannot
    # participate in source-based correlation, and a non-zero count is worth an
    # analyst's attention (source-less formatting is attacker-controllable).
    uncorrelated_event_count: int
    events: list[EventSummary]
    findings: list[CorrelatedFinding]
    recommended_actions: list[str]
    assumptions: list[str]


# Display name tracks the platform version — never hard-code a version here
# (drift-gated by tests/unit/test_agent_versioning.py).
_DEFAULT_NAME = versioned_agent_name("SOC Analyst Agent")


class SocAnalystAgent:
    """Analyze a log entry (plain text or JSON) and return structured findings."""

    def __init__(self, name: str = _DEFAULT_NAME) -> None:
        self.name = name

    def analyze_log(self, log_input: str | dict[str, Any]) -> dict[str, Any]:
        """Analyze a log entry or log block.

        Args:
            log_input: A plain-text log string or a structured dict/JSON string
                       with keys like ``message``, ``host``, ``user``, ``src_ip``,
                       ``timestamp``, ``severity``.
        """
        log_text, structured, parse_status = self._normalize_input(log_input)

        event_type = self._classify_event(log_text)
        severity = self._estimate_severity(log_text, event_type, structured)
        severity_score = self._score_severity(severity, log_text, event_type, structured)
        indicators = self._extract_indicators(log_text, structured)
        evidence = self._build_evidence(log_text, structured, event_type)

        assumptions = [
            "Analysis is based only on the supplied log input.",
            "No external enrichment, threat intelligence, or packet inspection was performed.",
        ]
        if parse_status == "malformed_json":
            # Surface the downgrade: structured fields (severity, user, src_ip)
            # were unavailable, so severity and privilege signals may be
            # understated. An evidence row keeps it visible in rendered reports.
            evidence.append(
                EvidenceEntry(
                    field="parse_status",
                    value="malformed_json",
                    significance=(
                        "Input resembled JSON but failed to parse; analyzed as plain "
                        "text without structured fields — severity may be understated."
                    ),
                )
            )
            assumptions.append(
                "Input resembled JSON but failed to parse; structured fields were "
                "not available to the analysis."
            )

        result = SocAnalysisResult(
            agent=self.name,
            summary=f"Detected probable {event_type} activity.",
            severity=severity,
            severity_score=severity_score,
            event_type=event_type,
            ocsf=ocsf_normalize(event_type),
            indicators=indicators,
            evidence=evidence,
            recommended_actions=self._recommend_actions(event_type, severity),
            assumptions=assumptions,
        )
        return asdict(result)

    # ------------------------------------------------------------------
    # Sequence correlation
    # ------------------------------------------------------------------

    def analyze_sequence(self, events: Sequence[str | dict[str, Any]]) -> dict[str, Any]:
        """Correlate an ordered batch of log events into sequence-level findings.

        Detects multi-event attack patterns a single-line analysis cannot see:

        * **Brute force** — at least ``_BRUTE_FORCE_THRESHOLD`` authentication
          failures from the same source indicator (``critical`` when a
          privileged account is targeted, else ``high``).
        * **Possible credential compromise** — an authentication failure
          followed later in the sequence by a successful login from the same
          source (always ``critical``).

        Events are assumed to be supplied in chronological order. Input
        validation is fail-closed: an empty or non-list input raises, and each
        event is validated by the same normalisation as ``analyze_log``. No
        network activity, scanning, or external enrichment is performed.

        Args:
            events: Ordered log entries, each a plain-text string or a
                structured dict (same forms accepted by ``analyze_log``).

        Returns:
            A dict (``SequenceAnalysisResult``) with per-event summaries,
            correlated findings, an overall severity/score, and recommended
            actions.
        """
        # Fail closed on the covariant-Sequence footgun: a bare ``str`` *is* a
        # Sequence, and iterating it would silently analyze single characters
        # as events. Accept any other non-empty sequence (list, tuple).
        if isinstance(events, str) or not isinstance(events, Sequence) or not events:
            raise ValueError("events must be a non-empty sequence of log entries.")

        summaries: list[EventSummary] = []
        privileged_indices: set[int] = set()
        malformed_count = 0
        for index, event in enumerate(events):
            log_text, structured, parse_status = self._normalize_input(event)
            if parse_status == "malformed_json":
                malformed_count += 1
            event_type = self._classify_event(log_text)
            severity = self._estimate_severity(log_text, event_type, structured)
            score = self._score_severity(severity, log_text, event_type, structured)
            summaries.append(
                EventSummary(
                    index=index,
                    event_type=event_type,
                    severity=severity,
                    severity_score=score,
                    indicators=self._extract_indicators(log_text, structured),
                    source=self._extract_source(log_text, structured),
                )
            )
            if self._is_privileged(log_text, structured):
                privileged_indices.add(index)

        findings = self._correlate(summaries, privileged_indices)

        # Overall severity is the strongest of (a) any correlated finding and
        # (b) the strongest individual event — a lower-severity correlation
        # must never downgrade a sequence containing a worse single event.
        # Events rank by severity label first, score second, so a bonus-boosted
        # lower-severity event cannot outrank a genuinely higher one.
        top_event = max(summaries, key=lambda s: (_SEVERITY_SCORES[s.severity], s.severity_score))
        overall: Severity
        if findings:
            top = max(findings, key=lambda f: _SEVERITY_SCORES[f.severity])
            # Correlated multi-event activity is worse than its worst single
            # event — same bonus style as the single-event scorer, capped.
            finding_score = min(_SEVERITY_SCORES[top.severity] + 10, 100)
            if _SEVERITY_SCORES[top.severity] >= _SEVERITY_SCORES[top_event.severity]:
                overall = top.severity
            else:
                overall = top_event.severity
            overall_score = max(finding_score, top_event.severity_score)
            summary = (
                f"Correlated {len(findings)} multi-event pattern(s) across "
                f"{len(events)} events; most severe: {top.pattern} from {top.source}."
            )
        else:
            overall = top_event.severity
            overall_score = top_event.severity_score
            summary = (
                f"No multi-event patterns detected across {len(events)} events; "
                f"highest single-event severity: {overall}."
            )

        assumptions = [
            "Events are assumed to be in chronological order as supplied.",
            "Analysis is based only on the supplied log input.",
            "No external enrichment, threat intelligence, or packet inspection was performed.",
        ]
        # Silent exclusions are themselves a signal: events with no extractable
        # source cannot participate in correlation, and JSON-looking events
        # that failed to parse were analyzed without structured fields. Both
        # are attacker-controllable via log formatting, so report them instead
        # of letting evasion look like a clean sequence.
        uncorrelated = sum(1 for s in summaries if s.source is None)
        if uncorrelated:
            assumptions.append(
                f"{uncorrelated} event(s) had no extractable source address and were "
                "excluded from source-based correlation."
            )
        if malformed_count:
            assumptions.append(
                f"{malformed_count} event(s) resembled JSON but failed to parse and "
                "were analyzed as plain text without structured fields."
            )

        result = SequenceAnalysisResult(
            agent=self.name,
            summary=summary,
            severity=overall,
            severity_score=overall_score,
            event_count=len(events),
            uncorrelated_event_count=uncorrelated,
            events=summaries,
            findings=findings,
            recommended_actions=self._recommend_sequence_actions(findings, overall),
            assumptions=assumptions,
        )
        return asdict(result)

    @staticmethod
    def _correlate(
        summaries: list[EventSummary],
        privileged_indices: set[int],
    ) -> list[CorrelatedFinding]:
        """Detect cross-event patterns; deterministic (sources scanned sorted).

        Correlation keys on each event's validated **source** (see
        ``_extract_source``) — never on the general indicator list, which can
        contain destination addresses shared by unrelated clients.
        """
        failures: dict[str, list[int]] = {}
        successes: dict[str, list[int]] = {}
        arp_events: dict[str, list[int]] = {}
        for entry in summaries:
            if entry.source is None:
                continue
            if entry.event_type == "authentication failure":
                failures.setdefault(entry.source, []).append(entry.index)
            elif entry.event_type == "successful login":
                successes.setdefault(entry.source, []).append(entry.index)
            elif entry.event_type == "arp spoofing":
                arp_events.setdefault(entry.source, []).append(entry.index)

        findings: list[CorrelatedFinding] = []
        for source, fail_indices in sorted(failures.items()):
            if len(fail_indices) >= _BRUTE_FORCE_THRESHOLD:
                privileged = any(i in privileged_indices for i in fail_indices)
                findings.append(
                    CorrelatedFinding(
                        pattern="brute_force",
                        source=source,
                        event_indices=list(fail_indices),
                        severity="critical" if privileged else "high",
                        description=(
                            f"{len(fail_indices)} authentication failures from {source}"
                            + (" targeting a privileged account." if privileged else ".")
                        ),
                    )
                )
            success_after = [i for i in successes.get(source, []) if i > fail_indices[0]]
            if success_after:
                # Only failures that precede the first correlated success are
                # evidence of the compromise chain; later failures are not.
                first_success = min(success_after)
                prior_failures = [i for i in fail_indices if i < first_success]
                findings.append(
                    CorrelatedFinding(
                        pattern="auth_failure_then_success",
                        source=source,
                        event_indices=sorted([*prior_failures, first_success]),
                        severity="critical",
                        description=(
                            f"Successful login from {source} after "
                            f"{len(prior_failures)} failed attempt(s) — possible "
                            "credential compromise."
                        ),
                    )
                )

        for source, indices in sorted(arp_events.items()):
            if len(indices) >= _ARP_SPOOF_BURST_THRESHOLD:
                findings.append(
                    CorrelatedFinding(
                        pattern="arp_spoof_burst",
                        source=source,
                        event_indices=list(indices),
                        severity="critical",
                        description=(
                            f"{len(indices)} ARP cache-poisoning indicators from "
                            f"{source} — active adversary-in-the-middle attempt; "
                            "traffic on this segment may be intercepted."
                        ),
                    )
                )
        return findings

    @staticmethod
    def _recommend_sequence_actions(
        findings: list[CorrelatedFinding],
        overall: Severity,
    ) -> list[str]:
        """Actions for a sequence analysis; pattern-specific, then escalation."""
        actions = [
            "Preserve the original log evidence.",
            "Correlate with adjacent timestamps.",
        ]
        if any(f.pattern == "brute_force" for f in findings):
            actions.extend(
                [
                    "Rate-limit or block the offending source address.",
                    "Review account lockout, MFA, and SSH exposure.",
                ]
            )
        if any(f.pattern == "auth_failure_then_success" for f in findings):
            actions.extend(
                [
                    "Treat the account as potentially compromised: force credential rotation.",
                    "Review follow-on session activity and terminate active sessions.",
                ]
            )
        if any(f.pattern == "arp_spoof_burst" for f in findings):
            actions.extend(
                [
                    "Isolate the offending MAC address at the switch port; capture "
                    "traffic on the affected segment before it is disturbed.",
                    "Treat credentials and session tokens used on that segment "
                    "during the window as exposed and rotate them.",
                    "Enable dynamic ARP inspection / port security on the segment.",
                ]
            )
        if overall in {"high", "critical"}:
            actions.append("Escalate for immediate human review.")
        return actions

    # ------------------------------------------------------------------
    # Input normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_input(
        log_input: str | dict[str, Any],
    ) -> tuple[str, dict[str, Any], ParseStatus]:
        """Return (flat_text, structured_fields, parse_status) from any input form.

        ``parse_status`` makes analysis degradation visible instead of silent:
        input that *looks like* JSON but fails to parse (truncated, malformed,
        or crafted almost-JSON) is analyzed as plain text — without structured
        fields such as ``severity`` and ``user`` — and is flagged
        ``malformed_json`` so downstream reports show the downgrade rather
        than a confident-looking full analysis.
        """
        if isinstance(log_input, dict):
            if not log_input:
                raise ValueError("log_input dict cannot be empty.")
            structured = {k: str(v) for k, v in log_input.items()}
            log_text = structured.get("message", " ".join(structured.values())).strip()
            if not log_text:
                raise ValueError("log_input contains no usable text.")
            return log_text, structured, "structured"

        if not isinstance(log_input, str):
            raise ValueError("log_input must be a string or dict.")

        text = log_input.strip()
        if not text:
            raise ValueError("log_input cannot be empty.")

        # Try to parse as JSON string
        if text.startswith("{"):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                return text, {}, "malformed_json"
            if isinstance(parsed, dict):
                structured = {k: str(v) for k, v in parsed.items()}
                log_text = structured.get("message", " ".join(structured.values())).strip()
                if not log_text:
                    raise ValueError("log_input contains no usable text.")
                return log_text, structured, "structured"

        return text, {}, "text"

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_event(log_text: str) -> str:
        lowered = log_text.lower()
        if "failed password" in lowered or "invalid user" in lowered:
            return "authentication failure"
        # ARP anomalies before the generic IDS/alert rule: an IDS alert *about*
        # ARP spoofing is still adversary-in-the-middle activity, and the
        # specific classification carries the T1557 mapping and severity.
        if "arp" in lowered and any(
            marker in lowered
            for marker in ("moved from", "is using my ip", "spoof", "poison", "duplicate")
        ):
            return "arp spoofing"
        # Further specific patterns before the generic IDS/alert rule, same
        # rationale as ARP: the specific classification carries the ATT&CK
        # mapping and severity even when the event arrives as an IDS alert.
        # These close the classifier gap with the shipped Sigma content
        # (account-creation / privileged-group / history-clear rule family).
        if (
            "history -c" in lowered
            or ".bash_history" in lowered
            or "log file cleared" in lowered
            or ("auditd" in lowered and any(m in lowered for m in ("stopped", "disabled")))
        ):
            return "log tampering"
        if (
            "group" in lowered
            and any(g in lowered for g in ("sudo", "wheel", "admin", "adm"))
            and any(m in lowered for m in ("usermod", "gpasswd", "added"))
        ):
            return "privileged group addition"
        if "useradd" in lowered or "new user" in lowered or "new account" in lowered:
            return "account creation"
        if any(m in lowered for m in ("nmap", "port scan", "portscan", "masscan")):
            return "port scan"
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

    # Whole words only: bare substring matching inflated severity on words
    # that merely *contain* an account name ("rootkit", "chroot", ...).
    _PRIVILEGED_WORD_RE = re.compile(r"\b(?:root|administrator)\b")

    @staticmethod
    def _is_privileged(log_text: str, structured: dict[str, Any]) -> bool:
        """True when the event involves a privileged account (root/administrator).

        The structured ``user``/``account`` field is authoritative when
        present; the flat log text is matched on whole words only, so
        "rootkit" or "chroot" no longer count as the root account.
        """
        user_val = structured.get("user", structured.get("account", "")).lower()
        if user_val in ("root", "administrator", "admin"):
            return True
        return bool(SocAnalystAgent._PRIVILEGED_WORD_RE.search(log_text.lower()))

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

        is_privileged = SocAnalystAgent._is_privileged(log_text, structured)
        if event_type == "authentication failure":
            return "high" if is_privileged else "medium"
        if event_type == "successful login":
            return "high" if is_privileged else "low"
        if event_type == "arp spoofing":
            # Adversary-in-the-middle setup: interception of credentials and
            # session data follows directly, so a single indicator is high.
            return "high"
        if event_type == "log tampering":
            # Destroying audit evidence is post-compromise behavior; treat a
            # single indicator as high — there is rarely a benign burst of it.
            return "high"
        if event_type == "privileged group addition":
            # Direct privilege escalation / persistence signal.
            return "high"
        if event_type == "account creation":
            # Low signal alone (routine onboarding), meaningful in sequence
            # with privilege changes — the Sigma correlation covers the chain.
            return "medium"
        if event_type == "port scan":
            return "medium"
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
        bonus = 0
        if SocAnalystAgent._is_privileged(log_text, structured):
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
    def _is_ipv4(token: str) -> bool:
        """True for a dotted-quad IPv4 address with in-range octets."""
        parts = token.split(".")
        return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

    @staticmethod
    def _is_ip(token: str) -> bool:
        """True for a valid IPv4 *or* IPv6 address literal.

        IPv6 matters for correlation coverage: matching only IPv4 would let an
        attacker on an IPv6 source evade sequence correlation by construction.
        Uses the stdlib parser (strict; rejects bare integers and hostnames).
        """
        try:
            ipaddress.ip_address(token)
        except ValueError:
            return False
        return True

    @staticmethod
    def _extract_source(log_text: str, structured: dict[str, Any]) -> str | None:
        """Return the validated *source* address for correlation, or ``None``.

        Uses an explicit structured source field when present, else the IPv4 or
        IPv6 address that directly follows ``from`` in plain text (bracketed
        ``[addr]`` IPv6 forms are unwrapped). Never falls back to the general
        indicator list — that list may contain destination addresses, and
        correlating on them would fabricate patterns (e.g. brute force "from"
        a destination shared by unrelated clients). Events that yield ``None``
        here are counted in ``uncorrelated_event_count`` so the exclusion is
        visible, never silent.
        """
        # src_host is the OpenCanary/canary event source field — without it,
        # canary events carry no source and silently drop out of correlation,
        # risk scoring, and labeling (found in review; pinned by test).
        for key in ("src_ip", "source_ip", "ip", "remote_addr", "src_host"):
            if key in structured:
                return str(structured[key])
        tokens = log_text.replace(",", " ").split()
        for pos, token in enumerate(tokens[:-1]):
            if token.lower() == "from":
                candidate = tokens[pos + 1].strip("[]():;")
                if SocAnalystAgent._is_ip(candidate):
                    return candidate
        return None

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
                if SocAnalystAgent._is_ipv4(stripped):
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
        if event_type == "log tampering":
            actions.extend(
                [
                    "Treat the host as compromised until reviewed — evidence destruction is post-compromise behavior.",
                    "Recover audit trail from remote/forwarded log copies.",
                ]
            )
        if event_type == "privileged group addition":
            actions.extend(
                [
                    "Verify the change against change-management records.",
                    "Review the target account's creation time and recent activity.",
                ]
            )
        if event_type == "account creation":
            actions.extend(
                [
                    "Confirm the account was provisioned through an approved process.",
                    "Watch for follow-on privilege changes on the same account.",
                ]
            )
        if event_type == "port scan":
            actions.extend(
                [
                    "Identify the scan source and whether it is an authorized scanner.",
                    "Review exposure of the probed ports and services.",
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
