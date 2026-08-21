"""Threat Intel Agent — indicator triage over the local intel library.

Classifies an indicator (IP / domain / hash / unknown) with the stdlib
``ipaddress`` parser — loopback, link-local (incl. 169.254.169.254), CGNAT,
multicast, and reserved space are recognized instead of being called
"public", and malformed addresses (leading-zero octets, non-ASCII digits)
are rejected by the parser rather than hand-rolled string checks. Public
indicators are then looked up in the committed intel library
(``intel/``): verdicts carry provenance, decayed confidence, and the
two-source corroboration cap; internal/reserved space is policy-suppressed.

Deterministic and network-free: ``as_of`` for decay is injected by the
caller or defaults to the store's newest retrieval date — never a wall
clock. Fail-soft on library absence: classification still works and the
result says the library was unavailable, never guesses.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from datetime import date
from typing import Any, Literal

from attack import AttackError
from intel import IntelStore, IntelStoreError, default_as_of, load_store, lookup_indicator

Confidence = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class ThreatIntelResult:
    indicator: str
    indicator_type: str
    risk_level: str
    confidence: Confidence
    explanation: str
    recommended_actions: list[str]


class ThreatIntelAgent:
    def __init__(self, store: IntelStore | None = None) -> None:
        # Fail-soft: a missing/invalid library must not break triage — the
        # agent still classifies, and results say enrichment was unavailable.
        if store is not None:
            self._store: IntelStore | None = store
        else:
            try:
                self._store = load_store()
            except (IntelStoreError, AttackError, OSError):
                self._store = None

    def analyze_indicator(self, indicator: str, *, as_of: date | None = None) -> dict[str, Any]:
        cleaned = indicator.strip()
        if not cleaned:
            raise ValueError("indicator cannot be empty")

        address = self._parse_ip(cleaned)
        if address is not None:
            return self._analyze_ip(cleaned, address, as_of)
        if "." in cleaned:
            return self._enriched(
                cleaned,
                indicator_type="domain",
                base_risk="unknown",
                base_confidence="medium",
                explanation="Domain requires DNS, WHOIS, and reputation review.",
                actions=[
                    "Check DNS records.",
                    "Review domain age and registrar.",
                    "Search logs for related DNS queries.",
                ],
                as_of=as_of,
            )
        return asdict(
            ThreatIntelResult(
                indicator=cleaned,
                indicator_type="unknown",
                risk_level="unknown",
                confidence="low",
                explanation="Indicator type could not be confidently classified.",
                recommended_actions=[
                    "Review original evidence.",
                    "Add parsing rules if this indicator appears repeatedly.",
                ],
            )
        )

    @staticmethod
    def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        """Strict stdlib parsing: leading-zero octets and non-ASCII digits fail."""
        if not value.isascii():
            return None
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            return None

    # Explicit internal-address membership. Deliberately NOT ipaddress.is_private,
    # which is wrong in both directions for this purpose: it returns True for
    # RFC 5737 documentation ranges (which must flow through enrichment — the
    # synthetic seed lives there) and its treatment of CGNAT 100.64/10 differs
    # across Python versions. Policy lists beat stdlib heuristics here.
    _INTERNAL_NETWORKS = tuple(
        ipaddress.ip_network(cidr)
        for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
    )

    def _analyze_ip(
        self,
        cleaned: str,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        as_of: date | None,
    ) -> dict[str, Any]:
        if any(address in network for network in self._INTERNAL_NETWORKS):
            return asdict(
                ThreatIntelResult(
                    indicator=cleaned,
                    indicator_type="private_ip",
                    risk_level="context-dependent",
                    confidence="high",
                    explanation=(
                        "Private IP addresses are internal and require local network context."
                    ),
                    recommended_actions=[
                        "Correlate with asset inventory.",
                        "Check authentication and firewall logs.",
                        "Determine whether the host behavior is expected.",
                    ],
                )
            )
        if address.is_loopback or address.is_link_local or address.is_multicast:
            kind = (
                "loopback_ip"
                if address.is_loopback
                else "link_local_ip"
                if address.is_link_local
                else "multicast_ip"
            )
            return asdict(
                ThreatIntelResult(
                    indicator=cleaned,
                    indicator_type=kind,
                    risk_level="context-dependent",
                    confidence="high",
                    explanation=(
                        "Reserved-scope address (loopback/link-local/multicast): it cannot "
                        "be an external actor — 169.254.169.254 in particular is the cloud "
                        "metadata service, a classic SSRF target, not a remote attacker."
                    ),
                    recommended_actions=[
                        "Treat as local-context evidence, not an external indicator.",
                        "If this address appears as a request *target*, review for SSRF.",
                    ],
                )
            )
        return self._enriched(
            cleaned,
            indicator_type="public_ip",
            base_risk="unknown",
            base_confidence="medium",
            explanation="Public IP requires external reputation enrichment before classification.",
            actions=[
                "Check threat intelligence feeds.",
                "Review geolocation and ASN.",
                "Correlate with IDS, firewall, and authentication events.",
            ],
            as_of=as_of,
        )

    def _enriched(
        self,
        cleaned: str,
        *,
        indicator_type: str,
        base_risk: str,
        base_confidence: Confidence,
        explanation: str,
        actions: list[str],
        as_of: date | None,
    ) -> dict[str, Any]:
        """Base classification + committed-library verdict when one exists."""
        result = asdict(
            ThreatIntelResult(
                indicator=cleaned,
                indicator_type=indicator_type,
                risk_level=base_risk,
                confidence=base_confidence,
                explanation=explanation,
                recommended_actions=actions,
            )
        )
        if self._store is None:
            result["intel"] = {"available": False, "note": "local intel library unavailable"}
            return result
        anchor = default_as_of(self._store) if as_of is None else as_of
        verdict = lookup_indicator(self._store, cleaned, as_of=anchor)
        result["intel"] = {
            "available": True,
            "as_of": anchor.isoformat(),
            "matched": verdict.matched,
            "risk": verdict.risk,
            "confidence": verdict.confidence,
            "decayed_score": verdict.decayed_score,
            "sources": list(verdict.sources),
            "references": list(verdict.references),
            "notes": list(verdict.notes),
        }
        if verdict.matched and verdict.risk in ("malicious", "suspicious"):
            result["risk_level"] = verdict.risk
            result["explanation"] = (
                f"{explanation} Local intel library: {verdict.risk} "
                f"(sources: {', '.join(verdict.sources)})."
            )
        return result


if __name__ == "__main__":
    agent = ThreatIntelAgent()
    print(agent.analyze_indicator("192.168.1.50"))
