"""Deterministic source labeling: scanner taxonomy, lab darknet, canary hits.

Implements the ingestion half of the deception/labeling research candidate,
fully local and deterministic (no feeds, no phone-home):

* **Four-way scanner taxonomy** (the GreyNoise-style label set): a source IP
  is labeled ``benign-scanner`` / ``suspicious`` / ``malicious`` / ``unknown``
  from *static, versioned, human-reviewed* lists — never a live service.
* **Lab darknet**: traffic addressed to designated unused subnets is
  auto-labeled ``suspicious`` — unused space should receive zero traffic, so
  anything arriving is recon, misconfiguration, or propagation by definition.
* **Canary awareness**: OpenCanary-style JSON events are recognized as a
  near-zero-false-positive signal (``is_canary_event``); any canary hit marks
  its source ``malicious`` for labeling purposes — nothing legitimate touches
  a canary.

The seed lists are deliberately code, not runtime config: changing them is a
reviewed PR (provenance + human review), never a runtime mutation. Documented
research-scanner ranges (Shodan, Censys, Shadowserver publish theirs) belong
in ``BENIGN_SCANNER_RANGES`` once verified against the provider's official
publication; the bundled entries use RFC 5737 documentation ranges so tests
and demos never touch real infrastructure.

Security posture (AGENTS.md §3/§5): read-only, network-free, fail-closed on
malformed input, and every label is explainable — each result carries the
rule that produced it.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass
from typing import Any, Literal

ScannerLabel = Literal["benign-scanner", "suspicious", "malicious", "unknown"]

#: Known research/vetted scanner source ranges (verify against the provider's
#: official publication before adding real ranges). Documentation range used
#: as the bundled example.
BENIGN_SCANNER_RANGES: tuple[str, ...] = ("192.0.2.0/29",)

#: Sources an operator has confirmed hostile (incident-derived; lab-scoped).
MALICIOUS_RANGES: tuple[str, ...] = ()

#: Designated unused ("darknet") subnets in the lab — traffic *to* these is
#: suspicious by definition. Documentation range as the bundled example.
LAB_DARKNET_SUBNETS: tuple[str, ...] = ("203.0.113.224/27",)


@dataclass(frozen=True)
class SourceLabel:
    """An explainable label for one source address."""

    source: str
    label: ScannerLabel
    rule: str


def _networks(ranges: tuple[str, ...]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    return [ipaddress.ip_network(r) for r in ranges]


def _in_any(ip: str, ranges: tuple[str, ...]) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in _networks(ranges))


def label_source(
    source: str,
    *,
    canary_hit: bool = False,
    darknet_destination: bool = False,
) -> dict[str, Any]:
    """Label one source address; deterministic, most-severe rule wins.

    Precedence (severe -> benign): canary hit > operator-confirmed malicious
    range > darknet destination > benign-scanner range > unknown. A source
    that trips a canary is malicious even if it also sits in a benign-scanner
    range — vetted scanners do not authenticate to canaries.
    """
    if not isinstance(source, str) or not source.strip():
        raise ValueError("source must be a non-empty string.")
    if canary_hit:
        return asdict(SourceLabel(source, "malicious", "canary interaction (near-zero-FP)"))
    if _in_any(source, MALICIOUS_RANGES):
        return asdict(SourceLabel(source, "malicious", "operator-confirmed malicious range"))
    if darknet_destination:
        return asdict(
            SourceLabel(source, "suspicious", "traffic to designated unused (darknet) subnet")
        )
    if _in_any(source, BENIGN_SCANNER_RANGES):
        return asdict(SourceLabel(source, "benign-scanner", "documented research-scanner range"))
    return asdict(SourceLabel(source, "unknown", "no matching list or deception signal"))


def is_darknet_destination(destination: str) -> bool:
    """True when ``destination`` falls inside a designated lab-darknet subnet."""
    return _in_any(destination, LAB_DARKNET_SUBNETS)


def is_canary_event(log_input: str | dict[str, Any]) -> bool:
    """True for an OpenCanary-style JSON event (dict or JSON string).

    OpenCanary events carry ``logtype`` (an integer code) plus ``src_host``
    and ``dst_host`` fields. Detection is structural — no network, no
    dependency on OpenCanary being installed — and conservative: anything
    that does not match the shape is simply not a canary event (never an
    error), so this can be probed against arbitrary log lines.
    """
    data: Any = log_input
    if isinstance(data, str):
        text = data.strip()
        if not text.startswith("{"):
            return False
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return False
    if not isinstance(data, dict):
        return False
    return "logtype" in data and ("src_host" in data or "dst_host" in data)


def canary_source(log_input: str | dict[str, Any]) -> str | None:
    """Return the source address from a canary event, or None if not one."""
    if not is_canary_event(log_input):
        return None
    data: Any = log_input
    if isinstance(data, str):
        data = json.loads(data.strip())
    source = data.get("src_host", "")
    return str(source) if source else None
