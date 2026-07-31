"""OCSF (Open Cybersecurity Schema Framework) event-class normalization.

Maps this platform's deterministic SOC ``event_type`` labels to their OCSF
event classes (category → class_uid → class_name), so classifier output is
aligned to the vendor-neutral schema the industry is converging on (OCSF
joined the Linux Foundation, Nov 2024). Pure, deterministic, offline, and
dependency-free: it is a static lookup over a versioned mapping table, not a
runtime schema fetch.

Reference: https://schema.ocsf.io/ (class UIDs below are from the 1.x schema).
The mapping is intentionally conservative — an unmapped event type returns the
Base Event class (uid 0) rather than guessing, so a new event type can never
be silently mis-normalized.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

# OCSF schema version this mapping table targets (recorded on every result so
# a future schema bump is an explicit, reviewable change).
OCSF_SCHEMA_VERSION = "1.5.0"


@dataclass(frozen=True)
class OcsfClass:
    """An OCSF event class: category + class identity."""

    category_uid: int
    category_name: str
    class_uid: int
    class_name: str


# OCSF Base Event — the fail-closed default for anything not explicitly mapped.
_BASE_EVENT = OcsfClass(0, "Uncategorized", 0, "Base Event")

# SOC event_type -> OCSF class. Categories: 1 System Activity, 2 Findings,
# 3 Identity & Access Management, 4 Network Activity, 6 Application Activity.
_EVENT_TYPE_TO_OCSF: dict[str, OcsfClass] = {
    "authentication failure": OcsfClass(3, "Identity & Access Management", 3002, "Authentication"),
    "successful login": OcsfClass(3, "Identity & Access Management", 3002, "Authentication"),
    "account creation": OcsfClass(3, "Identity & Access Management", 3001, "Account Change"),
    "privileged group addition": OcsfClass(
        3, "Identity & Access Management", 3001, "Account Change"
    ),
    "firewall block": OcsfClass(4, "Network Activity", 4001, "Network Activity"),
    "port scan": OcsfClass(4, "Network Activity", 4001, "Network Activity"),
    "arp spoofing": OcsfClass(4, "Network Activity", 4001, "Network Activity"),
    "network anomaly": OcsfClass(4, "Network Activity", 4001, "Network Activity"),
    "ids alert": OcsfClass(2, "Findings", 2004, "Detection Finding"),
    "log tampering": OcsfClass(1, "System Activity", 1008, "File System Activity"),
    "unknown security event": _BASE_EVENT,
}


def classify(event_type: str) -> OcsfClass:
    """Return the OCSF class for a SOC ``event_type`` (Base Event if unmapped)."""
    return _EVENT_TYPE_TO_OCSF.get(event_type, _BASE_EVENT)


def normalize(event_type: str) -> dict[str, Any]:
    """Return a JSON-ready OCSF descriptor for ``event_type``.

    Includes the schema version and a ``mapped`` flag so an unmapped type (fell
    through to Base Event) is visible rather than looking like a real class-0
    event.
    """
    ocsf = classify(event_type)
    descriptor = asdict(ocsf)
    descriptor["schema_version"] = OCSF_SCHEMA_VERSION
    descriptor["mapped"] = event_type in _EVENT_TYPE_TO_OCSF
    return descriptor
