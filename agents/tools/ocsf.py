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
    # 1008 is Event Log Activity in the OCSF 1.x System Activity category —
    # which is the right class for audit-log tampering. It was previously
    # labelled "File System Activity" here (that is 1001); the uid was always
    # correct, only the name was wrong.
    "log tampering": OcsfClass(1, "System Activity", 1008, "Event Log Activity"),
    "unknown security event": _BASE_EVENT,
}


# --------------------------------------------------------------------------
# Multi-source (XDR) classification
# --------------------------------------------------------------------------

# The tables above key off the text classifier's ``event_type``. Multi-source
# telemetry arrives already structured (see ``ingest/``), carrying a
# ``source_type`` and a vendor-stable ``activity`` — a far better basis for
# an OCSF class than re-deriving one from prose. These tables key off that
# pair, with the same conservative rule: no entry means Base Event, never a
# guess at the closest-looking class.

_PROCESS_ACTIVITY = OcsfClass(1, "System Activity", 1007, "Process Activity")
_FILE_ACTIVITY = OcsfClass(1, "System Activity", 1001, "File System Activity")
_MODULE_ACTIVITY = OcsfClass(1, "System Activity", 1005, "Module Activity")
_SCHEDULED_JOB = OcsfClass(1, "System Activity", 1006, "Scheduled Job Activity")
_EVENT_LOG_ACTIVITY = OcsfClass(1, "System Activity", 1008, "Event Log Activity")
_DETECTION_FINDING = OcsfClass(2, "Findings", 2004, "Detection Finding")
_AUTHENTICATION = OcsfClass(3, "Identity & Access Management", 3002, "Authentication")
_ACCOUNT_CHANGE = OcsfClass(3, "Identity & Access Management", 3001, "Account Change")
_NETWORK_ACTIVITY = OcsfClass(4, "Network Activity", 4001, "Network Activity")
_HTTP_ACTIVITY = OcsfClass(4, "Network Activity", 4002, "HTTP Activity")
_DNS_ACTIVITY = OcsfClass(4, "Network Activity", 4003, "DNS Activity")
_EMAIL_ACTIVITY = OcsfClass(4, "Network Activity", 4009, "Email Activity")
_API_ACTIVITY = OcsfClass(6, "Application Activity", 6003, "API Activity")

#: (source_type, activity) -> OCSF class. Activities are the vocabulary the
#: ``ingest/`` parsers emit, which is why they are enumerable at all.
_SOURCE_ACTIVITY_TO_OCSF: dict[tuple[str, str], OcsfClass] = {
    # Endpoint — Sysmon
    ("endpoint", "process creation"): _PROCESS_ACTIVITY,
    ("endpoint", "process terminated"): _PROCESS_ACTIVITY,
    ("endpoint", "process access"): _PROCESS_ACTIVITY,
    ("endpoint", "process tampering"): _PROCESS_ACTIVITY,
    ("endpoint", "create remote thread"): _PROCESS_ACTIVITY,
    ("endpoint", "image loaded"): _MODULE_ACTIVITY,
    ("endpoint", "driver loaded"): _MODULE_ACTIVITY,
    ("endpoint", "file created"): _FILE_ACTIVITY,
    ("endpoint", "file deleted"): _FILE_ACTIVITY,
    ("endpoint", "file delete detected"): _FILE_ACTIVITY,
    ("endpoint", "file stream created"): _FILE_ACTIVITY,
    ("endpoint", "file creation time changed"): _FILE_ACTIVITY,
    ("endpoint", "network connection"): _NETWORK_ACTIVITY,
    ("endpoint", "dns query"): _DNS_ACTIVITY,
    # Endpoint — auditd
    ("endpoint", "execve"): _PROCESS_ACTIVITY,
    ("endpoint", "syscall"): _PROCESS_ACTIVITY,
    ("endpoint", "proctitle"): _PROCESS_ACTIVITY,
    ("endpoint", "path"): _FILE_ACTIVITY,
    ("endpoint", "user_auth"): _AUTHENTICATION,
    ("endpoint", "user_login"): _AUTHENTICATION,
    ("endpoint", "user_acct"): _AUTHENTICATION,
    ("endpoint", "cred_acq"): _AUTHENTICATION,
    ("endpoint", "add_user"): _ACCOUNT_CHANGE,
    ("endpoint", "add_group"): _ACCOUNT_CHANGE,
    ("endpoint", "daemon_end"): _EVENT_LOG_ACTIVITY,
    ("endpoint", "daemon_abort"): _EVENT_LOG_ACTIVITY,
    ("endpoint", "service_start"): _SCHEDULED_JOB,
    ("endpoint", "service_stop"): _SCHEDULED_JOB,
    # Network — Zeek streams and Suricata event types share these names.
    ("network", "conn"): _NETWORK_ACTIVITY,
    ("network", "flow"): _NETWORK_ACTIVITY,
    ("network", "dns"): _DNS_ACTIVITY,
    ("network", "http"): _HTTP_ACTIVITY,
    ("network", "ssl"): _NETWORK_ACTIVITY,
    ("network", "tls"): _NETWORK_ACTIVITY,
    ("network", "alert"): _DETECTION_FINDING,
    ("network", "notice"): _DETECTION_FINDING,
    ("network", "anomaly"): _DETECTION_FINDING,
    # Identity
    ("identity", "sign-in"): _AUTHENTICATION,
    # Email
    ("email", "email delivery"): _EMAIL_ACTIVITY,
}

#: Okta reports a dotted event vocabulary; these prefixes are stable enough
#: to classify on. Anything else falls through to Base Event.
_IDENTITY_PREFIX_TO_OCSF: tuple[tuple[str, OcsfClass], ...] = (
    ("user.authentication", _AUTHENTICATION),
    ("user.session", _AUTHENTICATION),
    ("user.lifecycle", _ACCOUNT_CHANGE),
    ("user.account", _ACCOUNT_CHANGE),
    ("group.user_membership", _ACCOUNT_CHANGE),
    ("security.threat", _DETECTION_FINDING),
)

#: Per-domain defaults, used only where the whole domain maps to one class
#: without ambiguity. Endpoint, network, and identity are deliberately absent:
#: their records span several classes, so an unmatched activity there yields
#: Base Event rather than a plausible-looking wrong answer.
_SOURCE_DEFAULT_OCSF: dict[str, OcsfClass] = {
    "cloud": _API_ACTIVITY,
    "email": _EMAIL_ACTIVITY,
}


def classify(event_type: str) -> OcsfClass:
    """Return the OCSF class for a SOC ``event_type`` (Base Event if unmapped)."""
    return _EVENT_TYPE_TO_OCSF.get(event_type, _BASE_EVENT)


def classify_normalized(source_type: str, activity: str | None) -> OcsfClass:
    """Return the OCSF class for a normalized multi-source event.

    Args:
        source_type: One of the ``ingest`` domains (``endpoint``, ``network``,
            ``cloud``, ``identity``, ``email``, ``unknown``).
        activity: The parser's vocabulary term for what happened, or ``None``.

    Falls back to the domain default only where a domain maps unambiguously
    to one class, and otherwise to Base Event — an unrecognized activity is
    reported as unclassified rather than assigned the nearest-looking class.
    """
    key = (source_type, (activity or "").strip().lower())
    exact = _SOURCE_ACTIVITY_TO_OCSF.get(key)
    if exact is not None:
        return exact
    if source_type == "identity" and activity:
        lowered = activity.strip().lower()
        for prefix, ocsf in _IDENTITY_PREFIX_TO_OCSF:
            if lowered.startswith(prefix):
                return ocsf
    return _SOURCE_DEFAULT_OCSF.get(source_type, _BASE_EVENT)


def normalize_source_event(source_type: str, activity: str | None) -> dict[str, Any]:
    """JSON-ready OCSF descriptor for a normalized multi-source event.

    ``mapped`` is ``True`` only when the class came from an explicit table
    entry or prefix rule — a domain default or a Base Event fallback reports
    ``False``, so "we classified this" is never confused with "we defaulted".
    """
    ocsf = classify_normalized(source_type, activity)
    descriptor = asdict(ocsf)
    descriptor["schema_version"] = OCSF_SCHEMA_VERSION
    key = (source_type, (activity or "").strip().lower())
    prefixed = source_type == "identity" and any(
        (activity or "").strip().lower().startswith(prefix)
        for prefix, _ in _IDENTITY_PREFIX_TO_OCSF
    )
    descriptor["mapped"] = key in _SOURCE_ACTIVITY_TO_OCSF or prefixed
    return descriptor


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
