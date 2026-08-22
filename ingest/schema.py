"""The canonical normalized event — one shape for five telemetry domains.

Today the platform reasons over syslog-shaped text through a keyword
classifier. That works for one domain and fails for the rest: a CloudTrail
``AssumeRole`` record or an Entra sign-in has no ``src_ip``, no flat message,
and nothing a keyword ladder can grip. This module defines the shape every
source is translated *into*, so downstream layers stop caring where an event
came from.

Design (DESIGN.md §5, new boundary 9):

* **OCSF-aligned, not OCSF-complete.** Field names follow the Open
  Cybersecurity Schema Framework's vocabulary (``actor``, ``device``,
  ``src_endpoint``, ``cloud``) so the model is recognizable and the existing
  ``agents/tools/ocsf.py`` class mapping applies. It is a working subset, not
  a claim of conformance — stated plainly rather than implied.
* **Fail closed and visible.** ``parse_status`` records how well the source
  was understood. Partial understanding is never presented as full: an event
  the parser could only partly read says so, and downstream reports surface
  the degradation instead of a confident-looking analysis.
* **Nothing derived is silently authoritative.** ``raw_excerpt`` keeps a
  bounded slice of the original for evidence, and every extracted field is
  either present or absent — never inferred from an absence.
* **Deterministic and offline.** No clock reads, no network, no filesystem.
  Timestamps come from the event; when a source omits one, the field stays
  ``None`` rather than being back-filled with "now", which would fabricate
  ordering the correlator later depends on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

#: The five telemetry domains the platform ingests. ``unknown`` is a real
#: outcome, not a failure to try: a source that cannot be confidently
#: identified is labelled rather than guessed into the wrong parser.
SourceType = Literal["endpoint", "network", "cloud", "identity", "email", "unknown"]

#: How completely the source was understood.
#: ``structured`` — parsed by a domain parser that recognized the format.
#: ``partial``    — recognized, but required fields were missing or malformed.
#: ``text``       — no parser claimed it; carried as opaque text.
ParseStatus = Literal["structured", "partial", "text"]

#: Bounds applied to every untrusted field. Telemetry arrives from systems the
#: platform does not control; an oversized field is either a bug upstream or
#: an attempt to exhaust memory downstream, and neither should be honored.
MAX_FIELD_LEN = 2048
MAX_RAW_EXCERPT = 4096
MAX_OBSERVABLES = 64
MAX_NESTING_DEPTH = 32
#: Hard ceiling on a single record. Beyond this the record is not parsed at
#: all — it is carried as a bounded excerpt with a note, so the event is
#: still visible to an analyst without a multi-megabyte payload traversing
#: the pipeline.
MAX_RAW_BYTES = 256 * 1024


@dataclass(frozen=True, slots=True)
class Actor:
    """Who acted — the identity dimension, however the source names it."""

    user_name: str | None = None
    user_uid: str | None = None
    #: User principal name / email form (``jdoe@corp.example``).
    user_principal: str | None = None
    #: Cloud identity (an ARN, a service-principal id).
    identity: str | None = None
    #: The process that acted, where the source has one.
    process_name: str | None = None
    process_pid: str | None = None
    parent_process_name: str | None = None
    command_line: str | None = None


@dataclass(frozen=True, slots=True)
class Device:
    """Where it happened."""

    hostname: str | None = None
    device_id: str | None = None
    ip: str | None = None
    os: str | None = None


@dataclass(frozen=True, slots=True)
class Endpoint:
    """One side of a network conversation."""

    ip: str | None = None
    port: str | None = None
    domain: str | None = None


@dataclass(frozen=True, slots=True)
class CloudContext:
    """Cloud control-plane coordinates."""

    provider: str | None = None
    account_uid: str | None = None
    region: str | None = None
    service: str | None = None


@dataclass(frozen=True, slots=True)
class EmailContext:
    """Message metadata.

    Deliberately carries a ``subject`` but no body: message content is the
    most sensitive field in the corpus and the detection value lives in the
    metadata. There is no field for a body, so one cannot be added by
    accident (AGENTS.md §5 — sensitive data by default).
    """

    sender: str | None = None
    recipients: tuple[str, ...] = ()
    subject: str | None = None
    message_id: str | None = None
    #: Verdict a mail platform already reached, carried verbatim.
    delivery_action: str | None = None
    urls: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    """One telemetry event in the platform's canonical shape."""

    source_type: SourceType
    #: The product that emitted it (``sysmon``, ``zeek``, ``cloudtrail``…).
    vendor: str
    #: Vendor's own event identifier, where one exists.
    vendor_event_id: str | None
    #: Epoch seconds. ``None`` when the source carried no usable timestamp —
    #: never back-filled, because fabricated ordering corrupts correlation.
    timestamp: float | None
    #: Human-readable summary, used by the existing text classifier as a
    #: fallback and rendered in reports.
    message: str
    activity: str | None
    parse_status: ParseStatus
    actor: Actor = field(default_factory=Actor)
    device: Device = field(default_factory=Device)
    src_endpoint: Endpoint = field(default_factory=Endpoint)
    dst_endpoint: Endpoint = field(default_factory=Endpoint)
    cloud: CloudContext = field(default_factory=CloudContext)
    email: EmailContext = field(default_factory=EmailContext)
    #: Atomic indicators extracted from the event, deduplicated and ordered.
    observables: tuple[str, ...] = ()
    #: Bounded slice of the original, retained as evidence.
    raw_excerpt: str = ""
    #: Why the parse was partial, when it was. Empty for a clean parse.
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Allow-list projection — only declared fields serialize.

        Same discipline as the response layer: an event's raw payload never
        rides along into a downstream artifact, because there is no field for
        it beyond the bounded excerpt.
        """
        return {
            "source_type": self.source_type,
            "vendor": self.vendor,
            "vendor_event_id": self.vendor_event_id,
            "timestamp": self.timestamp,
            "message": self.message,
            "activity": self.activity,
            "parse_status": self.parse_status,
            "actor": {
                "user_name": self.actor.user_name,
                "user_uid": self.actor.user_uid,
                "user_principal": self.actor.user_principal,
                "identity": self.actor.identity,
                "process_name": self.actor.process_name,
                "process_pid": self.actor.process_pid,
                "parent_process_name": self.actor.parent_process_name,
                "command_line": self.actor.command_line,
            },
            "device": {
                "hostname": self.device.hostname,
                "device_id": self.device.device_id,
                "ip": self.device.ip,
                "os": self.device.os,
            },
            "src_endpoint": {
                "ip": self.src_endpoint.ip,
                "port": self.src_endpoint.port,
                "domain": self.src_endpoint.domain,
            },
            "dst_endpoint": {
                "ip": self.dst_endpoint.ip,
                "port": self.dst_endpoint.port,
                "domain": self.dst_endpoint.domain,
            },
            "cloud": {
                "provider": self.cloud.provider,
                "account_uid": self.cloud.account_uid,
                "region": self.cloud.region,
                "service": self.cloud.service,
            },
            "email": {
                "sender": self.email.sender,
                "recipients": list(self.email.recipients),
                "subject": self.email.subject,
                "message_id": self.email.message_id,
                "delivery_action": self.email.delivery_action,
                "urls": list(self.email.urls),
            },
            "observables": list(self.observables),
            "raw_excerpt": self.raw_excerpt,
            "notes": list(self.notes),
        }

    def to_match_view(self) -> dict[str, str]:
        """Flatten to the string map detection rules match against.

        This is the bridge to ``agents/tools/sigma_eval`` and the mapping
        engine: both take a flat ``dict[str, str]``. Absent fields are omitted
        rather than rendered as empty strings, so a rule keyed on a field the
        source never carried simply does not fire — the same fail-quiet
        semantics the evaluator already gives a missing field.
        """
        flat: dict[str, str] = {
            "source_type": self.source_type,
            "vendor": self.vendor,
            "message": self.message,
        }
        pairs: tuple[tuple[str, str | None], ...] = (
            ("activity", self.activity),
            ("user", self.actor.user_name),
            ("user_principal", self.actor.user_principal),
            ("identity", self.actor.identity),
            ("image", self.actor.process_name),
            ("parent_image", self.actor.parent_process_name),
            ("command_line", self.actor.command_line),
            ("host", self.device.hostname),
            ("device_id", self.device.device_id),
            ("src_ip", self.src_endpoint.ip),
            ("src_port", self.src_endpoint.port),
            ("dst_ip", self.dst_endpoint.ip),
            ("dst_port", self.dst_endpoint.port),
            ("dst_domain", self.dst_endpoint.domain),
            ("cloud_provider", self.cloud.provider),
            ("cloud_account", self.cloud.account_uid),
            ("cloud_region", self.cloud.region),
            ("cloud_service", self.cloud.service),
            ("email_sender", self.email.sender),
            ("email_subject", self.email.subject),
            ("delivery_action", self.email.delivery_action),
        )
        for key, value in pairs:
            if value:
                flat[key] = value
        return flat
