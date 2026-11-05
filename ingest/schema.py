# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

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

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Literal, TypeVar, cast, get_args

from ingest.errors import MalformedProjectionError

#: One of the nested groups whose every field is an optional string. Named so
#: :func:`_clip_group` keeps the group's own type rather than widening every
#: caller's. ``EmailContext`` is excluded: it also carries two collections,
#: so it is bounded field by field.
_GroupT = TypeVar("_GroupT", "Actor", "Device", "Endpoint", "CloudContext")

#: The five telemetry domains the platform ingests. ``unknown`` is a real
#: outcome, not a failure to try: a source that cannot be confidently
#: identified is labelled rather than guessed into the wrong parser.
SourceType = Literal["endpoint", "network", "cloud", "identity", "email", "unknown"]

#: How completely the source was understood.
#: ``structured`` — parsed by a domain parser that recognized the format.
#: ``partial``    — recognized, but required fields were missing or malformed.
#: ``text``       — no parser claimed it; carried as opaque text.
ParseStatus = Literal["structured", "partial", "text"]

#: Literal members for read-time validation, derived from the types above
#: via ``get_args`` so a new source type or parse status cannot be accepted
#: by one and rejected by the other.
SOURCE_TYPE_VALUES: frozenset[str] = frozenset(get_args(SourceType))
PARSE_STATUS_VALUES: frozenset[str] = frozenset(get_args(ParseStatus))

#: Bounds applied to every untrusted field. Telemetry arrives from systems the
#: platform does not control; an oversized field is either a bug upstream or
#: an attempt to exhaust memory downstream, and neither should be honored.
MAX_FIELD_LEN = 2048
MAX_RAW_EXCERPT = 4096
MAX_OBSERVABLES = 64
#: How many entries a single declared evidence path may contribute when it
#: lands on a container. A record carrying a thousand-element list must not
#: be able to inflate an excerpt, and a parser that models a list models a
#: bounded one — ``email``'s recipient cap is the same number for the same
#: reason.
MAX_PROJECTED_ITEMS = 32
#: Parser notes per event. Bounded for the same reason as observables:
#: on read the ceiling is what distinguishes a record this platform wrote
#: from one that grew outside it.
MAX_NOTES = 64
MAX_NESTING_DEPTH = 32
#: Hard ceiling on a single record. Beyond this the record is not parsed at
#: all — it is carried as a bounded excerpt with a note, so the event is
#: still visible to an analyst without a multi-megabyte payload traversing
#: the pipeline.
MAX_RAW_BYTES = 256 * 1024
#: Ceiling on one event's canonical projection (:func:`canonical_json`), in
#: UTF-8 bytes. The store refuses a projection past it, and it is defined here
#: rather than there because this package is the one that has to *apply* it:
#: every bound above is per field, and a sum of bounded fields has no ceiling
#: of its own. ``store.schema`` re-exports this constant, so the number the
#: store refuses past and the number :func:`fit_projection` fits under are one
#: definition and cannot drift. See :meth:`NormalizedEvent.bounded`.
MAX_PROJECTION_BYTES = 64 * 1024


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

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> NormalizedEvent:
        """Rebuild an event from :meth:`to_dict`, validating fail-closed.

        The inverse of the allow-list projection, and deliberately the *only*
        one: a second hand-rolled reader living beside the writer is how two
        definitions of one shape drift apart. ``store/`` reads events back
        through this method rather than reimplementing the mapping.

        Unlike :func:`ingest.normalize`, this does **not** degrade. A
        projection is not raw telemetry — it is a record this platform wrote
        itself. A missing key, a wrong type, an undeclared key, or a field
        past its bound means the row is corrupt or was edited outside this
        platform, and rebuilding a plausible-looking event from a damaged row
        would launder that damage into every analysis drawn from it.

        Bounds are re-asserted rather than trusted: the writer applied them,
        but the bytes have been outside this process since.
        """
        if not isinstance(payload, Mapping):
            raise MalformedProjectionError(
                f"event projection must be a mapping, got {type(payload).__name__}"
            )
        _require_exact_keys(payload, _EVENT_KEYS, "event")
        return cls(
            source_type=cast(
                SourceType, _literal(payload, "source_type", SOURCE_TYPE_VALUES, "event")
            ),
            vendor=_text(payload, "vendor", "event", required=True),
            vendor_event_id=_optional_text(payload, "vendor_event_id", "event"),
            timestamp=_optional_epoch(payload, "timestamp", "event"),
            message=_text(payload, "message", "event", required=False),
            activity=_optional_text(payload, "activity", "event"),
            parse_status=cast(
                ParseStatus, _literal(payload, "parse_status", PARSE_STATUS_VALUES, "event")
            ),
            actor=Actor(**_group(payload, "actor", _ACTOR_KEYS)),
            device=Device(**_group(payload, "device", _DEVICE_KEYS)),
            src_endpoint=Endpoint(**_group(payload, "src_endpoint", _ENDPOINT_KEYS)),
            dst_endpoint=Endpoint(**_group(payload, "dst_endpoint", _ENDPOINT_KEYS)),
            cloud=CloudContext(**_group(payload, "cloud", _CLOUD_KEYS)),
            email=_email_from(payload),
            observables=_str_tuple(payload, "observables", "event", MAX_OBSERVABLES),
            raw_excerpt=_text(
                payload, "raw_excerpt", "event", required=False, limit=MAX_RAW_EXCERPT
            ),
            notes=_str_tuple(payload, "notes", "event", MAX_NOTES),
        )

    def bounded(self) -> NormalizedEvent:
        """Return this event as the store will accept it: every bound, per field and in total.

        :meth:`clipped` applies each field's own bound, and that used to be the
        whole of this method. It was not enough to keep the promise made below,
        that a direct caller can make any event storable. ``from_dict`` bounds
        fields one at a time, while the store also refuses a projection past
        :data:`MAX_PROJECTION_BYTES`, and a sum of individually bounded fields
        has no ceiling of its own: thirty scalars at ``MAX_FIELD_LEN`` and four
        lists of sixty-four entries allow a projection of 2,351,090 bytes in
        four-byte characters, about thirty-six times the ceiling.
        Measured through ``ingest.normalize`` on ``2c92e3f``: a Defender record
        with thirty 2,000-character URLs, as one 61,670-byte line (under
        ``collect/``'s 64 KiB line cap), projected to 66,729 bytes. A Sysmon
        record with **no list entries at all**, its modelled fields 2,048 CJK
        characters each, projected to 79,278. That one is a 104,875-byte line,
        so ``collect/`` would cut it before parsing, but ``normalize`` is not
        only reached through ``collect/``, and it shows that bounding the lists
        harder could not have been enough on its own.

        So this also fits the total, through :func:`fit_projection`. An event
        already within the ceiling comes back from that step unchanged. Like
        :meth:`clipped`, this is silent; ``ingest.normalize`` calls the two
        steps separately, so that it can note which one bit and demote
        ``parse_status``.
        """
        return fit_projection(self.clipped())[0]

    def clipped(self) -> NormalizedEvent:
        """Return this event with every per-field read-time bound applied on write.

        The write-side twin of the validation in :meth:`from_dict`, kept
        beside it for the reason ``from_dict`` itself exists: a bound
        *asserted* in one place and *applied* in another drifts, and when
        this one drifted the symptom was not a rejected record but a stored
        one that could never be read back.

        **The defect this closes.** Every individual field a parser writes is
        bounded by ``text()`` at :data:`MAX_FIELD_LEN`. ``message`` is not a
        field — it is assembled from several of them, and nothing re-bounded
        the result, while ``from_dict`` validates it at ``MAX_FIELD_LEN``
        like any other. An ordinary encoded-PowerShell ``CommandLine`` —
        the single most common malicious artifact in endpoint telemetry —
        produces a 2168-character message, which ``append`` accepted and
        every subsequent ``query`` then refused with
        ``MalformedProjectionError``. ``run_cycle`` does not catch it, so one
        such record stopped every later detection cycle on that store, for
        good. Nine of the fifteen ingest fixtures reproduce it under
        ``MAX_FIELD_LEN``-length field values, across eight of the ten
        vendors. Measured end to end before the fix, and the same defect
        class as the ``_unrecognized`` message bound recorded in
        ``ingest/normalize.py`` — found by looking for its siblings.

        Truncation is mechanical and silent *here*; ``ingest.normalize``
        notes it and demotes ``parse_status``, because a summary cut short can
        drop the only copy of a value that lives nowhere else (a CloudTrail
        ``mfaAuthenticated``, a Defender ``ThreatTypes``), and a reader must
        be able to tell a complete summary from a cut one.

        ``timestamp`` is the one bound that is not a length. A value the reader
        refuses (NaN, an infinity, an integer past float range) becomes
        ``None``, through the reader itself (:func:`_storable_epoch`). No parser
        produces one, so on ``ingest.normalize``'s path this never changes an
        event. It exists so a direct caller can make any event storable, which
        is what :meth:`bounded`, built on this, is for.
        """
        return replace(
            self,
            timestamp=_storable_epoch(self.timestamp),
            vendor=self.vendor[:MAX_FIELD_LEN],
            vendor_event_id=_clip(self.vendor_event_id),
            message=self.message[:MAX_FIELD_LEN],
            activity=_clip(self.activity),
            actor=_clip_group(self.actor, _ACTOR_KEYS),
            device=_clip_group(self.device, _DEVICE_KEYS),
            src_endpoint=_clip_group(self.src_endpoint, _ENDPOINT_KEYS),
            dst_endpoint=_clip_group(self.dst_endpoint, _ENDPOINT_KEYS),
            cloud=_clip_group(self.cloud, _CLOUD_KEYS),
            email=_clip_email(self.email, MAX_FIELD_LEN),
            observables=_clip_each(self.observables, MAX_OBSERVABLES),
            raw_excerpt=self.raw_excerpt[:MAX_RAW_EXCERPT],
            notes=_clip_each(self.notes, MAX_NOTES),
        )

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


# --------------------------------------------------------------------------
# Read-time validation for :meth:`NormalizedEvent.from_dict`.
#
# These exist because a stored projection is untrusted on the way back in.
# The writer bounded every field, but the bytes have since been on disk,
# where anything with write access could have changed them. Each helper
# therefore checks rather than coerces, and names the offending key in the
# error so a corrupt row is diagnosable without dumping telemetry into a log.
#
# The declared-key tuples mirror :meth:`NormalizedEvent.to_dict` exactly.
# ``_require_exact_keys`` enforces the mirror in *both* directions, which is
# what lets ``store/`` treat a schema change as a versioned migration instead
# of silently reading old rows into a new shape.
# --------------------------------------------------------------------------

_ACTOR_KEYS = (
    "user_name",
    "user_uid",
    "user_principal",
    "identity",
    "process_name",
    "process_pid",
    "parent_process_name",
    "command_line",
)
_DEVICE_KEYS = ("hostname", "device_id", "ip", "os")
_ENDPOINT_KEYS = ("ip", "port", "domain")
_CLOUD_KEYS = ("provider", "account_uid", "region", "service")
#: Scalar email fields. Note what is absent: there is no ``body`` key, and
#: ``_require_exact_keys`` rejects one if a row ever carries it — the
#: no-message-body invariant (DESIGN.md §4) holds on read, not just on parse.
_EMAIL_SCALAR_KEYS = ("sender", "subject", "message_id", "delivery_action")
_EMAIL_KEYS = (*_EMAIL_SCALAR_KEYS, "recipients", "urls")
_EVENT_KEYS = (
    "source_type",
    "vendor",
    "vendor_event_id",
    "timestamp",
    "message",
    "activity",
    "parse_status",
    "actor",
    "device",
    "src_endpoint",
    "dst_endpoint",
    "cloud",
    "email",
    "observables",
    "raw_excerpt",
    "notes",
)


def _require_exact_keys(payload: Mapping[str, Any], declared: tuple[str, ...], where: str) -> None:
    """Both directions: no undeclared keys, no missing ones."""
    present = set(payload)
    expected = set(declared)
    if undeclared := sorted(present - expected):
        raise MalformedProjectionError(f"{where}: undeclared key(s) {undeclared}")
    if missing := sorted(expected - present):
        raise MalformedProjectionError(f"{where}: missing key(s) {missing}")


def _text(
    payload: Mapping[str, Any],
    key: str,
    where: str,
    *,
    required: bool,
    limit: int = MAX_FIELD_LEN,
) -> str:
    """A present, bounded ``str``. ``required`` additionally forbids empty."""
    value = payload[key]
    if not isinstance(value, str):
        raise MalformedProjectionError(f"{where}.{key}: expected str, got {type(value).__name__}")
    if required and not value:
        raise MalformedProjectionError(f"{where}.{key}: must not be empty")
    if len(value) > limit:
        raise MalformedProjectionError(
            f"{where}.{key}: {len(value)} chars exceeds the {limit}-char bound"
        )
    return value


def _optional_text(payload: Mapping[str, Any], key: str, where: str) -> str | None:
    """``None`` or a bounded ``str`` — the shape every optional field has."""
    if payload[key] is None:
        return None
    return _text(payload, key, where, required=False)


#: The bound :func:`_optional_epoch`'s finiteness test compares against.
_INFINITY = float("inf")


def _optional_epoch(payload: Mapping[str, Any], key: str, where: str) -> float | None:
    """``None`` or epoch seconds.

    ``bool`` is excluded explicitly because it is a subclass of ``int``, so an
    unguarded numeric check would accept ``True`` as the timestamp ``1.0`` and
    silently place the event one second after the epoch.

    An ``int`` past ~1.8e308 has no ``float``, and the conversion raised
    ``OverflowError`` out of :meth:`NormalizedEvent.from_dict`. That breaks the
    one refusal it documents. Measured: a hash-valid stored row whose
    ``timestamp`` was ``10**400`` escaped ``store``'s read path as that error,
    and ``sli`` graded it "the probe raised OverflowError". It is now refused
    like any other malformed field. ``ingest/_coerce.py::epoch`` already
    guards the same conversion on the parse side.

    **NaN and the infinities are refused**, and that is a decision, not a
    tidy-up, because both sides used to accept them. ``json`` reads and writes
    ``NaN``, ``Infinity`` and ``-Infinity`` by default, so a hand-built event
    with one appended without error and read back unchanged. Measured through
    the store, each one corrupts the time model rather than failing: NaN is
    stored with ``occurred_at`` NULL, because SQLite stores NaN as NULL, so it
    drops out of every time window while its projection still carries a time.
    ``+inf`` is inside every ``since=`` window and ``-inf`` inside every
    ``until=`` window. None of them is a time any telemetry describes, and no
    parser produces one, since ``_coerce._plausible`` bounds every parsed
    timestamp. This is the read check, and ``EventStore.append`` runs the
    reader on every projection before it writes, so one check refuses them on
    both sides. :meth:`NormalizedEvent.bounded` maps them to ``None`` through
    this same function.
    """
    value = payload[key]
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise MalformedProjectionError(
            f"{where}.{key}: expected epoch seconds, got {type(value).__name__}"
        )
    try:
        seconds = float(value)
    except OverflowError as exc:
        raise MalformedProjectionError(
            f"{where}.{key}: an integer too large for epoch seconds"
        ) from exc
    # NaN fails every comparison and each infinity fails its own, so this one
    # chain is the finiteness test. It is written as a comparison, the same
    # way ``_coerce._plausible`` is, because ingest's import allow-list does
    # not carry ``math``, and widening a security control for one call is the
    # wrong trade.
    if not -_INFINITY < seconds < _INFINITY:
        raise MalformedProjectionError(f"{where}.{key}: epoch seconds must be finite")
    return seconds


def _storable_epoch(value: float | None) -> float | None:
    """The reader's own reading of ``value`` as a timestamp, or ``None``.

    The write-side twin of :func:`_optional_epoch`, for
    :meth:`NormalizedEvent.bounded`. It calls the reader rather than restating
    its rules, for the reason ``EventStore._project`` gives: a second list of
    bounds is what drifts. ``None`` is the schema's own meaning for "the source
    carried no usable timestamp", so an unusable one is dropped rather than
    replaced with a clock reading, the same rule ``_coerce.epoch`` applies when
    parsing.

    It returns what the reader returned, not ``value``, so the value checked is
    the value kept, which is the rule ``store.events._finite`` states. Returning
    ``value`` kept the wrong one for a ``float`` subclass whose ``__float__``
    answers ``1.0`` over an infinite payload: the check saw ``1.0``,
    ``bounded()`` kept the infinity, ``json`` wrote it as ``Infinity``, and
    ``append`` refused the event ``bounded()`` exists to make storable.
    Measured, and found by review.
    """
    try:
        return _optional_epoch({"timestamp": value}, "timestamp", "event")
    except MalformedProjectionError:
        return None


def _literal(payload: Mapping[str, Any], key: str, allowed: frozenset[str], where: str) -> str:
    """One of a closed set, so a stored row cannot widen a ``Literal``."""
    value = payload[key]
    if not isinstance(value, str) or value not in allowed:
        raise MalformedProjectionError(f"{where}.{key}: {value!r} is not one of {sorted(allowed)}")
    return value


def _str_tuple(payload: Mapping[str, Any], key: str, where: str, limit: int) -> tuple[str, ...]:
    """A bounded list of bounded strings, rebuilt as a tuple."""
    value = payload[key]
    if not isinstance(value, list):
        raise MalformedProjectionError(f"{where}.{key}: expected list, got {type(value).__name__}")
    if len(value) > limit:
        raise MalformedProjectionError(
            f"{where}.{key}: {len(value)} entries exceeds the {limit}-entry bound"
        )
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise MalformedProjectionError(
                f"{where}.{key}[{index}]: expected str, got {type(item).__name__}"
            )
        if len(item) > MAX_FIELD_LEN:
            raise MalformedProjectionError(
                f"{where}.{key}[{index}]: exceeds the {MAX_FIELD_LEN}-char bound"
            )
    return tuple(value)


def _clip(value: str | None, limit: int = MAX_FIELD_LEN) -> str | None:
    """Bound an optional string without turning absence into emptiness."""
    return value if value is None else value[:limit]


def _clip_each(values: tuple[str, ...], count: int, limit: int = MAX_FIELD_LEN) -> tuple[str, ...]:
    """Bound a tuple's length and each of its entries."""
    return tuple(value[:limit] for value in values[:count])


def _clip_group(group: _GroupT, declared: tuple[str, ...], limit: int = MAX_FIELD_LEN) -> _GroupT:
    """Bound every declared scalar on one nested group, by the same key list
    ``from_dict`` validates it with — so the two cannot name different fields.
    """
    return replace(group, **{name: _clip(getattr(group, name), limit) for name in declared})


def _clip_email(email: EmailContext, limit: int) -> EmailContext:
    """Bound ``email``, the one group with collection fields as well as scalars.

    Spelled out for the reason ``_email_from`` reads it by hand rather than
    through ``_group``. The entry count stays at its own bound whatever
    ``limit`` is: :func:`_capped` shortens entries and never drops one.
    """
    return EmailContext(
        sender=_clip(email.sender, limit),
        subject=_clip(email.subject, limit),
        message_id=_clip(email.message_id, limit),
        delivery_action=_clip(email.delivery_action, limit),
        recipients=_clip_each(email.recipients, MAX_OBSERVABLES, limit),
        urls=_clip_each(email.urls, MAX_OBSERVABLES, limit),
    )


def _group(
    payload: Mapping[str, Any], key: str, declared: tuple[str, ...]
) -> dict[str, str | None]:
    """One nested all-optional-string group (``actor``, ``device``, …)."""
    raw = payload[key]
    if not isinstance(raw, Mapping):
        raise MalformedProjectionError(f"event.{key}: expected mapping, got {type(raw).__name__}")
    _require_exact_keys(raw, declared, key)
    return {name: _optional_text(raw, name, key) for name in declared}


def _email_from(payload: Mapping[str, Any]) -> EmailContext:
    """``email`` — the one group with collection fields as well as scalars."""
    raw = payload["email"]
    if not isinstance(raw, Mapping):
        raise MalformedProjectionError(f"event.email: expected mapping, got {type(raw).__name__}")
    _require_exact_keys(raw, _EMAIL_KEYS, "email")
    return EmailContext(
        **{name: _optional_text(raw, name, "email") for name in _EMAIL_SCALAR_KEYS},
        recipients=_str_tuple(raw, "recipients", "email", MAX_OBSERVABLES),
        urls=_str_tuple(raw, "urls", "email", MAX_OBSERVABLES),
    )


# --------------------------------------------------------------------------
# The total bound: one projection, one ceiling.
#
# Every bound above is per field. The store also refuses a whole projection
# past MAX_PROJECTION_BYTES, and a sum of bounded fields has no ceiling of its
# own, so an event every field of which passed its own check could still be
# refused. The collector stores a source's lines in one transaction and moves
# its offset only once they are stored, so one such record stopped that source
# for good: every later line was never stored. See ``NormalizedEvent.bounded``
# for what was measured.
# --------------------------------------------------------------------------

#: Fields the cap never shortens. ``source_type`` and ``parse_status`` are
#: checked against closed sets on read and ``timestamp`` is a number, so none
#: of them can be shortened into something still valid. ``vendor`` is a
#: constant of the parser that read the record, and every other field is read
#: in its light. Together they are a few dozen bytes on every ``normalize``
#: path, so leaving them whole costs the fit nothing.
_UNCUT = frozenset({"source_type", "vendor", "parse_status", "timestamp"})


def canonical_json(payload: dict[str, Any]) -> str:
    """Serialize a projection deterministically.

    Sorted keys and no insignificant whitespace, so the same event always
    produces the same bytes and therefore the same ``event_id``. Unicode is
    preserved rather than escaped: telemetry carries non-ASCII hostnames and
    usernames, and escaping them would make the stored evidence harder to read
    for no gain.

    **Defined here, and re-exported by** ``store.schema``. The store hashes
    these bytes and refuses them past :data:`MAX_PROJECTION_BYTES`, and this
    package fits every event under that ceiling, so both sides must measure the
    same bytes. ``store`` imports ``ingest`` and never the reverse, so the one
    definition has to live on this side. ``from_dict`` is shared the same way,
    for the reason it gives: two definitions of one shape drift apart.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def projection_size(event: NormalizedEvent) -> int:
    """UTF-8 bytes of ``event``'s canonical projection, the size the store refuses past.

    Total, where the store's own ``encode`` is strict. An unpaired surrogate,
    which strict UTF-8 refuses, is counted through ``surrogatepass`` as three
    bytes, the size of the U+FFFD that conventionally replaces one. On every
    projection the store can encode the two counts are equal. A projection it
    cannot encode is refused there, for that reason and not for its size.
    Raising here would raise out of ``ingest.normalize``, whose second rule is
    that nothing a record contains may.
    """
    return len(canonical_json(event.to_dict()).encode("utf-8", "surrogatepass"))


def fit_projection(
    event: NormalizedEvent, *, reserve: int = 0
) -> tuple[NormalizedEvent, int | None]:
    """Fit ``event`` under :data:`MAX_PROJECTION_BYTES` with one cap on every value.

    Returns ``(event, None)``, the same object, when the projection is already
    within the ceiling. So no event the store could already hold is given a
    new ``event_id`` by this function. Otherwise it returns the event cut, and
    the cap ``L`` it was cut at. ``L`` is the largest number for which cutting
    every string longer than ``L`` characters down to ``L`` leaves the
    projection within ``MAX_PROJECTION_BYTES - reserve`` bytes. ``reserve`` is
    room the caller keeps for what it adds afterwards. ``ingest.normalize``
    keeps it for the note saying that this happened.

    **One cap, not an order of fields.** The owner chose this over cutting the
    excerpt, then list entries from the end, then the summary, then the rest.
    A value no longer than ``L`` is never touched, so a short indicator (an
    address, a hash, a port, a host name) survives any amount of padding in
    the fields around it. Every entry of every list is kept, shortened rather
    than dropped. Cutting in a fixed order would have let an attacker drop a
    phishing record's one malicious URL by padding the URLs before it and
    putting it last.

    **Observables are dropped whole, never shortened.** A prefix of an
    indicator can be an indicator nobody saw: a cut sha256 is a well-formed
    sha1 and a cut domain is another domain. Observables land in the store's
    indexed, append-only ``observables`` table, where a false join key is
    worse than a missing one (``ingest._coerce._scan_source`` records five
    rounds of learning that). So an observable longer than ``L`` is removed,
    and the others are kept exactly. URL observables are at most 264
    characters, so a cap that low is reached only by padding nearly every
    field to its limit.

    **Not shortened:** the fields in :data:`_UNCUT`. ``L`` is found by
    bisection over the exact measure (:func:`projection_size`), which never
    grows as ``L`` falls, so the result is deterministic. ``L = 0`` is the
    floor, where only those fields and the projection's own keys remain:
    1,211 bytes measured with a one-character ``vendor``, and still under
    10 KiB with a ``vendor`` at its own 2,048-character bound in four-byte
    characters.
    A caller passing a ``reserve`` so large that even the floor is over gets
    the floor back, over the ceiling, and the store refuses it.
    """
    if projection_size(event) <= MAX_PROJECTION_BYTES:
        return event, None
    budget = MAX_PROJECTION_BYTES - reserve
    low, high = 0, max(_cuttable_lengths(event.to_dict()), default=0)
    while low < high:
        middle = (low + high + 1) // 2
        if projection_size(_capped(event, middle)) <= budget:
            low = middle
        else:
            high = middle - 1
    return _capped(event, low), low


def _cuttable_lengths(value: Any, *, top: bool = True) -> Iterator[int]:
    """The length of every string :func:`_capped` may shorten, by reflection.

    Walks the projection rather than naming fields, so a field added to
    :meth:`NormalizedEvent.to_dict` is counted without anyone editing this.
    """
    if isinstance(value, str):
        yield len(value)
    elif isinstance(value, Mapping):
        for key, child in value.items():
            if not (top and key in _UNCUT):
                yield from _cuttable_lengths(child, top=False)
    elif isinstance(value, list):
        for child in value:
            yield from _cuttable_lengths(child, top=False)


def _capped(event: NormalizedEvent, cap: int) -> NormalizedEvent:
    """``event`` with every string past ``cap`` cut to it, and longer observables dropped.

    Everything but :data:`_UNCUT`. ``None`` stays ``None``, because
    :func:`_clip` keeps absence distinct from emptiness. A present value
    becomes empty only at ``cap == 0``, a floor nothing gets near. Measured:
    the worst case, every field at its bound in four-byte characters and every
    list full (2,351,090 bytes), fits at a cap of 73 through
    :meth:`NormalizedEvent.bounded` and of 71 with the room
    ``ingest.normalize`` keeps for its note, in about 12 ms.
    """
    return replace(
        event,
        vendor_event_id=_clip(event.vendor_event_id, cap),
        message=event.message[:cap],
        activity=_clip(event.activity, cap),
        actor=_clip_group(event.actor, _ACTOR_KEYS, cap),
        device=_clip_group(event.device, _DEVICE_KEYS, cap),
        src_endpoint=_clip_group(event.src_endpoint, _ENDPOINT_KEYS, cap),
        dst_endpoint=_clip_group(event.dst_endpoint, _ENDPOINT_KEYS, cap),
        cloud=_clip_group(event.cloud, _CLOUD_KEYS, cap),
        email=_clip_email(event.email, cap),
        observables=tuple(value for value in event.observables if len(value) <= cap),
        raw_excerpt=event.raw_excerpt[:cap],
        notes=tuple(note[:cap] for note in event.notes),
    )
