"""Front door: raw telemetry in, one canonical event out.

The whole point of this module is that *no downstream layer needs to know
where an event came from*. The classifier, the mapping engine, the behavioral
matcher, and the response planner all read a ``NormalizedEvent``; only this
module knows that CloudTrail spells it ``sourceIPAddress`` and Suricata
spells it ``src_ip``.

Three rules govern it, in this order:

1. **Recognize, never guess.** A record is parsed by a domain parser only
   when that parser's signature claims it on distinctive keys. Nothing is
   routed to the closest-looking parser: an unclaimed record becomes an
   ``unknown``-source event carrying its text. A mis-attributed record would
   produce a confident and wrong analysis, which is strictly worse than an
   explicit "not recognized".
2. **Degrade visibly, don't drop.** Oversized, over-nested, and undecodable
   input still yields an event — with ``parse_status`` demoted and a note
   saying what happened. Silently discarding telemetry is how a blind spot
   is manufactured.
3. **No ambient authority.** No clock, no filesystem, no network, no
   subprocess. Given the same bytes this module returns the same event,
   which is what makes the fixtures and digests downstream meaningful.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any

from ingest._coerce import depth_within, observables, text
from ingest.errors import UnsupportedInputError
from ingest.parsers import Signature, cloud, email, endpoint, identity, network
from ingest.schema import (
    MAX_NESTING_DEPTH,
    MAX_RAW_BYTES,
    MAX_RAW_EXCERPT,
    NormalizedEvent,
    SourceType,
)

#: Every signature the platform can recognize, grouped by domain. Order is
#: presentational only — recognition is by distinctive keys, and the parity
#: test asserts no two signatures claim the same record.
SIGNATURES: tuple[Signature, ...] = (
    endpoint.SIGNATURES
    + network.SIGNATURES
    + cloud.SIGNATURES
    + identity.SIGNATURES
    + email.SIGNATURES
)

#: The five domains, plus the honest fallback.
SOURCE_TYPES: tuple[SourceType, ...] = (
    "endpoint",
    "network",
    "cloud",
    "identity",
    "email",
    "unknown",
)


def detect_source(payload: Mapping[str, Any]) -> Signature | None:
    """Return the one signature that claims ``payload``, or ``None``.

    Ambiguity is resolved by refusing: if two signatures both claim a record,
    the record is *not* attributed to either. Two vendors' formats
    overlapping is a corpus bug to be fixed at the signature, not something
    to be papered over by picking whichever was registered first.
    """
    claimed = [signature for signature in SIGNATURES if _safely_recognizes(signature, payload)]
    if len(claimed) == 1:
        return claimed[0]
    return None


def _safely_recognizes(signature: Signature, payload: Mapping[str, Any]) -> bool:
    """Run a recognizer without letting a malformed record abort detection.

    A recognizer reaching into a field that turned out to be the wrong type
    should cost that one signature its claim, not the whole ingest.
    """
    try:
        return bool(signature.recognizes(payload))
    except (TypeError, ValueError, AttributeError, KeyError):
        return False


def normalize(raw: str | bytes | Mapping[str, Any]) -> NormalizedEvent:
    """Normalize one raw telemetry record.

    Accepts a decoded mapping, a JSON string, or plain log text. Raises
    :class:`~ingest.errors.UnsupportedInputError` only for a type that cannot
    be telemetry at all — malformed *content* degrades instead, because
    losing an event is the failure this layer exists to prevent.
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, Mapping):
        return _normalize_mapping(raw, excerpt=_excerpt_of(raw))
    if not isinstance(raw, str):
        raise UnsupportedInputError(
            f"telemetry must be a mapping, str, or bytes; got {type(raw).__name__}"
        )

    if len(raw) > MAX_RAW_BYTES:
        return _unrecognized(
            raw[:MAX_RAW_EXCERPT],
            notes=(
                f"record exceeds the {MAX_RAW_BYTES}-byte ceiling "
                f"({len(raw)} bytes); carried as an excerpt without parsing",
            ),
        )

    stripped = raw.strip()
    if stripped.startswith(("{", "[")):
        try:
            decoded = json.loads(stripped)
        except (json.JSONDecodeError, RecursionError):
            return _unrecognized(
                raw, notes=("input looked like JSON but did not decode; carried as text",)
            )
        if isinstance(decoded, Mapping):
            return _normalize_mapping(decoded, excerpt=raw[:MAX_RAW_EXCERPT])
        return _unrecognized(raw, notes=("decoded JSON was not an object; carried as text",))
    return _unrecognized(raw)


def normalize_many(records: Iterable[str | bytes | Mapping[str, Any]]) -> list[NormalizedEvent]:
    """Normalize a batch, preserving order.

    One unparseable record never costs the batch: each degrades to its own
    ``unknown`` event, and the caller sees exactly which ones did.
    """
    return [normalize(record) for record in records]


def _normalize_mapping(payload: Mapping[str, Any], *, excerpt: str) -> NormalizedEvent:
    if not depth_within(payload, MAX_NESTING_DEPTH):
        return _unrecognized(
            excerpt,
            notes=(
                f"record nests deeper than {MAX_NESTING_DEPTH} levels; "
                "carried as an excerpt without parsing",
            ),
        )
    signature = detect_source(payload)
    if signature is None:
        return _unrecognized(
            excerpt,
            notes=("no parser signature claimed this record; source left unattributed",),
        )
    try:
        event = signature.parse(payload)
    except (TypeError, ValueError, AttributeError, KeyError) as exc:
        return _unrecognized(
            excerpt,
            notes=(
                f"{signature.vendor} parser could not read this record "
                f"({type(exc).__name__}); carried as text",
            ),
        )
    # The excerpt is attached here rather than inside every parser, so no
    # parser can forget it and none can widen it.
    return _with_excerpt(event, excerpt)


def _with_excerpt(event: NormalizedEvent, excerpt: str) -> NormalizedEvent:
    """Attach the bounded raw excerpt to a parsed event."""
    from dataclasses import replace

    return replace(event, raw_excerpt=excerpt[:MAX_RAW_EXCERPT])


def _excerpt_of(payload: Mapping[str, Any]) -> str:
    """Render a decoded mapping back to a bounded excerpt for evidence.

    ``default=str`` keeps a payload containing a non-JSON-serializable value
    from raising here; the excerpt is evidence for a human, not a round-trip
    format.
    """
    try:
        return json.dumps(payload, sort_keys=True, default=str)[:MAX_RAW_EXCERPT]
    except (TypeError, ValueError, RecursionError):
        return str(payload)[:MAX_RAW_EXCERPT]


def _unrecognized(raw: str, *, notes: tuple[str, ...] = ()) -> NormalizedEvent:
    """The honest fallback: carried, labelled, and never mis-attributed."""
    message = text(raw, limit=MAX_RAW_EXCERPT) or ""
    return NormalizedEvent(
        source_type="unknown",
        vendor="unrecognized",
        vendor_event_id=None,
        timestamp=None,
        message=message,
        activity=None,
        parse_status="partial" if notes else "text",
        observables=observables(message),
        raw_excerpt=raw[:MAX_RAW_EXCERPT],
        notes=notes,
    )
