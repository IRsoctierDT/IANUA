# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

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
4. **Retain only what a parser modelled.** ``raw_excerpt`` is rebuilt from
   the paths a signature declared, never copied from the record. The store
   is append-only and ``event_id`` is a digest over the projection, so
   nothing written here can be redacted later — which makes what this module
   chooses to write the whole of the platform's data-retention posture. A
   field no parser models is evidence nobody asked for and liability
   everybody inherits.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import replace
from typing import Any

from ingest import keyvalue
from ingest._coerce import FieldPath, depth_within, observables, project, text
from ingest.errors import UnsupportedInputError
from ingest.parsers import Signature, cloud, email, endpoint, identity, network
from ingest.schema import (
    MAX_FIELD_LEN,
    MAX_NESTING_DEPTH,
    MAX_NOTES,
    MAX_PROJECTED_ITEMS,
    MAX_RAW_BYTES,
    MAX_RAW_EXCERPT,
    NormalizedEvent,
    ParseStatus,
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

#: Every path any signature declared it reads — the union of the ten
#: per-format allow-lists. A record no signature claims is projected through
#: this instead of being carried verbatim: a Defender export whose
#: ``NetworkMessageId`` was renamed upstream still yields its subject, its
#: sender and the platform's verdict, while a field no parser anywhere
#: models still yields nothing. Recognition breaking is the likeliest way a
#: body would otherwise reach the store, so this is the path that decides
#: whether the no-body rule holds in practice or only on the happy path.
MODELLED_FIELDS: tuple[FieldPath, ...] = tuple(
    sorted({path for signature in SIGNATURES for path in signature.fields})
)

#: How many withheld key names an unmodelled record's note may list. The
#: note is bounded at ``MAX_FIELD_LEN`` on write because ``from_dict``
#: validates it there on read; a note that exceeded it would make the event
#: writable and then permanently unreadable, which is the defect recorded in
#: ``_unrecognized`` below.
_MAX_NAMED_KEYS = MAX_PROJECTED_ITEMS

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
        return _normalize_mapping(raw)
    if not isinstance(raw, str):
        raise UnsupportedInputError(
            f"telemetry must be a mapping, str, or bytes; got {type(raw).__name__}"
        )

    if len(raw) > MAX_RAW_BYTES:
        return _unrecognized(
            evidence=raw[:MAX_RAW_EXCERPT],
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
                evidence=raw, notes=("input looked like JSON but did not decode; carried as text",)
            )
        if isinstance(decoded, Mapping):
            return _normalize_mapping(decoded, scanned=raw)
        return _unrecognized(
            evidence=raw, notes=("decoded JSON was not an object; carried as text",)
        )
    # Not JSON. It may still be structured: auditd and logfmt-style lines are
    # `key=value` runs, and the auditd recognizer in parsers/endpoint.py was
    # written expecting exactly the mapping that decodes to — nothing was
    # producing one. `decode` returns None for prose, which is most log text,
    # and the line is then carried as an excerpt exactly as before.
    pairs = keyvalue.decode(stripped)
    if pairs is not None:
        return _normalize_mapping(pairs, scanned=raw)
    return _unrecognized(evidence=raw)


def normalize_many(records: Iterable[str | bytes | Mapping[str, Any]]) -> list[NormalizedEvent]:
    """Normalize a batch, preserving order.

    One unparseable record never costs the batch: each degrades to its own
    ``unknown`` event, and the caller sees exactly which ones did.
    """
    return [normalize(record) for record in records]


def _normalize_mapping(
    payload: Mapping[str, Any], *, scanned: str | None = None
) -> NormalizedEvent:
    """Normalize a decoded record.

    ``scanned`` is the text this mapping decoded from, when there was one. It
    is used for **indicator extraction only**, on the branches where no
    parser claimed the record, so an IP or a hash in an unmodelled source is
    still joinable by ``correlation/``. It is never retained: every branch
    below derives its evidence from a declared-path projection, and
    ``tests/security`` asserts that nothing reachable only through
    ``scanned`` lands in ``raw_excerpt`` or ``message``. Keeping the two
    apart is the whole point of the parameter — the alternative, passing one
    string that is both, is how a mail body used to reach the store.
    """
    if not depth_within(payload, MAX_NESTING_DEPTH):
        return _unmodelled(
            payload,
            scanned=scanned,
            notes=(
                f"record nests deeper than {MAX_NESTING_DEPTH} levels; "
                "carried as an excerpt without parsing",
            ),
        )
    signature = detect_source(payload)
    if signature is None:
        return _unmodelled(
            payload,
            scanned=scanned,
            notes=("no parser signature claimed this record; source left unattributed",),
        )
    try:
        event = signature.parse(payload)
    except (TypeError, ValueError, AttributeError, KeyError) as exc:
        # The signature claimed the record, so its declared fields *are*
        # modelled even though reading them failed. The excerpt a debugger
        # needs is therefore this signature's own projection, not the union.
        return _unrecognized(
            evidence=_excerpt_for(signature.fields, payload),
            scanned=scanned if scanned is not None else _render(payload),
            notes=(
                f"{signature.vendor} parser could not read this record "
                f"({type(exc).__name__}); carried as text",
            ),
        )
    # The excerpt is attached here rather than inside every parser, so no
    # parser can forget it and none can widen it.
    return _finalize(_with_excerpt(event, _excerpt_for(signature.fields, payload)))


#: Said once, when a bound bit. Phrased so an analyst reading a cut summary
#: knows it is cut rather than wondering what the source left out.
_TRUNCATION_NOTE = (
    "one or more fields exceeded their bound and were truncated on write; "
    "the summary may be shorter than the source"
)


def _with_excerpt(event: NormalizedEvent, excerpt: str) -> NormalizedEvent:
    """Attach the bounded raw excerpt to a parsed event."""
    return replace(event, raw_excerpt=excerpt[:MAX_RAW_EXCERPT])


def _finalize(event: NormalizedEvent) -> NormalizedEvent:
    """Apply every read-time bound on the write side, and say so when one bit.

    Every *parsed* event passes through here, so a parser cannot forget the
    bound and a new parser inherits it — the same argument that puts excerpt
    assembly in this module rather than in ten parsers.

    The bound itself lives in ``NormalizedEvent.bounded()``, beside the
    validation it mirrors. What belongs *here* is the honesty: a truncated
    summary is a degraded parse, so it is noted and ``parse_status`` is
    demoted. ``message`` is assembled from several separately bounded fields
    and some of the values in it (a CloudTrail ``mfaAuthenticated``, a
    Defender ``ThreatTypes``) live nowhere else on the event, so silently
    cutting it would lose their only copy without saying so.
    """
    bounded = event.bounded()
    if bounded == event:
        return event
    # The note about truncation outranks a 64th parser note, so it is kept
    # rather than sliced off the end.
    notes = (*bounded.notes[: MAX_NOTES - 1], _TRUNCATION_NOTE)
    status: ParseStatus = (
        "partial" if bounded.parse_status == "structured" else bounded.parse_status
    )
    return replace(bounded, parse_status=status, notes=notes)


def _excerpt_for(fields: tuple[FieldPath, ...], payload: Mapping[str, Any]) -> str:
    """Render the declared paths of a record as its bounded evidence excerpt.

    The excerpt is *rebuilt*, never copied: :func:`~ingest._coerce.project`
    keeps only the paths ``fields`` names, so an un-modelled field has no
    route in. ``default=str`` keeps a non-JSON-serializable value from
    raising here; the excerpt is evidence for a human, not a round-trip
    format.
    """
    return _serialize(project(payload, fields))


def _render(payload: Mapping[str, Any]) -> str:
    """Serialize a whole record for indicator extraction. Never retained.

    The result is handed to :func:`~ingest._coerce.observables`, which pulls
    URLs, hashes, IPs and domains out of it and discards the rest. It is
    bounded at :data:`MAX_RAW_EXCERPT` to match what the text paths pass, so
    which indicators survive truncation does not depend on whether a record
    arrived as a mapping or as a line of JSON.
    """
    return _serialize(payload)


def _serialize(value: Mapping[str, Any]) -> str:
    """Render a mapping to bounded text, degrading rather than raising.

    One serializer for both the excerpt and the indicator scan, so the
    fallback is written and exercised once. ``default=str`` handles a value
    JSON cannot represent; the ``except`` is for a record that is circular or
    too deep for the encoder, which no decoded JSON can be but a caller
    passing a mapping directly certainly can. Nothing a record contains may
    raise out of ``normalize`` — that is rule 2, and an excerpt is not worth
    losing an event over.
    """
    try:
        return json.dumps(value, sort_keys=True, default=str)[:MAX_RAW_EXCERPT]
    except (TypeError, ValueError, RecursionError):
        return str(value)[:MAX_RAW_EXCERPT]


def _unmodelled(
    payload: Mapping[str, Any], *, scanned: str | None, notes: tuple[str, ...]
) -> NormalizedEvent:
    """Carry a record no parser claimed: modelled values, withheld remainder.

    Projected through :data:`MODELLED_FIELDS` rather than carried verbatim.
    An unclaimed record is the one case where *everything* about it is
    un-attributed, and it is also the likeliest route by which a field the
    platform refuses to model — a mail body above all — would reach an
    append-only store that cannot be redacted. So the values it keeps are
    the ones some parser somewhere justified, and the rest is named but not
    quoted: a key name tells an operator what signature to write, a value
    tells them what was in the mail.
    """
    projected = project(payload, MODELLED_FIELDS)
    withheld = sorted(
        name
        for name in (text(key) for key in payload)
        if name is not None and name not in projected
    )
    if withheld:
        notes = (*notes, _withheld_note(len(payload), withheld))
    return _unrecognized(
        evidence=_excerpt_for(MODELLED_FIELDS, payload),
        scanned=scanned if scanned is not None else _render(payload),
        notes=notes,
    )


def _withheld_note(total: int, withheld: list[str]) -> str:
    """State how much of a record was not retained, within the note bound.

    Counts the record's own top-level keys, which is what an operator needs
    to write a signature. A key that *is* modelled but whose un-named
    sub-keys were withheld does not appear here — the excerpt shows that
    directly, since an object at a declared path renders as its key names.
    """
    named = withheld[:_MAX_NAMED_KEYS]
    elided = len(withheld) - len(named)
    note = (
        f"{len(withheld)} of {total} top-level record keys are modelled by no parser; "
        f"their values are withheld from the excerpt (keys: {', '.join(named)}"
        + (f", and {elided} more" if elided else "")
        + ")"
    )
    # Bounded on write because ``from_dict`` validates each note at
    # ``MAX_FIELD_LEN`` on read. An attacker picks the key names, so this is
    # not a theoretical ceiling.
    return note[:MAX_FIELD_LEN]


def _unrecognized(
    *, evidence: str, scanned: str | None = None, notes: tuple[str, ...] = ()
) -> NormalizedEvent:
    """The honest fallback: carried, labelled, and never mis-attributed.

    ``evidence`` is what is retained — it becomes both ``message`` and
    ``raw_excerpt``. ``scanned`` is read for indicators and then dropped;
    when it is ``None`` the evidence is scanned instead, which is the case
    for every input that was never structured in the first place.

    ``message`` is bounded at :data:`MAX_FIELD_LEN`, like every other field,
    **not** at :data:`MAX_RAW_EXCERPT`. It used to be the latter, and that one
    constant made a line of 2049-4096 characters writable and then permanently
    unreadable: ``from_dict`` validates ``message`` at ``MAX_FIELD_LEN``, so
    ``append`` accepted the event and every subsequent ``query`` raised
    ``MalformedProjectionError`` — which ``run_cycle`` does not catch, so **every
    later detection cycle on that store failed**. One long log line, a padded
    username in a brute force or a URL in an application log, stopped the SOC.
    Reproduced end to end before the fix. Found by review.

    Only ``raw_excerpt`` carries the wider bound, which is what it is for: it is
    declared at ``MAX_RAW_EXCERPT`` on both sides (``schema.from_dict`` validates
    it there), so the fuller text is still retained as evidence.

    Observables are extracted from the *scanned* text rather than from the
    truncated message, which keeps this honest both ways: indicators are not
    lost when the evidence is narrowed, and narrowing the evidence is not
    quietly undone by the indicator set. It does not widen extraction either:
    :func:`observables` coerces each input through ``text()`` at the default
    ``MAX_FIELD_LEN``, so an indicator appearing only past character 2048 of a
    single line is not extracted — a pre-existing bound, measured on the
    unfixed code and recorded here rather than changed under cover of a fix.
    """
    retained = text(evidence, limit=MAX_RAW_EXCERPT) or ""
    searched = text(scanned if scanned is not None else evidence, limit=MAX_RAW_EXCERPT) or ""
    # Not routed through ``_finalize``: every field here is already written
    # within its own bound, and this ``message`` is the carried evidence
    # rather than an assembled summary, so its truncation is the documented
    # normal case and not a degradation to note. The property is asserted
    # either way — ``test_an_unrecognized_line_of_any_length_survives_a_
    # round_trip`` covers this path and
    # ``test_a_record_of_maximal_fields_still_reads_back`` covers both.
    return NormalizedEvent(
        source_type="unknown",
        vendor="unrecognized",
        vendor_event_id=None,
        timestamp=None,
        message=retained[:MAX_FIELD_LEN],
        activity=None,
        parse_status="partial" if notes else "text",
        observables=observables(searched),
        raw_excerpt=retained[:MAX_RAW_EXCERPT],
        notes=notes,
    )
