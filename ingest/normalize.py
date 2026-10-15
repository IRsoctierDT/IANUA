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
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, replace
from typing import Any

from ingest import keyvalue
from ingest._coerce import CUT_TOKEN, FieldPath, depth_within, observables, project, text
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
            evidence=_carried(raw[:MAX_RAW_EXCERPT]),
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
                evidence=_carried(raw),
                notes=("input looked like JSON but did not decode; carried as text",),
            )
        if isinstance(decoded, Mapping):
            return _normalize_mapping(decoded)
        return _unrecognized(
            evidence=_carried(raw),
            notes=("decoded JSON was not an object; carried as text",),
        )
    # Not JSON. It may still be structured: auditd and logfmt-style lines are
    # `key=value` runs, and the auditd recognizer in parsers/endpoint.py was
    # written expecting exactly the mapping that decodes to — nothing was
    # producing one. `decode` returns None for prose, which is most log text,
    # and the line is then carried as an excerpt exactly as before.
    pairs = keyvalue.decode(stripped)
    if pairs is not None:
        return _normalize_mapping(pairs)
    return _unrecognized(evidence=_carried(raw))


def normalize_many(records: Iterable[str | bytes | Mapping[str, Any]]) -> list[NormalizedEvent]:
    """Normalize a batch, preserving order.

    One unparseable record never costs the batch: each degrades to its own
    ``unknown`` event, and the caller sees exactly which ones did.
    """
    return [normalize(record) for record in records]


def _normalize_mapping(payload: Mapping[str, Any]) -> NormalizedEvent:
    """Normalize a decoded record.

    **This used to take a ``scanned`` parameter, and removing it is the fix.**
    It carried the text the mapping decoded from, for *indicator extraction
    only*, so that an IP or a hash in an unmodelled source stayed joinable by
    ``correlation/``. Its docstring claimed the separation held because
    ``tests/security`` asserts nothing reachable only through ``scanned``
    lands in ``raw_excerpt`` or ``message``. That was true, and silent about
    the third output: ``observables``, which is exactly where it landed.

    Measured on merged code — an unclaimed record whose un-modelled ``Body``
    read "Dear Mr.Jones, please urgently.Reply ... invoice 44.Smith at
    acct-7781.Watson" produced ``raw_excerpt`` of ``{}``, ``message`` of
    ``{}``, a note naming all three withheld keys, and five observables:
    ``Mr.Jones``, ``urgently.Reply``, ``44.Smith``, ``acct-7781.Watson``,
    ``Ms.Delacroix``. The ``observables`` table is indexed and feeds
    correlation joins, ``UPDATE`` is trigger-refused and ``event_id`` is a
    sha256 over the projection, so those names could only be removed by
    deleting whole rows.

    The parameter arrived for one reason (#206: do not lose indicators to a
    truncated ``message``) and became a hole for another, because what
    ``evidence`` *was* changed under it: stage 6 made it a declared-path
    projection while ``scanned`` stayed the raw record. Extracting from the
    retained evidence keeps the first property — the excerpt is bounded at
    ``MAX_RAW_EXCERPT`` and ``message`` at ``MAX_FIELD_LEN``, so indicators
    past character 2048 of the *evidence* still survive — and closes the
    second, because there is no longer a wider string to read.

    The owner chose this over a plausible-TLD check on the extractor, with
    the cost accepted and stated: an indicator that appears **only** in an
    un-modelled field of an unclaimed record is no longer extracted. §5's
    reason for scanning unclaimed records was that recognition breaking
    upstream is the likeliest route by which a real indicator arrives
    unparsed — that route now yields the modelled values and the withheld-key
    note, and not the indicator.
    """
    if not depth_within(payload, MAX_NESTING_DEPTH):
        return _unmodelled(
            payload,
            notes=(
                f"record nests deeper than {MAX_NESTING_DEPTH} levels; "
                "carried as an excerpt without parsing",
            ),
        )
    signature = detect_source(payload)
    if signature is None:
        return _unmodelled(
            payload,
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
            notes=(
                f"{signature.vendor} parser could not read this record "
                f"({type(exc).__name__}); carried as text",
            ),
        )
    # The excerpt is attached here rather than inside every parser, so no
    # parser can forget it and none can widen it.
    return _finalize(_with_excerpt(event, _excerpt_for(signature.fields, payload).text))


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


@dataclass(frozen=True, slots=True)
class _Excerpt:
    """The evidence text and the values it was rendered from, inseparably.

    One object rather than two parameters, because the two must not diverge —
    a second, *wider* source is exactly the defect this layer was just fixed
    for. ``values`` is the decomposition of ``text`` and nothing more.

    ``values`` is therefore **never wider than** ``text``: it is built by
    matching each leaf against the rendered string
    (:func:`_retained_values`), so a leaf the excerpt truncated away is not
    scanned either. Asserted directly rather than reasoned about — see
    ``test_every_observable_is_findable_in_the_retained_evidence`` — because
    this function has now been wrong in both directions.

    They are both needed because they are bounded differently.
    :func:`~ingest._coerce.observables` coerces **each value** through
    ``text()`` at ``MAX_FIELD_LEN``, which is what every parser relies on when
    it calls ``observables(sender_ip, sender, *urls)``. Handing it the
    serialized form instead applies a *per-field* bound to the *whole*
    projection. Measured: an unclaimed record with a 2048-character
    ``@timestamp`` and a ``Subject`` of ``visit http://modelled.example/path``
    — both modelled, and ``@timestamp`` sorting first — kept that URL in
    ``raw_excerpt`` at index 2085 and produced **no observables at all**,
    because the single concatenated string was cut at 2048. Removing the long
    field brought the indicator back, which is the tell that sort order
    decided it. Found by review; the cost this change documents was wider than
    the cost it claimed.
    """

    text: str
    values: tuple[Any, ...]


def _leaf_values(value: Any) -> Iterator[Any]:
    """Every scalar inside a projection, in the order the excerpt renders it.

    Mappings are walked in sorted-key order to match ``json.dumps(...,
    sort_keys=True)``, which is what makes :func:`_retained_values` able to
    find each leaf in the rendered text by scanning forward.

    Bounded by construction: :func:`~ingest._coerce.project` has already
    applied ``MAX_PROJECTED_ITEMS``, ``MAX_NESTING_DEPTH`` and the per-value
    ``MAX_FIELD_LEN``, so this cannot walk further than the projection goes.
    """
    if isinstance(value, Mapping):
        for key in sorted(value):
            yield from _leaf_values(value[key])
    elif isinstance(value, list | tuple):
        for child in value:
            yield from _leaf_values(child)
    else:
        yield value


def _retained_values(projected: Mapping[str, Any], rendered: str) -> tuple[Any, ...]:
    """The leaves wholly inside ``rendered`` — the scan source, never wider.

    **The invariant this exists to hold: every indicator must be findable in
    the evidence an operator can read.** The first version of this change
    handed ``observables()`` the serialized projection, which applied a
    *per-field* bound to the whole string and lost a late-sorting modelled
    field's indicator. The second handed it every leaf, which went too far the
    other way: ``_serialize`` truncates at ``MAX_RAW_EXCERPT``, so leaves past
    that cut were scanned while being absent from ``raw_excerpt`` **and**
    ``message``. Measured on that version — three declared 2048-character
    fields sorting before ``Subject`` — the URL appeared in ``observables``
    and in neither retained field. Both are the same mistake twice: deriving
    the scan source from something other than the text that is kept.

    So the leaves are matched against the rendered text, scanning forward.
    ``sort_keys=True`` makes the render order deterministic and equal to
    :func:`_leaf_values`' walk order, so one forward pass is enough and a
    value cannot be mistaken for an earlier identical one. ``_serialize`` has
    already sliced ``rendered`` to ``MAX_RAW_EXCERPT``, so a successful
    ``find`` is within the bound by construction, and a fragment the slice cut
    in half is not found at all. An explicit second bound check was written,
    measured to be unreachable, and removed rather than left as decorative
    defence.

    **Stopping the walk is not the same as discarding the rest of the text,
    and conflating the two was the fifth round.** The third version simply
    ``break``-ed on the leaf the slice had cut, which threw away the part of
    that leaf ``rendered`` still held. Measured on the merged code, with
    ``@timestamp`` at 2048 characters, ``Channel`` at 1500, and a ``Subject``
    whose value *begins* with a URL:

        raw_excerpt : 4096 chars, URL present and readable at index 3594
        observables : ()

    All three fields are modelled and the indicator is in the evidence an
    operator can read — which is round one's defect reached by a new route,
    and the reason it survived two property tests is that both are
    *implications* over ``event.observables``: an empty tuple satisfies them
    with zero iterations. Found by review.

    The tail is therefore handed over as one more value, with its final token
    trimmed off. **The trim is round six, and it is the first defect here
    that added something false rather than losing something true.** A hard
    character slice can land inside an indicator, and the untrimmed tail
    handed the severed prefix to ``observables()`` as though it were whole.
    Measured across padding offsets that move the cut through a ``Subject``:

        19 of 50 offsets yielded a truncated URL
        2 offsets yielded a truncated *hash* — a 64-character sha256 cut at
        40 and at 32 characters, which are well-formed sha1 and md5 shapes

    The hash case is the one that matters. A lost indicator is a gap; a
    40-character hex string that never hashed anything is a plausible IOC in
    an indexed, append-only join-key column, and ``correlation/entities.py``
    will join on it. The biconditional did not catch it, because that asks
    about one exact string and the exact string was neither retained nor
    extracted — ``False == False``. Found by review.

    So the tail is cut back past its last
    :data:`~ingest._coerce.INDICATOR_TERMINATORS` character. Every extractor's
    character class is a subset of ``_URL``'s, so a string ending on a
    terminator cannot be ending inside a match, and a test pins that
    derivation rather than trusting this paragraph. The cost is the mirror of
    the gain: an indicator genuinely ending at the excerpt boundary is now
    dropped, because nothing in the retained text distinguishes it from one
    the slice severed.

    It still needs no argument about its relationship to the excerpt, because
    it **is a slice of the excerpt** — ``rendered[offset:]``, trimmed, not
    something re-derived from the projection and then reasoned about. Every earlier version of this function
    derived its scan source from the projection and argued the correspondence;
    each argument was true of the case in front of it and false of another.
    The containment here is syntactic, so round two cannot return through it:
    an indicator past the cut is not in ``rendered`` at all, and so not in any
    slice of it (measured — the round-two record's tail is 2031 characters and
    does not contain its URL).

    Two residuals, stated rather than implied. The tail is one value, so
    ``MAX_FIELD_LEN`` bounds it once: when the walk stops early enough that
    the tail exceeds 2048 characters, an indicator in its later part is still
    not extracted. And key *names* in ``rendered`` are retained but scanned
    only when they fall inside this tail, so "every indicator in the excerpt
    is extracted" is true of values and not of keys.

    One honest caveat about the sort: a plant that walks in insertion order
    instead leaves every test green, because :func:`~ingest._coerce.project`
    happens to build the projection in an order the forward scan tolerates.
    The sort is therefore **not** currently load-bearing — it makes this
    function's correctness independent of ``project``'s insertion order rather
    than dependent on it, which is worth the two characters, and it is
    recorded as uncovered rather than claimed as tested.
    """
    kept: list[Any] = []
    offset = 0
    for value in _leaf_values(projected):
        try:
            fragment = json.dumps(value, default=str)
        except (TypeError, ValueError, RecursionError):  # pragma: no cover - defensive
            break
        found = rendered.find(fragment, offset)
        if found < 0:
            # Either the slice cut this leaf in half, or ``_serialize`` fell
            # back and this leaf is not in the text at all. Both stop the walk:
            # past this point no leaf is reliably placed. But whatever
            # ``rendered`` still holds from ``offset`` on **is** retained
            # evidence, so it is handed over as one value rather than
            # discarded — that omission was the fifth round on this function.
            # Trimmed, because the slice can land mid-indicator and a severed
            # indicator is worse than a lost one: it is a *false* join key in
            # an append-only index. See the docstring for the measurement.
            tail = CUT_TOKEN.sub("", rendered[offset:])
            if tail:
                kept.append(tail)
            break
        kept.append(value)
        offset = found + len(fragment)
    return tuple(kept)


def _excerpt_for(fields: tuple[FieldPath, ...], payload: Mapping[str, Any]) -> _Excerpt:
    """Render the declared paths of a record as its bounded evidence excerpt.

    The excerpt is *rebuilt*, never copied: :func:`~ingest._coerce.project`
    keeps only the paths ``fields`` names, so an un-modelled field has no
    route in. ``default=str`` keeps a non-JSON-serializable value from
    raising here; the excerpt is evidence for a human, not a round-trip
    format.
    """
    projected = project(payload, fields)
    rendered = _serialize(projected)
    return _Excerpt(rendered, _retained_values(projected, rendered))


def _carried(raw: str) -> _Excerpt:
    """Evidence that is the record itself, for input that never decoded.

    ``values`` is the one string, which is what the text paths have always
    scanned: §5 records that anything which never decoded to a mapping is
    carried verbatim, so there is no projection to decompose and nothing to
    withhold from the scan.
    """
    return _Excerpt(raw, (raw,))


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


def _unmodelled(payload: Mapping[str, Any], *, notes: tuple[str, ...]) -> NormalizedEvent:
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
    # Compared on the record's **own** key names, not on their sanitized forms.
    # ``text()`` strips control characters, so sanitizing first made the note
    # wrong three ways at once, measured: a key spelled ``Body\n\x07`` was
    # reported as ``Body``, which the record does not contain; a key spelled
    # ``Subject\x00`` sanitized to a name that *is* in the projection and so
    # was not reported at all, though its value was withheld; and two raw keys
    # collapsing to one name double-counted. Sanitizing is for display, and
    # now happens after the comparison.
    withheld = [key for key in payload if key not in projected]
    if withheld:
        notes = (*notes, _withheld_note(len(payload), withheld))
    return _unrecognized(
        evidence=_excerpt_for(MODELLED_FIELDS, payload),
        notes=notes,
    )


def _withheld_note(total: int, withheld: list[str]) -> str:
    """State how much of a record was not retained, within the note bound.

    Counts the record's own top-level keys, which is what an operator needs
    to write a signature. A key that *is* modelled but whose un-named
    sub-keys were withheld does not appear here — the excerpt shows that
    directly, since an object at a declared path renders as its key names.

    The count comes from the raw keys and the names from ``text()``, so a key
    whose name cannot be rendered at all is still counted among the elided
    rather than disappearing from the total.
    """
    names = [name for name in (text(key) for key in sorted(withheld)) if name is not None]
    named = names[:_MAX_NAMED_KEYS]
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


def _unrecognized(*, evidence: _Excerpt, notes: tuple[str, ...] = ()) -> NormalizedEvent:
    """The honest fallback: carried, labelled, and never mis-attributed.

    ``evidence`` is what is retained: its ``text`` becomes ``message`` and
    ``raw_excerpt``, and its ``values`` — the same projection, undivided — are
    what indicators are read from. One parameter, deliberately: a second,
    *wider* source existed for indicator extraction and became the route by
    which a withheld field reached the store (see :func:`_normalize_mapping`),
    so the decomposition travels with the text rather than beside it. See
    :class:`_Excerpt` for why both forms are needed.

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

    Observables are extracted from the retained evidence rather than from the
    truncated ``message``, which is what #206 asked for and still holds: the
    evidence is bounded at ``MAX_RAW_EXCERPT`` while ``message`` is cut at
    ``MAX_FIELD_LEN``, so an indicator between those two bounds is kept even
    though the summary no longer shows it. What no longer happens is reading a
    *wider* string than the evidence — that is the hole described in
    :func:`_normalize_mapping`.

    Each value is scanned on its own, so ``MAX_FIELD_LEN`` applies per field
    and not to the concatenation. The bound itself is unchanged and
    pre-existing: an indicator appearing only past character 2048 **of a
    single field** is still not extracted, which on a text path means past
    character 2048 of the line, since the line is the one value.
    """
    retained = text(evidence.text, limit=MAX_RAW_EXCERPT) or ""
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
        observables=observables(*evidence.values),
        raw_excerpt=retained[:MAX_RAW_EXCERPT],
        notes=notes,
    )
