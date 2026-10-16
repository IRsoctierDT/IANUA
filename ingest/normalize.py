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
from ingest._coerce import FieldPath, depth_within, observables, project, text
from ingest.errors import IngestError, UnsupportedInputError
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
        except (ValueError, RecursionError):
            # ``ValueError``, not ``json.JSONDecodeError``, and the widening is
            # the fix rather than tidying. ``JSONDecodeError`` *is* a
            # ``ValueError``, so this still catches every malformed document —
            # and it now also catches the one well-formed document CPython
            # refuses to decode: an integer literal past
            # ``sys.get_int_max_str_digits()`` (4300 digits by default), whose
            # conversion is quadratic. ``json.loads`` raises a bare
            # ``ValueError`` for it, anywhere in the document, nested or not.
            #
            # That raise escaped ``normalize`` entirely. Measured end to end:
            # a file of three lines, one of them a JSON object with a
            # 5000-digit number, gave two identical collector passes —
            # ``0 event(s) stored``, ``offsets held``, ``[first-run]``, exit 1
            # — because ``normalize_many`` built a list and
            # ``run_collector.py`` writes a source's cursor only after its
            # events are durable. The source was stalled permanently and the
            # two healthy lines in that file were never stored.
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

    **That sentence was false, and it is now held by two layers instead of
    asserted by one.** It is a consequence of rule 2 — nothing a record
    contains may raise out of ``normalize`` — and when rule 2 leaked, a list
    comprehension here turned one bad record into the loss of every record
    beside it. Measured: a three-line file with one JSON object holding a
    5000-digit integer stored **none** of the three, and because
    ``scripts/run_collector.py`` writes a source's cursor only once its events
    are durable, the source re-read the same window on every pass forever —
    two identical passes, ``offsets held``, ``[first-run]``, exit 1. Loud, and
    permanent, and recoverable only by editing a log the collector is licensed
    to read but never to write.

    The first layer is the fix: ``_coerce.text`` and ``_coerce.epoch`` are
    total over the numbers Python refuses to render, and the JSON decode guard
    catches ``ValueError`` rather than only ``JSONDecodeError``. This loop is
    the second, and it is deliberately the *wider* one — a batch boundary
    whose contract is "one bad record never costs the batch" cannot keep that
    contract by naming exception types, because the next leak will be a type
    nobody listed. ``tests/security`` pins that the committed corpus never
    reaches it, so it firing means something changed rather than something is
    tolerated.

    What it does not do is let the collector advance past records it failed to
    store: the degraded event *is* stored, so the cursor advance is honest.
    A raise from the store itself is outside this and still fails closed.
    """
    out: list[NormalizedEvent] = []
    for record in records:
        try:
            out.append(normalize(record))
        except IngestError:
            # Propagated, deliberately, and the first version of this loop did
            # not. ``ingest/errors.py`` draws the line this layer turns on:
            # malformed telemetry degrades, and only an input that cannot be
            # telemetry at all — a wrong Python type — raises, "because those
            # signal a caller bug rather than a bad log line". Absorbing
            # ``UnsupportedInputError`` here would launder exactly that bug
            # into a thousand degraded events, and ``MalformedProjectionError``
            # says a stored row was damaged after it was written, which the
            # same file says has no honest degradation. Measured: an object
            # with a raising ``__repr__`` came back as an event noting
            # ``UnsupportedInputError`` instead of refusing.
            raise
        except Exception as exc:
            # The outer layer. Deliberately unnamed: see the docstring.
            out.append(_normalization_raised(record, exc))
    return out


def _normalization_raised(record: Any, exc: BaseException) -> NormalizedEvent:
    """An event recording that a record was seen and could not be normalized.

    Must itself be total, or the second layer has the first layer's hole. So
    the evidence is built without rendering the record's values: a ``str`` or
    ``bytes`` record is carried as text, and a mapping contributes its key
    names only — the same "shape, not content" rule ``project`` applies, and
    the only rendering that cannot raise on a value Python will not print.

    The note names the exception *type* and not its message, because a
    message is often record content (a ``KeyError``'s is a key name) and this
    note is written to an append-only store that refuses ``UPDATE``.

    **The rendering is itself guarded, because the first version of it was
    not.** A ``Mapping`` subclass whose ``__iter__`` raises defeated the key-
    name branch — ``list(record)`` raises again, inside the ``except`` that
    was handling the first raise — and ``RuntimeError`` escaped
    ``normalize_many`` exactly as the ``ValueError`` had. Measured while
    writing this function, which is the point: a layer that exists because
    "the next leak will be a type nobody listed" cannot be total by listing
    types.
    """
    try:
        if isinstance(record, bytes):
            carried = record.decode("utf-8", errors="replace")[:MAX_RAW_EXCERPT]
        elif isinstance(record, str):
            carried = record[:MAX_RAW_EXCERPT]
        elif isinstance(record, Mapping):
            named = [text(key) for key in list(record)[:MAX_PROJECTED_ITEMS]]
            carried = json.dumps(sorted(key for key in named if key is not None))
        else:
            carried = type(record).__name__
    except Exception:
        # Not logged, and nothing here may reach a logger: ``ingest`` imports
        # no clock, no filesystem and no transport, which is what makes it
        # testable as a pure function (``tests/security`` pins all three). The
        # note below is the record of what happened, and it travels with the
        # event into the store rather than into a log the operator has to
        # correlate by hand.
        carried = "a record that could not be rendered"
    return _unrecognized(
        evidence=_carried(carried),
        notes=(
            f"normalizing this record raised {type(exc).__name__}; it is kept "
            f"unparsed so that the batch and the collector cursor survive it",
        ),
    )


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
    scanned either.

    **That is asserted, but not by the test this docstring used to name**, and
    the correction is measured rather than reasoned. Planting
    :func:`_retained_values` as the identity function — round two's defect,
    exactly — turns **three** cases red:

        test_an_indicator_is_extracted_only_when_the_excerpt_retains_it[in-the-cut-leaf]
        test_an_indicator_is_extracted_only_when_the_excerpt_retains_it[past-the-cut]
        test_an_unclaimed_records_observables_are_all_inside_its_excerpt[past-the-cut]

    ``test_every_observable_is_findable_in_the_retained_evidence`` is **not**
    among them: all thirty of its legs stay green, because on the committed
    corpus ``_retained_values`` is behaviourally the identity function anyway.
    Measured: 30 legs, 0 that drop a leaf, 307 of 307 leaves kept, largest
    ``raw_excerpt`` 679 characters against a 4096 bound, and **no** leg
    reaching that bound. A test cannot distinguish a function from its
    degenerate case on a corpus where they agree, and this docstring claimed
    it did.

    Only the unclaimed path reaches here at all —
    :func:`_normalize_mapping` passes ``_excerpt_for(...).text`` and discards
    ``.values`` — so none of this covers a *recognized* record, which is a
    separate open defect rather than a wording problem.

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
    #: True when ``text`` IS the record — nothing decoded, so nothing was
    #: projected and nothing withheld. Set by :func:`_carried` and by no one
    #: else, so the ``parse_status`` derived from it cannot be mis-declared by
    #: a caller: it follows from how the evidence was built.
    verbatim: bool = False


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
    ``find`` is within the bound by construction. An explicit second bound
    check was written, measured to be unreachable, and removed rather than
    left as decorative defence.

    This docstring also claimed that "a fragment the slice cut in half is not
    found at all", and **that is false** — found by review, measured. Key
    names and string values are rendered with identical quoting, so a leaf
    whose value happens to equal a key name matches the *key name's*
    occurrence, which precedes the value. At a padding where the ``Subject``
    value is removed from the excerpt entirely, leaving only the key
    ``"Subject"``, a leaf whose value is the string ``Subject`` is still kept
    and scanned. The retention invariant survives it — the key name is itself
    in the excerpt, so the indicator is still inside the retained text — but
    the *attribution* is wrong, and the sentence asserting it cannot happen
    was simply untrue.

    **The walk stops and nothing is salvaged, and that is the end of three
    rounds of trying to salvage.** Round five observed that simply breaking on
    the cut leaf throws away the part of it the excerpt still holds — an
    indicator readable at index 3594 of a 4096-character excerpt, extracted
    into nothing — and added a scan of the remaining text. The two rounds that
    followed were both defects *in that addition*, and both **fabricated**
    rather than lost:

    ====  ============================================  =====================
    rd    what the tail scan did                        outcome
    ====  ============================================  =====================
    5     added, to recover a retained indicator        recovers it
    6     matched a token the 4096 slice had severed    a sha1/md5 from a cut
                                                        sha256, 19/50 offsets
                                                        for a URL
    8     matched a token up to a JSON unicode escape      a URL that never
                                                        existed, 10/148
    9     ``observables()`` re-sliced the tail at        a 40-char sha1 from a
          ``MAX_FIELD_LEN`` **after** both guards        50-char hex run that
                                                        matches no hash
    ====  ============================================  =====================

    Round nine is why the mechanism is gone rather than patched again. Both of
    round six's and eight's guards operated on the tail *as it was built*, and
    round nine's cut happens downstream in ``text()``, where they cannot
    reach. Token-safety at construction cannot survive a later slice, so
    making the tail sound would mean token-safety at every boundary the value
    crosses — an open-ended blacklist, and three rounds of evidence that I
    guess its membership wrong.

    So the trade was measured and taken the other way. Removing the salvage
    loses exactly one case and removes three:

    ===============================  ==========  ==========  ============
    case                             retained    with tail   without
    ===============================  ==========  ==========  ============
    round 5, cut leaf, URL first     yes         exact       **none**
    round 9, 50-hex run              yes         fabricated  none
    round 6, cut mid-URL             no          none        none
    round 2, past the cut            no          none        none
    round 1, late-sorting            yes         exact       exact
    first leaf                       yes         exact       exact
    ===============================  ==========  ==========  ============

    One gap against zero false keys. ``AGENTS.md`` §3 orders that trade —
    most secure, fail closed — and the asymmetry is real rather than
    aesthetic: a missing indicator is a gap an operator can see in the excerpt
    and act on, while a fabricated one is an indexed, append-only join key
    that ``correlation/entities.py`` will join entities on, cannot be edited
    (``UPDATE`` is refused), and reads exactly like a real IOC.

    **What this costs, stated plainly so nobody re-adds it by accident.** An
    indicator inside the leaf the excerpt slice cut is retained and readable
    and is *not* extracted.
    ``test_an_indicator_is_extracted_only_when_the_excerpt_retains_it``
    pins that as the ``in-the-cut-leaf`` row with ``must_be_extracted=False``,
    so the loss is asserted rather than incidental.

    **The sort, measured rather than reasoned about.** An earlier version of
    this paragraph said the sort was not load-bearing "because ``project``
    happens to build the projection in an order the forward scan tolerates".
    That reasoning is false, and review was right to push on it. ``project``
    inserts top-level keys in *declaration* order, and ``sysmon`` is the one
    signature whose ``fields`` tuple is unsorted — it breaks at index 12
    (``provider_name`` before ``CommandLine``) and index 30 (``UtcTime``
    before ``EventData``). On a sysmon projection the two orders disagree, and
    walking in insertion order keeps **4 of 10** leaves rather than 10: the
    forward scan's ``offset`` runs past a value it has not reached yet, the
    ``find`` fails, and the walk stops. That is round one's defect.

    Where that can actually bite is narrower than it sounds, and worth writing
    down because three call sites look alike:

    ===========================================  ==================  =========
    call site                                    field list          sort?
    ===========================================  ==================  =========
    parse failure on a claimed record            ``signature.fields``  **yes**
    claimed record, parsed                       ``signature.fields``  no, only
                                                                       ``.text``
                                                                       is taken
    unclaimed record                             ``MODELLED_FIELDS``   no, it is
                                                                       sorted, so
                                                                       insertion
                                                                       order
                                                                       already
                                                                       agrees
    ===========================================  ==================  =========

    So the sort matters on the parse-failure branch alone. That branch is
    reachable and tested — ``tests/unit/test_evidence_projection.py`` forces an
    auditd parser failure — but auditd's declaration *is* sorted. For sysmon,
    the one signature where the sort earns its keep, no record was found that
    a signature claims and its parser then fails on: roughly a thousand
    hostile mutations across all fifteen committed fixtures produced zero such
    records, for all ten vendors.

    The honest summary is therefore neither "not load-bearing" nor
    "load-bearing": it is **correct insurance on a branch the one signature
    that needs it is not currently known to reach**, and removing it leaves
    every test green. ``test_the_leaf_walk_tolerates_an_unsorted_declaration``
    pins it at this function's own level, since no end-to-end record reaches
    it.
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
            # The slice cut this leaf, or ``_serialize`` fell back and the
            # leaf is not in the text at all. Either way the walk stops,
            # and nothing is salvaged from the text that remains — see the
            # docstring for the three rounds that salvaging cost.
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
    return _Excerpt(raw, (raw,), verbatim=True)


def _serialize(value: Mapping[str, Any]) -> str:
    """Render a mapping to bounded text, degrading rather than raising.

    One serializer for both the excerpt and the indicator scan, so the
    fallback is written and exercised once. ``default=str`` handles a value
    JSON cannot represent; the ``except`` is for a record that is circular or
    too deep for the encoder, which no decoded JSON can be but a caller
    passing a mapping directly certainly can. Nothing a record contains may
    raise out of ``normalize`` — that is rule 2, and an excerpt is not worth
    losing an event over.

    **Three tiers, because the second one raised on exactly the input it was
    there to absorb.** ``str(value)`` on a mapping renders its values, so a
    mapping holding an integer past ``sys.get_int_max_str_digits()`` raised
    ``ValueError`` out of the fallback — out of the function whose docstring
    states rule 2. ``json.dumps`` fails first on the same value (``default``
    is consulted only for types JSON cannot represent, and ``int`` is not one,
    so the encoder calls ``int.__repr__`` and that is what refuses), so both
    tiers were defeated by one value. The third tier renders key *names*
    only, which are strings and coerce through the now-total :func:`text`:
    shape, not content, exactly as ``project``'s second rule has it, and it
    cannot raise.
    """
    try:
        return json.dumps(value, sort_keys=True, default=str)[:MAX_RAW_EXCERPT]
    except (TypeError, ValueError, RecursionError):
        pass
    try:
        return str(value)[:MAX_RAW_EXCERPT]
    except (TypeError, ValueError, RecursionError):
        pass
    named = [text(key) for key in list(value)[:MAX_PROJECTED_ITEMS]]
    return json.dumps(sorted(key for key in named if key is not None))[:MAX_RAW_EXCERPT]


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
    withheld, examined = _withheld_fields(payload, projected)
    if withheld:
        notes = (*notes, _withheld_note(examined, withheld))
    return _unrecognized(
        evidence=_excerpt_for(MODELLED_FIELDS, payload),
        notes=notes,
    )


def _withheld_fields(
    payload: Any, projected: Any, prefix: str = "", depth: int = 0
) -> tuple[list[str], int]:
    """Withheld field paths at any depth, and how many paths were examined.

    **This used to compare top-level keys only, and the compensation its
    docstring claimed holds in one of three regimes.** That docstring said a
    modelled key whose sub-keys were withheld "does not appear here — the
    excerpt shows that directly, since an object at a declared path renders as
    its key names". Measured, on merged code:

    1. **Holds** when a declared path lands on a container and no *deeper*
       declared path is present: ``{"status": {"secretNote", "other"}}``
       renders as ``{"status": ["other", "secretNote"]}`` and both names are
       in the excerpt.
    2. **Defeated by** :func:`~ingest._coerce._graft`, whose own docstring
       says "The deeper path wins": with ``status`` *and* ``status.value``
       both declared, ``{"status": {"value": "Succeeded", "secretNote": "s"}}``
       renders as ``{"status": {"value": "Succeeded"}}`` and ``secretNote``
       is named **nowhere in the event**.
    3. **Never applies** when the container is only a path *prefix*, never
       declared on its own — which is **14 of the 18** nested top-level names
       across all ten signatures (``System``, ``EventData``, ``userIdentity``,
       ``deviceDetail``, ``http``, ``dns``, …). A genuine Windows Security
       4625, claimed by no signature because there is no Windows Security
       parser, retained ``{"System": {"Provider": {"Name": …}}}`` and said
       nothing at all about ``System.Correlation``.

    Regime 3 is the one that matters, because nested is what real Windows and
    cloud telemetry look like, and the §5 stage-6 amendment leans on this note
    as *the* compensation for what narrowing drops. So the walk descends.

    Two deliberate limits, both stated rather than discovered later:

    * **It does not descend past a shape-rendered container** (regime 1). The
      excerpt already names those keys, which is enough to write
      ``status.<key>``; going deeper would report paths whose parent is
      already visible.
    * **It does not descend into lists.** A declared path continuing through a
      sequence applies to each element (``project``'s third rule), so a list's
      *path* is reported once and its elements are not enumerated.

    Comparison is on the record's **raw** keys throughout; rendering for
    display happens in :func:`_withheld_note`, which is the ordering a
    previous defect established.
    """
    if depth > MAX_NESTING_DEPTH or not isinstance(payload, Mapping):
        return [], 0
    withheld: list[str] = []
    examined = 0
    for key in payload:
        label = f"{prefix}{key}"
        examined += 1
        # ``key not in projected`` works for both shapes a projection takes
        # here: a mapping, and the sorted list of key *names* that
        # ``_coerce._leaf`` renders for a container. A name present in that
        # list is in the excerpt and so is not withheld.
        if not isinstance(projected, (Mapping, list)) or key not in projected:
            child = payload[key]
            if isinstance(child, Mapping) and child:
                # Name the leaves rather than the container: a declared path
                # IS a leaf path, so these are the strings an operator writes.
                deeper, counted = _withheld_fields(child, None, f"{label}.", depth + 1)
                withheld.extend(deeper)
                examined += counted
            else:
                withheld.append(label)
            continue
        if isinstance(projected, Mapping):
            deeper, counted = _withheld_fields(payload[key], projected[key], f"{label}.", depth + 1)
            withheld.extend(deeper)
            examined += counted
    return withheld, examined


def _withheld_note(total: int, withheld: list[str]) -> str:
    """State how much of a record was not retained, within the note bound.

    The count comes from the raw paths and the names from ``text()``, so a
    path whose name cannot be rendered at all is still counted among the
    elided rather than disappearing from the total.
    """
    names = [name for name in (text(key) for key in sorted(withheld)) if name is not None]
    named = names[:_MAX_NAMED_KEYS]
    elided = len(withheld) - len(named)
    note = (
        f"{len(withheld)} of {total} record fields are modelled by no parser; "
        f"their values are withheld from the excerpt (fields: {', '.join(named)}"
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
        # Derived from the evidence, not from whether a note happened to be
        # attached. It used to be `"partial" if notes else "text"`, which made
        # three of the four verbatim regimes (a JSON record with a trailing
        # comma, a JSON array, a record over MAX_RAW_BYTES) read "partial" —
        # the status the schema documents as "recognized, but required fields
        # were missing" — while bare prose read "text". Measured; so nothing
        # downstream could tell verbatim retention from projection with
        # withholding. "text" is the documented meaning ("no parser claimed it;
        # carried as opaque text") and is now uniform across every verbatim
        # regime; the notes still say WHY the record was carried.
        parse_status="text" if evidence.verbatim else "partial",
        observables=observables(*evidence.values),
        raw_excerpt=retained[:MAX_RAW_EXCERPT],
        notes=notes,
    )
