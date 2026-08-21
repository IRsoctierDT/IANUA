"""Reference validation against the pinned corpus.

The merge-blocking teeth of the "ongoing database" requirement: every
operational surface that names a technique (Sigma tags, mapping rules, the
Navigator layer, correlation scenarios) validates its references here, so a
revoked or deprecated ID surfaces loudly — with its successor named — instead
of rotting silently. ``lookup("T1064")`` answers "deprecated, no replacement"
rather than the indistinguishable-from-a-typo ``None``.
"""

from __future__ import annotations

import re

from attack.errors import AttackError
from attack.model import Corpus, ReferenceVerdict

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

#: Bound on successor-chain walks — a well-formed corpus never chains this
#: deep, so hitting the bound is itself an integrity signal.
_MAX_SUCCESSOR_HOPS = 10


def validate_reference(technique_id: str, corpus: Corpus) -> ReferenceVerdict:
    """Return the verdict for one technique reference (never raises on data).

    Malformed *input* raises (the caller passed something that is not a
    technique ID); data-driven outcomes — unknown, revoked, deprecated — are
    verdicts, so gate scripts can report every problem in one pass.
    """
    if not isinstance(technique_id, str) or not _TECHNIQUE_ID_RE.fullmatch(technique_id):
        raise AttackError(f"not a technique ID: {technique_id!r}")

    technique = corpus.techniques.get(technique_id)
    if technique is None:
        tombstone = corpus.tombstones.get(technique_id)
        if tombstone is not None:
            return ReferenceVerdict(
                technique_id=technique_id,
                status=tombstone.status,
                name=tombstone.name or None,
                successor=tombstone.successor,
                problems=(f"{technique_id} is {tombstone.status} in the pinned release",),
            )
        return ReferenceVerdict(
            technique_id=technique_id,
            status="unknown",
            problems=(f"{technique_id} does not exist in the pinned ATT&CK release",),
        )

    if technique.status == "active":
        return ReferenceVerdict(technique_id=technique_id, status="active", name=technique.name)

    tombstone = corpus.tombstones.get(technique_id)
    successor = tombstone.successor if tombstone is not None else None
    problem = f"{technique_id} ({technique.name}) is {technique.status}"
    if successor:
        problem += f"; successor: {successor}"
    return ReferenceVerdict(
        technique_id=technique_id,
        status=technique.status,
        name=technique.name,
        successor=successor,
        problems=(problem,),
    )


def resolve_current(technique_id: str, corpus: Corpus) -> ReferenceVerdict:
    """Follow revoked→successor chains to the current technique (bounded).

    Deprecated techniques have no successor by definition and resolve to
    themselves (status ``deprecated``) — the caller decides what to do; this
    function never substitutes silently.
    """
    seen: set[str] = set()
    current = technique_id
    for _ in range(_MAX_SUCCESSOR_HOPS):
        if current in seen:
            raise AttackError(f"successor cycle detected at {current!r}")
        seen.add(current)
        verdict = validate_reference(current, corpus)
        if verdict.status != "revoked" or verdict.successor is None:
            return verdict
        current = verdict.successor
    raise AttackError(f"successor chain exceeds {_MAX_SUCCESSOR_HOPS} hops from {technique_id!r}")


def check_references(technique_ids: list[str], corpus: Corpus) -> list[ReferenceVerdict]:
    """Validate a batch of references; return only the failing verdicts."""
    return [
        verdict
        for technique_id in technique_ids
        if not (verdict := validate_reference(technique_id, corpus)).ok
    ]
