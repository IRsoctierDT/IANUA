"""Deterministic lookup and matching over the validated intel library.

No clock, no network: ``as_of`` is always injected by the caller (the
orchestrator derives it from the batch's own event timestamps, falling back
to the store's newest ``retrieved`` date — deterministic either way).

Poisoning containment at query time (defense in depth over the ingest
checks): never-flag suppression runs again here, and network-observable
indicator types require **two sources with distinct declared upstreams** for
a ``malicious`` verdict — a single feed's word caps at ``suspicious``, so one
poisoned source can never brand infrastructure malicious on its own.
"""

from __future__ import annotations

from datetime import date
from typing import Literal, cast

from attack import Corpus

from intel.decay import FLOOR, decayed_score, score_to_confidence
from intel.model import (
    CORROBORATION_TYPES,
    AtomicVerdict,
    BehaviorMatch,
    BehaviorStatus,
    IntelStore,
)
from intel.store import never_flagged


def default_as_of(store: IntelStore) -> date:
    """The store's newest retrieval date — the deterministic fallback anchor."""
    dates = [source.retrieved for source in store.sources.values()]
    dates += [indicator.retrieved for indicator in store.atomic.values()]
    return date.fromisoformat(max(dates))


def lookup_indicator(store: IntelStore, value: str, *, as_of: date) -> AtomicVerdict:
    """Verdict for one atomic value at ``as_of`` (exact, case-insensitive)."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("indicator value must be a non-empty string.")
    needle = value.strip().lower()

    if never_flagged(needle, store.never_flag):
        return AtomicVerdict(
            value=needle,
            matched=False,
            risk="suppressed",
            confidence="none",
            decayed_score=0.0,
            sources=(),
            references=(),
            notes=(
                "Address is inside the never-flag list (internal/reserved space); "
                "intel verdicts are suppressed by policy — investigate locally.",
            ),
        )

    hits = [ind for ind in store.atomic.values() if ind.value == needle]
    if not hits:
        return AtomicVerdict(
            value=needle,
            matched=False,
            risk="unknown",
            confidence="none",
            decayed_score=0.0,
            sources=(),
            references=(),
            notes=("No committed indicator matches this value.",),
        )

    live = [(ind, decayed_score(ind, as_of=as_of)) for ind in hits]
    live = [(ind, score) for ind, score in live if score >= FLOOR]
    if not live:
        return AtomicVerdict(
            value=needle,
            matched=True,
            risk="expired",
            confidence="none",
            decayed_score=0.0,
            sources=tuple(sorted({ind.source_id for ind in hits})),
            references=tuple(sorted({ind.reference for ind in hits})),
            notes=(
                "Matching indicators exist but have expired or decayed below the "
                "actionable floor — treat as historical context only.",
            ),
        )

    top_score = max(score for _, score in live)
    worst_risk: Literal["malicious", "suspicious", "benign"] = "benign"
    for ind, _ in live:
        if ind.risk == "malicious":
            worst_risk = "malicious"
            break
        if ind.risk == "suspicious":
            worst_risk = "suspicious"
    source_ids = sorted({ind.source_id for ind, _ in live})
    upstreams = {store.sources[sid].upstream for sid in source_ids}
    notes: list[str] = []
    if (
        worst_risk == "malicious"
        and any(ind.indicator_type in CORROBORATION_TYPES for ind, _ in live)
        and len(upstreams) < 2
    ):
        worst_risk = "suspicious"
        notes.append(
            "Single-source network indicator: capped at 'suspicious' pending "
            "corroboration from an independent upstream (poisoning containment)."
        )
    return AtomicVerdict(
        value=needle,
        matched=True,
        risk=worst_risk,
        confidence=cast('Literal["low", "medium", "high", "none"]', score_to_confidence(top_score)),
        decayed_score=round(top_score, 4),
        sources=tuple(source_ids),
        references=tuple(sorted({ind.reference for ind, _ in live})),
        notes=tuple(notes),
    )


def behavior_status(
    record_last_reviewed: str,
    record_interval_days: int,
    techniques: tuple[str, ...],
    corpus: Corpus,
    *,
    as_of: date,
) -> tuple[BehaviorStatus, tuple[str, ...]]:
    """Compute a behavioral record's aging status (pure function)."""
    notes: list[str] = []
    for technique_id in techniques:
        technique = corpus.techniques.get(technique_id)
        if technique is not None and technique.status != "active":
            tombstone = corpus.tombstones.get(technique_id)
            successor = tombstone.successor if tombstone else None
            notes.append(
                f"ATT&CK anchor {technique_id} is {technique.status} in the pinned "
                f"release{f' (successor: {successor})' if successor else ''} — "
                "re-anchor this record."
            )
    if notes:
        return "stale-anchor", tuple(notes)
    reviewed = date.fromisoformat(record_last_reviewed)
    if (as_of - reviewed).days > record_interval_days:
        return (
            "review-due",
            (
                f"Last human review {record_last_reviewed} exceeds the "
                f"{record_interval_days}-day interval — re-review before relying on it.",
            ),
        )
    return "active", ()


def match_behaviors(
    store: IntelStore, event_type: str, corpus: Corpus, *, as_of: date
) -> list[BehaviorMatch]:
    """Behavioral records covering ``event_type``, with computed status."""
    if not isinstance(event_type, str) or not event_type.strip():
        raise ValueError("event_type must be a non-empty string.")
    needle = event_type.strip().lower()
    matches: list[BehaviorMatch] = []
    for record in store.behaviors:
        if needle not in record.event_types:
            continue
        status, notes = behavior_status(
            record.last_reviewed,
            record.review_interval_days,
            record.attack_techniques,
            corpus,
            as_of=as_of,
        )
        matches.append(BehaviorMatch(record=record, status=status, notes=notes))
    return matches
