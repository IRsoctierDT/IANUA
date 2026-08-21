"""Typed, immutable views over the local threat-intelligence library.

Two indicator kinds with deliberately different lifecycles (the Pyramid of
Pain, encoded rather than asserted):

* **Atomic indicators** (IPs, domains, URLs, hashes) are trivial for an
  adversary to rotate, so their value decays on a clock: each carries a hard
  ``expires`` date and an exponential confidence decay from ``retrieved``.
* **Behavioral records** describe *how* an adversary operates (ATT&CK-anchored
  TTP markers). Changing behavior is expensive, so these do not decay on a
  clock — they age on a human review interval and on ATT&CK revisions: a
  deprecated/revoked anchor degrades a record to ``stale``, never deletes it.

Pure data holders — no I/O, no clock (``as_of`` is always injected), no
network (enforced by ``tests/security/test_intel_no_egress.py``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Confidence = Literal["low", "medium", "high"]
Risk = Literal["malicious", "suspicious", "benign"]
AtomicType = Literal["ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email"]
BehaviorStatus = Literal["active", "review-due", "stale-anchor"]

#: Network-observable types where a single feed's word is never enough: one
#: poisoned source must not be able to brand infrastructure malicious.
CORROBORATION_TYPES: frozenset[str] = frozenset({"ipv4", "ipv6", "domain", "url"})


@dataclass(frozen=True, slots=True)
class Source:
    """A registered intel source with provenance and license posture."""

    source_id: str
    name: str
    url: str
    license: str
    upstream: str
    retrieved: str


@dataclass(frozen=True, slots=True)
class AtomicIndicator:
    """One atomic indicator with full provenance and a mandatory expiry."""

    indicator_type: AtomicType
    value: str
    risk: Risk
    confidence: Confidence
    source_id: str
    first_seen: str
    retrieved: str
    expires: str
    tlp: str
    reference: str


@dataclass(frozen=True, slots=True)
class BehavioralRecord:
    """An ATT&CK-anchored behavioral indicator (TTP) the platform can match."""

    record_id: str
    title: str
    description: str
    attack_techniques: tuple[str, ...]
    event_types: tuple[str, ...]
    markers: tuple[str, ...]
    false_positives: tuple[str, ...]
    confidence: Confidence
    source_id: str
    last_reviewed: str
    review_interval_days: int


@dataclass(frozen=True, slots=True)
class IntelStore:
    """The fully validated library."""

    sources: dict[str, Source]
    atomic: dict[str, AtomicIndicator]
    behaviors: tuple[BehavioralRecord, ...]
    never_flag: tuple[str, ...]
    attack_version: str


@dataclass(frozen=True, slots=True)
class AtomicVerdict:
    """The outcome of one atomic lookup at a given ``as_of``."""

    value: str
    matched: bool
    risk: Risk | Literal["unknown", "suppressed", "expired"]
    confidence: Confidence | Literal["none"]
    decayed_score: float
    sources: tuple[str, ...]
    references: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BehaviorMatch:
    """A behavioral record matched to an event, with its computed status."""

    record: BehavioralRecord
    status: BehaviorStatus
    notes: tuple[str, ...]
