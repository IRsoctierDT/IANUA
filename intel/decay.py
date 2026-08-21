"""Deterministic aging for intel content. No clock reads — ``as_of`` is injected.

Atomic confidence decays exponentially from ``retrieved`` with a per-type
half-life (an IP rotates in weeks; a file hash identifies its exact payload
for as long as that payload circulates). Behavioral records age on their
declared review interval instead — see ``intel.match`` for the ATT&CK-anchor
half of behavioral staleness.
"""

from __future__ import annotations

import math
from datetime import date

from intel.model import AtomicIndicator

#: Confidence label -> base score for decay arithmetic.
_CONFIDENCE_SCORE: dict[str, float] = {"low": 0.3, "medium": 0.6, "high": 1.0}

#: Per-type half-life in days. Ordered by how cheaply an adversary rotates
#: the indicator (Pyramid of Pain): network locators decay fast, content
#: hashes slowly (a hash stays a precise payload identifier; what fades is
#: the chance the payload is still in circulation).
HALF_LIFE_DAYS: dict[str, float] = {
    "url": 14.0,
    "ipv4": 30.0,
    "ipv6": 30.0,
    "domain": 90.0,
    "email": 90.0,
    "md5": 365.0,
    "sha1": 365.0,
    "sha256": 365.0,
}

#: Below this decayed score an indicator no longer supports any verdict.
FLOOR = 0.15


def decayed_score(indicator: AtomicIndicator, *, as_of: date) -> float:
    """The indicator's confidence score at ``as_of`` (0.0 once expired)."""
    if as_of > date.fromisoformat(indicator.expires):
        return 0.0
    age_days = (as_of - date.fromisoformat(indicator.retrieved)).days
    if age_days < 0:
        # An indicator "retrieved in the future" relative to the analysis
        # window contributes nothing rather than a confident anachronism.
        return 0.0
    half_life = HALF_LIFE_DAYS[indicator.indicator_type]
    return _CONFIDENCE_SCORE[indicator.confidence] * math.pow(2.0, -age_days / half_life)


def score_to_confidence(score: float) -> str:
    """Project a decayed score back onto the coarse label scale."""
    if score >= 0.75:
        return "high"
    if score >= 0.4:
        return "medium"
    if score >= FLOOR:
        return "low"
    return "none"
