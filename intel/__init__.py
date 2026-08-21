"""IANUA's local threat-intelligence library — first-party, behavioral, expiring.

The durable half of "threat intelligence" is behavioral (ATT&CK-anchored TTP
records this repository authors); the atomic half ships as a small synthetic
seed (RFC 5737/3849/2606 values only) so lookups, decay, and corroboration
are exercisable from a clean clone without publishing accusations about real
third-party infrastructure. No live feed ships; no module here opens a
socket or reads a clock (``as_of`` is injected). See DESIGN.md §5 boundary 6
and §11 (2026-08-21).
"""

from intel.decay import HALF_LIFE_DAYS, decayed_score, score_to_confidence
from intel.match import default_as_of, lookup_indicator, match_behaviors
from intel.model import (
    AtomicIndicator,
    AtomicVerdict,
    BehavioralRecord,
    BehaviorMatch,
    IntelStore,
    Source,
)
from intel.store import IntelStoreError, load_store, never_flagged

__all__ = [
    "HALF_LIFE_DAYS",
    "AtomicIndicator",
    "AtomicVerdict",
    "BehaviorMatch",
    "BehavioralRecord",
    "IntelStore",
    "IntelStoreError",
    "Source",
    "decayed_score",
    "default_as_of",
    "load_store",
    "lookup_indicator",
    "match_behaviors",
    "never_flagged",
    "score_to_confidence",
]
