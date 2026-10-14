"""Correlation error taxonomy.

Imports nothing first-party, so the layering is structural — the same
discipline as ``ingest/errors.py``, ``store/errors.py`` and ``attack/errors.py``.

The distinction that matters here mirrors ``ingest/``'s: correlation runs over
telemetry that is already normalized, so *content* problems are expected and
degrade visibly (an entity that cannot be resolved stands alone; an event that
links to nothing yields no incident). Only a caller mistake raises — bad
thresholds, or input that is not what the signature says.
"""

from __future__ import annotations


class CorrelationError(ValueError):
    """Base class for correlation failures."""


class ThresholdError(CorrelationError):
    """A threshold is not usable.

    Raised rather than clamped. Thresholds decide what counts as an incident,
    and silently substituting a default for a nonsensical value would make the
    output unexplainable: an analyst reading "3 events" has no way to know the
    minimum was quietly changed under them.
    """
