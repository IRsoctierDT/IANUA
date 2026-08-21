"""Error taxonomy for the local ATT&CK corpus.

``attack/`` is the shared technique vocabulary read by agents, detections
gates, correlation, and scripts. It deliberately imports **no first-party
module** — including the agents' ``ValidationError`` — so the layering
(vocabulary below control plane) is structural, not aspirational. All errors
derive from ``ValueError`` so existing fail-closed callers that catch
``ValueError`` keep working.
"""

from __future__ import annotations


class AttackError(ValueError):
    """Base class for every error the attack corpus raises."""


class AttackIntegrityError(AttackError):
    """Committed corpus data failed verification against the signed pin.

    Tampering or corruption — this is a hard failure: callers must not fall
    back to the damaged data.
    """


class AttackUnavailableError(AttackError):
    """The corpus is absent (not yet built / not shipped in this checkout).

    Distinct from :class:`AttackIntegrityError` so callers can degrade soft to
    an explicit "corpus unavailable" state — absence is never a guess, and
    never silently treated as an empty corpus.
    """
