"""Risk-Based Alerting (RBA) engine — deterministic entity risk scoring.

Aggregates individual scored events into per-entity ("risk object") scores over
a sliding time window, and raises a *risk finding* only when accumulated risk
crosses a threshold. This is the Splunk-ES / Elastic-entity-risk pattern
implemented as pure, deterministic Python: it turns the SOC Analyst Agent's
per-event severity scores into low-noise, prioritized, entity-centric findings
without collapsing distinct low-severity events into background noise.

Design (DESIGN.md §5; AGENTS.md §3):
- **Deterministic & network-free.** Given the same ordered events and config,
  the same findings result. No clocks are read internally — event timestamps
  are supplied by the caller (or fall back to arrival order), so runs are
  reproducible and testable.
- **Fail-closed input validation.** Malformed contributions raise
  ``ValueError`` at the boundary rather than silently scoring zero.
- **Explainable.** Every finding carries the exact contributing events and
  their weighted scores — an analyst can see *why* an entity crossed the line,
  never an opaque number.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

# Default risk threshold. An entity whose windowed, decayed score reaches this
# raises a finding. Tuned to ~one critical (90) or two-to-three mediums.
DEFAULT_THRESHOLD = 90.0

# Default sliding window (seconds): contributions older than this relative to
# the newest contribution for an entity no longer count toward its score.
DEFAULT_WINDOW_SECONDS = 3600

# Per-event-type multipliers. Repeated *recon* is less alarming than repeated
# *evidence destruction*; the deterministic classifier's event_type drives this
# so scoring stays explainable and tunable in one place.
DEFAULT_WEIGHTS: dict[str, float] = {
    "log tampering": 1.5,
    "privileged group addition": 1.4,
    "successful login": 1.2,
    "authentication failure": 1.0,
    "arp spoofing": 1.3,
    "account creation": 1.0,
    "port scan": 0.8,
    "firewall block": 0.6,
    "ids alert": 0.7,
    "network anomaly": 0.5,
    "unknown security event": 0.5,
}


@dataclass(frozen=True)
class RiskContribution:
    """One scored event's contribution to an entity's risk.

    ``entity`` is the risk object (e.g. a source IP, host, or user). ``score``
    is the SOC severity score (0-100). ``timestamp`` is an epoch-seconds float
    supplied by the caller; when omitted the engine uses arrival order so
    behavior stays deterministic without reading a clock.
    """

    entity: str
    event_type: str
    score: float
    timestamp: float | None = None
    detail: str = ""


@dataclass(frozen=True)
class RiskFinding:
    """An entity whose accumulated, weighted risk crossed the threshold."""

    entity: str
    total_score: float
    threshold: float
    contribution_count: int
    dominant_event_type: str
    contributions: list[dict[str, Any]] = field(default_factory=list)


class RiskEngine:
    """Accumulate weighted, time-windowed risk per entity; raise on threshold.

    Weights and threshold are injected (least surprise, easy tuning). The engine
    holds no external state and performs no I/O.
    """

    def __init__(
        self,
        *,
        threshold: float = DEFAULT_THRESHOLD,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        weights: dict[str, float] | None = None,
        default_weight: float = 1.0,
    ) -> None:
        if threshold <= 0:
            raise ValueError("threshold must be positive.")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive.")
        self.threshold = float(threshold)
        self.window_seconds = float(window_seconds)
        self.weights = dict(DEFAULT_WEIGHTS if weights is None else weights)
        self.default_weight = float(default_weight)

    def weight_for(self, event_type: str) -> float:
        """Return the multiplier for ``event_type`` (default when unlisted)."""
        return self.weights.get(event_type, self.default_weight)

    def score(self, contributions: Sequence[RiskContribution]) -> list[RiskFinding]:
        """Return risk findings for every entity that crosses the threshold.

        Contributions are grouped by entity; within an entity, only those inside
        the sliding window ending at that entity's newest contribution count.
        Findings are returned most-risky first (deterministic tie-break on
        entity name). Input is validated fail-closed.
        """
        if not isinstance(contributions, Sequence):
            raise ValueError("contributions must be a sequence.")

        by_entity: dict[str, list[tuple[int, RiskContribution]]] = {}
        for arrival, contribution in enumerate(contributions):
            if not isinstance(contribution, RiskContribution):
                raise ValueError("each contribution must be a RiskContribution.")
            entity = contribution.entity
            if not isinstance(entity, str) or not entity.strip():
                raise ValueError("contribution.entity must be a non-empty string.")
            if not isinstance(contribution.score, (int, float)) or contribution.score < 0:
                raise ValueError("contribution.score must be a non-negative number.")
            by_entity.setdefault(entity, []).append((arrival, contribution))

        findings: list[RiskFinding] = []
        for entity, items in by_entity.items():
            finding = self._score_entity(entity, items)
            if finding is not None:
                findings.append(finding)

        findings.sort(key=lambda f: (-f.total_score, f.entity))
        return findings

    def _score_entity(
        self, entity: str, items: list[tuple[int, RiskContribution]]
    ) -> RiskFinding | None:
        """Score one entity's windowed contributions; return a finding or None."""
        # Determine the window anchor: the newest supplied timestamp. When no
        # contribution carries a timestamp, every contribution counts (arrival
        # order is monotonic, so behavior is still deterministic).
        stamps = [c.timestamp for _, c in items if c.timestamp is not None]
        anchor = max(stamps) if stamps else None

        def in_window(c: RiskContribution) -> bool:
            # No anchor -> no time filtering. With an anchor, timeless
            # contributions always count; timestamped ones must be inside it.
            if anchor is None or c.timestamp is None:
                return True
            return (anchor - c.timestamp) <= self.window_seconds

        windowed = [(a, c) for (a, c) in items if in_window(c)]
        total = 0.0
        type_totals: dict[str, float] = {}
        rows: list[dict[str, Any]] = []
        for _, c in sorted(windowed, key=lambda ac: ac[0]):
            weighted = c.score * self.weight_for(c.event_type)
            total += weighted
            type_totals[c.event_type] = type_totals.get(c.event_type, 0.0) + weighted
            rows.append(
                {
                    "event_type": c.event_type,
                    "raw_score": c.score,
                    "weight": self.weight_for(c.event_type),
                    "weighted_score": round(weighted, 2),
                    "detail": c.detail,
                }
            )

        if total < self.threshold:
            return None

        # Dominant type = the event type contributing the most weighted risk;
        # deterministic tie-break on the type name.
        dominant = min(type_totals.items(), key=lambda kv: (-kv[1], kv[0]))[0]
        return RiskFinding(
            entity=entity,
            total_score=round(total, 2),
            threshold=self.threshold,
            contribution_count=len(rows),
            dominant_event_type=dominant,
            contributions=rows,
        )

    def score_as_dicts(self, contributions: Sequence[RiskContribution]) -> list[dict[str, Any]]:
        """Convenience: ``score`` results as plain dicts for JSON/report output."""
        return [asdict(f) for f in self.score(contributions)]


def contributions_from_analyses(
    analyses: Iterable[dict[str, Any]],
    *,
    entity_key: str = "source",
) -> list[RiskContribution]:
    """Build risk contributions from SOC ``analyze_log`` result dicts.

    Extracts the entity from ``entity_key`` (defaulting to the ``source``
    field an analysis may carry), else the first indicator, else ``"unknown"``.
    Deterministic and fail-soft: an analysis missing a score contributes 0.
    """
    contributions: list[RiskContribution] = []
    for analysis in analyses:
        if not isinstance(analysis, dict):
            raise ValueError("each analysis must be a dict.")
        entity = analysis.get(entity_key)
        if not entity:
            indicators = analysis.get("indicators") or []
            entity = indicators[0] if indicators else "unknown"
        contributions.append(
            RiskContribution(
                entity=str(entity),
                event_type=str(analysis.get("event_type", "unknown security event")),
                score=float(analysis.get("severity_score", 0) or 0),
                detail=str(analysis.get("summary", "")),
            )
        )
    return contributions
