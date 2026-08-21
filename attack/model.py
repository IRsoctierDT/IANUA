"""Typed, immutable views over the distilled ATT&CK corpus.

Pure data holders (frozen, slotted dataclasses) — no I/O, no clock, no
network. Field values come verbatim from the distilled shards, which are in
turn distilled from the pinned MITRE ATT&CK STIX bundle by
``scripts/update_attack.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

#: Lifecycle status of a technique in the pinned ATT&CK release. ``revoked``
#: objects have a successor (the ``revoked-by`` relationship); ``deprecated``
#: objects are retired with no replacement pointer — the asymmetry is MITRE's,
#: and the corpus preserves it rather than papering over it.
Status = Literal["active", "deprecated", "revoked"]


@dataclass(frozen=True, slots=True)
class Tactic:
    """One ATT&CK tactic (kill-chain phase)."""

    shortname: str
    name: str
    tactic_id: str


@dataclass(frozen=True, slots=True)
class Technique:
    """One ATT&CK technique or sub-technique."""

    technique_id: str
    name: str
    status: Status
    tactics: tuple[str, ...]
    platforms: tuple[str, ...]
    parent_id: str | None
    url: str
    description: str = ""


@dataclass(frozen=True, slots=True)
class Analytic:
    """A detection analytic attached to a strategy (ATT&CK v18+ model)."""

    name: str
    description: str
    log_sources: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DetectionStrategy:
    """A named detection strategy covering a technique."""

    name: str
    analytics: tuple[Analytic, ...] = ()


@dataclass(frozen=True, slots=True)
class TechniqueDetection:
    """Detection guidance for one technique: strategies + data components."""

    technique_id: str
    strategies: tuple[DetectionStrategy, ...] = ()
    data_components: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TechniqueRelationships:
    """Who mitigates and who uses a technique (behavioral intel)."""

    technique_id: str
    mitigations: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()
    software: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Tombstone:
    """Ledger entry for a technique that left active service."""

    technique_id: str
    status: Status
    name: str
    successor: str | None


@dataclass(frozen=True, slots=True)
class ReferenceVerdict:
    """Outcome of validating a technique reference against the corpus."""

    technique_id: str
    status: Status | Literal["unknown"]
    name: str | None = None
    successor: str | None = None
    problems: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """True only for a reference that resolves to an active technique."""
        return self.status == "active"


@dataclass(frozen=True, slots=True)
class Freshness:
    """Advisory currency report: version distance, never a gate input."""

    pinned_version: str
    latest_known_version: str
    version_distance: int
    latest_modified: str
    pin_age_days: int


@dataclass(frozen=True, slots=True)
class Corpus:
    """The fully loaded, integrity-verified corpus."""

    attack_version: str
    tactics: dict[str, Tactic]
    techniques: dict[str, Technique]
    detection: dict[str, TechniqueDetection] = field(default_factory=dict)
    relationships: dict[str, TechniqueRelationships] = field(default_factory=dict)
    tombstones: dict[str, Tombstone] = field(default_factory=dict)
