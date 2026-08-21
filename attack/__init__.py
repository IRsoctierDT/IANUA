"""IANUA's local, version-pinned MITRE ATT&CK vocabulary.

The shared technique corpus every layer reads: distilled from a pinned,
hash-verified MITRE ATT&CK STIX bundle by ``scripts/update_attack.py``,
committed as small integrity-verified shards, and never fetched at runtime.
This package imports **no first-party module** and holds **no third-party
dependency** — stdlib only, no clock, no network (enforced by
``tests/security/test_attack_no_network.py``).

MITRE ATT&CK® is a registered trademark of The MITRE Corporation; the
distilled content is used under MITRE's Terms of Use with attribution — see
``attack/ATTRIBUTION.md`` and ``NOTICE``.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from attack.errors import AttackError, AttackIntegrityError, AttackUnavailableError
from attack.model import (
    Analytic,
    Corpus,
    DetectionStrategy,
    Freshness,
    ReferenceVerdict,
    Tactic,
    Technique,
    TechniqueDetection,
    TechniqueRelationships,
    Tombstone,
)
from attack.pin import Pin, load_pin
from attack.refs import check_references, resolve_current, validate_reference
from attack.store import load_corpus

COLLECTION_INDEX_PATH = Path(__file__).resolve().parent / "collection-index.json"

__all__ = [
    "Analytic",
    "AttackError",
    "AttackIntegrityError",
    "AttackUnavailableError",
    "Corpus",
    "DetectionStrategy",
    "Freshness",
    "Pin",
    "ReferenceVerdict",
    "Tactic",
    "Technique",
    "TechniqueDetection",
    "TechniqueRelationships",
    "Tombstone",
    "check_references",
    "freshness",
    "load_corpus",
    "load_pin",
    "resolve_current",
    "validate_reference",
]


def _parse_version(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def freshness(*, today: date, pin: Pin | None = None) -> Freshness:
    """Advisory currency report against the committed collection-index snapshot.

    Version distance — how many known releases are newer than the pin — is the
    signal; elapsed days is context only. **Never a gate input**: freshness has
    no exit code and no committed artifact, by design (a time-dependent gate
    turns the build red with no commit). The clock is injected (``today``) so
    this module stays deterministic and clock-free.
    """
    resolved_pin = load_pin() if pin is None else pin
    if not COLLECTION_INDEX_PATH.is_file():
        raise AttackUnavailableError(f"collection index snapshot missing: {COLLECTION_INDEX_PATH}")
    try:
        snapshot = json.loads(COLLECTION_INDEX_PATH.read_bytes())
    except json.JSONDecodeError as exc:
        raise AttackIntegrityError(f"collection index snapshot invalid: {exc}") from exc
    versions = snapshot.get("versions")
    if not isinstance(versions, list) or not versions:
        raise AttackIntegrityError("collection index snapshot has no versions list")

    pinned = _parse_version(resolved_pin.attack_version)
    known: list[tuple[tuple[int, ...], str, str]] = []
    for row in versions:
        if not isinstance(row, dict) or not isinstance(row.get("version"), str):
            raise AttackIntegrityError("collection index snapshot row malformed")
        known.append((_parse_version(row["version"]), row["version"], str(row.get("modified", ""))))
    known.sort()
    latest = known[-1]
    distance = sum(1 for parsed, _, _ in known if parsed > pinned)
    retrieved = date.fromisoformat(resolved_pin.retrieved)
    return Freshness(
        pinned_version=resolved_pin.attack_version,
        latest_known_version=latest[1],
        version_distance=distance,
        latest_modified=latest[2],
        pin_age_days=(today - retrieved).days,
    )
