"""Human attestations for manual controls — reviewable, expiring, committed.

Manual controls (e.g. GitHub branch protection) cannot be verified offline, so
a human attests them instead. Attestations live in a **committed** JSON file
(``compliance/attestations.json``) so they are reviewable in a PR, survive
clones, and feed the deterministic trust-page snapshot. Each attestation
expires; an expired attestation reverts the control to "requires attestation"
rather than passing forever on a stale claim.

Security considerations:
- The file is validated fail-closed: malformed entries, unknown fields, bad
  dates, duplicates, or an expiry before the attestation date all raise
  :class:`AttestationError` instead of being partially trusted.
- Attestor names and notes never reach the public trust page — its snapshot
  schema carries only ids, titles, categories, and statuses.
- :func:`record` refuses to attest automated controls (evidence must come
  from the check, not a human override) and unknown control ids.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from compliance.controls import registry

_STORE = Path("compliance") / "attestations.json"
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_FIELDS = {"control_id", "attested_by", "date", "expires", "note"}


class AttestationError(ValueError):
    """The attestation store is malformed or an entry is invalid (fail closed)."""


@dataclass(frozen=True)
class Attestation:
    """One human attestation of a manual control."""

    control_id: str
    attested_by: str
    date: str  # ISO yyyy-mm-dd
    expires: str  # ISO yyyy-mm-dd, inclusive
    note: str

    def valid_on(self, day: str) -> bool:
        """True when ``day`` (ISO date) falls inside the attested window."""
        if not _DATE_RE.match(day):
            raise AttestationError(f"invalid date for validity check: {day!r}")
        return self.date <= day <= self.expires


def store_path(root: Path) -> Path:
    """The committed attestation store under ``root``."""
    return root / _STORE


def _parse_entry(raw: object, context: str) -> Attestation:
    if not isinstance(raw, dict):
        raise AttestationError(f"{context}: expected an object")
    if set(raw) != _FIELDS:
        raise AttestationError(
            f"{context}: fields must be exactly {sorted(_FIELDS)}, got {sorted(raw)}"
        )
    values = {k: raw[k] for k in _FIELDS}
    for key, value in values.items():
        if not isinstance(value, str) or not value.strip():
            raise AttestationError(f"{context}.{key}: expected a non-empty string")
    for key in ("date", "expires"):
        if not _DATE_RE.match(values[key]):
            raise AttestationError(f"{context}.{key}: expected ISO date, got {values[key]!r}")
    att = Attestation(**{k: str(v) for k, v in values.items()})
    if att.expires < att.date:
        raise AttestationError(f"{context}: expires ({att.expires}) precedes date ({att.date})")
    return att


def load(path: Path) -> Mapping[str, Attestation]:
    """Load and validate the attestation store; absent file means none.

    Returns a mapping keyed by control id. Fails closed on any malformation —
    a partially trusted attestation file could silently mark controls passing.
    """
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise AttestationError(f"{path.name}: invalid JSON — {exc}") from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise AttestationError(f"{path.name}: expected an object with version 1")
    raw_entries = data.get("attestations")
    if not isinstance(raw_entries, list):
        raise AttestationError(f"{path.name}: 'attestations' must be an array")
    result: dict[str, Attestation] = {}
    for i, raw in enumerate(raw_entries):
        att = _parse_entry(raw, f"attestations[{i}]")
        if att.control_id in result:
            raise AttestationError(f"duplicate attestation for control {att.control_id}")
        result[att.control_id] = att
    return result


def record(
    path: Path,
    *,
    control_id: str,
    attested_by: str,
    date: str,
    expires: str,
    note: str,
) -> Attestation:
    """Add or replace the attestation for one manual control (deterministic write).

    The caller (a human, via the dashboard or CLI) reviews and commits the
    resulting file — recording is local; publishing stays a human action.
    """
    manual_ids = {c.id for c in registry() if not c.automated}
    if control_id not in manual_ids:
        raise AttestationError(
            f"control {control_id!r} is not a manual control (automated controls "
            "take evidence from their checks, not from attestations)"
        )
    attestation = _parse_entry(
        {
            "control_id": control_id,
            "attested_by": attested_by,
            "date": date,
            "expires": expires,
            "note": note,
        },
        "attestation",
    )
    current = dict(load(path))
    current[control_id] = attestation
    payload = {
        "version": 1,
        "attestations": [
            {
                "control_id": att.control_id,
                "attested_by": att.attested_by,
                "date": att.date,
                "expires": att.expires,
                "note": att.note,
            }
            for _, att in sorted(current.items())
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return attestation
