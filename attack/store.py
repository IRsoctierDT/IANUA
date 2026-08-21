"""Integrity-verified loader for the committed ATT&CK shards.

Every shard's SHA-256 is checked against the pin **before** its bytes are
parsed; a mismatch raises :class:`AttackIntegrityError` (hard fail — never
fall back to damaged data), while a missing corpus raises
:class:`AttackUnavailableError` (soft: callers degrade to an explicit
"unavailable" state, never a guess). Deterministic and offline: no clock, no
network, stdlib ``json`` only; a maliciously deep shard is caught as an
integrity error rather than escaping as ``RecursionError``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from attack.errors import AttackIntegrityError, AttackUnavailableError
from attack.model import (
    Analytic,
    Corpus,
    DetectionStrategy,
    Tactic,
    Technique,
    TechniqueDetection,
    TechniqueRelationships,
    Tombstone,
)
from attack.pin import Pin, load_pin

DATA_DIR = Path(__file__).resolve().parent / "data"

#: Per-shard size ceiling (bytes). Mirrors the repo's large-file discipline and
#: bounds memory before any read; the committed shards sit well under it.
MAX_SHARD_BYTES = 1024 * 1024

_STATUSES = {"active", "deprecated", "revoked"}


def _safe_load_json(raw: bytes, name: str) -> Any:
    """Parse shard bytes, converting a nesting bomb into an integrity error."""
    try:
        return json.loads(raw)
    except RecursionError as exc:  # depth bomb — not a ValueError subclass
        raise AttackIntegrityError(f"shard {name}: nesting depth exceeds parser limits") from exc
    except json.JSONDecodeError as exc:
        raise AttackIntegrityError(f"shard {name}: invalid JSON ({exc})") from exc


def read_shard(name: str, *, pin: Pin, data_dir: Path | None = None) -> Any:
    """Read one shard, enforcing size ceiling and pin hash before parsing."""
    directory = DATA_DIR if data_dir is None else data_dir
    expected = pin.shards.get(name)
    if expected is None:
        raise AttackIntegrityError(f"shard {name} is not listed in the pin")
    path = directory / name
    if not path.is_file():
        raise AttackUnavailableError(f"shard missing on disk: {path}")
    size = path.stat().st_size
    if size > MAX_SHARD_BYTES:
        raise AttackIntegrityError(f"shard {name}: {size} bytes exceeds ceiling {MAX_SHARD_BYTES}")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected:
        raise AttackIntegrityError(
            f"shard {name}: sha256 mismatch (expected {expected}, got {digest})"
        )
    return _safe_load_json(raw, name)


def _str_tuple(value: Any, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise AttackIntegrityError(f"{context}: expected a list of strings")
    return tuple(value)


def _merge_parts(names: list[str], *, pin: Pin, data_dir: Path | None) -> dict[str, Any]:
    """Merge the ``items`` maps of a logical document split across shards."""
    merged: dict[str, Any] = {}
    for name in names:
        document = read_shard(name, pin=pin, data_dir=data_dir)
        if not isinstance(document, dict) or not isinstance(document.get("items"), dict):
            raise AttackIntegrityError(f"shard {name}: expected an object with an 'items' map")
        for key, value in document["items"].items():
            if key in merged:
                raise AttackIntegrityError(f"shard {name}: duplicate item {key!r} across parts")
            merged[key] = value
    return merged


def _part_names(pin: Pin, prefix: str) -> list[str]:
    names = sorted(name for name in pin.shards if name.startswith(prefix))
    if not names:
        raise AttackIntegrityError(f"pin lists no shards with prefix {prefix!r}")
    return names


def load_corpus(*, pin: Pin | None = None, data_dir: Path | None = None) -> Corpus:
    """Load and verify the full corpus. Deterministic; raises fail-closed."""
    resolved_pin = load_pin() if pin is None else pin

    catalog = read_shard("catalog.json", pin=resolved_pin, data_dir=data_dir)
    if not isinstance(catalog, dict):
        raise AttackIntegrityError("catalog.json: expected an object")
    version = catalog.get("attack_version")
    if version != resolved_pin.attack_version:
        raise AttackIntegrityError(
            f"catalog version {version!r} disagrees with pin {resolved_pin.attack_version!r}"
        )

    tactics: dict[str, Tactic] = {}
    for shortname, row in dict(catalog.get("tactics", {})).items():
        tactics[shortname] = Tactic(
            shortname=shortname, name=str(row["name"]), tactic_id=str(row["tactic_id"])
        )

    descriptions = _merge_parts(
        _part_names(resolved_pin, "descriptions-"), pin=resolved_pin, data_dir=data_dir
    )

    techniques: dict[str, Technique] = {}
    for tid, row in dict(catalog.get("techniques", {})).items():
        if not isinstance(row, dict):
            raise AttackIntegrityError(f"catalog technique {tid!r}: expected an object")
        status = row.get("status")
        if status not in _STATUSES:
            raise AttackIntegrityError(f"technique {tid!r}: unknown status {status!r}")
        tactic_names = _str_tuple(row.get("tactics", []), f"technique {tid!r} tactics")
        for shortname in tactic_names:
            if shortname not in tactics:
                raise AttackIntegrityError(f"technique {tid!r}: unknown tactic {shortname!r}")
        description = descriptions.get(tid, "")
        if not isinstance(description, str):
            raise AttackIntegrityError(f"description for {tid!r}: expected a string")
        techniques[tid] = Technique(
            technique_id=tid,
            name=str(row["name"]),
            status=status,
            tactics=tactic_names,
            platforms=_str_tuple(row.get("platforms", []), f"technique {tid!r} platforms"),
            parent_id=row.get("parent") if isinstance(row.get("parent"), str) else None,
            url=str(row.get("url", "")),
            description=description,
        )

    detection: dict[str, TechniqueDetection] = {}
    for tid, row in _merge_parts(
        _part_names(resolved_pin, "detection-"), pin=resolved_pin, data_dir=data_dir
    ).items():
        strategies = tuple(
            DetectionStrategy(
                name=str(strategy["name"]),
                analytics=tuple(
                    Analytic(
                        name=str(analytic["name"]),
                        description=str(analytic.get("description", "")),
                        log_sources=_str_tuple(
                            analytic.get("log_sources", []), f"analytic in {tid!r}"
                        ),
                    )
                    for analytic in strategy.get("analytics", [])
                ),
            )
            for strategy in row.get("strategies", [])
        )
        detection[tid] = TechniqueDetection(
            technique_id=tid,
            strategies=strategies,
            data_components=_str_tuple(row.get("data_components", []), f"detection {tid!r}"),
        )

    relationships: dict[str, TechniqueRelationships] = {}
    for tid, row in _merge_parts(
        _part_names(resolved_pin, "relationships-"), pin=resolved_pin, data_dir=data_dir
    ).items():
        relationships[tid] = TechniqueRelationships(
            technique_id=tid,
            mitigations=_str_tuple(row.get("mitigations", []), f"relationships {tid!r}"),
            groups=_str_tuple(row.get("groups", []), f"relationships {tid!r}"),
            software=_str_tuple(row.get("software", []), f"relationships {tid!r}"),
        )

    tombstone_doc = read_shard("tombstones.json", pin=resolved_pin, data_dir=data_dir)
    tombstones: dict[str, Tombstone] = {}
    if not isinstance(tombstone_doc, dict) or not isinstance(tombstone_doc.get("entries"), dict):
        raise AttackIntegrityError("tombstones.json: expected an object with an 'entries' map")
    for tid, row in tombstone_doc["entries"].items():
        status = row.get("status")
        if status not in ("revoked", "deprecated"):
            raise AttackIntegrityError(f"tombstone {tid!r}: unknown status {status!r}")
        successor = row.get("successor")
        if status == "revoked" and not isinstance(successor, str):
            raise AttackIntegrityError(f"tombstone {tid!r}: revoked entry needs a successor")
        tombstones[tid] = Tombstone(
            technique_id=tid,
            status=status,
            name=str(row.get("name", "")),
            successor=successor if isinstance(successor, str) else None,
        )

    return Corpus(
        attack_version=resolved_pin.attack_version,
        tactics=tactics,
        techniques=techniques,
        detection=detection,
        relationships=relationships,
        tombstones=tombstones,
    )
