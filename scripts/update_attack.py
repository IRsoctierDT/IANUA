#!/usr/bin/env python3
"""Build and verify the committed ATT&CK corpus from a human-staged bundle.

There is deliberately **no fetch mode**: obtaining the bundle is a §5.1
external-network action only a human performs (AGENTS.md §5.1). The human
downloads the versioned enterprise bundle from
https://github.com/mitre-attack/attack-stix-data into gitignored
``data/attack/`` and runs ``--build``; this script never opens a socket.

Modes:
    # Distill data/attack/enterprise-attack-<v>.json into attack/data/ shards
    # and (re)write the pin manifest:
    python scripts/update_attack.py --build --bundle enterprise-attack-19.2.json

    # CI / pre-commit integrity gate (no bundle needed, no files written):
    python scripts/update_attack.py --check

    # Sign the pin with the maintainer-held Ed25519 key (never stored here):
    ATTACK_PIN_ED25519_PRIVATE_KEY=<hex> python scripts/update_attack.py --sign

    # Advisory freshness report (never a gate):
    python scripts/update_attack.py --plan

Security considerations (AGENTS.md §5, DESIGN.md §5 boundary 5):
    * **Fail-closed integrity order** on build: size ceiling -> nesting-depth
      scan -> streaming SHA-256 -> parse. A rejected bundle gets a
      ``.REJECTED`` forensic marker and the previously committed shards stay
      authoritative.
    * **--check verifies, never regenerates** — CI does not hold the 54 MB
      bundle and must not. It checks the pin schema, the Ed25519 pin
      signature (when present), per-shard hashes and ceilings, canonical
      byte-exact rendering, and the tombstone/successor invariants.
    * **Tombstones are append-only**: a rebuild that would drop a ledger
      entry aborts rather than shrinking history.

Exit codes: 0 success / in sync · 1 drift or integrity failure · 2 bad input.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # script may run from anywhere
    sys.path.insert(0, str(REPO_ROOT))

from attack.errors import AttackError  # noqa: E402
from attack.pin import DEFAULT_PIN_PATH, load_pin, parse_pin, signing_payload  # noqa: E402
from attack.store import DATA_DIR, MAX_SHARD_BYTES, load_corpus  # noqa: E402

STAGING_DIR = REPO_ROOT / "data" / "attack"
COLLECTION_INDEX = REPO_ROOT / "attack" / "collection-index.json"

# Hard ceiling for a staged bundle when no pin exists yet; with a pin, the
# ceiling is the recorded size plus 50% headroom (a release grows, it does not
# triple). Both bound memory before any parse.
_FIRST_BUILD_MAX_BYTES = 120_000_000
_MAX_NESTING_DEPTH = 100
# Target payload per shard part, under the hard MAX_SHARD_BYTES ceiling.
_PART_BUDGET = 850_000

_MITRE = "mitre-attack"


def _canonical(document: Any) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _scan_depth(path: Path, limit: int) -> None:
    """Single streaming pass rejecting pathological nesting before json.loads."""
    depth = 0
    in_string = False
    escaped = False
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            for byte in chunk:
                if in_string:
                    if escaped:
                        escaped = False
                    elif byte == 0x5C:  # backslash
                        escaped = True
                    elif byte == 0x22:  # quote
                        in_string = False
                    continue
                if byte == 0x22:
                    in_string = True
                elif byte in (0x7B, 0x5B):  # { [
                    depth += 1
                    if depth > limit:
                        raise AttackError(f"bundle nesting exceeds depth {limit} (rejected)")
                elif byte in (0x7D, 0x5D):  # } ]
                    depth -= 1


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if isinstance(ref, dict) and ref.get("source_name") == _MITRE:
            ext = ref.get("external_id")
            return str(ext) if ext else None
    return None


def _external_url(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references", []):
        if isinstance(ref, dict) and ref.get("source_name") == _MITRE:
            return str(ref.get("url", ""))
    return ""


def _status(obj: dict[str, Any]) -> str:
    if obj.get("revoked"):
        return "revoked"
    if obj.get("x_mitre_deprecated"):
        return "deprecated"
    return "active"


def _distill(bundle: dict[str, Any]) -> dict[str, Any]:
    """Relationship-graph join over the STIX bundle -> logical documents.

    Every consumed object and relationship type must be present with a
    nonzero count — an upstream shape change (fields moving, relationship
    directions flipping) fails loudly here instead of silently emptying an
    index.
    """
    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        raise AttackError("bundle has no objects list")

    by_type: dict[str, list[dict[str, Any]]] = {}
    by_stix_id: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if not isinstance(obj, dict) or "type" not in obj:
            raise AttackError("bundle object without a type")
        by_type.setdefault(obj["type"], []).append(obj)
        if "id" in obj:
            by_stix_id[obj["id"]] = obj

    version = ""
    for collection in by_type.get("x-mitre-collection", []):
        version = str(collection.get("x_mitre_version", ""))
    if not version:
        raise AttackError("bundle carries no x-mitre-collection version")

    required = (
        "attack-pattern",
        "relationship",
        "x-mitre-tactic",
        "x-mitre-data-component",
        "course-of-action",
        "intrusion-set",
    )
    for type_name in required:
        if not by_type.get(type_name):
            raise AttackError(f"upstream shape change: no {type_name} objects in bundle")

    tactics: dict[str, dict[str, str]] = {}
    for tactic in by_type["x-mitre-tactic"]:
        shortname = str(tactic.get("x_mitre_shortname", ""))
        ext = _external_id(tactic)
        if not shortname or not ext:
            raise AttackError("tactic without shortname/external id")
        tactics[shortname] = {"name": str(tactic.get("name", "")), "tactic_id": ext}

    rels: dict[str, list[tuple[str, str]]] = {}
    for rel in by_type["relationship"]:
        rel_type = str(rel.get("relationship_type", ""))
        rels.setdefault(rel_type, []).append(
            (str(rel.get("source_ref", "")), str(rel.get("target_ref", "")))
        )
    for rel_type in ("subtechnique-of", "detects", "mitigates", "uses", "revoked-by"):
        if not rels.get(rel_type):
            raise AttackError(f"upstream shape change: no {rel_type} relationships in bundle")

    parent_of: dict[str, str] = {}
    for source, target in rels["subtechnique-of"]:
        child = by_stix_id.get(source)
        parent = by_stix_id.get(target)
        if child is None or parent is None:
            continue
        child_id, parent_id = _external_id(child), _external_id(parent)
        if child_id and parent_id:
            parent_of[child_id] = parent_id

    techniques: dict[str, dict[str, Any]] = {}
    descriptions: dict[str, str] = {}
    tombstone_entries: dict[str, dict[str, Any]] = {}
    revoked_by: dict[str, str] = {}
    for source, target in rels["revoked-by"]:
        source_obj, target_obj = by_stix_id.get(source), by_stix_id.get(target)
        if source_obj is None or target_obj is None:
            continue
        if source_obj.get("type") != "attack-pattern":
            continue
        old_id, new_id = _external_id(source_obj), _external_id(target_obj)
        if old_id and new_id:
            revoked_by[old_id] = new_id

    for pattern in by_type["attack-pattern"]:
        technique_id = _external_id(pattern)
        if not technique_id:
            raise AttackError(f"attack-pattern without a technique ID: {pattern.get('id')}")
        status = _status(pattern)
        phase_names = tuple(
            str(phase.get("phase_name", ""))
            for phase in pattern.get("kill_chain_phases", [])
            if isinstance(phase, dict) and phase.get("kill_chain_name") == _MITRE
        )
        for phase in phase_names:
            if phase not in tactics:
                raise AttackError(f"{technique_id}: unknown tactic shortname {phase!r}")
        row: dict[str, Any] = {
            "name": str(pattern.get("name", "")),
            "status": status,
            "tactics": sorted(phase_names),
            "platforms": sorted(str(p) for p in pattern.get("x_mitre_platforms", [])),
            "url": _external_url(pattern),
        }
        if technique_id in parent_of:
            row["parent"] = parent_of[technique_id]
        techniques[technique_id] = row
        descriptions[technique_id] = str(pattern.get("description", ""))
        if status != "active":
            entry: dict[str, Any] = {"status": status, "name": row["name"]}
            successor = revoked_by.get(technique_id)
            if status == "revoked":
                if successor is None:
                    raise AttackError(f"{technique_id} is revoked but has no revoked-by successor")
                entry["successor"] = successor
            tombstone_entries[technique_id] = entry

    data_component_names = {
        component["id"]: str(component.get("name", ""))
        for component in by_type["x-mitre-data-component"]
        if "id" in component
    }

    analytics_by_id = {a["id"]: a for a in by_type.get("x-mitre-analytic", []) if "id" in a}
    detection: dict[str, dict[str, Any]] = {}
    for source, target in rels["detects"]:
        strategy = by_stix_id.get(source)
        target_obj = by_stix_id.get(target)
        if strategy is None or target_obj is None or target_obj.get("type") != "attack-pattern":
            continue
        technique_id = _external_id(target_obj)
        if not technique_id:
            continue
        analytics = []
        components: set[str] = set()
        for analytic_ref in strategy.get("x_mitre_analytic_refs", []):
            analytic = analytics_by_id.get(analytic_ref)
            if analytic is None:
                continue
            log_sources: set[str] = set()
            for log_ref in analytic.get("x_mitre_log_source_references", []):
                if not isinstance(log_ref, dict):
                    continue
                name = str(log_ref.get("name", ""))
                channel = str(log_ref.get("channel", ""))
                if name:
                    log_sources.add(f"{name}:{channel}" if channel else name)
                component = data_component_names.get(
                    str(log_ref.get("x_mitre_data_component_ref", ""))
                )
                if component:
                    components.add(component)
            analytics.append(
                {
                    "name": str(analytic.get("name", "")),
                    "description": str(analytic.get("description", "")),
                    "log_sources": sorted(log_sources),
                }
            )
        entry = detection.setdefault(technique_id, {"strategies": [], "data_components": set()})
        entry["strategies"].append({"name": str(strategy.get("name", "")), "analytics": analytics})
        entry["data_components"] |= components
    if not detection:
        raise AttackError("upstream shape change: detects relationships produced no coverage")
    for entry in detection.values():
        entry["strategies"].sort(key=lambda s: str(s["name"]))
        entry["data_components"] = sorted(entry["data_components"])

    relationships: dict[str, dict[str, set[str]]] = {}

    def _rel_entry(technique_id: str) -> dict[str, set[str]]:
        return relationships.setdefault(
            technique_id, {"mitigations": set(), "groups": set(), "software": set()}
        )

    for source, target in rels["mitigates"]:
        coa = by_stix_id.get(source)
        target_obj = by_stix_id.get(target)
        if coa is None or target_obj is None or target_obj.get("type") != "attack-pattern":
            continue
        technique_id = _external_id(target_obj)
        if technique_id:
            _rel_entry(technique_id)["mitigations"].add(str(coa.get("name", "")))
    for source, target in rels["uses"]:
        user = by_stix_id.get(source)
        target_obj = by_stix_id.get(target)
        if user is None or target_obj is None or target_obj.get("type") != "attack-pattern":
            continue
        technique_id = _external_id(target_obj)
        if not technique_id:
            continue
        if user.get("type") == "intrusion-set":
            _rel_entry(technique_id)["groups"].add(str(user.get("name", "")))
        elif user.get("type") in ("malware", "tool"):
            _rel_entry(technique_id)["software"].add(str(user.get("name", "")))
    relationships_sorted = {
        technique_id: {key: sorted(values) for key, values in entry.items()}
        for technique_id, entry in relationships.items()
    }

    return {
        "version": version,
        "tactics": tactics,
        "techniques": techniques,
        "descriptions": descriptions,
        "detection": detection,
        "relationships": relationships_sorted,
        "tombstones": tombstone_entries,
    }


def _split_items(logical: str, items: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Split a logical items-map into deterministic parts under the budget."""
    parts: dict[str, dict[str, Any]] = {}
    current: dict[str, Any] = {}
    size = 0
    index = 1
    for key in sorted(items):
        entry_size = len(_canonical({key: items[key]}))
        if current and size + entry_size > _PART_BUDGET:
            parts[f"{logical}-{index:02d}.json"] = {"items": current}
            index += 1
            current, size = {}, 0
        current[key] = items[key]
        size += entry_size
    parts[f"{logical}-{index:02d}.json"] = {"items": current}
    return parts


def _merge_tombstones(new_entries: dict[str, Any], previous_path: Path) -> dict[str, Any]:
    """Append-only merge: an existing ledger entry may never disappear."""
    previous_entries: dict[str, Any] = {}
    parent_sha256 = None
    parent_count = 0
    if previous_path.is_file():
        raw = previous_path.read_bytes()
        parent_sha256 = hashlib.sha256(raw).hexdigest()
        previous = json.loads(raw)
        previous_entries = dict(previous.get("entries", {}))
        parent_count = len(previous_entries)
    merged = dict(previous_entries)
    merged.update(new_entries)
    dropped = set(previous_entries) - set(merged)
    if dropped:  # pragma: no cover - merge above cannot drop, guard stays
        raise AttackError(f"tombstone ledger would shrink: {sorted(dropped)}")
    return {
        "entries": merged,
        "parent_count": parent_count,
        "parent_sha256": parent_sha256,
    }


def build(bundle_name: str, retrieved: str) -> int:
    bundle_path = STAGING_DIR / Path(bundle_name).name
    if not bundle_path.is_file():
        print(f"ERROR: staged bundle not found: {bundle_path}", file=sys.stderr)
        print(
            "Stage it first (human action, AGENTS.md §5.1): download the versioned\n"
            "enterprise bundle from https://github.com/mitre-attack/attack-stix-data\n"
            f"into {STAGING_DIR}/ — this script never fetches.",
            file=sys.stderr,
        )
        return 2

    ceiling = _FIRST_BUILD_MAX_BYTES
    if DEFAULT_PIN_PATH.is_file():
        # An unreadable pin keeps the conservative first-build ceiling.
        with contextlib.suppress(AttackError):
            ceiling = int(load_pin().bundle_size_bytes * 1.5)
    size = bundle_path.stat().st_size
    if size > ceiling:
        _reject_bundle(bundle_path, f"size {size} exceeds ceiling {ceiling}")
        return 1

    try:
        _scan_depth(bundle_path, _MAX_NESTING_DEPTH)
    except AttackError as exc:
        _reject_bundle(bundle_path, str(exc))
        return 1

    sha256 = _sha256_file(bundle_path)
    try:
        bundle = json.loads(bundle_path.read_bytes())
    except (json.JSONDecodeError, RecursionError) as exc:
        _reject_bundle(bundle_path, f"parse failure: {exc}")
        return 1

    try:
        distilled = _distill(bundle)
    except AttackError as exc:
        _reject_bundle(bundle_path, str(exc))
        return 1

    shards: dict[str, Any] = {
        "catalog.json": {
            "attack_version": distilled["version"],
            "tactics": distilled["tactics"],
            "techniques": distilled["techniques"],
        },
        "tombstones.json": _merge_tombstones(distilled["tombstones"], DATA_DIR / "tombstones.json"),
    }
    shards.update(_split_items("descriptions", distilled["descriptions"]))
    shards.update(_split_items("detection", distilled["detection"]))
    shards.update(_split_items("relationships", distilled["relationships"]))

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for stale in DATA_DIR.glob("*.json"):
        if stale.name not in shards:
            stale.unlink()
    digests: dict[str, str] = {}
    for name, document in shards.items():
        rendered = _canonical(document)
        if len(rendered) > MAX_SHARD_BYTES:
            print(f"ERROR: shard {name} would be {len(rendered)} bytes", file=sys.stderr)
            return 1
        (DATA_DIR / name).write_bytes(rendered)
        digests[name] = hashlib.sha256(rendered).hexdigest()

    pin_document: dict[str, Any] = {
        "schema": 1,
        "attack_version": distilled["version"],
        "retrieved": retrieved,
        "bundle": {"file_name": bundle_path.name, "size_bytes": size, "sha256": sha256},
        "shards": digests,
        # A rebuild invalidates any prior signature; the maintainer re-signs
        # with --sign (key ceremony in attack/README.md).
        "signature": None,
    }
    parse_pin(pin_document)  # self-check before writing
    DEFAULT_PIN_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_PIN_PATH.write_bytes(_canonical(pin_document))

    staged_index = STAGING_DIR / "index.json"
    if staged_index.is_file():
        index = json.loads(staged_index.read_bytes())
        for collection in index.get("collections", []):
            if collection.get("name") == "Enterprise ATT&CK":
                snapshot = {
                    "name": collection["name"],
                    "versions": [
                        {"version": row["version"], "modified": row.get("modified", "")}
                        for row in collection.get("versions", [])
                    ],
                }
                COLLECTION_INDEX.write_bytes(_canonical(snapshot))

    load_corpus()  # prove the committed result loads fail-closed
    print(
        f"OK: distilled ATT&CK {distilled['version']} -> {len(shards)} shards "
        f"({len(distilled['techniques'])} techniques, "
        f"{len(shards['tombstones.json']['entries'])} tombstones). "
        "Pin written unsigned — run --sign."
    )
    return 0


def _reject_bundle(bundle_path: Path, reason: str) -> None:
    """Refuse the staged bundle, leaving a forensic marker; audit the denial."""
    marker = bundle_path.with_suffix(bundle_path.suffix + ".REJECTED")
    marker.write_text(f"{reason}\n", encoding="utf-8")
    print(f"REJECTED: {reason} (marker: {marker})", file=sys.stderr)
    try:  # best-effort audit; the rejection itself must not depend on it
        from agents.policies.audit import AuditLogger

        audit_dir = REPO_ROOT / "data" / "attack"
        audit_dir.mkdir(parents=True, exist_ok=True)
        AuditLogger(audit_dir / "update_attack_audit.jsonl").record(
            actor="scripts/update_attack.py",
            action=f"reject staged bundle {bundle_path.name}",
            action_class="read_only",
            decision="deny",
            reason=reason,
        )
    except Exception as exc:  # audit backend absent in minimal envs — say so
        print(f"note: rejection not audited ({exc})", file=sys.stderr)


def check() -> int:
    try:
        pin = load_pin()
    except AttackError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    problems: list[str] = []

    for name, expected in pin.shards.items():
        path = DATA_DIR / name
        if not path.is_file():
            problems.append(f"shard missing: {name}")
            continue
        raw = path.read_bytes()
        if len(raw) > MAX_SHARD_BYTES:
            problems.append(f"shard {name} exceeds {MAX_SHARD_BYTES} bytes")
        if hashlib.sha256(raw).hexdigest() != expected:
            problems.append(f"shard {name}: sha256 mismatch against pin")
            continue
        document = json.loads(raw)
        if _canonical(document) != raw:
            problems.append(f"shard {name}: not in canonical rendering")
    for path in DATA_DIR.glob("*.json"):
        if path.name not in pin.shards:
            problems.append(f"unpinned shard on disk: {path.name}")

    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1

    try:
        corpus = load_corpus(pin=pin)
    except AttackError as exc:
        print(f"FAIL: corpus does not load: {exc}", file=sys.stderr)
        return 1

    for technique_id, tombstone in corpus.tombstones.items():
        if tombstone.status == "revoked":
            successor = tombstone.successor
            if not successor:
                problems.append(f"tombstone {technique_id}: revoked without successor")
            elif successor not in corpus.techniques and successor not in corpus.tombstones:
                problems.append(f"tombstone {technique_id}: successor {successor} unresolvable")
    for technique_id, technique in corpus.techniques.items():
        if technique.status != "active" and technique_id not in corpus.tombstones:
            problems.append(f"{technique_id} is {technique.status} but has no tombstone entry")
        if technique.parent_id and technique.parent_id not in corpus.techniques:
            problems.append(f"{technique_id}: parent {technique.parent_id} not in corpus")

    if pin.signature is not None:
        try:
            from agents.policies.signing import Ed25519Verifier
            from attack.pin import load_pin_document

            document = load_pin_document()
            verifier = Ed25519Verifier(bytes.fromhex(pin.signature.public_key))
            if not verifier.verify(signing_payload(document), pin.signature.signature):
                problems.append("pin signature does not verify")
        except RuntimeError as exc:
            problems.append(f"pin is signed but verification unavailable: {exc}")
    else:
        print(
            "NOTE: pin is unsigned — hash checks detect corruption, not tampering. "
            "Run --sign with the maintainer key (see attack/README.md)."
        )

    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    print(
        f"OK: ATT&CK corpus {pin.attack_version} verified "
        f"({len(corpus.techniques)} techniques, {len(corpus.tombstones)} tombstones, "
        f"signature {'verified' if pin.signature else 'absent'})."
    )
    return 0


def sign() -> int:
    import os

    key_hex = os.environ.get("ATTACK_PIN_ED25519_PRIVATE_KEY", "")
    public_key = os.environ.get("ATTACK_PIN_ED25519_PUBLIC_KEY", "")
    if not key_hex or not public_key:
        print(
            "ERROR: set ATTACK_PIN_ED25519_PRIVATE_KEY and ATTACK_PIN_ED25519_PUBLIC_KEY\n"
            "(hex, 32 raw bytes each; generate with\n"
            "agents.policies.signing.generate_ed25519_keypair). The private key is\n"
            "held by the maintainer only — never committed, never stored by an agent.",
            file=sys.stderr,
        )
        return 2
    try:
        from agents.policies.signing import Ed25519Signer, Ed25519Verifier
        from attack.pin import load_pin_document

        document = load_pin_document()
        signer = Ed25519Signer(bytes.fromhex(key_hex))
        signature = signer.sign(signing_payload(document))
        # Prove the supplied public key matches the private key before writing
        # it into the pin — a mismatched pair would commit an unverifiable pin.
        if not Ed25519Verifier(bytes.fromhex(public_key)).verify(
            signing_payload(document), signature
        ):
            print("ERROR: public key does not match the private key", file=sys.stderr)
            return 2
    except (AttackError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    document["signature"] = {
        "algorithm": "ed25519",
        "public_key": public_key,
        "signature": signature,
    }
    parse_pin(document)
    DEFAULT_PIN_PATH.write_bytes(_canonical(document))
    print(f"OK: pin signed (public key {public_key[:16]}…). Commit the updated pin.")
    return 0


def plan() -> int:
    from attack import freshness

    report = freshness(today=date.today())
    print(
        f"pinned: {report.pinned_version} · latest known: {report.latest_known_version} "
        f"({report.latest_modified or 'unknown date'}) · versions behind: "
        f"{report.version_distance} · pin age: {report.pin_age_days} days"
    )
    if report.version_distance:
        print(
            "Refresh (human action): download the new bundle from\n"
            "https://github.com/mitre-attack/attack-stix-data into data/attack/,\n"
            "then run --build, review the diff, re-run the reference gates, --sign."
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--build", action="store_true", help="distill a staged bundle")
    mode.add_argument("--check", action="store_true", help="verify the committed corpus")
    mode.add_argument("--sign", action="store_true", help="sign the pin (maintainer key)")
    mode.add_argument("--plan", action="store_true", help="advisory freshness report")
    parser.add_argument("--bundle", help="staged bundle file name inside data/attack/")
    parser.add_argument(
        "--retrieved",
        default=date.today().isoformat(),
        help="ISO date the bundle was retrieved (default: today)",
    )
    args = parser.parse_args(argv)
    if args.build:
        if not args.bundle:
            parser.error("--build requires --bundle <file-name>")
        return build(args.bundle, args.retrieved)
    if args.sign:
        return sign()
    if args.plan:
        return plan()
    return check()


if __name__ == "__main__":
    raise SystemExit(main())
