#!/usr/bin/env python3
"""Generate a CycloneDX Software Bill of Materials (SBOM) for this repository.

The repository spans two package ecosystems:

* **Python** — audited by ``pip-audit`` (the sanctioned SCA gate, AGENTS.md §7),
  which already emits a CycloneDX document enriched with known-vulnerability data.
* **npm** — resolved from ``package-lock.json``. No npm SBOM tool is installed,
  so this module derives components directly from the lockfile, fully offline.

This script performs **no network access**: it consumes the pre-generated Python
SBOM and the committed lockfile, then writes:

* ``security/sbom/npm.cdx.json``  — npm components (CycloneDX 1.5)
* ``security/sbom/sbom.cdx.json`` — merged Python + npm document (CycloneDX 1.5)

Security considerations:
    * Inputs are local, trusted repository files; no untrusted/LLM input is parsed.
    * ``integrity`` hashes from the lockfile are decoded into CycloneDX hash
      entries so downstream consumers can verify component provenance.
    * The script is deterministic and idempotent — re-running overwrites the
      outputs with identical content for identical inputs.

Usage:
    # 1. Audit + emit the Python SBOM from the pinned lock (queries advisory DBs):
    python -m pip_audit -r security/sbom/requirements.lock \
        -f cyclonedx-json -o security/sbom/python.cdx.json
    # 2. Merge with npm components (offline):
    python scripts/generate_sbom.py --timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

# Stable namespace for deriving deterministic CycloneDX serial numbers.
_SBOM_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "ianua/sbom")

# PEP 503 name normalisation for PyPI Package URLs.
_PYPI_NAME_RE = re.compile(r"[-_.]+")

REPO_ROOT = Path(__file__).resolve().parent.parent
SBOM_DIR = REPO_ROOT / "security" / "sbom"

SPEC_VERSION = "1.5"
# CycloneDX hash algorithm names keyed by Subresource-Integrity prefix.
_SRI_ALGORITHMS = {"sha512": "SHA-512", "sha384": "SHA-384", "sha256": "SHA-256"}


def _sri_to_hash(integrity: str) -> dict[str, str] | None:
    """Convert an npm Subresource-Integrity string to a CycloneDX hash entry.

    Args:
        integrity: e.g. ``"sha512-3NX/...=="`` (algorithm + base64 digest).

    Returns:
        A ``{"alg": ..., "content": <hex>}`` dict, or ``None`` if the value is
        empty or uses an unrecognised/malformed algorithm.
    """
    if not integrity or "-" not in integrity:
        return None
    prefix, _, b64 = integrity.partition("-")
    alg = _SRI_ALGORITHMS.get(prefix.lower())
    if alg is None:
        # Present but unrecognised — surface it (the component is still emitted,
        # just without a provenance hash) rather than dropping it silently.
        print(f"warning: unsupported integrity algorithm '{prefix}'", file=sys.stderr)
        return None
    try:
        digest_hex = binascii.hexlify(base64.b64decode(b64, validate=True)).decode("ascii")
    except (binascii.Error, ValueError):
        return None
    return {"alg": alg, "content": digest_hex}


def _purl(name: str, version: str) -> str:
    """Build an npm Package URL (purl), scope-aware for ``@scope/name``."""
    if name.startswith("@") and "/" in name:
        scope, _, pkg = name.partition("/")
        return f"pkg:npm/{scope}/{pkg}@{version}"
    return f"pkg:npm/{name}@{version}"


def build_npm_components(lockfile: Path) -> list[dict[str, Any]]:
    """Derive CycloneDX components from an npm ``package-lock.json`` (v2/v3).

    Args:
        lockfile: Path to ``package-lock.json``.

    Returns:
        A sorted, de-duplicated list of CycloneDX component objects. The root
        package (the ``""`` key) is intentionally excluded — it is the SBOM
        subject, not a dependency.
    """
    data = json.loads(lockfile.read_text(encoding="utf-8"))
    packages: dict[str, Any] = data.get("packages", {})
    seen: set[str] = set()
    components: list[dict[str, Any]] = []

    for path, meta in packages.items():
        if not path.startswith("node_modules/"):
            continue
        name = path.rsplit("node_modules/", 1)[-1]
        version = meta.get("version")
        if not name or not version:
            continue
        purl = _purl(name, version)
        if purl in seen:
            continue
        seen.add(purl)

        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
            "scope": "optional" if meta.get("dev") else "required",
        }
        if (license_id := meta.get("license")) and isinstance(license_id, str):
            component["licenses"] = [{"license": {"id": license_id}}]
        if hash_entry := _sri_to_hash(meta.get("integrity", "")):
            component["hashes"] = [hash_entry]
        components.append(component)

    components.sort(key=lambda c: c["purl"])
    return components


def _enrich_pypi_purls(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Backfill PyPI Package URLs on components that lack one.

    ``pip-audit`` emits CycloneDX components with ``name``/``version`` but no
    ``purl``. A purl is how SBOM consumers match a component against advisory
    databases, so we synthesise ``pkg:pypi/<normalised-name>@<version>`` (PEP 503
    normalisation) for any component missing one. Components that already carry a
    purl (e.g. npm) are left untouched.

    Args:
        components: CycloneDX component objects, mutated in place.

    Returns:
        The same list, for convenient chaining.
    """
    for component in components:
        if component.get("purl"):
            continue
        name, version = component.get("name"), component.get("version")
        if not name or not version:
            continue
        normalised = _PYPI_NAME_RE.sub("-", name).lower()
        component["purl"] = f"pkg:pypi/{normalised}@{version}"
    return components


def _make_refs_deterministic(
    components: list[dict[str, Any]], vulnerabilities: list[dict[str, Any]]
) -> None:
    """Replace ``pip-audit``'s random ``bom-ref`` values with stable purls.

    ``pip-audit`` assigns each component a randomly-generated ``bom-ref`` (e.g.
    ``BomRef.5446...``), which makes the SBOM differ on every run. We rewrite
    each component's ``bom-ref`` to its (deterministic) purl and remap any
    ``vulnerabilities[].affects[].ref`` that pointed at the old value, so
    vulnerability-to-component linkage is preserved. Both arguments are mutated
    in place.

    Args:
        components: components whose ``bom-ref`` should become their purl.
        vulnerabilities: vulnerability objects whose ``affects`` refs are remapped.
    """
    remap: dict[str, str] = {}
    for component in components:
        purl = component.get("purl")
        old_ref = component.get("bom-ref")
        if not purl:
            continue
        if old_ref and old_ref != purl:
            remap[old_ref] = purl
        component["bom-ref"] = purl

    for vuln in vulnerabilities:
        for affected in vuln.get("affects", []):
            ref = affected.get("ref")
            if ref in remap:
                affected["ref"] = remap[ref]


def _serial_number(timestamp: str, components: list[dict[str, Any]]) -> str:
    """Derive a deterministic CycloneDX ``serialNumber`` (URN UUID).

    `actions/attest-sbom` detects CycloneDX by the presence of ``bomFormat`` *and*
    ``serialNumber``, so the field is required for the SBOM to be attestable. We
    derive it (UUIDv5) from the timestamp and the component purls rather than
    using a random UUID, so generation stays byte-for-byte reproducible: identical
    inputs always yield the same serial number.
    """
    key = timestamp + "\n" + "\n".join(sorted(c.get("purl", c.get("name", "")) for c in components))
    return f"urn:uuid:{uuid.uuid5(_SBOM_NAMESPACE, key)}"


def _root_component() -> dict[str, Any]:
    """Build the metadata.component describing the repository itself."""
    pkg = json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))
    return {
        "type": "application",
        "bom-ref": "root-component",
        "name": pkg.get("name", "ianua"),
        "version": str(pkg.get("version", "0.0.0")),
    }


def _metadata(timestamp: str) -> dict[str, Any]:
    """Assemble the CycloneDX metadata block."""
    return {
        "timestamp": timestamp,
        "tools": {
            "components": [
                {"type": "application", "name": "pip-audit", "group": "pypa"},
                {"type": "application", "name": "generate_sbom.py", "group": "scripts"},
            ]
        },
        "component": _root_component(),
    }


def merge(
    python_sbom: Path, npm_components: list[dict[str, Any]], timestamp: str
) -> dict[str, Any]:
    """Merge the pip-audit Python SBOM with derived npm components.

    Python components carry over verbatim (preserving any ``vulnerabilities``
    block pip-audit attached). The result is a single CycloneDX 1.5 document.
    """
    py_doc = json.loads(python_sbom.read_text(encoding="utf-8"))
    py_components: list[dict[str, Any]] = _enrich_pypi_purls(py_doc.get("components", []))
    vulns: list[dict[str, Any]] = py_doc.get("vulnerabilities", [])
    _make_refs_deterministic(py_components, vulns)
    py_components.sort(key=lambda c: c.get("purl") or c.get("name", ""))

    components = py_components + npm_components
    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": _serial_number(timestamp, components),
        "version": 1,
        "metadata": _metadata(timestamp),
        "components": components,
    }
    if vulns:
        doc["vulnerabilities"] = vulns
    return doc


def _write_json(path: Path, doc: dict[str, Any]) -> None:
    """Write ``doc`` as pretty-printed, newline-terminated JSON."""
    path.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _is_valid_timestamp(timestamp: str) -> bool:
    """Return True if ``timestamp`` is a parseable ISO-8601 instant.

    The value is embedded verbatim in the SBOM ``metadata.timestamp``; rejecting
    garbage early keeps a malformed CLI argument out of the published artifact.
    """
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def main() -> int:
    """CLI entry point. Returns a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--timestamp",
        required=True,
        help="UTC ISO-8601 build timestamp, e.g. 2026-06-22T00:00:00Z",
    )
    parser.add_argument(
        "--python-sbom",
        type=Path,
        default=SBOM_DIR / "python.cdx.json",
        help="Path to the pip-audit CycloneDX output.",
    )
    parser.add_argument(
        "--lockfile",
        type=Path,
        default=REPO_ROOT / "package-lock.json",
        help="Path to package-lock.json.",
    )
    args = parser.parse_args()

    if not _is_valid_timestamp(args.timestamp):
        print(f"error: --timestamp is not valid ISO-8601: {args.timestamp!r}", file=sys.stderr)
        return 2
    for label, path in (("lockfile", args.lockfile), ("Python SBOM", args.python_sbom)):
        if not path.is_file():
            print(f"error: {label} not found: {path}", file=sys.stderr)
            return 2

    SBOM_DIR.mkdir(parents=True, exist_ok=True)

    try:
        npm_components = build_npm_components(args.lockfile)
        npm_doc: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": SPEC_VERSION,
            "serialNumber": _serial_number(args.timestamp, npm_components),
            "version": 1,
            "metadata": _metadata(args.timestamp),
            "components": npm_components,
        }
        _write_json(SBOM_DIR / "npm.cdx.json", npm_doc)

        merged = merge(args.python_sbom, npm_components, args.timestamp)
        _write_json(SBOM_DIR / "sbom.cdx.json", merged)
    except json.JSONDecodeError as exc:
        print(f"error: malformed JSON in an input file: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: file I/O failed: {exc}", file=sys.stderr)
        return 1

    py_count = len(merged["components"]) - len(npm_components)
    print(
        f"SBOM written: {py_count} Python + {len(npm_components)} npm "
        f"= {len(merged['components'])} components -> {SBOM_DIR}/sbom.cdx.json"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
