#!/usr/bin/env python3
"""Drift + validity gate for the committed threat-intelligence library.

Mirrors ``check_mapping_rules.py``: a canonicalized digest over every
committed intel data file (``intel/*.json``, ``intel/seed/``,
``intel/behaviors/``) must match ``intel/store.sha256``, and the whole
library must load fail-closed against the pinned ATT&CK corpus — so a
version bump that retires an anchored technique, a non-allow-listed license,
a TLP above CLEAR, or a never-flagged address in the seed all fail here,
loudly, before merge.

Modes:
    python scripts/check_intel_store.py --check    # CI / pre-commit gate
    python scripts/check_intel_store.py --update   # rewrite store.sha256

Exit codes: 0 in sync · 1 drift or invalid store · 2 bad input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # script may run from anywhere
    sys.path.insert(0, str(REPO_ROOT))

INTEL_DIR = REPO_ROOT / "intel"
DIGEST_PATH = INTEL_DIR / "store.sha256"


def _data_files() -> list[Path]:
    files = [
        *sorted(INTEL_DIR.glob("*.json")),
        *sorted((INTEL_DIR / "seed").glob("*.json")),
        *sorted((INTEL_DIR / "behaviors").glob("*.json")),
    ]
    if not files:
        raise ValueError(f"no intel data files under {INTEL_DIR}")
    return files


def compute_digest() -> str:
    """Canonicalized digest over every data file, sorted relative-path order."""
    digest = hashlib.sha256()
    for path in _data_files():
        document = json.loads(path.read_bytes())
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
        digest.update(str(path.relative_to(INTEL_DIR)).encode("utf-8"))
        digest.update(b"\x00")
        digest.update(canonical.encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="verify digest + store validity")
    mode.add_argument("--update", action="store_true", help="rewrite store.sha256")
    args = parser.parse_args(argv)

    try:
        digest = compute_digest()
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.update:
        DIGEST_PATH.write_text(digest + "\n", encoding="utf-8")
        print(f"Wrote {DIGEST_PATH.relative_to(REPO_ROOT)} ({digest[:16]}…).")
        return 0

    committed = DIGEST_PATH.read_text(encoding="utf-8").strip() if DIGEST_PATH.is_file() else ""
    if committed != digest:
        print(
            "FAIL: intel store digest drifted — review the data change, then run\n"
            "`python scripts/check_intel_store.py --update` in the same PR.",
            file=sys.stderr,
        )
        return 1

    from intel import IntelStoreError, load_store

    try:
        store = load_store()
    except IntelStoreError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        f"OK: intel store verified ({len(store.sources)} sources, "
        f"{len(store.atomic)} atomic, {len(store.behaviors)} behavioral, "
        f"ATT&CK {store.attack_version}, digest {digest[:16]}…)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
