#!/usr/bin/env python3
"""Drift + validity gate for the committed mapping ruleset.

Two checks, both fail-closed:

1. **Digest** — the canonicalized content of every file under
   ``agents/mapping/rules/`` must hash to the committed
   ``agents/mapping/rules.sha256``. Canonicalization (sorted keys, compact
   separators, per-file, sorted filename order) makes the digest immune to
   whitespace/line-ending churn while any semantic edit fails the gate until
   the digest is regenerated in the same reviewed PR.
2. **Validity** — the store must load against the pinned ATT&CK corpus. This
   is where an ATT&CK version bump surfaces: a rule anchored to a technique
   the new pin marks revoked or deprecated fails THIS gate with the successor
   named, so stale mappings cannot merge.

Modes:
    python scripts/check_mapping_rules.py --check    # CI / pre-commit gate
    python scripts/check_mapping_rules.py --update   # rewrite rules.sha256

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

RULES_DIR = REPO_ROOT / "agents" / "mapping" / "rules"
DIGEST_PATH = REPO_ROOT / "agents" / "mapping" / "rules.sha256"


def compute_digest() -> str:
    """Canonicalized digest over every ruleset file, sorted filename order."""
    digest = hashlib.sha256()
    paths = sorted(RULES_DIR.glob("*.json"))
    if not paths:
        raise ValueError(f"no ruleset files under {RULES_DIR}")
    for path in paths:
        document = json.loads(path.read_bytes())
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(canonical.encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="verify digest + store validity")
    mode.add_argument("--update", action="store_true", help="rewrite rules.sha256")
    args = parser.parse_args(argv)

    try:
        digest = compute_digest()
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.update:
        DIGEST_PATH.write_text(digest + "\n", encoding="utf-8")
        print(f"Wrote {DIGEST_PATH.relative_to(REPO_ROOT)} ({digest[:16]}…).")
        return 0

    committed = DIGEST_PATH.read_text(encoding="utf-8").strip() if DIGEST_PATH.is_file() else ""
    if committed != digest:
        print(
            "FAIL: mapping ruleset digest drifted — review the rule change, then run\n"
            "`python scripts/check_mapping_rules.py --update` in the same PR.",
            file=sys.stderr,
        )
        return 1

    from agents.mapping import MappingStoreError, load_store

    try:
        store = load_store()
    except MappingStoreError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        f"OK: mapping ruleset verified ({len(store.rules)} rules, "
        f"ATT&CK {store.attack_version}, digest {digest[:16]}…)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
