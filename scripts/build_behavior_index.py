#!/usr/bin/env python3
"""Build and verify the derived behavioral-detection index.

The behavioral corpus is *authored* in YAML (``detections/behaviors/*.yml``,
the format detection engineers actually write) and *consumed* as a committed
JSON projection (``detections/behaviors.index.json``). That split keeps
PyYAML off the runtime import path: the matcher reads the index with stdlib
``json`` and never needs a third fail-soft ``ModuleNotFoundError`` branch —
a detection engine silently loading zero rules is a fail-*open*, not
fail-soft.

Validation is fail-closed and includes the **reference gate**: every
``attack.tXXXX`` tag must resolve to an *active* technique in the pinned
``attack/`` corpus. A rule anchored to a technique that a later ATT&CK
release revokes or deprecates fails this gate with the successor named, so
stale behavioral content cannot merge. Every rule must also carry a
``validation:`` marker declaring whether the telemetry it needs is actually
ingested today — aspirational coverage stays visibly aspirational.

Modes:
    python scripts/build_behavior_index.py            # regenerate the index
    python scripts/build_behavior_index.py --check    # CI / pre-commit gate

Exit codes: 0 success / in sync - 1 drift or invalid corpus - 2 bad input.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # script may run from anywhere
    sys.path.insert(0, str(REPO_ROOT))

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - yaml present in dev/CI
    print("PyYAML is required (pip install -e '.[dev]').", file=sys.stderr)
    raise SystemExit(2) from None

from attack import AttackError, load_corpus, validate_reference  # noqa: E402

BEHAVIORS_DIR = REPO_ROOT / "detections" / "behaviors"
OUTPUT = REPO_ROOT / "detections" / "behaviors.index.json"

_TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}

#: Whether the telemetry a rule needs is ingested by this platform today.
#: ``telemetry-required`` rules are honest placeholders: they replay against
#: fixtures but cannot fire in production until the sensor exists.
_VALID_VALIDATION = {"telemetry-available", "telemetry-required"}

_REQUIRED_FIELDS = (
    "title",
    "name",
    "id",
    "description",
    "level",
    "validation",
    "tags",
    "detection",
    "falsepositives",
)


class BehaviorCorpusError(ValueError):
    """Raised when the behavioral corpus fails validation (whole-corpus)."""


def _reject(reason: str) -> BehaviorCorpusError:
    return BehaviorCorpusError(f"invalid behavioral corpus: {reason}")


def _techniques(tags: Any, context: str) -> list[str]:
    if not isinstance(tags, list) or not tags:
        raise _reject(f"{context}: tags must be a non-empty list")
    found: list[str] = []
    for tag in tags:
        match = _TECHNIQUE_TAG.match(str(tag))
        if match:
            found.append(match.group(1).upper())
    if not found:
        raise _reject(f"{context}: no attack.tXXXX technique tag")
    return sorted(set(found))


def build_index(behaviors_dir: Path = BEHAVIORS_DIR) -> dict[str, Any]:
    """Validate the corpus and return the derived index (deterministic)."""
    corpus = load_corpus()
    entries: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    seen_ids: set[str] = set()

    for path in sorted(behaviors_dir.glob("*.yml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(rule, dict):
            raise _reject(f"{path.name}: rule is not a mapping")
        context = path.name

        for field in _REQUIRED_FIELDS:
            if field not in rule:
                raise _reject(f"{context}: missing required field {field!r}")

        name = str(rule["name"])
        if name in seen_names:
            raise _reject(f"{context}: duplicate rule name {name!r}")
        seen_names.add(name)

        rule_id = str(rule["id"])
        try:
            canonical_id = str(uuid.UUID(rule_id))
        except ValueError as exc:
            raise _reject(f"{context}: id is not a valid UUID ({exc})") from exc
        if canonical_id != rule_id:
            raise _reject(f"{context}: id is not in canonical UUID form")
        if rule_id in seen_ids:
            raise _reject(f"{context}: duplicate rule id {rule_id!r}")
        seen_ids.add(rule_id)

        level = str(rule["level"])
        if level not in _VALID_LEVELS:
            raise _reject(f"{context}: invalid level {level!r}")

        validation = str(rule["validation"])
        if validation not in _VALID_VALIDATION:
            raise _reject(
                f"{context}: validation must be one of {sorted(_VALID_VALIDATION)}, "
                f"got {validation!r}"
            )

        false_positives = rule["falsepositives"]
        if not isinstance(false_positives, list) or not false_positives:
            raise _reject(
                f"{context}: falsepositives must list at least one honest FP source — "
                "a detection with no stated false positives is an unreviewed detection"
            )

        detection = rule["detection"]
        if not isinstance(detection, dict) or "condition" not in detection:
            raise _reject(f"{context}: detection must be a mapping with a condition")

        techniques = _techniques(rule["tags"], context)
        for technique_id in techniques:
            try:
                verdict = validate_reference(technique_id, corpus)
            except AttackError as exc:
                raise _reject(f"{context}: {exc}") from exc
            if not verdict.ok:
                detail = "; ".join(verdict.problems) or verdict.status
                successor = f" (successor: {verdict.successor})" if verdict.successor else ""
                raise _reject(f"{context}: tag references a dead technique - {detail}{successor}")

        entries.append(
            {
                "name": name,
                "id": rule_id,
                "title": str(rule["title"]),
                "description": " ".join(str(rule["description"]).split()),
                "level": level,
                "validation": validation,
                "techniques": techniques,
                "false_positives": [str(item) for item in false_positives],
                "file": path.name,
            }
        )

    if not entries:
        raise _reject(f"no behavioral rules found under {behaviors_dir}")

    return {
        "schema": 1,
        "attack_version": corpus.attack_version,
        "behaviors": entries,
    }


def render(index: dict[str, Any]) -> str:
    """Serialize the index to stable, diff-friendly JSON."""
    return json.dumps(index, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the committed index is stale or invalid (writes nothing).",
    )
    args = parser.parse_args(argv)

    try:
        rendered = render(build_index())
    except (BehaviorCorpusError, AttackError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1 if isinstance(exc, BehaviorCorpusError) else 2

    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != rendered:
            print(
                "FAIL: behavioral index is stale - run `python scripts/build_behavior_index.py`",
                file=sys.stderr,
            )
            return 1
        count = len(json.loads(rendered)["behaviors"])
        print(f"OK: behavioral index in sync with the corpus ({count} rules).")
        return 0

    OUTPUT.write_text(rendered, encoding="utf-8")
    index = json.loads(rendered)
    ready = sum(1 for b in index["behaviors"] if b["validation"] == "telemetry-available")
    print(
        f"Wrote {OUTPUT.relative_to(REPO_ROOT)} ({len(index['behaviors'])} rules; "
        f"{ready} telemetry-available, {len(index['behaviors']) - ready} telemetry-required)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
