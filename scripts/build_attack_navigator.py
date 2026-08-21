#!/usr/bin/env python3
"""Generate a MITRE ATT&CK Navigator coverage layer from the Sigma corpus.

Reads every rule in ``detections/sigma/`` and emits an ATT&CK Navigator layer
(``docs/attack-navigator-layer.json``) that heatmaps the techniques the
platform detects — the DeTT&CT-style coverage view that makes detection gaps
visible technique-by-technique. Deterministic and offline: the layer is a pure
function of the committed rule inventory, so it is drift-gated exactly like the
status and trust pages.

Modes:
    # Regenerate docs/attack-navigator-layer.json from the Sigma corpus:
    python scripts/build_attack_navigator.py

    # CI/pre-commit drift gate — exit non-zero if the committed layer is stale
    # relative to the corpus (no files written):
    python scripts/build_attack_navigator.py --check

Security considerations (AGENTS.md §5, §6.1):
    * **No network, no secrets** — only the local Sigma corpus is read; the
      output contains technique IDs and rule titles, nothing sensitive.
    * **Input validation, fail-closed** — a rule whose ATT&CK tags are
      malformed raises rather than silently under-reporting coverage.
    * **Deterministic** — techniques and scores are sorted; identical inputs
      yield a byte-identical layer.

Exit codes: ``0`` success / in sync · ``1`` drift detected · ``2`` bad input.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - yaml present in dev/CI
    print("PyYAML is required (pip install -e '.[dev]').", file=sys.stderr)
    raise SystemExit(2) from None

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:  # script may run from anywhere
    sys.path.insert(0, str(_REPO_ROOT))

from attack import load_corpus, load_pin, validate_reference  # noqa: E402

_SIGMA_DIR = _REPO_ROOT / "detections" / "sigma"
_OUTPUT = _REPO_ROOT / "docs" / "attack-navigator-layer.json"

# ATT&CK technique tag pattern in Sigma: attack.tXXXX or attack.tXXXX.YYY
_TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def _extract_techniques(tags: Any) -> set[str]:
    """Return the uppercased ATT&CK technique IDs from a rule's tags list."""
    if tags is None:
        return set()
    if not isinstance(tags, list):
        raise ValueError(f"rule 'tags' must be a list, got {type(tags).__name__}")
    techniques: set[str] = set()
    for tag in tags:
        match = _TECHNIQUE_TAG.match(str(tag))
        if match:
            techniques.add(match.group(1).upper())
    return techniques


def build_layer(sigma_dir: Path = _SIGMA_DIR) -> dict[str, Any]:
    """Build the Navigator layer dict from the Sigma corpus (deterministic).

    Every technique tag is validated against the pinned local ATT&CK corpus
    (``attack/``): a tag that does not resolve, or resolves to a revoked or
    deprecated technique, raises — so a rule pinned to a dead technique cannot
    merge. The layer's ATT&CK version comes from the pin, never a hard-coded
    string. The layer itself stays a pure function of ``detections/sigma/``.
    """
    corpus = load_corpus()
    # technique_id -> list of rule titles covering it
    coverage: dict[str, list[str]] = {}
    for path in sorted(sigma_dir.glob("*.yml")):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(rule, dict):
            raise ValueError(f"{path.name}: rule is not a mapping")
        title = str(rule.get("title", path.stem))
        for technique in _extract_techniques(rule.get("tags")):
            verdict = validate_reference(technique, corpus)
            if not verdict.ok:
                detail = "; ".join(verdict.problems) or verdict.status
                raise ValueError(
                    f"{path.name}: tag references a dead technique — {detail}"
                    + (f" (successor: {verdict.successor})" if verdict.successor else "")
                )
            coverage.setdefault(technique, []).append(title)

    max_count = max((len(v) for v in coverage.values()), default=1)
    techniques = []
    for technique_id in sorted(coverage):
        titles = sorted(coverage[technique_id])
        techniques.append(
            {
                "techniqueID": technique_id,
                "score": len(titles),
                "color": "",
                "comment": (
                    "Detected by: "
                    + "; ".join(titles)
                    + f" — {corpus.techniques[technique_id].name}"
                ),
                "enabled": True,
                "metadata": [],
                "showSubtechniques": True,
            }
        )

    return {
        "name": "IANUA Detection Coverage",
        "versions": {
            "attack": load_pin().attack_version.split(".")[0],
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            "Techniques covered by the IANUA Sigma detection corpus, generated "
            "deterministically from detections/sigma/ by "
            "scripts/build_attack_navigator.py. Score = number of rules "
            "covering the technique."
        ),
        "sorting": 3,
        "gradient": {
            "colors": ["#ffe766", "#ff6666"],
            "minValue": 0,
            "maxValue": max_count,
        },
        "techniques": techniques,
        "hideDisabled": False,
    }


def render(layer: dict[str, Any]) -> str:
    """Serialize the layer to stable, diff-friendly JSON."""
    return json.dumps(layer, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the committed layer is stale (writes nothing).",
    )
    args = parser.parse_args(argv)

    try:
        rendered = render(build_layer())
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.check:
        current = _OUTPUT.read_text(encoding="utf-8") if _OUTPUT.exists() else ""
        if current != rendered:
            print(
                "ATT&CK Navigator layer is stale — run scripts/build_attack_navigator.py",
                file=sys.stderr,
            )
            return 1
        print("OK: ATT&CK Navigator layer is in sync with the Sigma corpus.")
        return 0

    _OUTPUT.write_text(rendered, encoding="utf-8")
    technique_count = len(json.loads(rendered)["techniques"])
    print(f"Wrote {_OUTPUT.relative_to(_REPO_ROOT)} ({technique_count} techniques).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
