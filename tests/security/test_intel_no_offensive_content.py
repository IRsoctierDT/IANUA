"""Committed intel content is detection-phrased — never an attack toolkit."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import pytest

_INTEL = Path(__file__).resolve().parents[2] / "intel"

_SHELLCODE_HEX = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")


def _all_strings(node: object) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, list):
        return [s for item in node for s in _all_strings(item)]
    if isinstance(node, dict):
        return [s for value in node.values() for s in _all_strings(value)]
    return []


@pytest.mark.security
def test_no_payloads_or_shellcode_shapes() -> None:
    for path in sorted(_INTEL.rglob("*.json")):
        for text in _all_strings(json.loads(path.read_text(encoding="utf-8"))):
            assert not _SHELLCODE_HEX.search(text), f"{path}: shellcode-shaped hex"
            if len(text) > 256 and re.fullmatch(r"[A-Za-z0-9+/=]+", text):
                decodable = True
                try:
                    base64.b64decode(text, validate=True)
                except (ValueError, TypeError):
                    decodable = False
                assert not decodable, f"{path}: oversized base64 blob committed"


@pytest.mark.security
def test_behaviors_are_detections_with_false_positives() -> None:
    document = json.loads((_INTEL / "behaviors" / "core.json").read_text(encoding="utf-8"))
    for record in document["behaviors"]:
        assert record["false_positives"], f"{record['id']}: detection needs falsepositives"
        assert record["markers"], f"{record['id']}: detection needs observable markers"
        # Markers describe what a DEFENDER observes; the schema has no field
        # capable of holding an attack command line, and no marker may smuggle
        # a ready-to-run payload invocation.
        for marker in record["markers"]:
            assert not marker.strip().startswith(("$", "#", "C:\\>")), (
                f"{record['id']}: marker looks like a runnable command prompt line"
            )
