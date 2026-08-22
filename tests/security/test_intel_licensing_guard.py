"""No committed intel or attack data may carry restricted markings or licenses."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from intel.store import ALLOWED_LICENSES

_REPO = Path(__file__).resolve().parents[2]


def _walk_json(root: Path) -> list[tuple[Path, object]]:
    return [
        (path, json.loads(path.read_text(encoding="utf-8")))
        for path in sorted(root.rglob("*.json"))
    ]


def _check(node: object, path: Path) -> None:
    if isinstance(node, dict):
        tlp = node.get("tlp")
        assert tlp in (None, "clear"), f"{path}: TLP {tlp!r} above CLEAR"
        assert node.get("redistributable") is not False, (
            f"{path}: non-redistributable content committed"
        )
        for value in node.values():
            _check(value, path)
    elif isinstance(node, list):
        for item in node:
            _check(item, path)


@pytest.mark.security
def test_no_restricted_tlp_or_redistribution_flags() -> None:
    for root in (_REPO / "intel", _REPO / "attack"):
        for path, document in _walk_json(root):
            _check(document, path)


@pytest.mark.security
def test_every_source_license_is_allow_listed() -> None:
    document = json.loads((_REPO / "intel" / "sources.json").read_text(encoding="utf-8"))
    for source in document["sources"]:
        assert source["license"] in ALLOWED_LICENSES
