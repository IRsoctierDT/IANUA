# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Single-source cap: only records that assert ``malicious`` corroborate.

DESIGN.md §5 boundary 6 — one poisoned feed caps at ``suspicious``. Measured
before the fix: a second upstream listing the value as ``benign`` lifted the
cap, so a poisoned feed branded infrastructure malicious whenever any other
feed had listed the value at all.
"""

from __future__ import annotations

import json
import shutil
from datetime import date
from pathlib import Path

import pytest

from intel import IntelStore, load_store, lookup_indicator

_INTEL = Path(__file__).resolve().parents[2] / "intel"
_VALUE = "198.51.100.250"  # RFC 5737 documentation space, absent from the seed
_AS_OF = date(2026, 8, 21)


def _store_with(tmp_path: Path, *records: dict[str, object]) -> IntelStore:
    work = tmp_path / "intel"
    shutil.copytree(
        _INTEL, work, ignore=shutil.ignore_patterns("*.py", "*.sha256", "*.md", "__pycache__")
    )
    seed_path = work / "seed" / "indicators.json"
    seed = json.loads(seed_path.read_text(encoding="utf-8"))
    template = dict(seed["indicators"][0])  # a valid ipv4 record to clone
    for overrides in records:
        record = dict(template)
        record.update(type="ipv4", value=_VALUE, confidence="high", **overrides)
        seed["indicators"].append(record)
    seed_path.write_text(json.dumps(seed), encoding="utf-8")
    return load_store(work)


@pytest.mark.security
@pytest.mark.parametrize("other_risk", ["benign", "suspicious"])
def test_second_upstream_not_asserting_malicious_does_not_lift_the_cap(
    tmp_path: Path, other_risk: str
) -> None:
    store = _store_with(
        tmp_path,
        {"risk": other_risk, "source_id": "synthetic-feed-alpha"},
        {"risk": "malicious", "source_id": "synthetic-feed-bravo"},
    )
    verdict = lookup_indicator(store, _VALUE, as_of=_AS_OF)
    assert verdict.risk == "suspicious", f"a lone malicious word plus {other_risk!r} is capped"
    assert verdict.notes and "capped" in verdict.notes[0]
    assert verdict.sources == ("synthetic-feed-alpha", "synthetic-feed-bravo")


@pytest.mark.security
def test_two_malicious_upstreams_corroborate(tmp_path: Path) -> None:
    store = _store_with(
        tmp_path,
        {"risk": "malicious", "source_id": "synthetic-feed-alpha"},
        {"risk": "malicious", "source_id": "synthetic-feed-bravo"},
    )
    verdict = lookup_indicator(store, _VALUE, as_of=_AS_OF)
    assert verdict.risk == "malicious" and verdict.notes == ()


@pytest.mark.security
def test_same_upstream_twice_is_one_word(tmp_path: Path) -> None:
    work = tmp_path / "intel"
    shutil.copytree(
        _INTEL, work, ignore=shutil.ignore_patterns("*.py", "*.sha256", "*.md", "__pycache__")
    )
    sources_path = work / "sources.json"
    sources = json.loads(sources_path.read_text(encoding="utf-8"))
    by_id = {s["source_id"]: s for s in sources["sources"]}
    by_id["synthetic-feed-bravo"]["upstream"] = by_id["synthetic-feed-alpha"]["upstream"]
    sources_path.write_text(json.dumps(sources), encoding="utf-8")
    seed_path = work / "seed" / "indicators.json"
    seed = json.loads(seed_path.read_text(encoding="utf-8"))
    template = dict(seed["indicators"][0])
    for source_id in ("synthetic-feed-alpha", "synthetic-feed-bravo"):
        record = dict(template)
        record.update(type="ipv4", value=_VALUE, risk="malicious", source_id=source_id)
        seed["indicators"].append(record)
    seed_path.write_text(json.dumps(seed), encoding="utf-8")
    verdict = lookup_indicator(load_store(work), _VALUE, as_of=_AS_OF)
    assert verdict.risk == "suspicious" and "capped" in verdict.notes[0]
