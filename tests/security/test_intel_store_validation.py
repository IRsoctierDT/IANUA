# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The intel library loads whole or not at all (DESIGN.md §5 boundary 6)."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from intel import IntelStoreError, load_store

_INTEL = Path(__file__).resolve().parents[2] / "intel"


def _workdir(tmp_path: Path) -> Path:
    work = tmp_path / "intel"
    work.mkdir()
    for name in ("never_flag.json", "sources.json"):
        shutil.copyfile(_INTEL / name, work / name)
    for sub in ("seed", "behaviors"):
        (work / sub).mkdir()
        for path in (_INTEL / sub).glob("*.json"):
            shutil.copyfile(path, work / sub / path.name)
    return work


def _mutate(work: Path, relative: str, mutate: Callable[[dict], None]) -> None:
    path = work / relative
    document = json.loads(path.read_text(encoding="utf-8"))
    mutate(document)
    path.write_text(json.dumps(document), encoding="utf-8")


_SEED = "seed/indicators.json"

_CASES: list[tuple[str, str, Callable[[dict], None]]] = [
    ("unknown seed field", _SEED, lambda d: d["indicators"][0].update(surprise=1)),
    ("missing expires", _SEED, lambda d: d["indicators"][0].pop("expires")),
    ("tlp above clear", _SEED, lambda d: d["indicators"][0].update(tlp="amber")),
    ("unregistered source", _SEED, lambda d: d["indicators"][0].update(source_id="ghost-feed")),
    ("unknown risk", _SEED, lambda d: d["indicators"][0].update(risk="catastrophic")),
    ("bad date", _SEED, lambda d: d["indicators"][0].update(retrieved="21/08/2026")),
    # fromisoformat accepts these; string ordering of mixed forms is wrong
    # (measured: an August expiry in basic form passed against a September
    # first_seen, and one basic-form retrieved moved default_as_of back).
    ("basic-form ISO date", _SEED, lambda d: d["indicators"][0].update(retrieved="20260814")),
    ("week-form ISO date", _SEED, lambda d: d["indicators"][0].update(expires="2026-W46-5")),
    (
        "expires before first_seen in mixed forms",
        _SEED,
        lambda d: d["indicators"][0].update(first_seen="2026-09-01", expires="20260801"),
    ),
    (
        "expires before first_seen",
        _SEED,
        lambda d: d["indicators"][0].update(first_seen="2026-07-01", expires="2026-06-01"),
    ),
    (
        "never-flagged address in seed",
        _SEED,
        lambda d: d["indicators"][0].update(type="ipv4", value="10.1.2.3"),
    ),
    (
        "ip version disagrees with type",
        _SEED,
        lambda d: d["indicators"][0].update(type="ipv6", value="203.0.113.9"),
    ),
    (
        "non-allow-listed license",
        "sources.json",
        lambda d: d["sources"][0].update(license="CC-BY-NC-4.0"),
    ),
    ("duplicate source", "sources.json", lambda d: d["sources"].append(d["sources"][0])),
    (
        "unknown attack anchor",
        "behaviors/core.json",
        lambda d: d["behaviors"][0].update(attack_techniques=["T9999"]),
    ),
    (
        "malformed attack anchor",
        "behaviors/core.json",
        lambda d: d["behaviors"][0].update(attack_techniques=["1110"]),
    ),
    (
        "behavior interval out of range",
        "behaviors/core.json",
        lambda d: d["behaviors"][0].update(review_interval_days=0),
    ),
    (
        "duplicate behavior id",
        "behaviors/core.json",
        lambda d: d["behaviors"].append(dict(d["behaviors"][0])),
    ),
    ("bad never_flag cidr", "never_flag.json", lambda d: d["cidrs"].append("not-a-cidr")),
    # Measured before the type check: both loaded — 2886729729 as 172.16.0.1/32,
    # True as 0.0.0.1/32 — a suppression entry no reviewer can read in a diff.
    ("int never_flag cidr", "never_flag.json", lambda d: d["cidrs"].append(2886729729)),
    ("bool never_flag cidr", "never_flag.json", lambda d: d["cidrs"].append(True)),
    # Measured before the isinstance guards: each raised TypeError (unhashable),
    # not IntelStoreError, so the agent's fail-soft path did not catch it.
    ("list-valued atomic type", _SEED, lambda d: d["indicators"][0].update(type=["ipv4"])),
    ("list-valued risk", _SEED, lambda d: d["indicators"][0].update(risk=[])),
    ("dict-valued confidence", _SEED, lambda d: d["indicators"][0].update(confidence={})),
    ("list-valued source_id", _SEED, lambda d: d["indicators"][0].update(source_id=[])),
    (
        "list-valued behavior confidence",
        "behaviors/core.json",
        lambda d: d["behaviors"][0].update(confidence=[]),
    ),
    (
        "list-valued behavior source_id",
        "behaviors/core.json",
        lambda d: d["behaviors"][0].update(source_id=[]),
    ),
]


@pytest.mark.security
@pytest.mark.parametrize(("label", "relative", "mutate"), _CASES, ids=[c[0] for c in _CASES])
def test_malformed_store_rejects_wholly(
    label: str, relative: str, mutate: Callable[[dict], None], tmp_path: Path
) -> None:
    work = _workdir(tmp_path)
    _mutate(work, relative, mutate)
    with pytest.raises(IntelStoreError):
        load_store(work)


@pytest.mark.security
@pytest.mark.parametrize(
    "relative", ["never_flag.json", "sources.json", _SEED, "behaviors/core.json"]
)
def test_nesting_bomb_is_a_store_error_not_a_recursion_error(relative: str, tmp_path: Path) -> None:
    # Measured before the guard: 500000 brackets (under the 512 KiB ceiling)
    # escaped as RecursionError, which the threat-intel agent's fail-soft
    # `except (IntelStoreError, AttackError, OSError)` does not catch.
    work = _workdir(tmp_path)
    (work / relative).write_bytes(b"[" * 500_000)
    with pytest.raises(IntelStoreError, match="nesting"):
        load_store(work)


@pytest.mark.security
def test_committed_store_is_valid() -> None:
    store = load_store()
    assert store.sources and store.atomic and store.behaviors


@pytest.mark.security
def test_deprecated_anchor_degrades_not_rejects(tmp_path: Path) -> None:
    # A deprecated ATT&CK anchor must NOT reject the record (an external
    # taxonomy may not switch off a working local detection) — it loads and
    # match-time status degrades to stale-anchor.
    from datetime import date

    from attack import load_corpus
    from intel import match_behaviors

    work = _workdir(tmp_path)
    _mutate(
        work,
        "behaviors/core.json",
        lambda d: d["behaviors"][0].update(attack_techniques=["T1064"]),  # deprecated in 19.2
    )
    store = load_store(work)
    corpus = load_corpus()
    matches = match_behaviors(
        store, store.behaviors[0].event_types[0], corpus, as_of=date(2026, 8, 21)
    )
    target = [m for m in matches if m.record.record_id == store.behaviors[0].record_id]
    assert target and target[0].status == "stale-anchor"
    assert "deprecated" in target[0].notes[0]
