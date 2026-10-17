# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The mapping ruleset loads whole or not at all (DESIGN.md §5 boundary 7).

A poisoned store poisons every future mapping, so no malformed store may ever
load partially, and every corpus-anchoring error must be loud and specific —
a revoked technique names its successor.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from agents.mapping import MappingStoreError, load_store, parse_store
from attack import Corpus, load_corpus

_RULES = Path(__file__).resolve().parents[2] / "agents" / "mapping" / "rules" / "core.json"


@pytest.fixture(scope="module")
def corpus() -> Corpus:
    return load_corpus()


@pytest.fixture()
def document() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(_RULES.read_text(encoding="utf-8"))
    return loaded


def _committed_revoked_id() -> str:
    corpus = load_corpus()
    return next(t.technique_id for t in corpus.tombstones.values() if t.status == "revoked")


_MUTATIONS: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
    ("unknown top-level field", lambda d: d.update(extra=1)),
    ("bad schema", lambda d: d.update(schema=2)),
    ("missing fallback", lambda d: d.pop("fallback")),
    ("empty rules", lambda d: d.update(rules=[])),
    ("duplicate rule id", lambda d: d["rules"].append(copy.deepcopy(d["rules"][0]))),
    ("unknown rule field", lambda d: d["rules"][0].update(surprise=True)),
    ("empty when", lambda d: d["rules"][0].update(when=[])),
    ("unknown clause field", lambda d: d["rules"][0]["when"][0].update(regex=".*")),
    ("unknown operator", lambda d: d["rules"][0]["when"][0].update(op="matches_regex")),
    ("unknown match field", lambda d: d["rules"][0]["when"][0].update(field="raw_bytes")),
    ("empty clause values", lambda d: d["rules"][0]["when"][0].update(values=[])),
    ("oversized clause value", lambda d: d["rules"][0]["when"][0].update(values=["x" * 500])),
    (
        "unknown technique id",
        lambda d: d["rules"][0]["techniques"][0].update(technique_id="T9999"),
    ),
    (
        "malformed technique id",
        lambda d: d["rules"][0]["techniques"][0].update(technique_id="1110"),
    ),
    (
        "tactic not on the technique",
        lambda d: d["rules"][0]["techniques"][0].update(tactic="impact"),
    ),
    (
        "unknown confidence",
        lambda d: d["rules"][0]["techniques"][0].update(confidence="certain"),
    ),
    (
        "techniques AND legacy on one rule",
        lambda d: d["rules"][0].update(legacy=copy.deepcopy(d["fallback"])),
    ),
    (
        "no techniques and no legacy",
        lambda d: d["rules"][0].update(techniques=[]),
    ),
    ("legacy with extra field", lambda d: d["fallback"].update(color="red")),
    # Type confusion. A list is unhashable, so a bare membership test raised
    # TypeError instead of MappingStoreError (measured) — still a failure, but
    # not the one error type the gate script and callers catch. And `True == 1`
    # / `1.0 == 1`, so a boolean or float schema loaded as schema 1.
    ("list-typed clause field", lambda d: d["rules"][0]["when"][0].update(field=["event_type"])),
    ("list-typed operator", lambda d: d["rules"][0]["when"][0].update(op=["equals"])),
    ("list-typed tactic", lambda d: d["rules"][0]["techniques"][0].update(tactic=["impact"])),
    ("list-typed confidence", lambda d: d["rules"][0]["techniques"][0].update(confidence=["high"])),
    ("list-typed legacy confidence", lambda d: d["fallback"].update(confidence=["low"])),
    ("boolean schema", lambda d: d.update(schema=True)),
    ("float schema", lambda d: d.update(schema=1.0)),
]


@pytest.mark.security
@pytest.mark.parametrize(("label", "mutate"), _MUTATIONS, ids=[m[0] for m in _MUTATIONS])
def test_malformed_store_rejects_wholly(
    label: str,
    mutate: Callable[[dict[str, Any]], None],
    document: dict[str, Any],
    corpus: Corpus,
) -> None:
    mutate(document)
    with pytest.raises(MappingStoreError):
        parse_store(document, corpus=corpus)


@pytest.mark.security
def test_revoked_technique_error_names_the_successor(
    document: dict[str, Any],
    corpus: Corpus,
) -> None:
    revoked_id = _committed_revoked_id()
    successor = corpus.tombstones[revoked_id].successor
    document["rules"][0]["techniques"][0]["technique_id"] = revoked_id
    with pytest.raises(MappingStoreError, match=f"revoked.*{successor}"):
        parse_store(document, corpus=corpus)


@pytest.mark.security
def test_deprecated_technique_rejects(document: dict[str, Any], corpus: Corpus) -> None:
    document["rules"][0]["techniques"][0]["technique_id"] = "T1064"
    with pytest.raises(MappingStoreError, match="deprecated"):
        parse_store(document, corpus=corpus)


@pytest.mark.security
def test_committed_store_is_valid(corpus: Corpus) -> None:
    document = json.loads(_RULES.read_text(encoding="utf-8"))
    store = parse_store(document, corpus=corpus)
    assert store.rules and store.fallback.technique_id == "UNKNOWN"


_MULTI_FILE_MUTATIONS: list[tuple[str, dict[str, Any]]] = [
    ("second file with schema 2", {"schema": 2, "rules": []}),
    ("second file with a typo'd rules key", {"schema": 1, "rule": []}),
    ("second file with an unknown top-level key", {"schema": 1, "rules": [], "extra": 1}),
    ("second file whose rules is not a list", {"schema": 1, "rules": {}}),
    ("second file with no schema", {"rules": []}),
]


@pytest.mark.security
@pytest.mark.parametrize(
    ("label", "extra"), _MULTI_FILE_MUTATIONS, ids=[m[0] for m in _MULTI_FILE_MUTATIONS]
)
def test_multi_file_store_validates_every_file(
    label: str, extra: dict[str, Any], tmp_path: Path, corpus: Corpus
) -> None:
    """The merge path held each file to less than the single-file path.

    Measured: a second file carrying ``schema: 2``, a typo'd ``rule`` key and
    an unknown key loaded silently and contributed nothing.
    """
    (tmp_path / "a_core.json").write_bytes(_RULES.read_bytes())
    (tmp_path / "b_extra.json").write_text(json.dumps(extra), encoding="utf-8")
    with pytest.raises(MappingStoreError):
        load_store(tmp_path, corpus=corpus)


@pytest.mark.security
def test_multi_file_store_merges_well_formed_files(tmp_path: Path, corpus: Corpus) -> None:
    document = json.loads(_RULES.read_text(encoding="utf-8"))
    fallback = document.pop("fallback")
    (tmp_path / "a_rules.json").write_text(json.dumps(document), encoding="utf-8")
    (tmp_path / "b_fallback.json").write_text(
        json.dumps({"schema": 1, "rules": [], "fallback": fallback}), encoding="utf-8"
    )
    store = load_store(tmp_path, corpus=corpus)
    assert len(store.rules) == len(document["rules"])
    assert store.fallback.technique_id == "UNKNOWN"
