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
from agents.mapping import MappingStoreError, parse_store
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
