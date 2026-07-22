"""Tests for the dashboard's resilient knowledge-base search.

The semantic backend (Qdrant + sentence-transformers) is optional
infrastructure; these tests pin the fail-soft contract: an unavailable backend
degrades to the offline lexical corpus with an honest backend label, and never
raises out of the search path.
"""

from __future__ import annotations

import pytest
from dashboard import kb_search
from dashboard.kb_search import KBResult, _category_of, search_kb_resilient


def test_category_derived_from_source_directory() -> None:
    assert _category_of("knowledge-base/nist/csf_2_overview.md") == "nist"
    assert _category_of("knowledge-base\\mitre\\attack.md") == "mitre"
    assert _category_of("orphan.md") == "knowledge-base"


def test_resilient_search_falls_back_when_semantic_backend_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(query: str, category: str | None = None, limit: int = 5) -> list[object]:
        raise ConnectionError("qdrant unreachable")

    monkeypatch.setattr(kb_search, "search_kb", _boom)
    results, backend = search_kb_resilient("NIST CSF functions", limit=3)

    assert backend == "local lexical (Qdrant unavailable)"
    assert results, "offline corpus should match a NIST query"
    for result in results:
        assert isinstance(result, KBResult)
        assert set(result.payload) == {"source", "category", "chunk_index", "text"}
        assert result.payload["chunk_index"] is None
        assert result.score > 0


def test_resilient_search_prefers_semantic_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    expected_payload = {"source": "doc.md", "category": "nist", "chunk_index": 2, "text": "chunk"}

    class _Point:
        score = 0.9
        payload = expected_payload

    monkeypatch.setattr(
        kb_search,
        "search_kb",
        lambda query, category=None, limit=5: [_Point()],
    )
    results, backend = search_kb_resilient("anything")
    assert backend == "qdrant semantic"
    assert results == [KBResult(score=0.9, payload=expected_payload)]


def test_fallback_category_filter_restricts_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        kb_search,
        "search_kb",
        lambda query, category=None, limit=5: (_ for _ in ()).throw(RuntimeError("down")),
    )
    results, backend = search_kb_resilient("incident response evidence", category="nist", limit=5)
    assert backend == "local lexical (Qdrant unavailable)"
    for result in results:
        assert result.payload["category"] == "nist"


def test_fallback_never_raises_even_on_blank_query(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        kb_search,
        "search_kb",
        lambda query, category=None, limit=5: (_ for _ in ()).throw(RuntimeError("down")),
    )
    results, backend = search_kb_resilient("   ")
    assert results == []
    assert backend == "local lexical (Qdrant unavailable)"
