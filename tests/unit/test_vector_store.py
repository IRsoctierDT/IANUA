"""Tests for the persistent SQLite vector store (rag/vector_store.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
from agents.tools.validation import ValidationError
from rag.ingest import Chunk
from rag.retrieve import InMemoryVectorStore, VectorStore
from rag.vector_store import SqliteVectorStore


def _chunk(name: str, idx: int = 0, char_start: int = 0) -> Chunk:
    return Chunk(source=name, index=idx, text=f"text-{name}", char_start=char_start)


def test_add_and_query_ranks_by_cosine(tmp_path: Path) -> None:
    with SqliteVectorStore(tmp_path / "v.db") as store:
        store.add(_chunk("a"), [1.0, 0.0])
        store.add(_chunk("b"), [0.0, 1.0])
        hits = store.query([0.9, 0.1], k=2)
    assert [c.source for c, _ in hits] == ["a", "b"]  # 'a' is more aligned
    assert hits[0][1] > hits[1][1]


def test_persists_across_reopen(tmp_path: Path) -> None:
    db = tmp_path / "v.db"
    with SqliteVectorStore(db) as store:
        store.add(_chunk("doc", idx=3, char_start=42), [1.0, 2.0, 3.0])
    # Reopen a fresh instance on the same file: data survives.
    with SqliteVectorStore(db) as reopened:
        assert len(reopened) == 1
        ((chunk, score),) = reopened.query([1.0, 2.0, 3.0], k=1)
        assert chunk.source == "doc"
        assert chunk.index == 3 and chunk.char_start == 42  # provenance round-trips
        assert score == pytest.approx(1.0)  # identical vector -> cosine 1


def test_add_many_batch(tmp_path: Path) -> None:
    with SqliteVectorStore(tmp_path / "v.db") as store:
        n = store.add_many([(_chunk("a"), [1.0, 0.0]), (_chunk("b"), [0.0, 1.0])])
        assert n == 2
        assert len(store) == 2


def test_dimension_is_enforced(tmp_path: Path) -> None:
    with SqliteVectorStore(tmp_path / "v.db") as store:
        store.add(_chunk("a"), [1.0, 0.0])
        with pytest.raises(ValidationError, match="dimension mismatch"):
            store.add(_chunk("b"), [1.0, 0.0, 0.0])
        with pytest.raises(ValidationError, match="dimension mismatch"):
            store.query([1.0, 0.0, 0.0], k=1)


def test_query_validates_k_and_empty_vector(tmp_path: Path) -> None:
    with SqliteVectorStore(tmp_path / "v.db") as store:
        store.add(_chunk("a"), [1.0, 0.0])
        with pytest.raises(ValidationError, match="k must be positive"):
            store.query([1.0, 0.0], k=0)
        with pytest.raises(ValidationError, match="non-empty"):
            store.add(_chunk("b"), [])


def test_empty_store_returns_no_hits(tmp_path: Path) -> None:
    with SqliteVectorStore(tmp_path / "v.db") as store:
        assert store.query([1.0, 0.0], k=5) == []
        assert len(store) == 0


def test_matches_in_memory_store_ranking(tmp_path: Path) -> None:
    data = [(_chunk("a"), [1.0, 0.0]), (_chunk("b"), [0.6, 0.8]), (_chunk("c"), [0.0, 1.0])]
    mem = InMemoryVectorStore()
    with SqliteVectorStore(tmp_path / "v.db") as disk:
        for chunk, vec in data:
            mem.add(chunk, vec)
            disk.add(chunk, vec)
        probe = [0.8, 0.2]
        mem_order = [c.source for c, _ in mem.query(probe, k=3)]
        disk_order = [c.source for c, _ in disk.query(probe, k=3)]
    assert mem_order == disk_order  # parity with the reference implementation


def test_satisfies_vector_store_protocol(tmp_path: Path) -> None:
    # Structural typing: a SqliteVectorStore is usable wherever a VectorStore is.
    store: VectorStore = SqliteVectorStore(tmp_path / "v.db")
    store.add(_chunk("a"), [1.0, 0.0])
    assert store.query([1.0, 0.0], k=1)[0][0].source == "a"
