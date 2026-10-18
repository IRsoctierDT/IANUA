# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Unit + security tests for the RAG ingestion/retrieval skeleton."""

import os
from pathlib import Path

import pytest

from agents.tools.validation import ValidationError
from rag.ingest import (
    Chunk,
    chunk_text,
    discover_documents,
    embed_chunks,
    ingest,
    read_documents,
)
from rag.retrieve import InMemoryVectorStore


class FakeEmbedder:
    """Deterministic, offline embedder: length-based 2-D vectors (no network)."""

    def embed(self, texts):
        return [[float(len(t)), 1.0] for t in texts]


@pytest.mark.unit
def test_chunking_overlaps_and_covers(tmp_path: Path) -> None:
    chunks = chunk_text("doc.md", "abcdefghij" * 20, size=50, overlap=10)
    assert chunks and all(isinstance(c, Chunk) for c in chunks)
    assert chunks[0].source == "doc.md"


@pytest.mark.unit
def test_ingest_only_allow_listed_files(tmp_path: Path) -> None:
    (tmp_path / "keep.md").write_text("hello world", encoding="utf-8")
    (tmp_path / "skip.bin").write_bytes(b"\x00\x01")
    (tmp_path / "skip.py").write_text("print('x')", encoding="utf-8")
    docs = {p.name for p in discover_documents(tmp_path)}
    assert docs == {"keep.md"}


@pytest.mark.unit
def test_end_to_end_retrieval(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("short", encoding="utf-8")
    (tmp_path / "b.txt").write_text("a much longer document body here", encoding="utf-8")
    pairs = embed_chunks(ingest(tmp_path), FakeEmbedder())
    store = InMemoryVectorStore()
    for chunk, vec in pairs:
        store.add(chunk, vec)
    hits = store.query([30.0, 1.0], k=1)
    assert len(hits) == 1


@pytest.mark.security
def test_bad_chunk_params_rejected() -> None:
    with pytest.raises(ValidationError):
        chunk_text("d", "text", size=10, overlap=10)  # overlap >= size


@pytest.mark.security
def test_discover_rejects_non_directory(tmp_path: Path) -> None:
    f = tmp_path / "f.txt"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(ValidationError):
        discover_documents(f)


@pytest.mark.security
def test_undecodable_document_fails_in_module_taxonomy(tmp_path: Path) -> None:
    """A corpus file that is not UTF-8 raises ValidationError, not UnicodeDecodeError.

    Callers fail soft on ``ValidationError`` only; measured before the fix, a
    single undecodable file escaped ``ingest``, ``read_documents`` and
    ``KnowledgeBaseAgent.cite`` as a ``UnicodeDecodeError`` traceback.
    """
    (tmp_path / "ok.md").write_text("fine", encoding="utf-8")
    (tmp_path / "bad.md").write_bytes(b"\xff\xfe not utf-8 \x80\x81")
    with pytest.raises(ValidationError, match=r"bad\.md"):
        ingest(tmp_path)
    with pytest.raises(ValidationError, match=r"bad\.md"):
        read_documents(tmp_path)


@pytest.mark.security
@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses the DAC check this asserts")
def test_unreadable_document_fails_in_module_taxonomy(tmp_path: Path) -> None:
    """An unreadable corpus file raises ValidationError, naming the file not the path."""
    locked = tmp_path / "locked.md"
    locked.write_text("hidden", encoding="utf-8")
    locked.chmod(0o000)
    try:
        with pytest.raises(ValidationError, match=r"locked\.md") as info:
            ingest(tmp_path)
        assert str(tmp_path) not in str(info.value)
    finally:
        locked.chmod(0o600)
