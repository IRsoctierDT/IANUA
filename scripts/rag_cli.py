"""rag_cli — one-command RAG pipeline: ingest -> embed -> query.

Ties the rag/ modules together behind a small argparse CLI. Secure-by-default:
embeddings go through OllamaEmbedder (loopback-only egress, fail closed). With
--offline, a deterministic local embedder is used so the pipeline runs with no
network at all (useful for tests, demos, and air-gapped labs).

Examples
--------
    # Query a local corpus using a local Ollama model
    python -m scripts.rag_cli --corpus ./corpus --query "zero trust segmentation" --k 3

    # Fully offline (no Ollama needed)
    python -m scripts.rag_cli --corpus ./corpus --query "ids tuning" --offline
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from agents.tools.validation import ValidationError
from rag.embeddings import OllamaEmbedder
from rag.ingest import Embedder, embed_chunks, ingest
from rag.retrieve import InMemoryVectorStore


class _OfflineEmbedder:
    """Deterministic, dependency-free embedder for --offline runs.

    Maps text to a fixed-width bag-of-characters vector. Not semantically rich,
    but stable and network-free -- enough to exercise the full pipeline.
    """

    DIMS = 32

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in texts:
            vec = [0.0] * self.DIMS
            for ch in text.lower():
                vec[ord(ch) % self.DIMS] += 1.0
            vectors.append(vec)
        return vectors


def build_index(corpus: Path, *, offline: bool, model: str) -> tuple[InMemoryVectorStore, Embedder]:
    """Ingest + embed a corpus into an in-memory vector store."""
    embedder: Embedder = _OfflineEmbedder() if offline else OllamaEmbedder(model=model)
    store = InMemoryVectorStore()
    pairs = embed_chunks(ingest(corpus), embedder)
    for chunk, vector in pairs:
        store.add(chunk, vector)
    return store, embedder


def run_query(store: InMemoryVectorStore, embedder: Embedder, query: str, k: int) -> list[str]:
    """Embed the query and return the top-k chunk previews."""
    (query_vec,) = embedder.embed([query])
    hits = store.query(query_vec, k=k)
    return [f"[{score:.3f}] {chunk.source}#{chunk.index}: {chunk.text[:120]}" for chunk, score in hits]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rag_cli", description="Ingest -> embed -> query a local corpus.")
    parser.add_argument("--corpus", required=True, type=Path, help="Path to the trusted corpus directory.")
    parser.add_argument("--query", required=True, help="Natural-language query string.")
    parser.add_argument("--k", type=int, default=5, help="Number of results to return (default 5).")
    parser.add_argument("--model", default="nomic-embed-text", help="Ollama embedding model.")
    parser.add_argument("--offline", action="store_true", help="Use the offline embedder (no Ollama/network).")
    args = parser.parse_args(argv)

    try:
        store, embedder = build_index(args.corpus, offline=args.offline, model=args.model)
        results = run_query(store, embedder, args.query, args.k)
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not results:
        print("no results (empty corpus?)")
        return 1
    for line in results:
        print(line)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
