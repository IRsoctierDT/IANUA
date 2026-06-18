"""Semantic search over the Qdrant-backed cybersecurity knowledge base.

Used by the dashboard's Knowledge Base Search tab. Requires a running Qdrant and
the sentence-transformers model; both are loaded lazily and cached.
"""

from __future__ import annotations

from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.models import FieldCondition, Filter, MatchValue
from sentence_transformers import SentenceTransformer

COLLECTION = "cybersecurity_kb_chunks"

_model: SentenceTransformer | None = None
_client: QdrantClient | None = None


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        _model = SentenceTransformer("all-MiniLM-L6-v2")
    return _model


def _get_client() -> QdrantClient:
    global _client
    if _client is None:
        _client = QdrantClient(url="http://localhost:6333", check_compatibility=False)
    return _client


def search_kb(query: str, category: str | None = None, limit: int = 5) -> list[Any]:
    """Return up to ``limit`` Qdrant points most similar to ``query``.

    Optionally filtered to a single ``category`` (anything but "all").
    """
    vector = _get_model().encode(query).tolist()

    query_filter = None

    if category and category != "all":
        query_filter = Filter(
            must=[
                FieldCondition(
                    key="category",
                    match=MatchValue(value=category),
                )
            ]
        )

    results = _get_client().query_points(
        collection_name=COLLECTION,
        query=vector,
        query_filter=query_filter,
        limit=limit,
    )

    return list(results.points)
