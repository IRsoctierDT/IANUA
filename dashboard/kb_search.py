"""Search over the cybersecurity knowledge base, resilient by design.

Used by the dashboard's Knowledge Base Search tab. The preferred backend is
semantic search against a local Qdrant instance (with the sentence-transformers
embedder); when Qdrant or the embedding stack is unavailable — a fresh
Codespace, a laptop without the services running, a minimal install — the
search **fails soft** to the local, dependency-free lexical retrieval agent
over the in-repo ``knowledge-base/`` corpus, so every dashboard feature stays
testable in any environment.

Security considerations: both backends are local-only (localhost Qdrant or
in-repo files); no query or result ever leaves the machine. Heavy third-party
imports are deferred into the functions that need them so importing this
module cannot fail on a minimal install.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # heavy optional deps: imported lazily at call time below
    from qdrant_client import QdrantClient
    from sentence_transformers import SentenceTransformer

COLLECTION = "cybersecurity_kb_chunks"

_model: SentenceTransformer | None = None
_client: QdrantClient | None = None


@dataclass(frozen=True)
class KBResult:
    """Backend-neutral search hit (same duck type as a Qdrant point)."""

    score: float
    payload: dict[str, Any] = field(default_factory=dict)


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer

        _model = SentenceTransformer("all-MiniLM-L6-v2")
    return _model


def _get_client() -> QdrantClient:
    global _client
    if _client is None:
        from rag.qdrant import make_client

        _client = make_client()
    return _client


def search_kb(query: str, category: str | None = None, limit: int = 5) -> list[Any]:
    """Return up to ``limit`` Qdrant points most similar to ``query``.

    Optionally filtered to a single ``category`` (anything but "all"). Raises
    when Qdrant or the embedding stack is unavailable — callers that must not
    break use :func:`search_kb_resilient`.
    """
    from qdrant_client.models import FieldCondition, Filter, MatchValue

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


def _search_local(query: str, category: str | None, limit: int) -> list[KBResult]:
    """Lexical retrieval over the in-repo corpus (no services, no network)."""
    from agents.knowledge_base_agent import KnowledgeBaseAgent

    references = KnowledgeBaseAgent().retrieve(query, k=limit)
    results = [
        KBResult(
            score=ref.score,
            payload={
                "source": ref.source,
                "category": _category_of(ref.source),
                "chunk_index": None,
                "text": ref.snippet,
            },
        )
        for ref in references
    ]
    if category and category != "all":
        results = [r for r in results if r.payload["category"] == category]
    return results


def _category_of(source: str) -> str:
    """Derive the category from a knowledge-base source path (its directory)."""
    parts = source.replace("\\", "/").split("/")
    return parts[-2] if len(parts) >= 2 else "knowledge-base"


def search_kb_resilient(
    query: str, category: str | None = None, limit: int = 5
) -> tuple[list[KBResult], str]:
    """Search with automatic fallback; never raises for an unavailable backend.

    Returns ``(results, backend)`` where ``backend`` names what actually served
    the query — ``"qdrant semantic"`` or ``"local lexical (Qdrant
    unavailable)"`` — so the UI can label results honestly instead of passing
    degraded output off as the primary path.
    """
    try:
        points = search_kb(query, category=category, limit=limit)
        return (
            [KBResult(score=p.score, payload=dict(p.payload or {})) for p in points],
            "qdrant semantic",
        )
    except Exception:
        # Connection refused, missing optional deps, absent collection, missing
        # embedding model — all degrade to the offline lexical corpus.
        return _search_local(query, category, limit), "local lexical (Qdrant unavailable)"
