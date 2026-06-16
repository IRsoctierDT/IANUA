"""In-memory cosine retrieval over embedded chunks.

A dependency-free default so the pipeline is testable on day one. Swap for a
real vector store (DESIGN.md §10) behind the same `VectorStore` protocol.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

from agents.tools.validation import ValidationError

from rag.ingest import Chunk


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    if len(a) != len(b):
        raise ValidationError("vector dimension mismatch")
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


class VectorStore(Protocol):
    def add(self, chunk: Chunk, vector: Sequence[float]) -> None: ...
    def query(self, vector: Sequence[float], k: int) -> list[tuple[Chunk, float]]: ...


@dataclass
class InMemoryVectorStore:
    """Reference VectorStore implementation. Not for large corpora."""

    _items: list[tuple[Chunk, list[float]]] = field(default_factory=list)

    def add(self, chunk: Chunk, vector: Sequence[float]) -> None:
        self._items.append((chunk, list(vector)))

    def query(self, vector: Sequence[float], k: int = 5) -> list[tuple[Chunk, float]]:
        if k <= 0:
            raise ValidationError("k must be positive")
        scored = [(c, _cosine(vector, v)) for c, v in self._items]
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:k]
