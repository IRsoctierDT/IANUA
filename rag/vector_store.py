"""Persistent, dependency-free vector store (SQLite) for the RAG pipeline.

:class:`~rag.retrieve.InMemoryVectorStore` is a fine reference, but it holds
everything in RAM and is lost on restart. :class:`SqliteVectorStore` implements
the same :class:`~rag.retrieve.VectorStore` protocol on top of the standard
library's ``sqlite3``: embeddings persist to a single file, survive restarts, and
scale past what fits comfortably in memory — with **no third-party dependency**.

Design / security (AGENTS.md §3-§5, DESIGN.md §10):
- **Least surface.** Pure stdlib (``sqlite3`` + ``array``); no network, no C
  extensions beyond CPython's bundled SQLite.
- **Parameterised SQL only.** Every query binds values — no string interpolation,
  so stored text/vectors can never inject SQL.
- **Validated boundaries.** Vector dimension is fixed on first insert and
  enforced thereafter; ``query`` rejects a non-positive ``k`` or a
  wrong-dimension probe (fail closed).
- **Compact + exact.** Vectors are stored as ``float32`` blobs; ranking is the
  same cosine similarity as the in-memory store, so results match.

Retrieval is still a linear cosine scan (SQLite has no native ANN index); the win
here is *persistence and scale*, not sublinear search. An ANN index (e.g. a real
vector DB) is the next step behind the same protocol.
"""

from __future__ import annotations

import sqlite3
from array import array
from collections.abc import Iterable, Sequence
from pathlib import Path
from types import TracebackType
from typing import Self

from agents.tools.validation import ValidationError

from rag.ingest import Chunk
from rag.retrieve import _cosine

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vectors (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    source     TEXT    NOT NULL,
    idx        INTEGER NOT NULL,
    char_start INTEGER NOT NULL,
    text       TEXT    NOT NULL,
    dim        INTEGER NOT NULL,
    vector     BLOB    NOT NULL
);
"""


def _to_blob(vector: Sequence[float]) -> bytes:
    return array("f", vector).tobytes()


def _from_blob(blob: bytes) -> list[float]:
    out = array("f")
    out.frombytes(blob)
    return list(out)


class SqliteVectorStore:
    """A persistent :class:`~rag.retrieve.VectorStore` backed by SQLite.

    Open the same ``path`` again to reuse previously added vectors. Usable as a
    context manager so the connection is always closed::

        with SqliteVectorStore("data/vectors.db") as store:
            store.add(chunk, vector)
            hits = store.query(query_vector, k=5)
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    # ---------------------------------------------------------------- lifecycle
    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def __len__(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM vectors").fetchone()
        return int(row[0])

    # ---------------------------------------------------------------- dimension
    def _dim(self) -> int | None:
        row = self._conn.execute("SELECT dim FROM vectors LIMIT 1").fetchone()
        return int(row[0]) if row is not None else None

    def _check_dim(self, vector: Sequence[float]) -> None:
        if not vector:
            raise ValidationError("vector must be non-empty")
        existing = self._dim()
        if existing is not None and len(vector) != existing:
            raise ValidationError(
                f"vector dimension mismatch: got {len(vector)}, store holds {existing}"
            )

    # ---------------------------------------------------------------- writes
    def add(self, chunk: Chunk, vector: Sequence[float]) -> None:
        """Persist one ``chunk`` and its embedding (dimension enforced)."""
        self._check_dim(vector)
        self._conn.execute(
            "INSERT INTO vectors (source, idx, char_start, text, dim, vector)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                chunk.source,
                chunk.index,
                chunk.char_start,
                chunk.text,
                len(vector),
                _to_blob(vector),
            ),
        )
        self._conn.commit()

    def add_many(self, items: Iterable[tuple[Chunk, Sequence[float]]]) -> int:
        """Batch-insert ``(chunk, vector)`` pairs in one transaction; returns count."""
        rows = []
        for chunk, vector in items:
            self._check_dim(vector)
            rows.append(
                (
                    chunk.source,
                    chunk.index,
                    chunk.char_start,
                    chunk.text,
                    len(vector),
                    _to_blob(vector),
                )
            )
        self._conn.executemany(
            "INSERT INTO vectors (source, idx, char_start, text, dim, vector)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
        self._conn.commit()
        return len(rows)

    # ---------------------------------------------------------------- reads
    def query(self, vector: Sequence[float], k: int = 5) -> list[tuple[Chunk, float]]:
        """Return the top-``k`` chunks by cosine similarity to ``vector``."""
        if k <= 0:
            raise ValidationError("k must be positive")
        self._check_dim(vector)
        scored: list[tuple[Chunk, float]] = []
        for source, idx, char_start, text, blob in self._conn.execute(
            "SELECT source, idx, char_start, text, vector FROM vectors"
        ):
            chunk = Chunk(source=source, index=idx, text=text, char_start=char_start)
            scored.append((chunk, _cosine(vector, _from_blob(blob))))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:k]
