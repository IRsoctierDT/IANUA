"""RAG ingestion skeleton: trusted local sources -> chunks -> embeddings.

Trust boundary (DESIGN.md §5): ingested documents are UNTRUSTED content. We
confine ingestion to a trusted root, accept only allow-listed extensions, and
never follow into directories outside the corpus. Embedding/vector-store calls
are abstracted behind protocols so the default build performs NO network egress.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from agents.tools.validation import ValidationError, resolve_within

# Allow-list of text formats we will ingest. Extend deliberately.
ALLOWED_SUFFIXES: frozenset[str] = frozenset({".txt", ".md", ".rst"})
MAX_FILE_BYTES: int = 5_000_000


@dataclass(frozen=True)
class Chunk:
    """A retrievable unit of text with provenance.

    ``char_start`` is the chunk text's exact character offset in the source
    document, so a citation can point back to the passage's location (and be
    verified against the source). Defaults to ``0`` for hand-built chunks.
    """

    source: str
    index: int
    text: str
    char_start: int = 0


class Embedder(Protocol):
    """Pluggable embedding backend (e.g. a local Ollama model)."""

    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


def discover_documents(corpus_root: Path) -> list[Path]:
    """List allow-listed files under a trusted corpus root.

    Symlinks and any path escaping the root are rejected (defense in depth).
    """
    root = corpus_root.resolve()
    if not root.is_dir():
        raise ValidationError(f"corpus root is not a directory: {corpus_root!r}")
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            continue  # do not follow symlinks out of the corpus
        if path.is_file() and path.suffix.lower() in ALLOWED_SUFFIXES:
            # confirm the resolved path is still inside root
            resolve_within(root, str(path.relative_to(root)))
            if path.stat().st_size <= MAX_FILE_BYTES:
                found.append(path)
    return found


def chunk_text(source: str, text: str, *, size: int = 800, overlap: int = 100) -> list[Chunk]:
    """Split text into overlapping character windows.

    Args:
        size: target chunk length in characters.
        overlap: characters shared between adjacent chunks for context.
    """
    if size <= 0 or overlap < 0 or overlap >= size:
        raise ValidationError("require size > 0 and 0 <= overlap < size")
    chunks: list[Chunk] = []
    step = size - overlap
    for i, start in enumerate(range(0, len(text) or 1, step)):
        raw = text[start : start + size]
        lead = len(raw) - len(raw.lstrip())  # chars dropped by lstrip
        window = raw.strip()
        if window:
            # char_start is the exact offset of ``window`` in ``text``, so
            # text[char_start : char_start + len(window)] == window.
            chunks.append(Chunk(source=source, index=i, text=window, char_start=start + lead))
    return chunks


def ingest(corpus_root: Path) -> list[Chunk]:
    """Discover, read, and chunk every allow-listed document in the corpus."""
    chunks: list[Chunk] = []
    for doc in discover_documents(corpus_root):
        text = doc.read_text(encoding="utf-8", errors="strict")
        chunks.extend(chunk_text(doc.name, text))
    return chunks


def read_documents(corpus_root: Path) -> dict[str, str]:
    """Map each allow-listed document's ``source`` name to its full text.

    Same trust boundary as :func:`ingest` (confined, allow-listed, no symlinks).
    Used to *verify* that a citation's quote appears verbatim in its source. If
    two documents share a basename the last read wins — matching the ``source``
    naming used by :func:`ingest`.
    """
    return {
        doc.name: doc.read_text(encoding="utf-8", errors="strict")
        for doc in discover_documents(corpus_root)
    }


def embed_chunks(chunks: Iterable[Chunk], embedder: Embedder) -> list[tuple[Chunk, list[float]]]:
    """Attach an embedding vector to each chunk via the injected backend."""
    items = list(chunks)
    vectors = embedder.embed([c.text for c in items])
    if len(vectors) != len(items):
        raise ValidationError("embedder returned mismatched vector count")
    return list(zip(items, vectors, strict=True))
