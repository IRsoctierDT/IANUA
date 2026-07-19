"""Passage-level, verifiable source citations for RAG retrieval.

The knowledge-base agent grounds analysis in a curated corpus. This engine turns
retrieval hits into **citations that quote the actual matching passage** (not a
document opening), carry an exact character-offset **locator** back into the
source, and can be **verified**: a quote that does not appear verbatim at its
recorded offset in its named source is rejected.

Why this matters (AGENTS.md §5, DESIGN.md §5): retrieval and any LLM narrative
built on it are only trustworthy if every cited claim points at real text a
reader (or an automated check) can confirm. :func:`verify_citation` is that check
— an anti-hallucination guard usable on citations a model *claims* to have used.

Deterministic and dependency-free (rarity-weighted term-overlap scoring), so it
is reproducible and CI-safe; it performs no network access.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from rag.ingest import Chunk

_TOKEN_RE = re.compile(r"[a-z0-9]{3,}")
#: Split on sentence-ending punctuation followed by whitespace.
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")


def _tokens(text: str) -> set[str]:
    return set(_TOKEN_RE.findall(text.lower()))


@dataclass(frozen=True)
class Citation:
    """A verifiable, passage-level citation.

    ``quote`` is verbatim source text; ``source[char_start:char_end] == quote``.
    """

    source: str
    score: float
    quote: str
    char_start: int
    char_end: int


def best_passage(query: str, text: str, *, max_chars: int = 240) -> str:
    """Return the sentence in ``text`` best matching ``query``, rarity-weighted.

    Query terms are weighted by their inverse sentence frequency within
    ``text`` (``log1p(N / (1 + df))``), so a sentence containing a term that is
    rare in the document outranks one containing only terms that appear
    throughout it — instead of tying and falling back to document order. With
    uniform frequencies this reduces exactly to plain term-overlap.

    The result is a verbatim substring of ``text`` (stripped, and trimmed to
    ``max_chars`` at a word boundary), so callers can locate it with
    ``text.find(...)``. Falls back to the leading sentence when nothing overlaps.
    """
    query_terms = _tokens(query)
    sentences = [s for s in _SENTENCE_SPLIT.split(text) if s.strip()]
    if not sentences:
        return ""

    sentence_terms = [_tokens(s) for s in sentences]
    n = len(sentences)
    weights = {
        term: math.log1p(n / (1 + sum(1 for terms in sentence_terms if term in terms)))
        for term in query_terms
    }
    total = sum(weights.values())

    def overlap(index: int) -> float:
        terms = sentence_terms[index]
        if not total or not terms:
            return 0.0
        return sum(weights[t] for t in query_terms & terms) / total

    best = sentences[max(range(n), key=overlap)]
    quote = best.strip()
    if len(quote) > max_chars:
        trimmed = quote[:max_chars].rsplit(" ", 1)[0].rstrip()
        quote = trimmed or quote[:max_chars]
    return quote


def build_citations(
    query: str,
    hits: Sequence[tuple[Chunk, float]],
    *,
    per_source: int = 1,
    max_quote_chars: int = 240,
    k: int = 3,
) -> list[Citation]:
    """Build passage-level citations from scored chunks (positive scores only).

    Chunks are taken best-first; at most ``per_source`` citations per source and
    ``k`` overall. Each citation's offset is derived from the quote's position in
    the chunk (``chunk.char_start + chunk.text.find(quote)``), so it points at the
    exact source location and round-trips through :func:`verify_citation`.
    """
    per_source_seen: dict[str, int] = {}
    citations: list[Citation] = []
    for chunk, score in sorted(hits, key=lambda h: -h[1]):
        if score <= 0.0:
            continue
        if per_source_seen.get(chunk.source, 0) >= per_source:
            continue
        quote = best_passage(query, chunk.text, max_chars=max_quote_chars)
        offset = chunk.text.find(quote)
        if not quote or offset < 0:
            continue
        start = chunk.char_start + offset
        citations.append(
            Citation(
                source=chunk.source,
                score=round(score, 4),
                quote=quote,
                char_start=start,
                char_end=start + len(quote),
            )
        )
        per_source_seen[chunk.source] = per_source_seen.get(chunk.source, 0) + 1
        if len(citations) >= k:
            break
    return citations


def verify_quote(quote: str, source_text: str) -> bool:
    """True iff ``quote`` is a non-empty verbatim substring of ``source_text``."""
    return bool(quote) and quote in source_text


def verify_citation(citation: Citation, sources: Mapping[str, str]) -> bool:
    """True iff the citation's quote sits verbatim at its offset in its source.

    ``sources`` maps ``source`` name → full document text (see
    :func:`rag.ingest.read_documents`). A citation whose source is unknown, whose
    quote is absent, or whose offset does not line up is rejected — the
    anti-hallucination guarantee.
    """
    text = sources.get(citation.source)
    if text is None or not verify_quote(citation.quote, text):
        return False
    return text[citation.char_start : citation.char_end] == citation.quote


def render_references(citations: Sequence[Citation]) -> str:
    """Render citations as a numbered Markdown references block."""
    if not citations:
        return "_No sources cited._"
    return "\n".join(
        f"{i}. **{c.source}** (chars {c.char_start}-{c.char_end}, "
        f'relevance {c.score:.2f}): "{c.quote}"'
        for i, c in enumerate(citations, 1)
    )
