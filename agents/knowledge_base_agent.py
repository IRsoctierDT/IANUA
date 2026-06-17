"""Knowledge Base Agent — grounds analysis in the curated cybersecurity corpus.

Given a query (or a SOC/MITRE result), this agent retrieves the most relevant
references from the local ``knowledge-base/`` corpus so incident reports can cite
authoritative framework context (MITRE ATT&CK, OWASP, NIST CSF, CIS, etc.).

Security & determinism (DESIGN.md §5):
- **No network egress.** Retrieval is a deterministic, dependency-free term-overlap
  score — no embedding service, no external calls. (The vector RAG pipeline in
  ``rag/`` remains the path for semantic search via a local model.)
- **Trusted, confined corpus.** Documents are loaded through ``rag.ingest.ingest()``,
  which enforces an extension allow-list, rejects symlinks, and confines reads to the
  corpus root (path-traversal safe).
- **Fails soft.** A missing or unreadable corpus yields no references rather than an
  error, so the agent pipeline degrades gracefully.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from rag.ingest import ingest

from agents.tools.validation import ValidationError

# Default location of the curated corpus, relative to the working directory.
DEFAULT_KB_ROOT = Path("knowledge-base")

# Tokenizer: lowercase alphanumeric words of length >= 3 (drops noise like "a", "of").
_TOKEN_RE = re.compile(r"[a-z0-9]{3,}")

# Common words that would otherwise inflate overlap scores without adding signal.
_STOPWORDS: frozenset[str] = frozenset(
    {
        "the",
        "and",
        "for",
        "with",
        "that",
        "this",
        "from",
        "are",
        "was",
        "were",
        "has",
        "have",
        "may",
        "any",
        "into",
        "use",
        "used",
        "uses",
        "per",
        "via",
        "not",
    }
)


def _tokenize(text: str) -> set[str]:
    """Return the set of meaningful lowercase tokens in ``text``."""
    return {tok for tok in _TOKEN_RE.findall(text.lower()) if tok not in _STOPWORDS}


@dataclass(frozen=True)
class KnowledgeReference:
    """A single retrieved knowledge-base reference with provenance."""

    source: str
    score: float
    snippet: str


class KnowledgeBaseAgent:
    """Retrieve relevant references from the local cybersecurity knowledge base."""

    def __init__(self, kb_root: Path | str = DEFAULT_KB_ROOT, *, snippet_chars: int = 160) -> None:
        self.kb_root = Path(kb_root)
        self.snippet_chars = snippet_chars

    def retrieve(self, query: str, k: int = 3) -> list[KnowledgeReference]:
        """Return the top-``k`` knowledge-base documents most relevant to ``query``.

        Relevance is the fraction of query terms that appear in a document's best
        chunk (deterministic, network-free). Results are aggregated to one reference
        per source document — ranked by that best score, with a clean snippet drawn
        from the document's opening so a report cites the framework, not a mid-table
        fragment. Only positive-scoring documents are returned.
        """
        if k <= 0:
            raise ValidationError("k must be positive")

        query_terms = _tokenize(query)
        if not query_terms:
            return []

        try:
            chunks = ingest(self.kb_root)
        except ValidationError:
            # Missing/unreadable corpus: fail soft with no references.
            return []

        # Aggregate per source: best chunk score + a snippet from the doc's opening.
        best_score: dict[str, float] = {}
        opening: dict[str, str] = {}
        for chunk in chunks:
            if chunk.index == 0:
                opening[chunk.source] = " ".join(chunk.text.split())[: self.snippet_chars]
            chunk_terms = _tokenize(chunk.text)
            if not chunk_terms:
                continue
            score = len(query_terms & chunk_terms) / len(query_terms)
            if score > best_score.get(chunk.source, 0.0):
                best_score[chunk.source] = score

        refs = [
            KnowledgeReference(
                source=source,
                score=score,
                snippet=opening.get(source, ""),
            )
            for source, score in best_score.items()
            if score > 0.0
        ]
        # Highest score first; ties broken by source name for determinism.
        refs.sort(key=lambda ref: (-ref.score, ref.source))
        return refs[:k]

    def reference_for_event(
        self,
        soc_result: dict[str, Any],
        mitre_result: dict[str, Any] | None = None,
        k: int = 3,
    ) -> list[dict[str, Any]]:
        """Build a query from a SOC (+ optional MITRE) result and retrieve references.

        Returns plain dicts (via ``asdict``) so the output composes cleanly with the
        rest of the agent pipeline's JSON-serializable results.
        """
        parts: list[str] = []
        for key in ("event_type", "summary"):
            value = soc_result.get(key)
            if isinstance(value, str):
                parts.append(value)
        if mitre_result is not None:
            for key in ("tactic", "technique"):
                value = mitre_result.get(key)
                if isinstance(value, str):
                    parts.append(value)

        query = " ".join(parts)
        return [asdict(ref) for ref in self.retrieve(query, k=k)]


if __name__ == "__main__":
    agent = KnowledgeBaseAgent()
    for ref in agent.retrieve("brute force authentication failure credential access", k=3):
        print(f"[{ref.score:.2f}] {ref.source}: {ref.snippet}")
