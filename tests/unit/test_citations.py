"""Tests for the passage-level, verifiable citation engine (rag/citations.py)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from agents.knowledge_base_agent import KnowledgeBaseAgent
from rag.citations import (
    Citation,
    best_passage,
    build_citations,
    render_references,
    verify_citation,
    verify_quote,
)
from rag.ingest import Chunk, read_documents

_DOC = (
    "Intro line about nothing in particular.\n\n"
    "Brute force attacks try many passwords against an account until one works. "
    "Defenders should rate-limit authentication and alert on repeated failures.\n\n"
    "Phishing is a separate social-engineering technique.\n"
)


# ---------------------------------------------------------------- best_passage
def test_best_passage_picks_the_matching_sentence() -> None:
    quote = best_passage("brute force passwords account", _DOC)
    assert "Brute force attacks try many passwords" in quote
    assert quote in _DOC  # verbatim substring


def test_best_passage_trims_to_word_boundary() -> None:
    quote = best_passage("brute force", _DOC, max_chars=20)
    assert len(quote) <= 20
    assert " " not in quote[-1:]  # no trailing partial word/space
    assert quote in _DOC


# ---------------------------------------------------------------- build + verify
def _hit(text: str, score: float, *, source: str = "kb.md", char_start: int = 0) -> tuple:
    return (Chunk(source=source, index=0, text=text, char_start=char_start), score)


def test_citation_offsets_are_exact_and_verify() -> None:
    # Chunk text sits at a known offset inside the source document.
    offset = _DOC.index("Brute force")
    chunk_text = _DOC[offset : offset + 200]
    cites = build_citations("brute force passwords", [_hit(chunk_text, 0.9, char_start=offset)])
    assert len(cites) == 1
    c = cites[0]
    assert _DOC[c.char_start : c.char_end] == c.quote  # exact locator
    assert verify_citation(c, {"kb.md": _DOC}) is True


def test_verify_rejects_a_fabricated_quote() -> None:
    c = Citation(
        source="kb.md", score=0.9, quote="planted text not in source", char_start=0, char_end=26
    )
    assert verify_citation(c, {"kb.md": _DOC}) is False
    assert verify_quote(c.quote, _DOC) is False


def test_verify_rejects_a_wrong_offset() -> None:
    c = build_citations("brute force", [_hit(_DOC, 0.9)])[0]
    moved = replace(c, char_start=c.char_start + 5, char_end=c.char_end + 5)
    assert verify_citation(moved, {"kb.md": _DOC}) is False  # quote present but not at offset


def test_verify_rejects_unknown_source() -> None:
    c = build_citations("brute force", [_hit(_DOC, 0.9)])[0]
    assert verify_citation(c, {}) is False


# ---------------------------------------------------------------- limits / shape
def test_positive_scores_only_and_k_limit() -> None:
    hits = [
        _hit("Brute force passwords account.", 0.9, source="a.md"),
        _hit("Rate limit authentication failures.", 0.5, source="b.md"),
        _hit("Irrelevant.", 0.0, source="c.md"),  # dropped (score 0)
    ]
    cites = build_citations("brute force authentication", hits, k=5)
    assert [c.source for c in cites] == ["a.md", "b.md"]  # c.md dropped, ranked by score


def test_per_source_cap() -> None:
    hits = [
        _hit("Brute force one.", 0.9, source="a.md"),
        _hit("Brute force two.", 0.8, source="a.md"),
    ]
    assert len(build_citations("brute force", hits, per_source=1)) == 1


def test_render_references_and_empty() -> None:
    assert render_references([]) == "_No sources cited._"
    cites = build_citations("brute force", [_hit(_DOC, 0.9)])
    rendered = render_references(cites)
    assert rendered.startswith("1. **kb.md**")
    assert "relevance 0.90" in rendered


# ---------------------------------------------------------------- end-to-end
def _corpus(tmp_path: Path) -> Path:
    root = tmp_path / "kb"
    root.mkdir()
    (root / "kb.md").write_text(_DOC, encoding="utf-8")
    return root


def test_agent_cite_returns_verifiable_passage_citations(tmp_path: Path) -> None:
    root = _corpus(tmp_path)
    agent = KnowledgeBaseAgent(root)
    cites = agent.cite("brute force passwords account", k=2)
    assert cites
    assert "Brute force" in cites[0].quote
    # Every citation round-trips against the real corpus.
    assert agent.verify_citations(cites) is True
    sources = read_documents(root)
    for c in cites:
        assert sources[c.source][c.char_start : c.char_end] == c.quote


def test_agent_verify_citations_detects_tampering(tmp_path: Path) -> None:
    agent = KnowledgeBaseAgent(_corpus(tmp_path))
    cites = agent.cite("brute force", k=1)
    tampered = [replace(cites[0], quote="fabricated claim")]
    assert agent.verify_citations(tampered) is False


def test_agent_cite_fails_soft_on_missing_corpus(tmp_path: Path) -> None:
    agent = KnowledgeBaseAgent(tmp_path / "does-not-exist")
    assert agent.cite("brute force") == []


@pytest.mark.parametrize("bad_k", [0, -1])
def test_agent_cite_rejects_nonpositive_k(tmp_path: Path, bad_k: int) -> None:
    with pytest.raises(ValueError):
        KnowledgeBaseAgent(_corpus(tmp_path)).cite("q", k=bad_k)
