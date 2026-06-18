from collections.abc import Sequence
from pathlib import Path

import pytest
from agents.knowledge_base_agent import KnowledgeBaseAgent, KnowledgeReference
from agents.tools.validation import ValidationError


def _make_kb(root: Path) -> Path:
    """Build a small, controlled corpus so assertions don't couple to real KB wording."""
    root.mkdir()
    (root / "mitre.md").write_text(
        "# MITRE ATT&CK\nadversary tactics techniques brute force credential access",
        encoding="utf-8",
    )
    (root / "owasp.md").write_text(
        "# OWASP Top 10\ninjection cross site scripting broken access control web application",
        encoding="utf-8",
    )
    return root


@pytest.mark.unit
def test_retrieve_surfaces_most_relevant_document(tmp_path: Path) -> None:
    kb = KnowledgeBaseAgent(_make_kb(tmp_path / "kb"))
    refs = kb.retrieve("brute force credential access", k=3)
    assert refs, "expected at least one reference"
    assert refs[0].source == "mitre.md"
    assert isinstance(refs[0], KnowledgeReference)
    assert refs[0].score > 0


@pytest.mark.unit
def test_retrieve_snippet_is_document_opening(tmp_path: Path) -> None:
    kb = KnowledgeBaseAgent(_make_kb(tmp_path / "kb"))
    refs = kb.retrieve("injection web application", k=1)
    assert len(refs) == 1
    top = refs[0]
    assert top.source == "owasp.md"
    assert top.snippet.startswith("# OWASP Top 10")  # opening, not a mid-chunk fragment


@pytest.mark.unit
def test_retrieve_one_reference_per_source(tmp_path: Path) -> None:
    kb = KnowledgeBaseAgent(_make_kb(tmp_path / "kb"))
    refs = kb.retrieve("access control web application tactics", k=10)
    sources = [r.source for r in refs]
    assert len(sources) == len(set(sources))  # no duplicate documents


@pytest.mark.unit
def test_retrieve_respects_k(tmp_path: Path) -> None:
    kb = KnowledgeBaseAgent(_make_kb(tmp_path / "kb"))
    refs = kb.retrieve("access control tactics techniques web", k=1)
    assert len(refs) <= 1


@pytest.mark.unit
def test_retrieve_is_deterministic(tmp_path: Path) -> None:
    kb = KnowledgeBaseAgent(_make_kb(tmp_path / "kb"))
    first = kb.retrieve("access control tactics", k=3)
    second = kb.retrieve("access control tactics", k=3)
    assert [(r.source, r.score) for r in first] == [(r.source, r.score) for r in second]


@pytest.mark.unit
def test_empty_or_stopword_query_returns_no_refs(tmp_path: Path) -> None:
    kb = KnowledgeBaseAgent(_make_kb(tmp_path / "kb"))
    assert kb.retrieve("", k=3) == []
    assert kb.retrieve("the and for with", k=3) == []  # all stopwords/short


@pytest.mark.unit
def test_non_positive_k_raises(tmp_path: Path) -> None:
    kb = KnowledgeBaseAgent(_make_kb(tmp_path / "kb"))
    with pytest.raises(ValidationError):
        kb.retrieve("anything", k=0)


@pytest.mark.unit
def test_missing_corpus_fails_soft(tmp_path: Path) -> None:
    kb = KnowledgeBaseAgent(tmp_path / "does-not-exist")
    assert kb.retrieve("brute force", k=3) == []


@pytest.mark.unit
def test_reference_for_event_builds_query_and_returns_dicts(tmp_path: Path) -> None:
    kb = KnowledgeBaseAgent(_make_kb(tmp_path / "kb"))
    soc = {"event_type": "authentication failure", "summary": "credential access attempt"}
    mitre = {"tactic": "Credential Access", "technique": "Brute Force"}
    refs = kb.reference_for_event(soc, mitre, k=2)
    assert isinstance(refs, list)
    assert refs and refs[0]["source"] == "mitre.md"
    assert set(refs[0]) == {"source", "score", "snippet"}  # asdict shape


# --- semantic mode -------------------------------------------------------------


class _FakeEmbedder:
    """Deterministic, network-free embedder: [#mitre, #owasp, bias] per text."""

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        vectors = []
        for text in texts:
            lowered = text.lower()
            vectors.append([float(lowered.count("mitre")), float(lowered.count("owasp")), 0.01])
        return vectors


class _DeadEmbedder:
    """Embedder that fails closed, like an unreachable Ollama."""

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        raise ValidationError("embedder unreachable")


@pytest.mark.unit
def test_default_mode_is_lexical(tmp_path: Path) -> None:
    kb = KnowledgeBaseAgent(_make_kb(tmp_path / "kb"))
    assert kb.mode == "lexical"


@pytest.mark.unit
def test_semantic_mode_ranks_by_injected_embedder(tmp_path: Path) -> None:
    kb = KnowledgeBaseAgent(_make_kb(tmp_path / "kb"), mode="semantic", embedder=_FakeEmbedder())
    refs = kb.retrieve("mitre attack overview", k=2)
    assert refs and refs[0].source == "mitre.md"
    assert all(isinstance(r, KnowledgeReference) for r in refs)


@pytest.mark.unit
def test_semantic_falls_back_to_lexical_when_embedder_fails(tmp_path: Path) -> None:
    kb = KnowledgeBaseAgent(_make_kb(tmp_path / "kb"), mode="semantic", embedder=_DeadEmbedder())
    # Lexical fallback still surfaces the right doc rather than raising.
    refs = kb.retrieve("brute force credential access", k=2)
    assert refs and refs[0].source == "mitre.md"


@pytest.mark.unit
def test_semantic_empty_query_returns_empty(tmp_path: Path) -> None:
    kb = KnowledgeBaseAgent(_make_kb(tmp_path / "kb"), mode="semantic", embedder=_FakeEmbedder())
    assert kb.retrieve("   ", k=3) == []
