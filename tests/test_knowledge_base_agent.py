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
