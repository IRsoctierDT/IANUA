from pathlib import Path

import pytest
from agents.knowledge_curator_agent import KnowledgeCuratorAgent


@pytest.fixture
def agent() -> KnowledgeCuratorAgent:
    return KnowledgeCuratorAgent()


@pytest.mark.unit
def test_curate_returns_expected_shape(agent: KnowledgeCuratorAgent) -> None:
    result = agent.curate("Some notes about SOC alert triage.")
    expected = {
        "agent",
        "title",
        "suggested_category",
        "suggested_filename",
        "tags",
        "summary",
        "key_points",
        "markdown",
        "assumptions",
    }
    assert set(result) == expected


@pytest.mark.unit
def test_category_suggestion(agent: KnowledgeCuratorAgent) -> None:
    assert agent.curate("MITRE ATT&CK tactic and technique notes")["suggested_category"] == "mitre"
    assert agent.curate("OWASP injection and XSS in web application")["suggested_category"] == (
        "owasp"
    )
    assert agent.curate("My grocery list and weekend plans")["suggested_category"] == "general"


@pytest.mark.unit
def test_title_and_filename_derived_from_first_sentence(agent: KnowledgeCuratorAgent) -> None:
    result = agent.curate("SOC alert triage notes. More detail follows here.")
    assert result["title"] == "SOC alert triage notes"
    assert result["suggested_filename"] == "soc-alert-triage-notes.md"


@pytest.mark.unit
def test_explicit_title_and_category_override(agent: KnowledgeCuratorAgent) -> None:
    result = agent.curate("anything", title="My Title", category="nist")
    assert result["title"] == "My Title"
    assert result["suggested_category"] == "nist"
    assert result["suggested_filename"] == "my-title.md"


@pytest.mark.unit
def test_key_points_prefer_bullets(agent: KnowledgeCuratorAgent) -> None:
    text = "Intro line.\n- first point\n- second point\n* third point"
    points = agent.curate(text)["key_points"]
    assert "first point" in points
    assert "second point" in points
    assert "third point" in points


@pytest.mark.unit
def test_markdown_is_kb_ready(agent: KnowledgeCuratorAgent) -> None:
    md = agent.curate("SOC notes. Detail.\n- preserve evidence")["markdown"]
    assert md.startswith("# ")
    assert "## Summary" in md
    assert "## Key Points" in md
    assert "Verify all facts" in md  # non-fabrication note present


@pytest.mark.unit
def test_tags_exclude_stopwords(agent: KnowledgeCuratorAgent) -> None:
    tags = agent.curate("the and for with detection detection detection alert")["tags"]
    assert "the" not in tags
    assert "detection" in tags


@pytest.mark.unit
@pytest.mark.parametrize("bad", ["", "   "])
def test_empty_input_raises(agent: KnowledgeCuratorAgent, bad: str) -> None:
    with pytest.raises(ValueError):
        agent.curate(bad)


@pytest.mark.unit
def test_non_string_input_raises(agent: KnowledgeCuratorAgent) -> None:
    with pytest.raises(ValueError):
        agent.curate(99)  # type: ignore[arg-type]


@pytest.mark.unit
def test_does_not_write_to_corpus(agent: KnowledgeCuratorAgent) -> None:
    """Curation only returns a proposed entry; it must not create files."""
    before = set(Path().glob("knowledge-base/**/*"))
    agent.curate("MITRE notes about techniques")
    after = set(Path().glob("knowledge-base/**/*"))
    assert before == after  # corpus unchanged
