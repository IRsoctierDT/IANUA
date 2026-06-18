import pytest
from agents.portfolio_documentation_agent import PortfolioDocumentationAgent


@pytest.fixture
def agent() -> PortfolioDocumentationAgent:
    return PortfolioDocumentationAgent()


@pytest.mark.unit
def test_document_returns_expected_shape(agent: PortfolioDocumentationAgent) -> None:
    result = agent.document("My Project", "Does a useful thing.")
    expected = {
        "agent",
        "title",
        "doc_type",
        "suggested_filename",
        "summary",
        "sections",
        "markdown",
        "assumptions",
    }
    assert set(result) == expected


@pytest.mark.unit
def test_case_study_follows_agents_md_section_order(agent: PortfolioDocumentationAgent) -> None:
    result = agent.document("P", "Some work.", doc_type="case_study")
    headings = [s["heading"] for s in result["sections"]]
    assert headings == [
        "Executive Summary",
        "Objectives",
        "Architecture / Process",
        "Implementation Steps",
        "Risks",
        "Cost Considerations",
        "Future Enhancements",
    ]


@pytest.mark.unit
def test_readme_sections(agent: PortfolioDocumentationAgent) -> None:
    result = agent.document("P", "Some work.", doc_type="readme", skills=["Python", "RAG"])
    headings = [s["heading"] for s in result["sections"]]
    assert headings == ["Overview", "Features", "Usage", "Skills Demonstrated", "Status"]
    skills_body = next(
        s["body"] for s in result["sections"] if s["heading"] == "Skills Demonstrated"
    )
    assert "Python" in skills_body
    assert "RAG" in skills_body


@pytest.mark.unit
def test_unfilled_sections_are_marked_todo_not_fabricated(
    agent: PortfolioDocumentationAgent,
) -> None:
    """Sections we can't derive must be explicit TODOs, never invented content."""
    result = agent.document("P", "A short description.", doc_type="case_study")
    bodies = {s["heading"]: s["body"] for s in result["sections"]}
    assert "TODO" in bodies["Implementation Steps"]
    assert "TODO" in bodies["Risks"]
    assert "TODO" in bodies["Cost Considerations"]


@pytest.mark.unit
def test_markdown_is_well_formed(agent: PortfolioDocumentationAgent) -> None:
    md = agent.document("My Project", "Work. More work.", doc_type="case_study")["markdown"]
    assert md.startswith("# My Project")
    assert "## Executive Summary" in md
    assert "Verify all claims" in md


@pytest.mark.unit
def test_suggested_filename_slugified(agent: PortfolioDocumentationAgent) -> None:
    result = agent.document("SOC Analyst Agent v0.2", "x")
    assert result["suggested_filename"] == "soc-analyst-agent-v0-2.md"


@pytest.mark.unit
def test_objectives_split_into_bullets(agent: PortfolioDocumentationAgent) -> None:
    result = agent.document("P", "First objective here. Second objective here.")
    features = next(s["body"] for s in result["sections"] if s["heading"] == "Features")
    assert features.count("- ") >= 2


@pytest.mark.unit
@pytest.mark.parametrize("name,desc", [("", "x"), ("P", ""), ("  ", "x"), ("P", "   ")])
def test_empty_inputs_raise(agent: PortfolioDocumentationAgent, name: str, desc: str) -> None:
    with pytest.raises(ValueError):
        agent.document(name, desc)


@pytest.mark.unit
def test_invalid_doc_type_raises(agent: PortfolioDocumentationAgent) -> None:
    with pytest.raises(ValueError):
        agent.document("P", "x", doc_type="blog")  # type: ignore[arg-type]
