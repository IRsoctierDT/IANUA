import pytest
from agents.business_proposal_agent import DISCLAIMER, BusinessProposalAgent


@pytest.fixture
def agent() -> BusinessProposalAgent:
    return BusinessProposalAgent()


@pytest.mark.unit
def test_draft_returns_expected_shape(agent: BusinessProposalAgent) -> None:
    result = agent.draft_proposal("Build a log triage pipeline.")
    expected = {
        "agent",
        "title",
        "client",
        "summary",
        "objectives",
        "detected_areas",
        "scope_items",
        "out_of_scope",
        "deliverables",
        "suggested_phases",
        "assumptions",
        "risks",
        "next_steps",
        "disclaimer",
    }
    assert set(result) == expected


@pytest.mark.unit
def test_detects_multiple_areas(agent: BusinessProposalAgent) -> None:
    result = agent.draft_proposal(
        "We need a SOC detection pipeline and a RAG knowledge base for compliance."
    )
    areas = result["detected_areas"]
    assert "security operations" in areas
    assert "knowledge / RAG" in areas
    assert "compliance / governance" in areas
    assert len(result["scope_items"]) >= 6


@pytest.mark.unit
def test_unmatched_needs_fall_back_to_general(agent: BusinessProposalAgent) -> None:
    result = agent.draft_proposal("Help us plan a company offsite event.")
    assert result["detected_areas"] == ["general engagement"]
    assert result["scope_items"]  # never empty


@pytest.mark.unit
def test_client_passthrough_and_default(agent: BusinessProposalAgent) -> None:
    assert agent.draft_proposal("x SOC pipeline", client="Acme")["client"] == "Acme"
    assert agent.draft_proposal("x SOC pipeline")["client"] == "unspecified"


@pytest.mark.unit
def test_disclaimer_is_non_binding(agent: BusinessProposalAgent) -> None:
    result = agent.draft_proposal("SOC pipeline")
    assert result["disclaimer"] == DISCLAIMER
    assert "not a binding offer" in result["disclaimer"]


@pytest.mark.unit
def test_no_pricing_committed(agent: BusinessProposalAgent) -> None:
    """Pricing/timeline must be flagged as human work, never asserted."""
    result = agent.draft_proposal("SOC pipeline and RAG knowledge base")
    assert any("estimat" in a.lower() for a in result["assumptions"])
    assert any("human" in s.lower() for s in result["next_steps"])
    assert "Pricing" in " ".join(result["out_of_scope"])


@pytest.mark.unit
def test_objectives_split_into_statements(agent: BusinessProposalAgent) -> None:
    result = agent.draft_proposal(
        "Ingest authentication logs. Score severity. Generate incident reports."
    )
    assert len(result["objectives"]) >= 2


@pytest.mark.unit
def test_suggested_phases_present(agent: BusinessProposalAgent) -> None:
    result = agent.draft_proposal("SOC pipeline")
    assert len(result["suggested_phases"]) == 5
    assert any(p.startswith("Discovery") for p in result["suggested_phases"])


@pytest.mark.unit
@pytest.mark.parametrize("bad", ["", "   "])
def test_empty_input_raises(agent: BusinessProposalAgent, bad: str) -> None:
    with pytest.raises(ValueError):
        agent.draft_proposal(bad)


@pytest.mark.unit
def test_non_string_input_raises(agent: BusinessProposalAgent) -> None:
    with pytest.raises(ValueError):
        agent.draft_proposal(42)  # type: ignore[arg-type]
