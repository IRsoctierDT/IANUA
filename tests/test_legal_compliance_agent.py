import pytest
from agents.legal_compliance_agent import DISCLAIMER, LegalComplianceAgent


@pytest.fixture
def agent() -> LegalComplianceAgent:
    return LegalComplianceAgent()


@pytest.mark.unit
def test_assess_returns_expected_shape(agent: LegalComplianceAgent) -> None:
    result = agent.assess_inquiry("We need to review an NDA before signing.")
    expected = {
        "agent",
        "inquiry_summary",
        "topic_area",
        "jurisdiction",
        "authority_checklist",
        "risk_flags",
        "recommended_actions",
        "escalation_required",
        "disclaimer",
        "assumptions",
    }
    assert set(result) == expected


@pytest.mark.unit
def test_topic_classification(agent: LegalComplianceAgent) -> None:
    assert agent.assess_inquiry("question about GDPR personal data")["topic_area"] == (
        "data protection / privacy"
    )
    assert agent.assess_inquiry("dispute over a contract clause")["topic_area"] == "contracts"
    assert agent.assess_inquiry("trademark infringement concern")["topic_area"] == (
        "intellectual property"
    )
    assert agent.assess_inquiry("what color should our logo be")["topic_area"] == (
        "general / unclassified"
    )


@pytest.mark.unit
def test_escalation_triggered_by_adversarial_terms(agent: LegalComplianceAgent) -> None:
    result = agent.assess_inquiry("We were served a lawsuit and a subpoena.")
    assert result["escalation_required"] is True
    assert "lawsuit" in result["risk_flags"]
    assert "subpoena" in result["risk_flags"]
    # Escalation advice is surfaced first.
    assert "Escalate" in result["recommended_actions"][0]


@pytest.mark.unit
def test_no_escalation_for_benign_inquiry(agent: LegalComplianceAgent) -> None:
    result = agent.assess_inquiry("Please help structure a routine vendor agreement review.")
    assert result["escalation_required"] is False
    assert result["risk_flags"] == []


@pytest.mark.unit
def test_disclaimer_always_present(agent: LegalComplianceAgent) -> None:
    result = agent.assess_inquiry("trademark question")
    assert result["disclaimer"] == DISCLAIMER
    assert "does not constitute legal advice" in result["disclaimer"]


@pytest.mark.unit
def test_jurisdiction_passthrough_and_default(agent: LegalComplianceAgent) -> None:
    with_jur = agent.assess_inquiry("contract review", jurisdiction="California")
    assert with_jur["jurisdiction"] == "California"
    without = agent.assess_inquiry("contract review")
    assert without["jurisdiction"].startswith("unspecified")


@pytest.mark.unit
def test_authority_checklist_is_research_pointers_not_assertions(
    agent: LegalComplianceAgent,
) -> None:
    """Every checklist item must be a 'verify' research pointer, never a legal assertion."""
    for query in ("GDPR data breach", "employee termination", "patent license", "anything"):
        checklist = agent.assess_inquiry(query)["authority_checklist"]
        assert checklist, "checklist must never be empty"
        assert all(item.lower().startswith("verify") for item in checklist)


@pytest.mark.unit
@pytest.mark.parametrize("bad", ["", "   "])
def test_empty_input_raises(agent: LegalComplianceAgent, bad: str) -> None:
    with pytest.raises(ValueError):
        agent.assess_inquiry(bad)


@pytest.mark.unit
def test_non_string_input_raises(agent: LegalComplianceAgent) -> None:
    with pytest.raises(ValueError):
        agent.assess_inquiry(123)  # type: ignore[arg-type]
