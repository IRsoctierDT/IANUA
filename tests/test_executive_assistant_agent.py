import pytest
from agents.executive_assistant_agent import ExecutiveAssistantAgent


@pytest.fixture
def agent() -> ExecutiveAssistantAgent:
    return ExecutiveAssistantAgent()


@pytest.mark.unit
def test_plan_returns_expected_shape(agent: ExecutiveAssistantAgent) -> None:
    result = agent.plan(["do a thing"])
    expected = {
        "agent",
        "items",
        "prioritized_order",
        "suggested_focus",
        "blockers",
        "open_questions",
        "decision_log_template",
        "assumptions",
    }
    assert set(result) == expected


@pytest.mark.unit
def test_priority_classification(agent: ExecutiveAssistantAgent) -> None:
    result = agent.plan(["Fix the urgent bug", "Refactor someday", "Write the report"])
    by_task = {it["task"]: it for it in result["items"]}
    assert by_task["Fix the urgent bug"]["priority"] == "high"
    assert by_task["Refactor someday"]["priority"] == "low"
    assert by_task["Write the report"]["priority"] == "medium"


@pytest.mark.unit
def test_blockers_are_flagged_and_high_priority(agent: ExecutiveAssistantAgent) -> None:
    result = agent.plan(["Blocked on the security review"])
    item = result["items"][0]
    assert item["is_blocker"] is True
    assert item["priority"] == "high"
    assert "Blocked on the security review" in result["blockers"]


@pytest.mark.unit
def test_prioritized_order_high_first(agent: ExecutiveAssistantAgent) -> None:
    result = agent.plan(["someday task", "urgent task", "normal task"])
    assert result["prioritized_order"][0] == "urgent task"
    assert result["prioritized_order"][-1] == "someday task"


@pytest.mark.unit
def test_stable_within_priority_band(agent: ExecutiveAssistantAgent) -> None:
    # Two medium tasks keep their input order.
    result = agent.plan(["first normal", "second normal"])
    assert result["prioritized_order"] == ["first normal", "second normal"]


@pytest.mark.unit
def test_open_questions_surfaced(agent: ExecutiveAssistantAgent) -> None:
    result = agent.plan(["Ship the release", "Should we migrate to v2?"])
    assert result["open_questions"] == ["Should we migrate to v2?"]


@pytest.mark.unit
def test_suggested_focus_respects_count(agent: ExecutiveAssistantAgent) -> None:
    result = agent.plan(["a urgent", "b urgent", "c urgent", "d urgent"], focus_count=2)
    assert len(result["suggested_focus"]) == 2


@pytest.mark.unit
def test_string_input_split_on_newlines_and_bullets(agent: ExecutiveAssistantAgent) -> None:
    result = agent.plan("- task one\n- task two\n- task three")
    assert result["prioritized_order"] == ["task one", "task two", "task three"]


@pytest.mark.unit
def test_decision_log_template_is_blank(agent: ExecutiveAssistantAgent) -> None:
    """The decision log must be an empty template, never invented content."""
    template = agent.plan(["x"])["decision_log_template"]
    assert set(template) == {"date", "decision", "rationale", "owner"}
    assert all(v.startswith("TODO") for v in template.values())


@pytest.mark.unit
def test_empty_input_raises(agent: ExecutiveAssistantAgent) -> None:
    with pytest.raises(ValueError):
        agent.plan("   ")
    with pytest.raises(ValueError):
        agent.plan([])


@pytest.mark.unit
def test_non_string_task_raises(agent: ExecutiveAssistantAgent) -> None:
    with pytest.raises(ValueError):
        agent.plan([1, 2])  # type: ignore[list-item]
