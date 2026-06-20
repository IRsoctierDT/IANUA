from dataclasses import FrozenInstanceError

import pytest
from agents.roles import (
    BUILDER,
    PLANNER,
    REVIEW_PRIORITIES,
    REVIEWER,
    ROLES,
    SECURITY,
    Role,
    get_role,
)


@pytest.mark.unit
def test_four_canonical_roles_registered() -> None:
    assert set(ROLES) == {"planner", "builder", "reviewer", "security"}
    assert all(isinstance(r, Role) for r in ROLES.values())


@pytest.mark.unit
def test_each_role_has_mandate_and_produces() -> None:
    for role in ROLES.values():
        assert role.mandate.strip()
        assert role.produces.strip()
        assert role.title.strip()


@pytest.mark.unit
def test_reviewer_carries_ordered_review_priorities() -> None:
    assert REVIEWER.priorities == REVIEW_PRIORITIES
    assert len(REVIEW_PRIORITIES) == 8
    # Security defects are the first priority (§6.1).
    assert REVIEW_PRIORITIES[0].lower().startswith("security defects")


@pytest.mark.unit
def test_security_role_leads_with_security_defects() -> None:
    assert SECURITY.priorities == (REVIEW_PRIORITIES[0],)


@pytest.mark.unit
def test_get_role_is_case_insensitive() -> None:
    assert get_role("Reviewer") is REVIEWER
    assert get_role("  planner ") is PLANNER


@pytest.mark.unit
def test_get_role_unknown_fails_closed() -> None:
    with pytest.raises(ValueError):
        get_role("overlord")


@pytest.mark.unit
def test_announce_includes_title_and_mandate() -> None:
    msg = BUILDER.announce()
    assert "Builder" in msg
    assert "smallest correct change" in msg


@pytest.mark.unit
def test_roles_are_immutable() -> None:
    with pytest.raises(FrozenInstanceError):
        PLANNER.title = "Overlord"  # type: ignore[misc]
