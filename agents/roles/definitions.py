"""Agent role specifications — codifies the AGENTS.md §6 operating roles.

Work in this repository is organized around four cooperating roles. The charter
requires that an agent **announce which role it is in** and honor that role's
responsibilities; this module makes those roles referenceable in code (e.g. for
an orchestrator to declare its role, or to drive a review checklist) rather than
living only as prose.

The content mirrors AGENTS.md §6 / §6.1 exactly — keep them in sync.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# AGENTS.md §6.1 — Review Priorities, in the order they must be applied.
REVIEW_PRIORITIES: tuple[str, ...] = (
    "Security defects (broken authz, injection, secret leakage, unsafe "
    "deserialization, SSRF, path traversal, weakened controls)",
    "Logic errors (incorrect behavior, wrong results, race conditions)",
    "Unhandled edge cases (empty/oversized/malformed input, partial failures, timeouts)",
    "Unsafe tool execution (shell/exec with unsanitized input, unsandboxed tools, "
    "missing allow-lists)",
    "Poor input validation (untyped boundaries, missing schema validation, trust of "
    "external/LLM data)",
    "Broken tests (failing, flaky, skipped, or missing coverage for new logic)",
    "Incomplete documentation (undocumented public surface, stale README/DESIGN)",
    "Violations of DESIGN.md (architectural drift, boundary erosion, naming breakage)",
)


@dataclass(frozen=True)
class Role:
    """A single operating role (AGENTS.md §6)."""

    key: str
    title: str
    mandate: str
    produces: str
    priorities: tuple[str, ...] = field(default_factory=tuple)

    def announce(self) -> str:
        """Return the role announcement an agent should make before acting (§6)."""
        return f"Acting as {self.title}: {self.mandate}"


PLANNER = Role(
    key="planner",
    title="Planner",
    mandate=(
        "Decompose the request; map it to modules; identify trust boundaries crossed; "
        "surface risks, assumptions, and dependencies."
    ),
    produces="A short plan + task list before code.",
)

BUILDER = Role(
    key="builder",
    title="Builder",
    mandate=(
        "Implement the smallest correct change; follow conventions (§4); keep security "
        "controls visible (§5)."
    ),
    produces="Working, typed, documented code.",
)

REVIEWER = Role(
    key="reviewer",
    title="Reviewer",
    mandate=(
        "Apply the review priorities (§6.1) in order; run the required checks (§7); "
        "reject anything that fails."
    ),
    produces="Pass/fail with specific findings.",
    priorities=REVIEW_PRIORITIES,
)

SECURITY = Role(
    key="security",
    title="Security",
    mandate=("Independent pass focused only on the security boundaries (§5) and tests/security."),
    produces="Sign-off or blocking findings.",
    priorities=(REVIEW_PRIORITIES[0],),  # security defects come first
)

# Registry, in the §6 workflow order.
ROLES: dict[str, Role] = {r.key: r for r in (PLANNER, BUILDER, REVIEWER, SECURITY)}


def get_role(key: str) -> Role:
    """Return the :class:`Role` for ``key`` (e.g. ``"reviewer"``); fail closed if unknown."""
    try:
        return ROLES[key.strip().lower()]
    except (AttributeError, KeyError) as exc:
        raise ValueError(f"unknown role: {key!r}; known roles: {sorted(ROLES)}") from exc
