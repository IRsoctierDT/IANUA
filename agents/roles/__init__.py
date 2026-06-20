"""Agent roles — the AGENTS.md §6 operating roles, referenceable in code.

Public API: the four canonical :class:`Role` instances (``PLANNER``, ``BUILDER``,
``REVIEWER``, ``SECURITY``), the ``ROLES`` registry, ``get_role()``, and the ordered
``REVIEW_PRIORITIES`` (§6.1).
"""

from __future__ import annotations

from agents.roles.definitions import (
    BUILDER,
    PLANNER,
    REVIEW_PRIORITIES,
    REVIEWER,
    ROLES,
    SECURITY,
    Role,
    get_role,
)

__all__ = [
    "BUILDER",
    "PLANNER",
    "REVIEWER",
    "REVIEW_PRIORITIES",
    "ROLES",
    "SECURITY",
    "Role",
    "get_role",
]
