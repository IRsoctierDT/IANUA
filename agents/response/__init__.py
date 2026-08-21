"""Plan-only containment layer — produces guidance, never actions.

IANUA does not execute containment. This package emits a draft
:class:`ResponsePlan` that a human operator carries out on systems they own
or are authorized to administer; ``tests/security/test_response_no_executor.py``
fails the build if executor code ever appears here. See
``agents/response/plan.py`` for why the boundary is closed by construction and
what would have to be designed first to open it.
"""

from agents.response.catalogue import ResponseCatalogueError, build_action, load_catalogue
from agents.response.plan import (
    MAX_TARGET_LEN,
    RESTRICT_ONLY_VERBS,
    ResponseAction,
    ResponsePlan,
    sanitize_target,
)
from agents.response.planner import ResponsePlanner

__all__ = [
    "MAX_TARGET_LEN",
    "RESTRICT_ONLY_VERBS",
    "ResponseAction",
    "ResponseCatalogueError",
    "ResponsePlan",
    "ResponsePlanner",
    "build_action",
    "load_catalogue",
    "sanitize_target",
]
