# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Plan-only containment layer — produces guidance, never actions.

Nothing executes a plan this package emits. It produces a draft
:class:`ResponsePlan` that a human operator carries out on systems they own
or are authorized to administer; ``tests/security/test_response_no_executor.py``
fails the build if executor code ever appears here. The one operator-invoked
action path that exists — a single pfSense alias edit, under a signed per-action
approval (``scripts/pfsense_containment.py``, stage 8) — lives outside this
package and does not read a plan. See
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
