"""Policy-guarded capability wrapper for agent tool surfaces.

The single, reusable enforcement primitive for *any* capability that reaches the
filesystem, network, or a model. It evaluates the action against the policy engine
(AGENTS.md §5/§5.1), records the decision to the tamper-evident audit trail, and
**fails closed** — only an ``allow`` decision runs; ``require_approval`` and ``deny``
raise :class:`ToolBlockedError`.

Both the MCP tool surface (``mcp/server.py``) and in-process agent tool adapters
route through :func:`enforce`, so enforcement is implemented and tested once.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from agents.policies import ActionClass, AuditLogger, PolicyDecision, PolicyEngine
from agents.tools.validation import ValidationError

R = TypeVar("R")


class ToolBlockedError(ValidationError):
    """Raised when a capability is blocked by policy (require_approval or deny)."""


def enforce(
    *,
    action_class: ActionClass,
    name: str,
    engine: PolicyEngine,
    audit: AuditLogger | None = None,
    actor: str = "tool",
) -> PolicyDecision:
    """Evaluate and audit a capability invocation; raise if it is not allowed.

    Returns the :class:`PolicyDecision` on ``allow``. Records the decision (including
    blocked attempts) when an ``audit`` logger is supplied. Fails closed: any
    non-``allow`` decision raises :class:`ToolBlockedError`.
    """
    decision = engine.decide(action_class=action_class, label=name)
    if audit is not None:
        audit.record(
            actor=actor,
            action=f"tool:{name}",
            action_class=decision.action_class,
            decision=decision.decision,
            reason=decision.reason,
        )
    if decision.decision != "allow":
        raise ToolBlockedError(
            f"tool {name!r} blocked by policy: {decision.decision} ({decision.reason})"
        )
    return decision


@dataclass
class GuardedCapability(Generic[R]):
    """Wrap a callable so each invocation is policy-gated and audited.

    Example::

        write = GuardedCapability(_write_file, name="write_file",
                                  action_class="destructive", engine=engine, audit=audit)
        write(path, data)   # raises ToolBlockedError unless allow-listed
    """

    func: Callable[..., R]
    name: str
    action_class: ActionClass
    engine: PolicyEngine
    audit: AuditLogger | None = None
    actor: str = "tool"

    def __call__(self, *args: Any, **kwargs: Any) -> R:
        enforce(
            action_class=self.action_class,
            name=self.name,
            engine=self.engine,
            audit=self.audit,
            actor=self.actor,
        )
        return self.func(*args, **kwargs)
