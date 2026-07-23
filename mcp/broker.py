"""Trust-broker seam for the MCP tool surface (DESIGN.md trust boundary #2).

Adds caller identity to the tool-dispatch trust model. The existing policy
engine gates *what kind* of action may run autonomously (action class); a
trust broker gates *who* may perform *which specific action on which
resource*. Both layers run on every brokered dispatch — defense in depth,
neither replaces the other.

The broker is consumed through a structural :class:`Protocol` so this module
adds no dependency: any object with a conforming ``authorize`` method works
(the IANUA Agent Trust Broker's ``PolicyEngine`` satisfies it directly).
Security consideration: when a registry carries a broker, dispatch fails
closed — a missing caller token, an unbound tool, or any non-allow decision
blocks the call before the handler runs.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from agents.tools.validation import ValidationError


class BrokerBlockedError(ValidationError):
    """Raised when the trust broker does not allow a dispatch (fail closed)."""


@runtime_checkable
class TrustBroker(Protocol):
    """Structural interface for an identity-aware authorization broker.

    ``authorize`` returns a decision object whose ``effect`` is either the
    string ``"allow"`` or an enum whose ``value`` is ``"allow"`` when the call
    may proceed; anything else blocks. ``reason`` is recorded in the error.
    """

    def authorize(
        self,
        token: str,
        action: str,
        resource: str,
        context: Mapping[str, str] | None = None,
    ) -> Any:
        """Evaluate one privileged action request for an identified caller."""
        ...  # pragma: no cover - protocol definition


@dataclass(frozen=True)
class BrokerBinding:
    """Maps one registered tool onto the broker's scope/resource model.

    ``scope`` is the broker-side action (e.g. ``fs:workspace.read``);
    ``resource`` derives the concrete resource string from validated tool
    arguments (e.g. the requested path). Binding is per-tool and explicit —
    when a broker is present, an unbound tool cannot be dispatched.
    """

    scope: str
    resource: Callable[[dict[str, Any]], str]


def authorize_or_raise(
    broker: TrustBroker,
    token: str | None,
    binding: BrokerBinding | None,
    tool_name: str,
    arguments: dict[str, Any],
) -> None:
    """Run the broker gate for one dispatch; raise ``BrokerBlockedError`` unless allowed.

    Fail-closed rules (ATB-01): no token -> blocked; no binding -> blocked;
    any decision other than ``allow`` (deny, escalate, unknown shape) -> blocked.
    """
    if token is None or not token:
        raise BrokerBlockedError(f"tool {tool_name!r}: caller identity token required")
    if binding is None:
        raise BrokerBlockedError(f"tool {tool_name!r}: no broker binding registered")

    decision = broker.authorize(token, binding.scope, binding.resource(arguments))
    effect = getattr(decision, "effect", None)
    effect_value = getattr(effect, "value", effect)
    if effect_value != "allow":
        reason = getattr(decision, "reason", "no reason supplied")
        raise BrokerBlockedError(f"tool {tool_name!r}: broker returned {effect_value!r} ({reason})")
