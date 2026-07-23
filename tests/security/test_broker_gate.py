"""Security tests: trust-broker gate on the MCP tool surface (mcp/broker.py).

The broker layer must fail closed on every path — missing token, unbound
tool, deny, escalate — and must compose with (never replace) the existing
action-class policy gate. A fake broker keeps this suite dependency-free.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from mcp.broker import BrokerBinding, BrokerBlockedError, authorize_or_raise
from mcp.server import Tool, ToolRegistry


@dataclass(frozen=True)
class _Decision:
    effect: str
    reason: str = "test"


@dataclass
class FakeBroker:
    """Records authorize calls and returns a scripted effect."""

    effect: str = "allow"
    calls: list[tuple[str, str, str]] = field(default_factory=list)

    def authorize(
        self,
        token: str,
        action: str,
        resource: str,
        context: Mapping[str, str] | None = None,
    ) -> _Decision:
        self.calls.append((token, action, resource))
        return _Decision(effect=self.effect)


def _registry(tmp_path: Path, broker: FakeBroker | None) -> ToolRegistry:
    registry = ToolRegistry(root=tmp_path, broker=broker)
    registry.register(
        Tool(
            name="echo",
            description="Return arguments unchanged (read-only test tool).",
            handler=lambda args: {"echo": args},
            broker_binding=BrokerBinding(
                scope="tool:log.read", resource=lambda args: str(args.get("path", ""))
            ),
        )
    )
    registry.register(
        Tool(
            name="unbound",
            description="Tool with no broker binding.",
            handler=lambda args: {"ran": True},
        )
    )
    return registry


def test_missing_token_fails_closed(tmp_path: Path) -> None:
    """Broker configured + no caller token -> blocked before the handler runs."""
    registry = _registry(tmp_path, FakeBroker())
    with pytest.raises(BrokerBlockedError, match="identity token required"):
        registry.dispatch("echo", {"path": "logs/lab/a.jsonl"})


def test_unbound_tool_fails_closed(tmp_path: Path) -> None:
    """Broker configured + tool without a binding -> blocked (closed world)."""
    registry = _registry(tmp_path, FakeBroker())
    with pytest.raises(BrokerBlockedError, match="no broker binding"):
        registry.dispatch("unbound", {}, token="ATB-ID-000001.sig")


@pytest.mark.parametrize("effect", ["deny", "escalate", "garbage"])
def test_non_allow_decisions_block(tmp_path: Path, effect: str) -> None:
    """Any decision other than allow — including unknown shapes — blocks."""
    registry = _registry(tmp_path, FakeBroker(effect=effect))
    with pytest.raises(BrokerBlockedError, match=effect):
        registry.dispatch("echo", {"path": "logs/lab/a.jsonl"}, token="ATB-ID-000001.sig")


def test_allow_runs_and_scopes_are_forwarded(tmp_path: Path) -> None:
    """An allow decision dispatches, and the broker saw scope + resource."""
    broker = FakeBroker(effect="allow")
    registry = _registry(tmp_path, broker)
    result = registry.dispatch("echo", {"path": "logs/lab/a.jsonl"}, token="ATB-ID-000001.sig")
    assert result == {"echo": {"path": "logs/lab/a.jsonl"}}
    assert broker.calls == [("ATB-ID-000001.sig", "tool:log.read", "logs/lab/a.jsonl")]


def test_broker_absent_preserves_existing_behavior(tmp_path: Path) -> None:
    """No broker configured -> dispatch behaves exactly as before (no regression)."""
    registry = _registry(tmp_path, None)
    assert registry.dispatch("echo", {"path": "x"}) == {"echo": {"path": "x"}}


def test_enum_style_effect_allows(tmp_path: Path) -> None:
    """Decision.effect may be an enum with .value == 'allow' (ATB shape)."""

    class _Effect:
        value = "allow"

    @dataclass(frozen=True)
    class _EnumDecision:
        effect: Any = field(default_factory=_Effect)
        reason: str = "least_privilege_grant"

    class EnumBroker:
        def authorize(
            self,
            token: str,
            action: str,
            resource: str,
            context: Mapping[str, str] | None = None,
        ) -> _EnumDecision:
            return _EnumDecision()

    binding = BrokerBinding(scope="tool:log.read", resource=lambda args: "logs/lab/a.jsonl")
    authorize_or_raise(EnumBroker(), "ATB-ID-000001.sig", binding, "echo", {})
