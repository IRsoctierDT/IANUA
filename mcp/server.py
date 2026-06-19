"""Minimal, secure-by-default MCP server stub.

Design goals (see DESIGN.md §3-§6, AGENTS.md §5-§6):
  * Allow-listed tool surface  -- only explicitly registered tools are callable.
  * Self-validating tools      -- every tool validates its own arguments.
  * Least privilege            -- filesystem reach is confined to a single root.
  * Fail closed                -- unknown tools / bad input raise, never guess.
  * Default-deny network       -- this stub performs NO network egress.

This is transport-agnostic scaffolding: wire `ToolRegistry.dispatch` into your
MCP transport of choice (stdio/websocket) once the real SDK is added.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agents.policies import ActionClass, AuditLogger, PolicyEngine
from agents.tools.validation import ValidationError, resolve_within

ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class Tool:
    """A single, named capability exposed to agents.

    ``action_class`` declares the capability's risk class so the registry's policy
    engine can gate it (AGENTS.md §5.1). Defaults to ``read_only``.
    """

    name: str
    description: str
    handler: ToolHandler
    action_class: ActionClass = "read_only"


@dataclass
class ToolRegistry:
    """Allow-list of callable tools, gated by the policy engine (AGENTS.md §5/§5.1).

    Every dispatch is evaluated by ``policy`` before the handler runs: only
    ``allow`` decisions execute; ``require_approval`` and ``deny`` are blocked
    (fail closed) so a non-read-only tool cannot run autonomously without an
    operator allow-list entry. When an ``audit`` logger is provided, each decision
    is recorded to the tamper-evident trail.
    """

    root: Path
    policy: PolicyEngine = field(default_factory=PolicyEngine)
    audit: AuditLogger | None = None
    actor: str = "mcp"
    _tools: dict[str, Tool] = field(default_factory=dict)

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"duplicate tool name: {tool.name!r}")
        self._tools[tool.name] = tool

    def list_tools(self) -> list[dict[str, str]]:
        return [{"name": t.name, "description": t.description} for t in self._tools.values()]

    def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Route a tool call. Unknown tool / blocked policy -> fail closed (§3, §5.1)."""
        tool = self._tools.get(name)
        if tool is None:
            raise ValidationError(f"tool not in allow-list: {name!r}")
        if not isinstance(arguments, dict):
            raise ValidationError("arguments must be an object")

        decision = self.policy.decide(action_class=tool.action_class, label=tool.name)
        if self.audit is not None:
            self.audit.record(
                actor=self.actor,
                action=f"tool:{tool.name}",
                action_class=decision.action_class,
                decision=decision.decision,
                reason=decision.reason,
            )
        if decision.decision != "allow":
            raise ValidationError(
                f"tool {name!r} blocked by policy: {decision.decision} ({decision.reason})"
            )

        return tool.handler(arguments)


def build_default_registry(
    root: Path,
    *,
    policy: PolicyEngine | None = None,
    audit: AuditLogger | None = None,
) -> ToolRegistry:
    """Construct a registry with one safe, illustrative read-only tool.

    Pass a configured ``policy`` (e.g. with operator allow-lists) and/or an
    ``audit`` logger to gate and record tool calls; both default to a fresh
    default-deny policy and no audit sink.
    """
    registry = ToolRegistry(
        root=root.resolve(),
        policy=policy or PolicyEngine(),
        audit=audit,
    )

    def read_text_file(args: dict[str, Any]) -> dict[str, Any]:
        """Read a UTF-8 text file confined to the registry root."""
        rel = args.get("path")
        if not isinstance(rel, str) or not rel:
            raise ValidationError("'path' (non-empty string) is required")
        # resolve_within blocks path traversal outside the trusted root.
        target = resolve_within(registry.root, rel)
        if not target.is_file():
            raise ValidationError(f"not a file: {rel!r}")
        max_bytes = 1_000_000
        if target.stat().st_size > max_bytes:
            raise ValidationError("file exceeds 1MB read limit")
        return {"path": rel, "content": target.read_text(encoding="utf-8")}

    registry.register(
        Tool(
            name="read_text_file",
            description="Read a UTF-8 text file confined to the server root (read-only).",
            handler=read_text_file,
        )
    )
    return registry
