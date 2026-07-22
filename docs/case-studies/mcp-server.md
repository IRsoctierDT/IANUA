# Case Study — Policy-Gated MCP Tool Surface

> **An MCP server where every tool call is allow-listed, self-validating, confined to a
> single filesystem root, and gated by a default-deny policy engine before it runs.**

| | |
|---|---|
| **Component** | MCP Server (`mcp/server.py`, `mcp/transport.py`) |
| **Domain** | Model Context Protocol · capability surfaces · least-privilege tool design |
| **Purpose** | Give agents a minimal, validated, auditable way to reach the filesystem — and nothing else |
| **Risk level** | Low — the default tool is read-only and path-confined; non-read-only tools fail closed without an operator allow-list |
| **Skill level required** | Python developer to add tools; operator to configure the allow-list |
| **Deployment complexity** | Low — standard-library stdio JSON-RPC; no external services |

---

## 1. Executive Summary

The MCP server is the **only sanctioned way** an agent reaches the filesystem in this
platform. It is deliberately small: a `ToolRegistry` holds an allow-list of named `Tool`s,
each of which validates its own arguments and declares a risk class. Every dispatch runs
through a **default-deny policy engine** before the handler executes — only `allow`
decisions run; `require_approval` and `deny` fail closed. When an audit logger is attached,
every decision (including blocked attempts) lands in a tamper-evident trail.

The shipped example tool, `read_text_file`, shows the posture end to end: it resolves the
requested path *inside* a trusted root (blocking traversal), refuses anything that isn't a
regular file, and caps reads at 1 MB. An agent cannot reach a path the server didn't
explicitly sanction, and cannot call a tool that isn't registered.

**Outcome:** the capability surface is load-bearing security, not documentation — a
prompt-injected agent can only invoke allow-listed, validated, policy-approved tools,
which contains the blast radius of any single bad instruction.

---

## 2. Objectives

1. **Allow-list the tool surface** — only explicitly registered tools are callable; an
   unknown tool name fails closed.
2. **Self-validating tools** — every tool validates its own arguments before acting; no
   handler trusts its input.
3. **Least privilege** — filesystem reach is confined to one resolved root, enforced per
   call, not just at startup.
4. **Gate by policy** — a non-read-only tool cannot run autonomously without an operator
   allow-list entry; the decision is auditable.
5. **Stay transport-agnostic** — the enforcement lives in `dispatch`, so any transport
   (stdio, websocket) reuses the same gate.

---

## 3. Architecture / Process

```
agent tool call ─▶ ToolRegistry.dispatch(name, arguments)
                     │  1. name in allow-list?        else → fail closed
                     │  2. arguments is an object?    else → fail closed
                     ▼
                enforce(action_class) ──▶ PolicyEngine.evaluate()
                     │                        allow → run
                     │                        require_approval / deny → block (fail closed)
                     ▼                        (AuditLogger records every decision)
                tool.handler(arguments)
                     │  self-validates args
                     ▼  resolve_within(root, path)  ← path-traversal safe, per call
                confined filesystem read
```

**Design invariants** (from [DESIGN.md](../../DESIGN.md) §3–§6 and [AGENTS.md](../../AGENTS.md) §5–§6):

- Unknown tool or non-object arguments → raise, never guess.
- Every filesystem reach goes through `resolve_within(root, …)`, re-checked on each call.
- The policy gate is in the single shared `enforce()` path, so no tool can bypass it.

---

## 4. Implementation Steps

### 4.1 The `Tool` and the allow-list

A `Tool` is a frozen record of `name`, `description`, `handler`, and an `action_class`
(defaulting to `read_only`). `ToolRegistry.register()` rejects duplicate names; `list_tools()`
exposes only names and descriptions. There is no reflection, no dynamic import — the set of
callable capabilities is exactly what was registered.

### 4.2 Gated dispatch

`dispatch()` is the choke point. It looks the tool up (missing → `ValidationError`), checks
that `arguments` is an object, then calls the shared `enforce()` helper with the tool's
`action_class`. `enforce()` evaluates the policy, records the decision to the optional audit
log, and raises `ToolBlockedError` (a `ValidationError`) if the decision isn't `allow`. Only
then does the handler run.

### 4.3 A least-privilege example tool

`read_text_file` demonstrates the contract every tool must honor:

- requires a non-empty `path` string (else validation error);
- calls `resolve_within(registry.root, rel)` so a `../../etc/passwd` style path can't escape
  the trusted root;
- confirms the target is a regular file;
- enforces a 1 MB read cap before returning `{path, content}`.

### 4.4 Wiring policy and audit

`build_default_registry(root, policy=…, audit=…)` constructs a registry with a default-deny
`PolicyEngine` and an optional `AuditLogger`. Operators opt specific non-read-only actions in
via the policy's allow-list; everything else fails closed. See the
[Policy & Audit case study](./policy-and-audit.md) for the engine and the hash-chained log.

---

## 5. Worked Example

**A registered, read-only, path-confined read succeeds:**

```python
from pathlib import Path
from mcp.server import build_default_registry

registry = build_default_registry(Path("knowledge-base"))
print(registry.list_tools())
# [{'name': 'read_text_file', 'description': 'Read a UTF-8 text file confined to the server root (read-only).'}]

result = registry.dispatch("read_text_file", {"path": "mitre/enterprise_attack_overview.md"})
print(result["path"], "→", len(result["content"]), "bytes")
```

**Three ways a call fails closed — by design:**

```python
registry.dispatch("delete_everything", {"path": "x"})   # ValidationError: tool not in allow-list
registry.dispatch("read_text_file", {"path": "../../etc/passwd"})  # ValidationError: path escapes root
registry.dispatch("read_text_file", {})                 # ValidationError: 'path' (non-empty string) is required
```

An unregistered tool, a traversal attempt, and malformed arguments all raise rather than
proceed. A tool declared with a non-read-only `action_class` is blocked unless an operator
has explicitly allow-listed that action in the policy engine.

---

## 6. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Prompt-injected agent invokes an arbitrary tool | Unauthorized action | Allow-list: only registered tools are callable; unknown → fail closed |
| Path traversal out of the server root | Arbitrary file read | `resolve_within(root, …)` re-checked on every call |
| A write/network tool runs autonomously | Data loss / exfiltration | `action_class` gate: non-read-only fails closed without an operator allow-list entry |
| Malformed arguments reach a handler | Crash / undefined behavior | `dispatch` validates argument shape; each tool re-validates its own inputs |
| Silent, unauditable tool use | No forensic trail | Optional `AuditLogger` records every decision, including blocked attempts |

---

## 7. Cost Considerations

Standard-library only — stdio JSON-RPC transport, no broker, no external service, effectively
zero runtime cost. Adding a real MCP SDK or a networked transport is an explicit, gated
decision; the enforcement in `dispatch` is reused unchanged regardless of transport.

---

## 8. Future Enhancements

- **Per-tool argument schemas** — declare and validate a JSON schema per tool at register time.
- **Scoped roots per tool** — allow different tools different confined roots.
- **Rate limiting / quotas** — bound how often and how much a tool can be called per session.
- **Container sandboxing** — run tool execution rootless with seccomp/AppArmor ([DESIGN.md](../../DESIGN.md) §10).
- **Signed audit head** — anchor the audit chain head for stronger tamper-evidence.

---

## 9. Reproduce It Yourself

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run the stdio JSON-RPC server against a confined root:
MCP_ROOT=./knowledge-base python -m mcp.transport
# Speaks line-delimited JSON-RPC 2.0 — methods: initialize | tools/list | tools/call

# Exercise the registry directly:
python -c "
from pathlib import Path
from mcp.server import build_default_registry
r = build_default_registry(Path('knowledge-base'))
print(r.list_tools())
print(r.dispatch('read_text_file', {'path': 'mitre/enterprise_attack_overview.md'})['path'])
"

# Security + unit tests for the tool surface:
python -m pytest tests/unit/test_mcp_server.py tests/unit/test_mcp_transport.py tests/security/test_guarded_tool.py
```

---

*Part of the [IANUA](../../README.md). Security tooling here is
for defensive, authorized-lab use only — see [AGENTS.md](../../AGENTS.md) §5.*
