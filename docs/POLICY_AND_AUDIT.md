# Policy & Audit Layer

## Executive Summary

The `agents/policies/` layer turns the AGENTS.md §5 / §5.1 security boundaries from
documentation into **enforced, testable code**: a default-deny **policy engine** that
classifies an intended action and returns *allow / require-approval / deny*, and a
**tamper-evident audit log** that records security-relevant decisions in a hash chain.

| | |
|---|---|
| **Purpose** | Enforce approval gates and produce an auditable trail of security-relevant decisions |
| **Risk level** | Low — read-only evaluation + append-only logging; no destructive or external actions |
| **Skill level required** | Developer to integrate; analyst to read the audit log |
| **Deployment complexity** | Low — pure Python standard library, deterministic, network-free |

## Objectives

1. Make the charter's approval gates (§5.1) executable, not aspirational.
2. Keep §5 prohibitions **non-negotiable** — no override can allow them.
3. Provide **auditability** (§3): security-relevant decisions leave a tamper-evident record.
4. Stay deterministic, dependency-free, and fully tested.

## Architecture / Process

```
intended action ─▶ PolicyEngine.evaluate()
                      │  classify → map to decision (default-deny, fail-closed)
                      ▼
                 PolicyDecision (allow | require_approval | deny)
                      │
        guard() ──────┴────▶ AuditLogger.record()  ─▶  hash-chained JSONL
                                                         (verify() detects tampering)
```

- **`approval.py`** — `classify_action()` maps a description to an `ActionClass`
  (read_only · destructive · external_network · deployment · dependency ·
  secret_handling · boundary_crossing · unknown). `PolicyEngine.evaluate()` applies
  the policy: read-only → allow; gated classes → require_approval; `boundary_crossing`
  → deny; **unknown → require_approval (fail closed)**.
- **`audit.py`** — `AuditLogger.record()` appends a JSON line whose `entry_hash`
  chains the previous entry's hash. `verify()` recomputes the chain end-to-end and
  returns `False` on any edit, insertion, or deletion.
- **`guard()`** — evaluate + record in one call.

## Implementation Steps (to adopt in a tool)

```python
from agents.policies import PolicyEngine, AuditLogger, guard

engine = PolicyEngine(allow=["deploy to staging"])     # optional operator overrides
logger = AuditLogger("data/audit/audit.log")            # data/ is gitignored

decision = guard("Delete the database", engine=engine, logger=logger, actor="orchestrator")
if decision.requires_human:
    ...  # stop and obtain approval (AGENTS.md §5.1) — do not proceed
elif decision.decision == "deny":
    ...  # refuse — §5 prohibition
```

## Risks

| Risk | Mitigation |
|------|-----------|
| Misclassification of a novel action | Unknown class **fails closed** to require_approval |
| Allow-list used to smuggle a prohibition | Allow-list **cannot** override `boundary_crossing` |
| Audit log edited to hide an action | Hash chain — `verify()` detects edits/insertions/deletions |
| Secrets written into the audit log | Log records decisions/short reasons only; callers must not pass payloads (§5) |

## Cost Considerations

Zero runtime cost beyond local file I/O; pure standard library, no external services.

## Adoption status

- ✅ **MCP tool surface (`mcp/server.py`)** — `ToolRegistry.dispatch` gates every
  tool call through the policy engine: each `Tool` declares an `action_class`, and
  only `allow` decisions execute (`require_approval`/`deny` fail closed). An optional
  `AuditLogger` records every decision, including blocked attempts. Read-only tools
  run as before; a non-read-only tool needs an operator allow-list entry to run.

## Future Enhancements

- Extend `action_class` declarations as write/network tools are added.
- Optional signing of the audit chain head for stronger tamper-evidence.
- A policy-as-code config file for per-environment allow/deny lists.
