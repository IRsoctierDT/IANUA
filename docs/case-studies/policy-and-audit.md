# Case Study — Policy Engine & Tamper-Evident Audit Log

> **Turning a security charter from prose into enforced, testable code: a default-deny
> policy engine that classifies every intended action, and a hash-chained audit log that
> detects any edit, insertion, or deletion.**

| | |
|---|---|
| **Component** | Policy & Audit Layer (`agents/policies/`) |
| **Domain** | Policy-as-code · approval gates · auditability · governance |
| **Purpose** | Make the AGENTS.md §5/§5.1 boundaries executable and produce a tamper-evident trail of security-relevant decisions |
| **Risk level** | Low — read-only evaluation + append-only logging; no destructive or external actions |
| **Skill level required** | Developer to integrate; analyst to read the audit log |
| **Deployment complexity** | Low — pure Python standard library, deterministic, network-free |

---

## 1. Executive Summary

A security charter that lives only in a Markdown file is a suggestion. This layer makes it
**load-bearing**. The `PolicyEngine` classifies an intended action into a risk class and
returns one of three decisions — `allow`, `require_approval`, or `deny` — defaulting to
denial when it can't confidently classify. The `AuditLogger` appends each security-relevant
decision as a JSON line whose hash chains to the previous entry, so `verify()` can detect any
tampering after the fact.

The two are combined in a single `guard()` call, and the same enforcement path is wired into
the MCP tool surface so that *every* tool dispatch is gated. The result is that the platform's
approval gates (AGENTS.md §5.1) and its non-negotiable prohibitions (§5) are enforced by code,
not honored by convention.

**Outcome:** an agent cannot autonomously take a gated action, an operator can't accidentally
allow-list a hard prohibition, and no one can quietly rewrite history in the audit log without
`verify()` catching it.

---

## 2. Objectives

1. Make the charter's approval gates (§5.1) **executable**, not aspirational.
2. Keep §5 prohibitions **non-negotiable** — no operator override can allow them.
3. Provide **auditability** (§3): security-relevant decisions leave a tamper-evident record.
4. **Fail closed** — an unrecognized action defaults to `require_approval`, never to `allow`.
5. Stay deterministic, dependency-free, and fully tested.

---

## 3. Architecture / Process

```
intended action ─▶ classify_action() ─▶ ActionClass
                                          (read_only · destructive · external_network ·
                                           deployment · dependency · secret_handling ·
                                           boundary_crossing · unknown)
                          │
                          ▼
                 PolicyEngine.evaluate()      read_only            → allow
                                              gated classes         → require_approval
                                              boundary_crossing     → deny (cannot be overridden)
                                              unknown               → require_approval (fail closed)
                          │
      guard() ───────────┴────▶ AuditLogger.record() ─▶ hash-chained JSONL
                                                          entry_hash = H(entry || prev_hash)
                                                          verify() recomputes the whole chain
```

**Design invariants** (from [DESIGN.md](../../DESIGN.md) §3, §5–§6):

- Default deny: ambiguous or unknown actions require human approval.
- The allow-list can promote gated classes to `allow`, but **cannot** override a
  `boundary_crossing` prohibition.
- The audit log is append-only and self-verifying; the record holds decisions and short
  reasons, never secret payloads.

---

## 4. Implementation Steps

### 4.1 Classify the action (`approval.py`)

`classify_action()` maps a plain-English action description to an `ActionClass`. Read-only
work classifies as `read_only`; deleting data, reaching the network, deploying, changing
dependencies, or handling secrets each get their own gated class; anything unrecognized is
`unknown`.

### 4.2 Evaluate against policy

`PolicyEngine.evaluate()` applies the rules: `read_only` → `allow`; gated classes →
`require_approval`; `boundary_crossing` → `deny`; `unknown` → `require_approval` (**fail
closed**). An operator may pass an `allow` list to promote specific gated actions, but a
prohibition can never be promoted.

### 4.3 Chain the audit log (`audit.py`)

`AuditLogger.record()` appends a JSON line whose `entry_hash` is computed over the entry plus
the previous entry's hash. Because each entry commits to the one before it, editing,
inserting, or deleting any line breaks the chain — and `verify()` recomputes the chain
end-to-end and returns `False` on any discrepancy.

### 4.4 One-call enforcement

`guard(action, engine=…, logger=…, actor=…)` evaluates and records in a single call and
returns a `PolicyDecision`. Callers branch on it:

```python
from agents.policies import PolicyEngine, AuditLogger, guard

engine = PolicyEngine(allow=["deploy to staging"])   # optional operator overrides
logger = AuditLogger("data/audit/audit.log")          # data/ is gitignored

decision = guard("Delete the database", engine=engine, logger=logger, actor="orchestrator")
if decision.requires_human:
    ...  # stop and obtain approval (AGENTS.md §5.1) — do not proceed
elif decision.decision == "deny":
    ...  # refuse — §5 prohibition
```

---

## 5. Worked Example

**Classification drives the decision, and denial cannot be overridden:**

```python
from agents.policies import PolicyEngine

engine = PolicyEngine()                                             # default-deny, no overrides
print(engine.evaluate("Read a log file").decision)                 # allow      (read_only)
print(engine.evaluate("Delete the production database").decision)  # require_approval
print(engine.evaluate("Frobnicate the widget").decision)           # require_approval (unknown → fail closed)
```

**Tamper detection — the chain catches an edit:**

```python
from agents.policies import AuditLogger

log = AuditLogger("data/audit/demo.log")
log.record(actor="mcp", action="read_text_file", action_class="read_only",
           decision="allow", reason="read_only")
log.record(actor="mcp", action="delete", action_class="destructive",
           decision="require_approval", reason="destructive")
assert log.verify() is True          # intact chain

# ...anyone edits a line in data/audit/demo.log to hide the 'delete' attempt...
assert log.verify() is False         # recomputed hash chain no longer matches → tampering detected
```

The read is allowed autonomously; the destructive and the unrecognized actions both stop for
a human; and any later rewrite of the log is detectable.

---

## 6. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Misclassification of a novel action | Unauthorized autonomous action | Unknown class **fails closed** to `require_approval` |
| Allow-list used to smuggle a prohibition | Bypass of a §5 boundary | Allow-list **cannot** override `boundary_crossing` |
| Audit log edited to hide an action | Lost forensic trail | Hash chain — `verify()` detects edits, insertions, and deletions |
| Secrets written into the audit log | Credential leak via logs | Log records decisions/short reasons only; callers must not pass payloads (§5) |
| Gate present but not wired in | Enforcement is theater | `enforce()` is the shared path the MCP `ToolRegistry` calls on every dispatch |

---

## 7. Cost Considerations

Zero runtime cost beyond local file I/O — pure standard library, no external services, no
database. The audit log is a plain append-only JSONL file that any analyst can read.

---

## 8. Adoption Status

- ✅ **MCP tool surface (`mcp/server.py`)** — `ToolRegistry.dispatch` gates every tool call
  through the policy engine via the shared `enforce()` helper; each `Tool` declares an
  `action_class`, only `allow` decisions execute, and an optional `AuditLogger` records every
  decision including blocked attempts. See the [MCP Server case study](./mcp-server.md).

---

## 9. Future Enhancements

- Extend `action_class` declarations as write/network tools are added.
- Optionally sign the audit chain head for stronger tamper-evidence.
- A policy-as-code config file for per-environment allow/deny lists (OPA-style).
- Property-based fuzzing of `classify_action()` to harden classification.

---

## 10. Reproduce It Yourself

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

python -c "
from agents.policies import PolicyEngine
e = PolicyEngine()
for a in ['Read a log file', 'Delete the production database', 'Frobnicate the widget']:
    print(f'{a!r:40} -> {e.evaluate(a).decision}')
"

# Security tests for the policy engine and the audit chain:
python -m pytest tests/security/test_policy_engine.py tests/security/test_audit_logger.py
```

---

*Part of the [AI Operator Cyber Command Center](../../README.md). Security tooling here is
for defensive, authorized-lab use only — see [AGENTS.md](../../AGENTS.md) §5.*
