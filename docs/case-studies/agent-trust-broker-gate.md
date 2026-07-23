# Case Study — Agent Trust Broker Gate on the MCP Tool Surface

> **Zero-Trust caller identity for agent tool calls: every dispatch can now answer
> not just "may this kind of action run?" but "may *this agent* do *this specific
> thing* to *this resource* — right now?"**

| | |
|---|---|
| **Component** | Trust-broker seam (`mcp/broker.py`) + [IANUA Agent Trust Broker](https://github.com/IRsoctierDT/agent-trust-broker) (external reference implementation) |
| **Domain** | Zero-Trust authorization · agent identity · prompt-injection containment |
| **Purpose** | Gate MCP tool dispatch on verified caller identity and per-action scope authorization, layered on top of the existing action-class policy engine |
| **Risk level** | Low — adds a deny-path control; no network egress, no new dependency, no behavior change when disabled |
| **Skill level required** | Python developer to wire a broker; security engineer to author scopes/bindings |
| **Deployment complexity** | Low — optional field on `ToolRegistry`; broker injected at construction |

---

## 1. Executive Summary

IANUA's MCP tool surface already enforced *what kind* of action may run autonomously:
every registered tool declares an action class, and `ToolRegistry.dispatch` routes each
call through the default-deny policy engine (`agents/policies/`). What it could not
express was *who* is calling. Any code path holding the registry held every tool at the
registry's authority — agent identity was not part of the trust model.

This change adds that dimension as a **second, additive layer**. A `TrustBroker` — any
object satisfying a narrow structural protocol — can be attached to the registry. When
present, every dispatch must carry a caller token; the broker verifies the identity and
authorizes the tool's declared `(scope, resource)` request *before* the existing
action-class gate runs. Both layers evaluate on every brokered call: the broker answers
"may this caller do this?", the action-class engine answers "may this kind of action run
autonomously?" — defense in depth, with neither control replacing the other.

The reference broker is the **IANUA Agent Trust Broker** (separate repository): HMAC-signed
15-minute identities minted from least-privilege role bindings, deterministic
allow/deny/escalate evaluation, depth-1 attenuating delegation with cascade revocation,
and a hash-chained, tamper-evident audit log — the EAODS reference implementation of
PAT-0001 / EAODS-CTRL-000184.

**Outcome:** a prompt-injected agent that asks for a tool outside its role's scopes is
now blocked (or escalated to a human) by identity, not merely by tool classification —
and the attempt is a logged, attributable security event.

---

## 2. Objectives

1. **Add caller identity without weakening anything** — the existing `enforce()` path
   must run unchanged on every call (AGENTS.md §2.6: controls stay visible).
2. **No new dependency** — consume the broker through a structural `Protocol`; the
   `atb` package satisfies it, but `pyproject.toml` is untouched (§5.1 dependency gate).
3. **Fail closed when enabled** — missing token, unbound tool, or any non-allow
   decision blocks before the handler runs; unknown decision shapes block too.
4. **Zero regression when absent** — no broker configured ⇒ dispatch behavior is
   byte-for-byte what it was, pinned by test.
5. **Contain prompt injection at the authorization boundary** — LLM output is data;
   an injection-steered out-of-scope request must fail closed and be attributable.

---

## 3. Architecture / Process

```
agent (holds ATB-issued token)
        │  dispatch(name, arguments, token=...)
        ▼
┌──────────────────────────────────────────────────────┐
│ ToolRegistry.dispatch                                │
│                                                      │
│  1. allow-list lookup ── unknown tool? ─▶ fail closed│
│  2. broker gate (if broker configured)               │
│       token missing ──────────────────▶ fail closed  │
│       tool unbound ───────────────────▶ fail closed  │
│       broker.authorize(token,          ▶ deny/escal. │
│         scope, resource)   ─ not allow ▶ fail closed │
│  3. action-class gate (unchanged)                    │
│       enforce(action_class, policy, audit)           │
│  4. tool handler runs                                │
└──────────────────────────────────────────────────────┘
```

- **`mcp/broker.py`** — `TrustBroker` protocol (`authorize(token, action, resource,
  context) -> decision`), per-tool `BrokerBinding` (broker-side scope + a callable that
  derives the concrete resource from validated arguments), and `authorize_or_raise`
  (the fail-closed gate; raises `BrokerBlockedError`, a `ValidationError`).
- **`mcp/server.py`** — `Tool` gains optional `broker_binding`; `ToolRegistry` gains
  optional `broker`; `dispatch` gains keyword-only `token`. Three fields, one call —
  the enforcement order above is the entire change.
- **Broker side** (external repo): scopes come from a closed-world catalog; bindings
  give each IANUA agent role exactly the scopes its published function needs; `net:egress`
  is bound to **no role** and always escalates to a human (AGENTS.md §5.1).

---

## 4. Implementation Steps

1. Pre-flight per the charter: read `DESIGN.md`, mapped the existing trust boundaries,
   and confirmed the policy layer (`agents/policies/`, decision log 2026-06-19) must be
   composed with, not replaced.
2. Authored the broker design first (ATB-01 identity/policy model, ATB-02 scope catalog
   and delegation rules) and implemented it in the external repository — typed,
   stdlib-only, with a T1–T12 conformance suite where every test asserts a denial.
3. Added `mcp/broker.py` (protocol + binding + gate) and the three-field seam in
   `mcp/server.py`.
4. Wrote `tests/security/test_broker_gate.py` with a dependency-free fake broker:
   missing-token, unbound-tool, deny/escalate/garbage decisions, scope-and-resource
   forwarding, ATB enum-shaped decisions, and the no-broker regression pin.
5. Ran the full §7 gate plus the §7.1 format check; merged via reviewed PR
   ([#119](https://github.com/IRsoctierDT/IANUA/pull/119)) with all required CI green.

---

## 5. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Broker outage bricks the tool surface | Broker is optional per registry; when configured, failing closed is the *intended* posture — availability of privileged tools is subordinate to authorization integrity |
| Scope/binding drift vs. actual tool behavior | Bindings live in the broker repo as reviewed code; the broker's closed-world catalog rejects unregistered scopes at import time |
| Injection that stays *within* granted scopes | Not addressed by authorization (by design); residual risk is owned by human review of consequential outputs — documented in THR-0002 |
| Two audit trails (registry's + broker's) diverge | Both are hash-chained and append-only; broker decisions carry the caller identity, registry decisions carry the action class — correlation, not duplication |

---

## 6. Cost Considerations

Zero new dependencies, zero services, zero network calls. The broker evaluation is pure
in-memory computation (HMAC verify + set membership + pattern match) — negligible
per-dispatch overhead. The external broker repo runs its own CI; IANUA's pipeline is
unchanged beyond the new security tests.

---

## 7. Future Enhancements

- **Escalation queue (ATB Milestone 2)** — persist `escalate` decisions and record the
  human approval/denial as part of the audit chain, closing the loop on §5.1 gates.
- **Bound default tools** — ship `BrokerBinding`s for the built-in registry tools so a
  brokered deployment is turnkey.
- **Decision-log cross-linking** — stamp the broker's `ATB-DEC-` id into the registry's
  audit record for one-hop correlation between the two chains.
- **Orchestrator integration** — mint per-sub-agent delegated identities in the
  orchestrator so multi-agent runs carry attenuated, revocable authority end to end.
