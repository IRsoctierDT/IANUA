# Response Layer — containment as a plan, not a capability

> **IANUA does not execute containment actions.** `agents/response/` produces
> a draft plan a human operator carries out. There is no executor, no arming
> flag, and no code path from a plan to a host —
> `tests/security/test_response_no_executor.py` fails the build if one appears.

## Purpose · Risk level · Skill level · Deployment complexity

- **Purpose:** turn triage output into evidence-linked, ATT&CK-anchored
  containment guidance with per-action rollback and a named human owner.
- **Risk level:** low by construction — the artifact is text; nothing acts.
- **Skill level required:** incident-response experience to execute the plan;
  none to read it.
- **Deployment complexity:** none; no agents, credentials, or connectivity.

## Why the boundary is closed

This is not caution for its own sake. Four properties of *this repository*
make execution unbuildable today without weakening something:

| Control | What it means for execution |
|---|---|
| `mcp/sandbox` hard-codes `--network none`, `--cap-drop ALL`, `--read-only`, no PID namespace | It cannot signal a host process or hold `CAP_NET_ADMIN`. Making it able to would weaken an existing control (AGENTS.md §2.6). |
| `agents/policies/approval.py` resolves its allow-list **before** the policy table | An allow-list entry is a standing, permanent, unscoped grant — not per-invocation human approval. |
| `guarded.enforce(report_only=True)` | Bypasses the raise entirely; it is a reporting mode, not an approval mode. |
| `AuditLogger.record` takes five strings, no payload slot | An approval could not be bound to a specific target even if one existed. |

Add to that: the repository has **no caller identity**. Opening this boundary
therefore requires designing an explicit, signed, expiring, per-target
approval primitive first — a separate reviewed change, never a flag.

There is also an operational argument. A containment action driven by a
poisoned intel entry or a false positive is a self-inflicted outage, and an
agent holding kill authority on a compromised host is itself a
privilege-escalation target. The detection substrate here is a keyword
classifier plus a modest rule corpus with an unquantified false-positive
rate. Automating disruption on that basis would be indefensible.

## The tiered model

| Tier | What | Who acts |
|---|---|---|
| **0 — Collect** | Memory capture, process tree, log preservation. Always first. | Human analyst |
| **1 — Plan** | *This artifact.* Generated automatically; executes nothing. | IANUA |
| **2 — Reversible containment** | Session revocation, host network isolation, scoped egress block. | Human administrator |
| **3 — Irreversible** | Credential reset, file quarantine, process termination. | Human administrator |

**Ordering is a safety property, not presentation.** Plans always order
tier 0 before tier 2 before tier 3, and every evidence-affecting action pulls
its prerequisite ahead of itself. Terminating a process destroys its volatile
memory — frequently the only place an implant is unpacked and its
configuration readable — so memory capture is a hard prerequisite, asserted
by a security test.

## What the schema cannot express

Catalogue verbs are a closed allow-list: `collect`, `revoke`, `isolate`,
`block`, `reset`, `quarantine`, `terminate`. Every one *restricts* an
adversary's capability. There is deliberately no verb for gaining access,
moving laterally, scanning, or acting on a third party — an offensive action
cannot be written into this catalogue, and a test asserts the allow-list
never admits one. Validation additionally requires a human `owner`, a
rollback statement (irreversible actions must say plainly that they cannot be
undone), and a prerequisite on anything evidence-affecting.

## Weak signal produces no plan

`plan_for_event` returns `None` when the attributed techniques do not warrant
containment — a port scan or an unattributed IDS alert gets nothing. Proposing
action on weak evidence is precisely how false positives become outages, so
the absence of a plan is a designed outcome, not a gap.

## Allow-list projection

Plans serialize through an explicit field projection over frozen dataclasses:
only declared fields are emitted. Raw log text, incident free-text, and
environment values have no field to travel in. The single caller-supplied
string is a target label, reduced to a bounded identifier alphabet.
`tests/security/test_response_plan_no_leak.py` seeds incidents with an API
key, a `.env` line, a bearer token, a PEM header, and a password, and asserts
none survives into any rendering.
