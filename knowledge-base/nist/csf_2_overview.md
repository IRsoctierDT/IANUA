# NIST Cybersecurity Framework (CSF) 2.0 — Overview

**Framework:** NIST Cybersecurity Framework
**Version:** 2.0 (published February 2024)
**Authoritative source:** <https://www.nist.gov/cyberframework>

> CSF 2.0 is a voluntary framework of cybersecurity outcomes, applicable to
> organizations of any size or sector. The headline change from 1.1 is the new
> **Govern** function, which sits across the other five and establishes
> organizational risk-management strategy, roles, and oversight.

## The six functions

| Function | Purpose |
|----------|---------|
| **Govern (GV)** | Establish and monitor cybersecurity risk-management strategy, expectations, and policy. (New in 2.0; cross-cutting.) |
| **Identify (ID)** | Understand assets, suppliers, and risks to systems, people, and data. |
| **Protect (PR)** | Safeguards to manage risk — access control, awareness, data security, platform security. |
| **Detect (DE)** | Find and analyze possible attacks and compromises. |
| **Respond (RS)** | Take action on a detected incident — triage, analysis, mitigation, communication. |
| **Recover (RC)** | Restore assets and operations affected by an incident. |

## Structure

The framework Core is organized as **Functions → Categories → Subcategories**
(specific outcomes). CSF 2.0 also provides **Implementation Tiers** (Partial →
Risk Informed → Repeatable → Adaptive) and **Profiles** (current vs. target state)
to scope and prioritize adoption.

## How this knowledge base uses it

The AI Operator Cyber Command Center structures its incident response, evidence
handling, and governance documentation around CSF functions:

- **Detect / Respond** — the SOC Analyst and Orchestrator agents map directly to
  detection and response outcomes.
- **Govern** — `AGENTS.md` and the approval gates implement governance-function
  expectations (roles, risk strategy, oversight).
- **Identify / Protect / Recover** — guide future roadmap items.

> CSF 2.0 aligns with **CIS Controls v8.1** (see `knowledge-base/cis/`), which maps
> its safeguards to the six functions.
