# Architecture

## Summary

IANUA is a layered, local-first AI operations platform. As of v2.0.0 every
layer is operational: a deterministic agent pipeline (SOC analysis with
multi-event sequence correlation, MITRE ATT&CK mapping, threat intel,
incident reports with verified passage citations), a governed RAG knowledge
system (rarity-weighted retrieval, embedded-by-default Qdrant), a default-deny
policy engine with a tamper-evident signed audit chain enforced at the MCP
tool surface, sandboxed tool execution, a Streamlit command center, and a
fail-fast CI pipeline with drift gates and a human-approved Pages deploy.

## Architecture Rule

Agents recommend, draft, classify, summarize, and structure. Humans approve
destructive, external, legal, financial, or security-sensitive actions.

## Where the Detail Lives

- `DESIGN.md` — canonical architecture, trust boundaries, decision log.
- `AGENTS.md` — the binding operating charter (gates, boundaries, roles).
- `docs/PROJECT_STATUS.md` — current version and component status.
- `docs/case-studies/` — per-component engineering case studies.

## STICHES Integration

`DESIGN.md` controls the documentation and UI identity. Any dashboard,
report, or agent-generated artifact follows its color, typography, layout,
and governance rules.
