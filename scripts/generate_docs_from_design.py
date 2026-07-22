"""Regenerate core Markdown files from the STICHES/DESIGN.md identity.

Deterministic and idempotent: each run writes the same content for the same
templates. ``README.md`` is deliberately NOT generated — it is a curated,
hand-maintained document, and regenerating it from a template would destroy
it (this happened once; the exclusion is the fix).
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content.strip() + "\n", encoding="utf-8")


def generate() -> None:
    if not (ROOT / "DESIGN.md").exists():
        raise FileNotFoundError("DESIGN.md is required in the project root.")
    write(
        "00_Project_Charter.md",
        """
# Project Charter

## Project Name

IANUA™ — Master v2 STICHES Edition

## Purpose

Create a professional-grade command center for AI operations, cybersecurity automation, agentic workflows, RAG knowledge systems, governance, and portfolio development.

## Strategic Position

The project develops operator capability: the ability to design, govern, secure, and document repeatable AI-enabled systems.

## Objectives

- Build AI agents for cybersecurity, research, documentation, and business workflows.
- Develop a governed RAG knowledge system.
- Produce portfolio-ready evidence of practical technical skill.
- Maintain safety, auditability, and human approval gates.
- Use STICHES/DESIGN.md as the canonical identity system.

## Success Standard

Every major workflow must be repeatable, documented, testable, secure, explainable, and portfolio-ready.
""",
    )
    write(
        "01_Architecture.md",
        """
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
""",
    )
    write(
        "02_90_Day_Roadmap.md",
        """
# 90-Day Roadmap

## Cycle 1 (completed) — Foundation to v2.0.0

The original 90-day plan is done and shipped:

- Repository, charter (AGENTS.md), STICHES/DESIGN.md identity, CI. ✅
- SOC Analyst Agent through v0.2 and beyond: JSON input, severity scoring,
  multi-event sequence correlation. ✅
- RAG knowledge system: ingestion, chunking, embedded vector store,
  rarity-weighted retrieval, verified citations. ✅
- All eight agent blueprints implemented (see `03_Agent_Blueprints.md`). ✅
- Governance enforced in code: default-deny policy engine, tamper-evident
  signed audit chain, sandboxed MCP tool execution. ✅
- Markdown + PDF incident reports; Streamlit command center; GitHub Pages
  status site behind a human approval gate. ✅
- Supply chain: SBOM attestation, hash-pinned locks, SHA-pinned actions,
  secret-scanning baseline, drift gates. ✅

## Cycle 2 (current) — Enhancement, not new surface

All eight agent blueprints are built; further work deepens existing
components:

- Detection engineering depth: more Sigma rules and chain correlations
  mapped to the agent vocabulary.
- Case studies kept current with each shipped enhancement.
- Coverage and test depth on the newest surfaces (dashboard glue, PDF
  pipeline).
- Operational polish: embedded-Qdrant ingest ergonomics, report enrichment.

Progress is tracked in `docs/PROJECT_STATUS.md` and `docs/Changelog.md`.
""",
    )
    write(
        "03_Agent_Blueprints.md",
        """
# Agent Blueprints

All eight blueprints are **built and operational** (v2.0.0). Every agent
derives its version from `pyproject.toml` automatically and announces itself
as `<Agent> v<platform version>`.

## SOC Analyst Agent — built

Analyzes logs and alerts (string or structured JSON). Produces severity +
score, event type, indicators, recommended actions, assumptions, and
evidence. Correlates ordered event batches into multi-event findings:
brute force and failure-then-success credential compromise.

## Threat Intelligence Agent — built

Classifies and enriches indicators from single events or sequence-wide
indicator unions; deterministic and network-free.

## Vulnerability Assessment Agent — built

Converts scan results into remediation priorities.

## Legal/Compliance Research Agent — built

Supports issue analysis, authority review, citation checklists, and draft
preparation. It does not replace legal counsel.

## Business Proposal Agent — built

Converts client needs into structured proposals and scopes of work.

## Knowledge Curator Agent — built

Organizes notes, transcripts, PDFs, and research into retrieval-ready
knowledge.

## Portfolio Documentation Agent — built

Turns lab work into GitHub-ready README files, reports, and case studies.

## Executive Assistant Agent — built

Supports planning, prioritization, review cycles, and decision logs.

## Supporting agents (beyond the original blueprints)

MITRE Mapper (ATT&CK technique mapping), Incident Report (Markdown/PDF with
sequence findings and verified citations), Knowledge Base (rarity-weighted
retrieval with provenance), Detection Matcher (Sigma content via ATT&CK
tags), and the Orchestrator (single-event and sequence pipelines).
""",
    )
    write(
        "04_Environment_Setup.md",
        """
# Environment Setup

## Required

- Git
- Python 3.11+ (CI runs 3.11 and 3.12)

## Optional (feature-dependent)

- Ollama — local LLM narratives (`LLM_MODEL`, pipeline works without it)
- Docker or Podman — compose lab stack and sandbox-enforcement tests
- Node.js — DESIGN.md lint tooling and npm SBOM regeneration

Qdrant needs **no install**: the vector store runs embedded (in-process,
zero listening ports) unless `QDRANT_URL` opts in to a server.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
pre-commit install && pre-commit install --hook-type pre-push
cp .env.example .env   # documented keys only; fill locally, never commit
```

Dashboard extras: `pip install -e ".[dashboard]"` (Streamlit, qdrant-client,
sentence-transformers).

## Validate

```bash
python -m pytest
ruff check . && ruff format --check .
mypy agents scripts tests dashboard mcp rag
bandit -c pyproject.toml -r agents scripts mcp
python agents/soc_analyst_agent.py
streamlit run dashboard/app.py
```

## Zero-install alternative

GitHub Codespaces: **Code → Codespaces → Create** on the repository page.
The devcontainer installs everything and launches the dashboard in your
browser (port 8501, private by default).
""",
    )
    write(
        "05_Governance_Rules.md",
        """
# Governance Rules

`AGENTS.md` is the binding operating charter; these are the operating rules
in brief.

## Mandatory Controls

1. No secrets in GitHub — enforced by gitleaks in CI and a reviewed
   detect-secrets baseline in pre-commit.
2. No sensitive client, legal, or personal data in public repositories.
3. No unauthorized scanning or offensive tooling — lawful-lab scope only.
4. Human approval required for destructive or external actions — codified
   in the default-deny policy engine (`agents/policies/`), enforced at the
   MCP tool surface, and recorded in a tamper-evident signed audit chain.
5. High-stakes outputs must separate facts, assumptions, analysis,
   recommendations, and unknowns.
6. Meaningful code changes must be tested — CI gates: pytest with ≥85%
   coverage, ruff, mypy, bandit, pip-audit, CodeQL, drift gates.
7. Agent-generated documents must follow `DESIGN.md`.

## Human Approval Required Before

- Sending emails
- Filing complaints
- Publishing reports
- Running scans outside an authorized lab
- Changing firewall rules
- Deleting data
- Installing unknown software
- Using sensitive personal data
- Deploying GitHub Pages (the `github-pages` environment gate is kept by
  design and is never to be weakened or bypassed)
""",
    )
    write(
        "06_Portfolio_Tracker.md",
        """
# Portfolio Tracker

| Project | Skill Demonstrated | Status | Evidence |
|---|---|---:|---|
| SOC Analyst Agent (+ sequence correlation) | Cybersecurity automation | Shipped | `agents/`, `docs/case-studies/soc-analyst-v0.2.md` |
| RAG Knowledge Base (verified citations) | Retrieval systems | Shipped | `rag/`, `docs/case-studies/rag-pipeline.md` |
| Policy Engine + Tamper-Evident Audit | AI safety and controls | Shipped | `agents/policies/`, `docs/case-studies/policy-and-audit.md` |
| MCP Server + Sandboxed Tools | Secure agent infrastructure | Shipped | `mcp/`, `docs/case-studies/mcp-server.md` |
| Detection Engineering (Sigma) | Detection content | Shipped | `detections/`, `docs/case-studies/detection-matcher-and-orchestrator.md` |
| Streamlit Command Center | Full-stack AI operations | Shipped | `dashboard/`, `docs/dashboard/STREAMLIT_DASHBOARD.md` |
| Incident Reports (Markdown + PDF) | Reporting automation | Shipped | `docs/case-studies/incident-report-agent.md` |
| Supply Chain (SBOM, pins, drift gates) | Software supply-chain security | Shipped | `security/sbom/`, CI workflows |
| Legal/Compliance Agent | Research workflow | Shipped | `agents/legal_compliance_agent.py` |
| Business Proposal Agent | Business automation | Shipped | `agents/business_proposal_agent.py` |
| STICHES/DESIGN.md System | Design-system governance | Active | `DESIGN.md` |
| Governance System | AI safety and controls | Active | `AGENTS.md` and policies |
""",
    )
    write(
        "07_First_Build_Sprint.md",
        """
# First Build Sprint (historical record — completed)

This sprint is **done**; it bootstrapped the repository that became
IANUA v2.0.0. Kept as a record of the founding definition-of-done.

## Goal

Make the project executable, testable, reviewable, and design-system
governed.

## Definition of Done (all met)

- `python agents/soc_analyst_agent.py` runs. ✅
- `pytest` passes. ✅
- `DESIGN.md` exists. ✅
- `AGENTS.md` exists. ✅
- GitHub CI exists. ✅
- Documentation regeneration script exists. ✅

## Current cadence

Work now lands as reviewed pull requests gated by the full CI pipeline
(AGENTS.md §7-§8), tracked in `docs/PROJECT_STATUS.md`, logged in
`docs/ENGINEERING_LOG.md`, and released via tagged versions in
`docs/Changelog.md`.
""",
    )
    write(
        "08_Codex_Review_Workflow.md",
        """
# Codex Review Workflow

## Purpose

Use Codex as a disciplined review partner for bugs, edge cases, test gaps,
security risks, and repository consistency — on top of the automated gates
(ruff, mypy, bandit, pip-audit, gitleaks, CodeQL, pytest + coverage, drift
gates), which run on every pull request.

## PR Review Prompt

```text
@codex review

Please focus on security defects, logic errors, unhandled edge cases, unsafe external actions, missing tests, and violations of AGENTS.md or DESIGN.md.
```

## Required Review Areas

- Security (AGENTS.md §6.1 priority order: security → logic → edge cases →
  unsafe execution → validation → tests → docs → design drift)
- Type safety
- Test coverage
- Documentation accuracy
- Human approval gates
- Repository conventions
- STICHES/DESIGN.md consistency

## Closing the loop

Every review finding gets a reply citing the fix commit, and the thread is
resolved once addressed — findings are never silently dismissed.
""",
    )
    write(
        "09_Master_Architecture_Blueprint.md",
        """
# Master Architecture Blueprint

## Command-Center Model

This project is a layered AI operations system, not a loose collection of
scripts. As of v2.0.0 all ten layers are operational.

## Core Layers

1. Development Console — venv/uv toolchain, pre-commit, Codespaces
2. AI Model Layer — local Ollama (optional; pipeline is deterministic
   without it)
3. Knowledge Layer — curated corpus under `knowledge-base/`
4. RAG Layer — ingestion, chunking, embedded vector store, rarity-weighted
   retrieval, verified citations
5. Agent Layer — eight blueprints + supporting agents, auto-versioned
6. Cybersecurity Lab Layer — Sigma detections, sample-log fixtures,
   compose lab stack
7. Automation Layer — orchestrated pipelines (single-event and sequence),
   scheduled maintenance CLIs
8. Governance Layer — policy engine, signed audit chain, sandbox,
   approval gates
9. Portfolio Layer — case studies, status page, portfolio docs
10. Dashboard Layer — Streamlit command center

## STICHES/DESIGN.md Layer

The design layer governs documentation identity, dashboard styling,
agent-generated report structure, and future UI token exports.

## Build Stance

All eight agent blueprints are built. Further work is **enhancement of
existing components, not new surface**: deeper detections, richer reports,
harder gates, better tests. Candidates and progress live in
`docs/PROJECT_STATUS.md`.
""",
    )
    write(
        "architecture/SYSTEM_MAP.md",
        """
# System Map

## Main Layers

- Local Development
- AI Models
- Knowledge Base
- RAG
- Agents
- Cyber Lab
- Automations
- Governance
- Portfolio
- Dashboard
- STICHES/DESIGN.md Identity

Consult `../DESIGN.md` before generating UI, dashboard, documentation, or portfolio surfaces.
""",
    )
    write(
        "portfolio/12_Month_Portfolio_Roadmap.md",
        """
# 12-Month Portfolio Roadmap

## Quarter 1 — done

Foundation, SOC Analyst Agent, CI, tests, prompt library, STICHES/DESIGN.md integration.

## Quarter 2 — done

RAG system, Knowledge Curator Agent, Legal/Compliance Research Agent.

## Quarter 3 — done (expanded)

Incident reporting (Markdown + PDF), vulnerability assessment, detection
engineering (Sigma + chain correlations), policy/audit enforcement,
sandboxed MCP tools, supply-chain attestation.

## Quarter 4 — in progress

Dashboard shipped (Streamlit command center) and portfolio case studies
published; remaining: pfSense/Suricata lab workflows and the professional
presentation package.
""",
    )
    write(
        "workflows/OPERATOR_WORKFLOWS.md",
        """
# Operator Workflows

## Cyber Log to Incident Report

Classify event, estimate severity, extract indicators, and generate a report.

## Log Batch to Correlated Incident

Upload or select an ordered event batch; the sequence pipeline correlates
multi-event patterns (brute force, failure-then-success), anchors the report
on the most severe event, and attaches verified citations.

## Document to Knowledge Base

Ingest, summarize, tag, chunk, and store for retrieval.

## Legal/Compliance Issue to Research Outline

Separate facts, authority, analysis, recommendations, and unknowns.

## Lab Work to Portfolio

Convert commands, screenshots, observations, and findings into a GitHub-ready case study.

## Design-System Regeneration

Update `DESIGN.md`, then run:

```bash
python scripts/generate_docs_from_design.py
```
""",
    )
    write(
        "security/DATA_CLASSIFICATION.md",
        """
# Data Classification

## Public

Safe for GitHub.

## Internal

Private planning and non-sensitive drafts.

## Confidential

Client data, legal facts, personal identifiers, secrets, tokens, private logs.

## Rule

When uncertain, classify as Confidential.
""",
    )
    write(
        "dashboards/DASHBOARD_CONCEPT.md",
        """
# Dashboard Concept

## Purpose

Create an operational view of agents, cyber alerts, knowledge ingestion, project status, and portfolio progress.

## Status

Shipped as the Streamlit command center (`dashboard/app.py`): SOC workflow,
batch sequence correlation, knowledge-base search (fail-soft backends),
system health, and report views. See `docs/dashboard/STREAMLIT_DASHBOARD.md`.

## STICHES/DESIGN.md Guidance

Dashboard components should use the design tokens in `DESIGN.md` and preserve the command-center identity.

## Future Modules

- Agent status
- Task queue
- Alert queue
- Knowledge ingestion queue
- Portfolio progress
- Governance warnings
- Weekly review panel
""",
    )
    write(
        "docs/DESIGN_MD_IMPLEMENTATION.md",
        """
# STICHES / DESIGN.md Implementation

## Purpose

This project uses `DESIGN.md` as the canonical design and documentation identity.

## What DESIGN.md Controls

- Visual identity
- Documentation tone
- Color and typography tokens
- UI and dashboard guidance
- Agent-facing design rationale
- Governance-aware documentation style

## Regenerate Markdown

```bash
python scripts/generate_docs_from_design.py
```

## Validate DESIGN.md

```bash
npx @google/design.md lint DESIGN.md
```

## Export Tokens

```bash
npx @google/design.md export --format json-tailwind DESIGN.md > tailwind.theme.json
npx @google/design.md export --format css-tailwind DESIGN.md > theme.css
```
""",
    )


if __name__ == "__main__":
    generate()
    print("Generated Master v2 STICHES Markdown files.")
