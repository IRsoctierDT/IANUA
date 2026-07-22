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
