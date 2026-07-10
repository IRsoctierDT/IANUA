# AI Operator Cyber Command Center

## Current Version

v1.8.0 — **agent suite complete** (all eight core agent blueprints built, plus
supporting agents). See [`docs/Changelog.md`](./Changelog.md) for the full history.

## Operational Components

### Infrastructure

- GitHub Repository (public) with branch protection + full CI/CD
- Python virtual environment (`uv.lock` as the dependency source of truth)
- Docker / Ollama / Qdrant local stack
- VS Code development environment

### AI Components

- Sentence Transformers (local embeddings)
- Qwen3:4B via Ollama (loopback-only, fail-closed)
- Local RAG pipeline (ingest → chunk → embed → cited retrieval; offline mode)
- Vector stores: in-memory (default) + persistent SQLite (`rag/vector_store.py`,
  survives restarts) behind one `VectorStore` protocol

### Agents

Core blueprints:

- SOC Analyst Agent
- MITRE ATT&CK Mapper Agent
- Threat Intelligence Agent
- Vulnerability Assessment Agent
- Knowledge Base Agent
- Incident Report Agent
- Detection Matcher Agent
- Orchestrator Agent

Supporting agents:

- Legal / Compliance Research Agent
- Business Proposal Agent
- Knowledge Curator Agent
- Portfolio Documentation Agent
- Executive Assistant Agent

### Interfaces & Governance

- Streamlit command-center dashboard (SOC workflow, batch, KB search, health, reports)
- Published **status page** (`docs/status.html`) — deterministically generated from
  `docs/status.data.json`, drift-gated in CI, served via GitHub Pages
- Policy-gated MCP tool surface (allow-listed, path-confined, self-validating)
- Policy engine (default-deny policy-as-code) + tamper-evident, hash-chained audit log
- CI/CD: ruff, mypy, bandit, pip-audit, gitleaks, coverage gate, CycloneDX SBOM
- Signed **SBOM + SLSA build-provenance** attestations (Sigstore/OIDC, verified on `main`)

### Qdrant Collections

- cybersecurity_kb
- cybersecurity_kb_chunks
- soc_events

## Completed Milestones

### v0.1.0

- Local AI stack operational; SOC Analyst Agent; Qdrant integration

### v0.2.0

- Chunked RAG ingestion; citation-aware retrieval; Ollama integration

### v0.3.0

- Incident Report Agent; Markdown report generation

### v1.x — agent suite build-out

- MITRE mapper, threat intel, vulnerability assessment, knowledge base,
  detection matcher, and orchestrator agents
- Supporting agents (legal/compliance, business proposal, knowledge curator,
  portfolio documentation, executive assistant)

### v1.8.0 — agent suite complete

- All eight core agent blueprints built
- Source-cited cybersecurity knowledge base (OWASP Top 10:2025, MITRE ATT&CK,
  NIST CSF 2.0, CIS Controls v8.1, Security+ SY0-701)
- Portfolio-grade case studies for every component (`docs/case-studies/`)

## Current Model Inventory

- qwen3:4b

## Hardening Status

See [`docs/HARDENING_ROADMAP.md`](./HARDENING_ROADMAP.md).

- ✅ Policy-as-code allow/deny layer
- ✅ Tamper-evident audit logging (hash-chained; rotation + retention with a
  checkpoint that keeps pruned history detectable)
- ✅ Property-based fuzzing of tool input validators
- ✅ Signed SBOM + SLSA build-provenance attestation in CI
- ✅ Rootless seccomp/AppArmor sandbox for MCP tool execution (report-mode
  default; enforce mode on Linux hosts with a rootless runtime, fail-closed)

## Outstanding / Next

- ✅ Signed audit-log head hash — HMAC (`AUDIT_HMAC_KEY`) or asymmetric Ed25519
  (`.[crypto]`, public-key-only verification); ✅ scheduled retention job
  (`scripts/audit_maintenance.py`)
- Functional: ✅ PDF incident reports (`.[pdf]` extra, reportlab);
  ✅ multi-document ingestion (`rag/ingest.py`); ✅ verifiable passage-level
  source-citation engine (`rag/citations.py`, `KnowledgeBaseAgent.cite()`)

## Repository Status

Operational
