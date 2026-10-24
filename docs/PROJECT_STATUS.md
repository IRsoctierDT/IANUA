# IANUA

## Current Version

v2.3.1 — **Immutable Releases & Gate Hardening** — a patch release on v2.3.0's SOC
platform, whose components are listed under **SOC Platform** below. It is the first
immutable release: GitHub locks a published release's tag and assets, and the release
workflow never uploads to a locked release. It also tightens three gates. A file
named like an option can no longer make the pre-commit secret scan pass. The
pre-commit hooks run the locked toolchain rather than pins of their own. Compliance
control CFG-02 accepts only IP literals, so a dashboard bound to `localhost` now
fails it. See [`docs/Changelog.md`](./Changelog.md) for the full history, including
the known issue carried over from v2.3.0.

## Operational Components

### Infrastructure

- GitHub Repository (public) with branch protection + full CI/CD
- Python virtual environment (`uv.lock` as the dependency source of truth)
- Docker / Ollama / Qdrant local stack
- VS Code development environment

### SOC Platform

- `store/` — durable, append-only event store (stdlib `sqlite3`), tamper-evident
  on read and attestable for backup
- `correlation/` — entity resolution across domains and incident assembly
- `pipeline/` + `scripts/run_pipeline.py` — scheduled detection cycle
  (at-least-once, resumable cursor)
- `collect/` + `scripts/run_collector.py` — local log collection from
  operator-declared, read-only sources
- `scripts/run_retention.py` — retention that reports by default and deletes only
  under a committed grant
- `scripts/run_backup.py` — verifiable backup, `--verify`, and the
  `--verify-restore` promotion gate (`docs/RESTORE.md`)
- `sli/` + `scripts/report_sli.py` — service-level indicators for the platform
  itself (fail-closed)

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

### v1.9.0 — tamper-evident audit, sandboxed tools, verifiable RAG

- Default-deny policy engine with a tamper-evident audit log, enforced at the MCP
  tool surface
- Rootless seccomp/AppArmor container sandbox for MCP tools, enforced by a
  real-container CI job
- Passage-level source citations, a persistent SQLite vector store, and PDF
  export for incident reports
- CycloneDX SBOM with Sigstore-signed SBOM and SLSA provenance attestations;
  `uv.lock` as the dependency source of truth, behind a drift gate

### v2.0.0 — the IANUA identity era

- The platform is IANUA everywhere: repository, docs, Pages and dashboard, with
  `scripts/rename_to_ianua.py --check` guarding against legacy identifiers
- One-click GitHub Codespaces test environment (`.devcontainer/`)
- Dashboard batch flow runs the correlated sequence pipeline

### v2.1.0 — Detection Intelligence & XDR Foundation

- Multi-source telemetry ingest (`ingest/`): ten log sources across five domains,
  normalized into one event shape with OCSF classification
- Detection-intelligence layer: a version-pinned, hash-verified local MITRE
  ATT&CK corpus (`attack/`) and a reviewed mapping ruleset (`agents/mapping/`)
- Apache-2.0 licensing

### v2.2.0 — Release Automation & Control Integrity

- Release automation: `scripts/prepare_release.py` and a human-approved,
  CI-verified tag-and-publish flow (`docs/RELEASING.md`)
- The attestation-expiry gate compares against the current date, with a
  30-day warning window
- Path and assertion reconciliation audit (`docs/PATH_RECONCILIATION_AUDIT.md`)

### v2.3.0 — Production SOC Foundations

- The seven SOC platform components listed under **SOC Platform** above: event
  store, correlation, detection cycle, collection, retention, backup and
  restore verification, and the platform's own SLIs
- GitHub Releases publish the curated changelog section as their body

### v2.3.1 — Immutable Releases & Gate Hardening

- Releases are immutable: tags and assets lock when published, and `release.yml`
  never uploads to a locked release
- Pre-commit hooks run the locked toolchain, and a dash-named file can no longer
  pass the secret scan
- Compliance control CFG-02 accepts IP literals only

## Current Model Inventory

- qwen3:4b

## Hardening Status

See [`docs/HARDENING_ROADMAP.md`](./HARDENING_ROADMAP.md).

- ✅ Policy-as-code allow/deny layer
- ✅ Tamper-evident audit logging (hash-chained; rotation + retention with a
  checkpoint that keeps pruned history detectable)
- ✅ Property-based fuzzing of tool input validators, plus coverage-guided fuzzing
  (Atheris) of the parsers that read untrusted input
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
