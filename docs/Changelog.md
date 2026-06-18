# Changelog

All notable changes to this project. Versions correspond to git tags.

## v1.8.0 — Agent suite complete

**Milestone: all eight agent blueprints from `03_Agent_Blueprints.md` are built.**

### Added
- **Knowledge Base Agent** — grounds incident reports in the curated cybersecurity
  corpus; deterministic term-overlap retrieval, wired into the orchestrator and the
  incident report ("Knowledge Base References" section).
- **Opt-in semantic retrieval** for the Knowledge Base Agent (`mode="semantic"`):
  local-embedding cosine ranking via the loopback-only, fail-closed `OllamaEmbedder`,
  with automatic fallback to lexical when Ollama is unreachable.
- **Vulnerability Assessment Agent** — ranks authorized scan findings into a
  remediation priority order (no scanning; unrated findings stay "unknown").
- **Legal/Compliance Research Agent** — triages a legal inquiry into a
  verify-don't-assert authority checklist (no advice, no fabricated citations).
- **Business Proposal Agent** — structures client needs into a reviewable
  proposal / SOW draft (drafts only, no invented pricing).
- **Knowledge Curator Agent** — organizes raw notes into retrieval-ready KB entries.
- **Portfolio Documentation Agent** — drafts READMEs/case studies in the AGENTS.md
  §9 structure.
- **Executive Assistant Agent** — prioritizes tasks/notes into a reviewable plan
  with blockers and a decision-log template.
- **SOC Analyst Agent v0.2 case study** (`docs/case-studies/`).
- Expanded, **source-cited** cybersecurity knowledge base (OWASP Top 10:2025,
  MITRE ATT&CK, NIST CSF 2.0, CIS Controls v8.1, Security+ SY0-701, SOC).

### Changed
- Dashboard SOC tab shows a severity metric and surfaces KB references; dashboard
  dependencies declared (`pip install -e ".[dashboard]"`) and added to the mypy gate.
- `OrchestratorAgent.process_log` takes an explicit `report_path` (test isolation).
- CI hardened: gitleaks `pull-requests: read`, CodeQL v4 + `actions: read`, all
  GitHub Actions bumped to Node 24-native versions; `SECURITY.md` refreshed.

### Quality
- Test suite expanded to **135 passing**, **~93% coverage**; ruff + mypy + bandit
  green across `agents`, `scripts`, `tests`, and `dashboard`.

## v1.7.0
- Fix dashboard health panel integration

## v1.6.0
- Add dashboard knowledge base search

## v1.5.0
- Add category-filtered knowledge base search

## v1.4.0
- Expand chunked ingestion across the full knowledge base

## v1.3.0
- Expand cybersecurity knowledge base sources

## v1.1.0
- Add dashboard documentation and screenshot checklist

## v1.0.0
- Add v1 usage guide and release notes

## v0.9.0
- Add batch log processing CLI

## v0.8.0
- Add CLI runner for incident workflow

## v0.7.0
- Add orchestrator agent

## v0.6.0
- Add PDF incident report generation

## v0.5.0
- Added Threat Intelligence Agent
- Added indicator classification
- Added threat intelligence test suite

## v0.4.0
- Added MITRE Mapper Agent
- Integrated MITRE ATT&CK mapping into incident reports

## v0.3.0
- Added Incident Report Agent

## v0.2.0
- Added chunked RAG pipeline

## v0.1.0
- Initial local AI stack
