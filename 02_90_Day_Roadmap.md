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
