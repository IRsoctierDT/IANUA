# IANUA

A **portfolio-grade, local-first command center** for AI operations, cybersecurity
automation, RAG knowledge systems, and agentic workflows — built secure-by-default
(least privilege, auditability, defense-in-depth, human-in-the-loop for every
irreversible action).

Every component is designed to demonstrate repeatable, documented, testable, and
reviewable engineering — suitable for a portfolio, a client engagement, or a production
security operation.

---

## What's built

| Component | Layer | Status |
|---|---|---|
| **SOC Analyst Agent v0.2** — JSON/text log triage, severity scoring (0-100), evidence table, MITRE mapping, incident report ([case study](./docs/case-studies/soc-analyst-v0.2.md)) | Agent | Complete |
| **Incident Report Agent** — Markdown incident reports from structured SOC + MITRE output | Agent | Complete |
| **MITRE Mapper Agent** — ATT&CK tactic/technique mapping with confidence scoring | Agent | Complete |
| **Threat Intel Agent** — IOC enrichment and indicator summarization | Agent | Complete |
| **Vulnerability Assessment Agent** — ranks authorized scan findings into a remediation priority order ([doc](./docs/agents/VULNERABILITY_ASSESSMENT_AGENT.md)) | Agent | Complete |
| **Knowledge Base Agent** — grounds incident reports in the cited cybersecurity corpus | Agent | Complete |
| **Business Proposal Agent** — structures client needs into a reviewable proposal / SOW draft ([doc](./docs/agents/BUSINESS_PROPOSAL_AGENT.md)) | Agent | Complete |
| **Legal/Compliance Research Agent** — triages a legal inquiry into a verify-don't-assert authority checklist ([doc](./docs/agents/LEGAL_COMPLIANCE_AGENT.md)) | Agent | Complete |
| **Knowledge Curator Agent** — organizes raw notes into retrieval-ready KB entries ([doc](./docs/agents/KNOWLEDGE_CURATOR_AGENT.md)) | Agent | Complete |
| **Portfolio Documentation Agent** — drafts GitHub-ready READMEs/case studies (AGENTS.md §9 structure) ([doc](./docs/agents/PORTFOLIO_DOCUMENTATION_AGENT.md)) | Agent | Complete |
| **Executive Assistant Agent** — prioritizes tasks/notes into a reviewable plan with blockers & decision log ([doc](./docs/agents/EXECUTIVE_ASSISTANT_AGENT.md)) | Agent | Complete |
| **Orchestrator Agent** — Multi-agent workflow coordination | Agent | Complete |
| **RAG Pipeline** — Local document ingestion → chunking → Ollama embeddings → in-memory retrieval | RAG | Complete |
| **MCP Server** — Model context protocol server (stdio JSON-RPC) with allow-listed, validated tools | MCP | Complete |
| **Governance system** — `AGENTS.md` operating charter, CI/CD with bandit + gitleaks + pip-audit + mypy, least-privilege job permissions | Governance | Active |
| **Dashboard** — Streamlit command center: SOC workflow (severity + KB grounding), batch processing, KB search, system health, reports | Dashboard | Complete |

**All eight agent blueprints are built.** Further work is enhancement, not new surface.

### Case studies

Ten portfolio-grade write-ups — one per component — each following the [AGENTS.md](./AGENTS.md)
§9 standard with a worked example (real command output) and a reproduce-it-yourself section.
Full index: [`docs/case-studies/`](./docs/case-studies/README.md).

| Case study | Layer |
|---|---|
| [SOC Analyst Agent v0.2](./docs/case-studies/soc-analyst-v0.2.md) — raw log line → triaged, MITRE-mapped, human-reviewable incident, fully local | Agent |
| [MITRE ATT&CK Mapper Agent](./docs/case-studies/mitre-mapper-agent.md) — deterministic event → tactic/technique with confidence & evidence | Agent |
| [Threat Intelligence Agent](./docs/case-studies/threat-intel-agent.md) — indicator triage that returns `unknown` + "enrich first" instead of guessing | Agent |
| [Vulnerability Assessment Agent](./docs/case-studies/vulnerability-assessment-agent.md) — ranks authorized scan findings into a defensible remediation order | Agent |
| [Knowledge Base Agent](./docs/case-studies/knowledge-base-agent.md) — cited corpus grounding; deterministic lexical default, safe semantic fallback | Agent/RAG |
| [Incident Report Agent](./docs/case-studies/incident-report-agent.md) — composes a safe Markdown report with an opt-in, fail-soft AI narrative | Agent |
| [Detection Matcher & Orchestrator](./docs/case-studies/detection-matcher-and-orchestrator.md) — triage→Sigma detection loop + full multi-agent pipeline in one call | Agent |
| [Local RAG Pipeline](./docs/case-studies/rag-pipeline.md) — confined ingest → chunk → embed → cited retrieval; fully offline mode | RAG |
| [Policy-Gated MCP Tool Surface](./docs/case-studies/mcp-server.md) — allow-listed, self-validating, path-confined, policy-gated tool calls | MCP |
| [Policy Engine & Tamper-Evident Audit Log](./docs/case-studies/policy-and-audit.md) — default-deny policy-as-code + hash-chained, verifiable audit trail | Governance |

---

## Architecture

Ten-layer command-center model (see [`DESIGN.md`](./DESIGN.md) for full trust boundaries and decision log):

```
Human (approves gates, owns secrets)
    │
    ▼
Orchestrator (agents/)
    ├── Local LLM (Ollama, loopback-only)
    ├── RAG pipeline (rag/) ──► Vector store
    ├── MCP tools (mcp/) ──────► Filesystem / lab data
    └── Detections (detections/)
```

**Architecture rule:** agents recommend, draft, classify, summarize, and structure.
Humans approve destructive, external, legal, financial, or security-sensitive actions.

---

## Governance

| Doc | Purpose |
|---|---|
| [`AGENTS.md`](./AGENTS.md) | Operating charter for any coding agent (also `CLAUDE.md`) |
| [`DESIGN.md`](./DESIGN.md) | Architecture, trust boundaries, decision log |
| [`SECURITY.md`](./SECURITY.md) | Vulnerability reporting & security policy |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | Human + agent contribution workflow |
| [`docs/HARDENING_ROADMAP.md`](./docs/HARDENING_ROADMAP.md) | Planned defense-in-depth hardening workstreams |

---

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
pre-commit install --hook-type pre-push
detect-secrets scan > .secrets.baseline   # one-time, then review & commit
```

**Run the SOC Analyst Agent:**
```bash
python agents/soc_analyst_agent.py
# or pass structured JSON:
python -c "
from agents.soc_analyst_agent import SocAnalystAgent
import json, pprint
result = SocAnalystAgent().analyze_log({
    'timestamp': '2025-06-15T14:00:00Z',
    'host': 'web-01',
    'user': 'root',
    'src_ip': '10.0.0.5',
    'message': 'Accepted password for root from 10.0.0.5 port 22'
})
pprint.pprint(result)
"
```

**One-command RAG pipeline (ingest → embed → query):**
```bash
# Local Ollama embeddings:
python -m scripts.rag_cli --corpus ./corpus --query "zero trust segmentation" --k 3
# Fully offline / no Ollama (deterministic embedder — good for CI/air-gapped labs):
python -m scripts.rag_cli --corpus ./corpus --query "ids tuning" --offline
```

**Run the MCP server (stdio):**
```bash
MCP_ROOT=./data python -m mcp.transport
# Speaks line-delimited JSON-RPC 2.0; methods: initialize | tools/list | tools/call
```

**Run the dashboard (Streamlit command center):**
```bash
pip install -e ".[dashboard]"     # streamlit + qdrant-client + sentence-transformers
streamlit run dashboard/app.py
# Tabs: SOC Workflow · Batch Processing · Knowledge Base Search · System Health · Reports
# KB search and health panels degrade gracefully if Qdrant/Ollama aren't running.
```

---

## Quality gates (must be green — [`AGENTS.md`](./AGENTS.md) §7)

```bash
python -m compileall .
python -m pytest                 # unit + integration + security; 85% coverage gate
ruff check .
mypy agents scripts tests dashboard
bandit -c pyproject.toml -r agents scripts
```

---

## Layout

```
agents/       orchestration, roles, tools, policies   tests/        unit | integration | security
rag/          ingestion → retrieval                    infra/        IaC / deploy (gated)
mcp/          MCP servers exposed to agents            detections/   defensive, lab-scoped content
scripts/      operational & RAG tooling                data/         lab data only (gitignored)
cli/          user-facing entry points — run_incident.py, batch_run_incidents.py
```

---

> Security tooling here is for **defensive, authorized-lab use only**.
> See [`AGENTS.md`](./AGENTS.md) §5 and [`SECURITY.md`](./SECURITY.md).