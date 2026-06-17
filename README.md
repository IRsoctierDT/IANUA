# AI Operator Cyber Command Center

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
| **SOC Analyst Agent v0.2** — JSON/text log triage, severity scoring (0-100), evidence table, MITRE mapping, incident report | Agent | Complete |
| **SOC Analyst Agent v0.2** — JSON/text log triage, severity scoring (0-100), evidence table, MITRE mapping, incident report ([case study](./docs/case-studies/soc-analyst-v0.2.md)) | Agent | Complete |
| **Incident Report Agent** — Markdown incident reports from structured SOC + MITRE output | Agent | Complete |
| **MITRE Mapper Agent** — ATT&CK tactic/technique mapping with confidence scoring | Agent | Complete |
| **Threat Intel Agent** — IOC enrichment and indicator summarization | Agent | Complete |
| **Orchestrator Agent** — Multi-agent workflow coordination | Agent | Complete |
| **RAG Pipeline** — Local document ingestion → chunking → Ollama embeddings → in-memory retrieval | RAG | Complete |
| **MCP Server** — Model context protocol server (stdio JSON-RPC) with allow-listed, validated tools | MCP | Complete |
| **Governance system** — `AGENTS.md` operating charter, CI/CD with bandit + gitleaks + pip-audit + mypy, least-privilege job permissions | Governance | Active |
| **Dashboard** — AI ops UI with tabbed layout | Dashboard | In Progress |

**Agents planned:** Legal/Compliance Research · Business Proposal · Knowledge Curator · Portfolio Documentation · Executive Assistant

### Case studies

- [SOC Analyst Agent v0.2](./docs/case-studies/soc-analyst-v0.2.md) — raw log line → triaged, MITRE-mapped, human-reviewable incident report, fully local.

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

---

## Quality gates (must be green — [`AGENTS.md`](./AGENTS.md) §7)

```bash
python -m compileall .
python -m pytest                 # unit + integration + security; 85% coverage gate
ruff check .
mypy agents scripts tests
bandit -c pyproject.toml -r agents scripts
```

---

## Layout

```
agents/       orchestration, roles, tools, policies   tests/        unit | integration | security
rag/          ingestion → retrieval                    infra/        IaC / deploy (gated)
mcp/          MCP servers exposed to agents            detections/   defensive, lab-scoped content
scripts/      operational CLI entrypoints              data/         lab data only (gitignored)
```

---

> Security tooling here is for **defensive, authorized-lab use only**.
> See [`AGENTS.md`](./AGENTS.md) §5 and [`SECURITY.md`](./SECURITY.md).
