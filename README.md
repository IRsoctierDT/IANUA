# AI Operator Cyber Command Center

Portfolio-grade environment for **AI operations, cybersecurity automation, RAG systems,
and agentic workflows** — built secure-by-default (least privilege, auditability, defense
in depth, human-in-the-loop for irreversible actions).

## Governance
- **[AGENTS.md](./AGENTS.md)** — operating charter for any coding agent (also `CLAUDE.md`).
- **[DESIGN.md](./DESIGN.md)** — architecture, trust boundaries, decision log.
- **[SECURITY.md](./SECURITY.md)** — vulnerability reporting & policy.
- **[CONTRIBUTING.md](./CONTRIBUTING.md)** — human + agent workflow.

## Quickstart
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
pre-commit install --hook-type pre-push
detect-secrets scan > .secrets.baseline   # one-time, then review & commit
```

## Quality gates (must be green — AGENTS.md §7)
```bash
python -m compileall .
python -m pytest                 # incl. tests/security, 85% coverage gate
ruff check .
mypy agents scripts tests
bandit -c pyproject.toml -r agents scripts
```

## Layout
```
agents/      orchestration, roles, tools, policies   tests/       unit | integration | security
rag/         ingestion → retrieval                   infra/       IaC / deploy (gated)
mcp/         MCP servers exposed to agents            detections/  defensive, lab-scoped content
scripts/     operational CLI entrypoints             data/        lab data only (gitignored)
```

## Run the MCP server (stdio)
```bash
# Speaks line-delimited JSON-RPC 2.0 over stdio; root confined to ./data.
MCP_ROOT=./data python -m mcp.transport
# methods: initialize | tools/list | tools/call
```

## One-command pipeline (ingest → embed → query)
```bash
# Uses local Ollama embeddings:
python -m scripts.rag_cli --corpus ./corpus --query "zero trust segmentation" --k 3
# Fully offline (no Ollama, deterministic embedder) — good for CI/air-gapped labs:
python -m scripts.rag_cli --corpus ./corpus --query "ids tuning" --offline
```

## Embeddings (local Ollama)
```python
from rag.embeddings import OllamaEmbedder   # default-deny egress; loopback only
from rag.ingest import ingest, embed_chunks
from rag.retrieve import InMemoryVectorStore

embedder = OllamaEmbedder(model="nomic-embed-text")   # talks to 127.0.0.1:11434
pairs = embed_chunks(ingest(Path("./corpus")), embedder)
store = InMemoryVectorStore()
for chunk, vec in pairs:
    store.add(chunk, vec)
```
> `OllamaEmbedder` enforces a host allow-list, bounded timeout, and fails closed. To reach a
> non-loopback Ollama host, pass `allowed_hosts=frozenset({...})` deliberately (AGENTS.md §5.1).

> Security tooling here is for **defensive, lawful-lab use only**. See AGENTS.md §5.
