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
