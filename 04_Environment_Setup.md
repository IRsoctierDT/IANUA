# Environment Setup

## Required Local Stack

- Homebrew
- Git
- Python 3.12+
- VS Code or Cursor
- Docker or Podman
- Ollama
- PostgreSQL
- Qdrant
- Node.js
- GitHub CLI

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

## Validate Local AI Stack

```bash
ollama run llama3.1
curl http://localhost:6333
psql postgres
python agents/soc_analyst_agent.py
pytest
```
