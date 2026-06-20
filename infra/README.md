# Infra — Local Lab Stack

## Purpose

A reproducible local stack for the services the command center talks to: **Ollama**
(local LLM + embeddings), **Qdrant** (vector store), and **Postgres** (provisioned per
the Environment Setup). Brings the project's "local-first AI stack" from documentation
to a one-command, runnable environment.

| | |
|---|---|
| **Risk level** | Low — local lab only; all ports bound to `127.0.0.1`, no external exposure |
| **Skill level required** | Basic Docker |
| **Deployment complexity** | Low — `docker compose up -d` |

## Objectives

1. Make the documented Required Local Stack runnable and reproducible.
2. Stay **secure-by-default**: loopback-only ports, pinned images, no baked-in secrets.
3. Persist data in named volumes — never in the repo working tree.

## Architecture / Process

| Service | Image (pinned) | Local address | Used by |
|---------|----------------|---------------|---------|
| Ollama | `ollama/ollama:0.5.4` | `127.0.0.1:11434` | `rag.embeddings`, dashboard |
| Qdrant | `qdrant/qdrant:v1.12.4` | `127.0.0.1:6333` | dashboard KB search, `scripts/*_cyber_kb*` |
| Postgres | `postgres:16-alpine` | `127.0.0.1:5432` | provisioned (not yet used by code) |

## Implementation Steps

```bash
cp .env.example .env          # from the repo root; then set POSTGRES_PASSWORD
docker compose --env-file .env -f infra/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml ps          # check health
# pull the embedding + generation models once Ollama is up:
docker exec aiocc-ollama ollama pull nomic-embed-text
docker exec aiocc-ollama ollama pull qwen3.5:9b          # LLM_MODEL (~6.6GB)
```

Tear down (data persists in volumes): `docker compose -f infra/docker-compose.yml down`.
Remove data too: add `-v`.

## Risks

| Risk | Mitigation |
|------|-----------|
| Service exposed to the network | Every port binds to `127.0.0.1` only |
| Secret committed to the repo | Password comes from `.env` (gitignored); compose **fails closed** if `POSTGRES_PASSWORD` is unset |
| Supply-chain drift from `:latest` | Image tags are pinned |
| Data loss on container rebuild | Named volumes persist `ollama`, `qdrant`, `postgres` |

## Cost Considerations

Free and local — no cloud or paid services. Disk grows with pulled models and the
vector store; prune volumes when finished.

## Future Enhancements

- A `Makefile`/script wrapper (`make stack-up`) for the common commands.
- Healthchecks for Ollama and Qdrant once a curl-capable base or readiness probe is wired.
- Drop Postgres if it remains unused, or add the first schema/migration when it is.
