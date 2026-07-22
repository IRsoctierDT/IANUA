# Case Study — Knowledge Base Agent

> **Grounds incident reports in a curated cybersecurity corpus — returning cited,
> source-attributed references — with a deterministic lexical default and an opt-in
> semantic mode that falls back safely when the local model is unreachable.**

| | |
|---|---|
| **Component** | Knowledge Base Agent (`agents/knowledge_base_agent.py`) |
| **Domain** | RAG grounding · citation · framework alignment (MITRE, OWASP, NIST, CIS) |
| **Purpose** | Retrieve the most relevant corpus references for an event so reports cite authoritative framework context |
| **Risk level** | Low — read-only over a confined corpus; default mode is network-free |
| **Skill level required** | Analyst to run; Python developer to extend |
| **Deployment complexity** | Low — pure Python default; optional local Ollama for semantic mode |

---

## 1. Executive Summary

The Knowledge Base Agent answers a simple but important question: *what authoritative guidance
applies to this event?* Given a query — or a SOC/MITRE result — it retrieves the most relevant
documents from the local `knowledge-base/` corpus (MITRE ATT&CK, OWASP, NIST CSF, CIS,
Security+ notes) and returns one cited reference per source with a relevance score and a clean
snippet.

It ships two retrieval modes with a deliberate default. **Lexical** — a deterministic,
dependency-free term-overlap score — is the default because incident-report grounding must be
reproducible, network-free, and CI-testable. **Semantic** — local-embedding cosine similarity
via the loopback-only `OllamaEmbedder` — is opt-in for better relevance, and **falls back to
lexical** if the model is unreachable so the pipeline never breaks. Both load the corpus through
the same path-traversal-safe ingestion, and a missing corpus fails soft to "no references"
rather than an error.

**Outcome:** incident reports cite real framework context with provenance, and the grounding
step is reproducible enough to unit-test yet upgradeable to semantic search without changing
callers.

---

## 2. Objectives

1. **Cite, don't paraphrase** — return source-attributed references with scores and snippets so
   reports link back to authoritative guidance.
2. **Default to reproducible** — lexical retrieval is deterministic, network-free, and CI-safe.
3. **Offer better relevance safely** — semantic mode is opt-in and falls back to lexical if the
   embedder is unreachable.
4. **Confine and trust the corpus** — load only through path-traversal-safe ingestion; no PII or
   client data.
5. **Fail soft** — a missing/unreadable corpus yields no references, never a crash.

---

## 3. Architecture / Process

```
 query  (or SOC + MITRE result → built query)
    │
    ▼
 ┌────────────────────────┐   ingest(knowledge-base/)  ← allow-list, symlink-safe, confined
 │ KnowledgeBaseAgent      │
 │  .retrieve(query, k)    │   mode = lexical (default): term-overlap score
 │                         │   mode = semantic (opt-in): Ollama cosine → fallback to lexical
 └───────────┬─────────────┘   aggregate best chunk per source; positive scores only
    │
    ▼
 [ KnowledgeReference(source, score, snippet), ... ]  (top-k, ranked)
```

**Design invariants** (from [DESIGN.md](../../DESIGN.md) §5, decision log 2026-06-17/18):

- Lexical is the default: deterministic, network-free, CI-safe.
- Semantic mode falls back to lexical if the loopback-only, fail-closed embedder is unreachable.
- Corpus reads go through `rag.ingest` for shared path-traversal safety; missing corpus →
  fail soft.

---

## 4. Implementation Steps

### 4.1 Trusted ingestion, shared with the RAG pipeline

`retrieve()` loads the corpus via `rag.ingest.ingest()` — the same extension allow-list,
symlink refusal, and root confinement used by the [RAG Pipeline](./rag-pipeline.md). A missing
or unreadable corpus is caught and returns `[]` rather than raising.

### 4.2 Deterministic lexical scoring (default)

`_lexical_scores()` tokenizes query and chunks into meaningful lowercase terms (length ≥ 3,
stopwords dropped) and scores each source by the fraction of query terms present in its best
chunk. No network, fully reproducible — this is what the agent pipeline uses by default.

### 4.3 Opt-in semantic scoring with fallback

`_semantic_scores()` embeds the query and every chunk via the local `OllamaEmbedder` and ranks
by cosine similarity. If the embedder fails closed (Ollama unreachable), `retrieve()` catches
the `ValidationError` and **falls back to lexical** — the caller never sees a failure.

### 4.4 Aggregate to cited references

`_aggregate()` keeps the best-scoring chunk per source, drops non-positive scores, sorts
high-first (stable by source), and attaches a clean snippet from each document's opening.
`reference_for_event()` builds a query from a SOC (+ optional MITRE) result and returns plain
dicts that compose cleanly with the rest of the pipeline.

---

## 5. Worked Example

**Command:**

```bash
python -m agents.knowledge_base_agent
```

**Output** (real output — lexical mode, default):

```
[0.67] enterprise_attack_overview.md: # MITRE ATT&CK — Enterprise Matrix Overview  **Framework:** MITRE ATT&CK® ...
[0.50] soc_fundamentals.md: # SOC Fundamentals  **Topic:** Security Operations Center (SOC) practice ...
[0.33] top_10_overview.md: # OWASP Top 10:2025 — Web Application Security Risks ...
```

For the query `brute force authentication failure credential access`, the top reference is the
**ATT&CK Enterprise overview** (score 0.67) — exactly the framework context a T1110 finding
should cite — followed by SOC fundamentals and the OWASP Top 10. Each result carries its
**source file** and a snippet, so the [Incident Report Agent](./incident-report-agent.md) can
render them as cited **Knowledge Base References**. Switching to `mode="semantic"` re-ranks by
embedding similarity when Ollama is running, and silently falls back to this lexical output when
it isn't.

---

## 6. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Semantic mode breaks when Ollama is down | Pipeline failure | Falls back to deterministic lexical scoring automatically |
| Path traversal / symlink escape in corpus load | Read outside corpus | Loads via `rag.ingest` (allow-list, symlink refusal, confinement) |
| Non-reproducible grounding | Untestable reports | Lexical default is deterministic and CI-safe |
| Missing/unreadable corpus | Crash mid-pipeline | Fails soft: returns no references |
| Irrelevant references cited | Misleading context | Only positive-scoring sources returned; best-chunk-per-source aggregation |

---

## 7. Cost Considerations

The default lexical mode is pure Python, deterministic, and network-free — zero marginal cost,
fully offline. Semantic mode uses a local Ollama embedding model (free, loopback-only). No paid
APIs or hosted vector services are used unless explicitly, gated, and cost-justified
([DESIGN.md](../../DESIGN.md) §9).

---

## 8. Future Enhancements

- **Chunk-level citations** — cite the exact passage, not just the source document.
- **Corpus expansion** — add more curated framework material (still trusted, no client data).
- **Hybrid ranking** — blend lexical and semantic scores for robustness.
- **Freshness metadata** — record source edition/date so citations note their version.

---

## 9. Reproduce It Yourself

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Lexical (default, deterministic, offline):
python -c "
from agents.knowledge_base_agent import KnowledgeBaseAgent
for r in KnowledgeBaseAgent().retrieve('brute force authentication failure credential access', k=3):
    print(f'[{r.score:.2f}] {r.source}: {r.snippet[:80]}')
"

# Semantic (opt-in; needs local Ollama, else falls back to lexical):
python -c "
from agents.knowledge_base_agent import KnowledgeBaseAgent
a = KnowledgeBaseAgent(mode='semantic')
for r in a.retrieve('zero trust network segmentation', k=3):
    print(f'[{r.score:.3f}] {r.source}')
"

python -m pytest tests/test_knowledge_base_agent.py
```

---

*Part of the [IANUA](../../README.md). Security tooling here is
for defensive, authorized-lab use only — see [AGENTS.md](../../AGENTS.md) §5.*
