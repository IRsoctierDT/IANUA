# Case Study — Local RAG Pipeline

> **A trusted-corpus retrieval pipeline that ingests, chunks, embeds, and ranks
> local documents — with a fully offline mode so it runs in an air-gapped lab or CI
> with no network at all.**

| | |
|---|---|
| **Component** | RAG Pipeline (`rag/` + `scripts/rag_cli.py`) |
| **Domain** | Retrieval-augmented generation · local knowledge systems · secure ingestion |
| **Purpose** | Turn a directory of trusted documents into ranked, cited retrieval results a human or agent can act on |
| **Risk level** | Low — read-only over a confined corpus; default build performs no network egress |
| **Skill level required** | Developer to integrate; analyst to run the CLI |
| **Deployment complexity** | Low — pure standard library; optional local Ollama for richer embeddings |

---

## 1. Executive Summary

The RAG pipeline takes a directory of trusted local documents and returns ranked,
source-attributed passages for a natural-language query. It is built as four small,
single-responsibility modules — ingestion, embedding, retrieval, and a CLI that ties
them together — each with an explicit trust boundary.

Two design choices make it portfolio-grade rather than a demo. First, **ingestion is
treated as untrusted**: reads are confined to the corpus root, symlinks are refused,
only allow-listed extensions are accepted, and files over a size cap are skipped.
Second, **the network is opt-in**: the default embedding backend is a local Ollama
model constrained to loopback, and an `--offline` deterministic embedder lets the whole
pipeline run with zero network — ideal for CI, demos, and air-gapped labs.

**Outcome:** a single command turns `./knowledge-base` into ranked, cited results, and
the same code path is exercised identically whether or not a model server is running.

---

## 2. Objectives

1. **Confine ingestion to a trusted root** — treat every ingested document as untrusted
   content that must not let a read escape the corpus directory.
2. **Preserve provenance** — every retrievable chunk carries its source file and index
   so results can be cited, not just surfaced.
3. **Make the network opt-in** — embeddings default to a loopback-only local model, and
   a deterministic offline embedder must exercise the *entire* pipeline with no egress.
4. **Stay dependency-light** — the core uses only the Python standard library, so the
   package has no heavy runtime dependency to run or test.
5. **Be swappable** — embedder and vector store sit behind protocols so a production
   vector database can replace the in-memory reference store without touching callers.

---

## 3. Architecture / Process

```
   corpus/ (trusted local docs)
          │
          ▼
   ┌───────────────┐   discover_documents(): allow-list suffixes,
   │  rag.ingest   │   reject symlinks, confine to root, size cap
   └───────┬───────┘
          │ Chunk(source, index, text)  ← overlapping char windows
          ▼
   ┌───────────────┐   OllamaEmbedder (loopback-only, fail-closed)
   │ rag.embeddings│   ── or ──  _OfflineEmbedder (deterministic, no net)
   └───────┬───────┘
          │ (Chunk, vector) pairs
          ▼
   ┌───────────────┐   cosine similarity, top-k
   │ rag.retrieve  │   InMemoryVectorStore  (VectorStore protocol)
   └───────┬───────┘
          │ ranked (chunk, score)
          ▼
   human / agent  ──►  cited results:  [score] source#index: preview
```

**Design invariants** (from [DESIGN.md](../../DESIGN.md) §5):

- Ingested documents are untrusted; the reader never follows a symlink or a path that
  resolves outside the corpus root.
- The embedder and vector store are `Protocol`s — the default build performs no network
  egress, and a real backend is a drop-in.
- Retrieval returns *provenance-bearing* results (source + chunk index), never anonymous
  text blobs.

---

## 4. Implementation Steps

### 4.1 Confined ingestion (`rag/ingest.py`)

`discover_documents()` resolves the corpus root, then walks it accepting only files whose
suffix is in `ALLOWED_SUFFIXES` (`.txt`, `.md`, `.rst`). Symlinks are skipped so a link
can't smuggle a read outside the corpus, each candidate is re-checked with `resolve_within`
(defense in depth), and files over `MAX_FILE_BYTES` (5 MB) are dropped.

### 4.2 Overlapping chunking

`chunk_text()` splits each document into overlapping character windows (default 800 chars,
100-char overlap). The overlap preserves context across boundaries so a passage that
straddles a window is still retrievable. Each window becomes a frozen `Chunk(source, index,
text)` — the unit of provenance.

### 4.3 Pluggable embedding

`embed_chunks()` attaches a vector to each chunk via an injected `Embedder`. In the default
build that's `OllamaEmbedder`, which enforces a loopback host allow-list, a bounded timeout,
and **fails closed** on any error (never a silent zero vector). With `--offline`, the CLI
swaps in `_OfflineEmbedder`, a deterministic bag-of-characters embedder that needs no network.

### 4.4 Cosine retrieval

`InMemoryVectorStore` scores every stored vector against the query vector with cosine
similarity and returns the top-k `(chunk, score)` pairs. It implements the `VectorStore`
protocol, so a production store (e.g. Qdrant) can replace it behind the same interface.

### 4.5 One-command CLI (`scripts/rag_cli.py`)

`build_index()` runs ingest → embed into a store; `run_query()` embeds the query and formats
the top-k hits as `[score] source#index: preview`. A `ValidationError` (e.g. a bad corpus
path) exits non-zero with a clear message rather than a stack trace.

---

## 5. Worked Example

**Command** — query the curated knowledge base fully offline (no Ollama, no network):

```bash
python -m scripts.rag_cli --corpus ./knowledge-base --query "zero trust segmentation" --k 3 --offline
```

**Output** (real output, abridged):

```
[0.860] csf_2_overview.md#2: ent vs. target state) to scope and prioritize adoption. ## How this knowledge base uses it ...
[0.854] cis_controls_overview.md#2: ould meet. - **IG2** — for organizations managing more sensitive data ...
[0.849] soc_fundamentals.md#0: # SOC Fundamentals **Topic:** Security Operations Center (SOC) practice ...
```

Each result carries its **source file and chunk index** (`csf_2_overview.md#2`) and a
cosine score, so the passage is citable. The same command with the Ollama backend —

```bash
python -m scripts.rag_cli --corpus ./knowledge-base --query "zero trust segmentation" --k 3
```

— runs the identical pipeline through a local embedding model; only the embedder changes.

> The offline embedder is deterministic, not semantically rich — it exists to exercise the
> full pipeline in CI and air-gapped runs. Semantic relevance comes from the local model.

---

## 6. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Path traversal / symlink escape during ingest | Read outside the corpus | `resolve_within` confinement + symlink refusal + extension allow-list |
| Silent embedding failure returns a bad vector | Wrong or empty retrieval | `OllamaEmbedder` fails closed; mismatched vector counts raise |
| Unbounded network egress via the embedder | Data exfiltration / dependency on a remote service | Loopback-only host allow-list; `--offline` needs no network at all |
| Oversized or binary files break ingestion | Crash / memory blowup | Size cap (5 MB) + strict UTF-8 decode + suffix allow-list |
| Results without provenance | Unciteable, unauditable retrieval | Every chunk carries `source` + `index`; the CLI prints both |

---

## 7. Cost Considerations

The offline path is **pure Python standard library** — zero external services, zero API
keys, effectively zero marginal cost, and fully air-gappable. The local Ollama embedding
model is also free and loopback-only. A managed vector database or a hosted embedding API
is an explicit, gated decision with a documented cost justification — never a silent default
(see [DESIGN.md](../../DESIGN.md) §9).

---

## 8. Future Enhancements

- **Persistent vector store** — swap `InMemoryVectorStore` for Qdrant behind the existing
  `VectorStore` protocol for corpora that don't fit in memory.
- **Token-aware chunking** — chunk on token/sentence boundaries instead of raw characters.
- **Hybrid retrieval** — combine lexical (BM25-style) and vector scores for robustness.
- **Incremental ingestion** — hash documents and re-embed only what changed.
- **Corpus provenance manifest** — record source, hash, and ingest time per document.

---

## 9. Reproduce It Yourself

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Fully offline (no Ollama, no network) — exercises the whole pipeline:
python -m scripts.rag_cli --corpus ./knowledge-base --query "zero trust segmentation" --k 3 --offline

# Local Ollama embeddings (loopback-only) — richer semantic relevance:
python -m scripts.rag_cli --corpus ./knowledge-base --query "ids tuning" --k 3

# Run the tests (unit + integration, including the RAG CLI):
python -m pytest tests/unit/test_rag.py tests/integration/test_rag_cli.py
```

---

*Part of the [IANUA](../../README.md). Security tooling here is
for defensive, authorized-lab use only — see [AGENTS.md](../../AGENTS.md) §5.*
