# Knowledge Curator Agent

## Purpose

Organize raw notes, transcripts, or research text into a **retrieval-ready knowledge
entry** — a suggested title, knowledge-base category, tags, summary, key points, a
slugified filename, and a clean Markdown body ready for ingestion into
`knowledge-base/` (and thus retrievable by the Knowledge Base Agent). This closes the
loop: curate raw input → corpus → retrieval.

| | |
|---|---|
| **Risk level** | Low — reorganizes supplied text only; no fabrication, no corpus writes. |
| **Skill level required** | Analyst to run; a human reviews before adding to the corpus. |
| **Deployment complexity** | Low — pure Python, deterministic, no external services. |

## Inputs

- `text` (str, required) — raw notes, transcript, or research text.
- `title` (str, optional) — title override; otherwise derived from the first sentence.
- `category` (str, optional) — KB category override; otherwise auto-suggested.

## Outputs

A JSON-serializable dict (`CuratedEntry`) with `title`, `suggested_category`,
`suggested_filename`, `tags`, `summary`, `key_points`, a KB-ready `markdown` body,
and `assumptions`.

## Dependencies

None beyond the Python standard library. Deterministic and network-free.

## Example Usage

```python
from agents.knowledge_curator_agent import KnowledgeCuratorAgent

agent = KnowledgeCuratorAgent()
entry = agent.curate(
    "SOC alert triage notes. The analyst classifies the event and scores severity.\n"
    "- Preserve evidence\n- Correlate timestamps\n- Escalate high-risk incidents."
)
# -> suggested_category "cybersecurity", clean title/filename, bullet key points,
#    and a Markdown body ready for human review and placement under knowledge-base/.
```

## Limitations

- **Structures, does not publish.** It returns a proposed entry; it never writes into
  the corpus. Adding curated content to the knowledge base is a human-reviewed step
  (the corpus is a trusted source; see `rag/ingest.py`).
- **No fabrication.** It reorganizes and summarizes the supplied text only; it does
  not invent facts, sources, or citations.
- **Heuristic** category/tag/summary extraction — confirm before relying on them.

## Future Improvements

- Optional, human-confirmed write step that places the entry under `knowledge-base/`.
- Smarter summarization and multi-section key-point extraction.
- De-duplication against existing corpus entries before proposing a new file.
