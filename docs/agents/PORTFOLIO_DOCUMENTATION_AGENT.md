# Portfolio Documentation Agent

## Purpose

Turn a description of lab/project work into a GitHub-ready Markdown document — a
README or a case study — following the project's documentation standard
(AGENTS.md §9). Returns a structured draft (sections + assembled Markdown +
suggested filename) for human review.

| | |
|---|---|
| **Risk level** | Low — drafts only; no fabrication; never writes or publishes. |
| **Skill level required** | Analyst to run; author fills TODOs and reviews before publishing. |
| **Deployment complexity** | Low — pure Python, deterministic, no external services. |

## Inputs

- `project_name` (str, required) — becomes the document title.
- `description` (str, required) — plain-language description of the work.
- `doc_type` ("readme" | "case_study", default "readme").
- `skills` (list[str], optional) — skills the work demonstrates (README only).

## Outputs

A JSON-serializable dict (`DocumentationDraft`) with `title`, `doc_type`,
`suggested_filename`, `summary`, `sections` (heading/body pairs), an assembled
`markdown` body, and `assumptions`. Case studies follow the AGENTS.md §9 order:
Executive Summary · Objectives · Architecture/Process · Implementation Steps ·
Risks · Cost Considerations · Future Enhancements.

## Dependencies

None beyond the Python standard library. Deterministic and network-free.

## Example Usage

```python
from agents.portfolio_documentation_agent import PortfolioDocumentationAgent

agent = PortfolioDocumentationAgent()
draft = agent.document(
    "SOC Analyst Agent v0.2",
    "Triages security logs, scores severity, maps to MITRE ATT&CK, writes reports.",
    doc_type="case_study",
    skills=["Python", "Detection engineering", "RAG"],
)
# -> AGENTS.md §9 case-study sections; derivable parts filled, the rest marked TODO.
```

## Limitations

- **Drafts only.** Returns Markdown; never writes files or publishes (those are
  human-reviewed steps, AGENTS.md §5.1).
- **No fabrication.** Sections it cannot derive from the description are explicit
  `TODO` placeholders — it never invents results, metrics, or sources.
- **Heuristic** summarization and objective extraction; confirm before publishing.

## Future Improvements

- Pull real specifics from a project's code/tests to pre-fill more sections.
- Additional document templates (runbook, ADR) reusing the same section engine.
- Optional, human-confirmed write step into `docs/`.
