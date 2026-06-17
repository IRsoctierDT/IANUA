# Business Proposal Agent

## Purpose

Convert a plain-language description of client needs into a structured proposal /
scope-of-work (SOW) skeleton for human review: objectives, in-scope and out-of-scope
items, suggested delivery phases, deliverables, assumptions, risks, and next steps.

| | |
|---|---|
| **Risk level** | Low–medium — outputs are client-facing drafts; mitigated by drafting-only scope and a non-binding disclaimer. |
| **Skill level required** | Analyst to run; a human estimates pricing/timeline and approves before sending. |
| **Deployment complexity** | Low — pure Python, deterministic, no external services. |

## Inputs

- `needs` (str, required) — plain-language description of what the client wants.
- `client` (str, optional) — client name; recorded as "unspecified" when omitted.

## Outputs

A JSON-serializable dict (`ProposalDraft`) with `title`, `client`, `summary`,
`objectives`, `detected_areas`, `scope_items`, `out_of_scope`, `deliverables`,
`suggested_phases`, `assumptions`, `risks`, `next_steps`, and a mandatory
`disclaimer`.

## Dependencies

None beyond the Python standard library. Deterministic and network-free.

## Example Usage

```python
from agents.business_proposal_agent import BusinessProposalAgent

agent = BusinessProposalAgent()
draft = agent.draft_proposal(
    "We need a SOC automation pipeline to triage authentication logs and generate "
    "incident reports, plus a RAG knowledge base of security frameworks.",
    client="Acme Corp",
)
# -> detected_areas ["security operations", "knowledge / RAG", "agent automation"],
#    tailored scope_items, standard 5-phase plan, non-binding disclaimer.
```

## Limitations

- **Drafts only.** Never sends, publishes, or commits; a human reviews and issues
  the proposal (publishing is a human-approval gate, AGENTS.md §5.1).
- **No pricing or binding commitments.** Cost, timeline, and SLAs appear only as
  placeholders to be estimated by a human.
- **Heuristic scope detection.** Capability-area detection is keyword-based and must
  be confirmed with the client.

## Future Improvements

- Configurable proposal templates per engagement type.
- Effort-estimation scaffolding (still human-confirmed).
- Export to the report/PDF pipeline once a draft is approved.
