"""Business Proposal Agent.

Converts a plain-language description of client needs into a structured proposal /
scope-of-work (SOW) skeleton: objectives, in-scope and out-of-scope items, suggested
delivery phases, deliverables, assumptions, risks, and next steps.

Scope & guardrails (AGENTS.md §5/§9; governance rules):
- It **drafts only**. It never sends, publishes, or commits to anything — a human
  reviews and issues the proposal (publishing is a human-approval gate).
- It does **not** invent pricing, fixed timelines, or contractual commitments. Cost
  and schedule appear only as explicit placeholders to be estimated by a human.
- Output is deterministic and network-free.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Any

from agents import versioned_agent_name


def _md_line(text: str) -> str:
    """Collapse untrusted text to one line so it cannot inject Markdown structure."""
    return " ".join(str(text).split())


# Detect capability areas in the needs text -> tailored scope items.
# Each area contributes concrete, reviewable scope lines (no pricing/commitments).
_SCOPE_RULES: list[tuple[str, frozenset[str], tuple[str, ...]]] = [
    (
        "security operations",
        frozenset({"security", "soc", "siem", "threat", "incident", "detection", "log"}),
        (
            "Stand up log ingestion and alert-triage workflow.",
            "Define detection and severity-scoring criteria.",
            "Establish incident-report and escalation procedures.",
        ),
    ),
    (
        "knowledge / RAG",
        frozenset({"rag", "knowledge", "retrieval", "embedding", "search", "corpus"}),
        (
            "Curate and ingest the trusted document corpus.",
            "Build the retrieval pipeline and relevance evaluation.",
            "Integrate retrieval into the target workflow with citations.",
        ),
    ),
    (
        "agent automation",
        frozenset({"agent", "automation", "workflow", "orchestration", "pipeline"}),
        (
            "Map the target workflow and human approval gates.",
            "Implement the agent/orchestration components with tests.",
            "Document operating procedures and guardrails.",
        ),
    ),
    (
        "compliance / governance",
        frozenset({"compliance", "governance", "audit", "policy", "nist", "cis", "iso"}),
        (
            "Map requirements to a recognized control framework (to be confirmed).",
            "Produce policy and procedure documentation.",
            "Define an audit and evidence-collection process.",
        ),
    ),
]

# Standard delivery phases for a professional engagement.
_DEFAULT_PHASES: tuple[str, ...] = (
    "Discovery — confirm requirements, constraints, and success criteria.",
    "Design — propose architecture and approach for sign-off.",
    "Implementation — build in reviewable increments with tests.",
    "Validation — verify against success criteria; security review.",
    "Handover — documentation, runbooks, and knowledge transfer.",
)

DISCLAIMER = (
    "Draft proposal for internal review only. Pricing, timelines, and commitments are "
    "placeholders to be estimated and confirmed by a human; this is not a binding offer. "
    "Requires review and approval before being sent to a client (AGENTS.md §5.1)."
)

_SENTENCE_SPLIT = re.compile(r"[.;\n]+")


@dataclass(frozen=True)
class ProposalDraft:
    """Structured, non-binding proposal / scope-of-work skeleton."""

    agent: str
    title: str
    client: str
    summary: str
    objectives: list[str]
    detected_areas: list[str]
    scope_items: list[str]
    out_of_scope: list[str]
    deliverables: list[str]
    suggested_phases: list[str]
    assumptions: list[str]
    risks: list[str]
    next_steps: list[str]
    disclaimer: str


# Display name tracks the platform version — never hard-code a version here
# (drift-gated by tests/unit/test_agent_versioning.py).
_DEFAULT_NAME = versioned_agent_name("Business Proposal Agent")


class BusinessProposalAgent:
    """Turn client needs into a structured, reviewable proposal draft."""

    def __init__(self, name: str = _DEFAULT_NAME) -> None:
        self.name = name

    def draft_proposal(self, needs: str, *, client: str | None = None) -> dict[str, Any]:
        """Return a structured proposal draft from a description of client needs.

        Args:
            needs: Plain-language description of what the client wants.
            client: Optional client name. Recorded as "unspecified" when omitted.
        """
        if not isinstance(needs, str):
            raise ValueError("needs must be a string.")
        cleaned = needs.strip()
        if not cleaned:
            raise ValueError("needs cannot be empty.")

        client_name = client.strip() if client and client.strip() else "unspecified"
        areas, scope_items = self._detect_scope(cleaned.lower())
        objectives = self._extract_objectives(cleaned)

        result = ProposalDraft(
            agent=self.name,
            title=f"Proposal: {self._summarize(cleaned, limit=60)}",
            client=client_name,
            summary=self._summarize(cleaned),
            objectives=objectives,
            detected_areas=areas,
            scope_items=scope_items,
            out_of_scope=[
                "Anything not explicitly listed in scope (added via change request).",
                "Production deployment to systems outside the agreed environment.",
                "Pricing, legal terms, and SLAs (to be defined by a human).",
            ],
            deliverables=[
                "Signed-off scope of work.",
                "Implemented solution in reviewable increments.",
                "Tests and documentation.",
                "Handover materials and runbooks.",
            ],
            suggested_phases=list(_DEFAULT_PHASES),
            assumptions=[
                "Draft is based only on the supplied description of needs.",
                "Effort, pricing, and timeline require human estimation.",
                "Scope detection is heuristic and must be confirmed with the client.",
            ],
            risks=[
                "Unconfirmed requirements may change scope.",
                "Timeline and effort are not yet estimated.",
                "Dependencies on client-provided access or data are not yet confirmed.",
            ],
            next_steps=[
                "Confirm objectives and scope with the client.",
                "Estimate effort, timeline, and pricing (human).",
                "Review and approve before sending (human).",
            ],
            disclaimer=DISCLAIMER,
        )
        return asdict(result)

    def sow_markdown(self, draft: dict[str, Any]) -> str:
        """Render a draft as a review-ready SOW document.

        Follows the charter's deliverable structure (AGENTS.md §9): Executive
        Summary · Objectives · Architecture/Process · Implementation Steps ·
        Risks · Cost Considerations · Future Enhancements. Cost figures are
        explicit human-estimation placeholders — this agent never invents
        pricing or commitments. Untrusted text is collapsed to single lines.
        """
        line = _md_line
        sections = [
            f"# {line(draft.get('title', 'Proposal'))}",
            "",
            f"> {line(draft.get('disclaimer', DISCLAIMER))}",
            "",
            "## Executive Summary",
            f"- Client: {line(draft.get('client', 'unspecified'))}",
            f"- {line(draft.get('summary', ''))}",
            f"- Capability areas detected: "
            f"{line(', '.join(draft.get('detected_areas', [])) or 'none')}",
            "",
            "## Objectives",
            *[f"- {line(o)}" for o in draft.get("objectives", [])],
            "",
            "## Architecture / Process (proposed scope)",
            *[f"- {line(s)}" for s in draft.get("scope_items", [])],
            "",
            "### Out of Scope",
            *[f"- {line(s)}" for s in draft.get("out_of_scope", [])],
            "",
            "## Implementation Steps",
            *[
                f"{i}. {line(phase)}"
                for i, phase in enumerate(draft.get("suggested_phases", []), start=1)
            ],
            "",
            "### Deliverables",
            *[f"- {line(d)}" for d in draft.get("deliverables", [])],
            "",
            "## Risks",
            *[f"- {line(r)}" for r in draft.get("risks", [])],
            "",
            "## Cost Considerations",
            "| Item | Estimate |",
            "|---|---|",
            "| Effort (per phase) | _To be estimated by a human_ |",
            "| Timeline | _To be estimated by a human_ |",
            "| Pricing model | _To be selected and priced by a human_ |",
            "| Third-party costs (licenses, infra) | _To be confirmed by a human_ |",
            "",
            "## Future Enhancements",
            "- Candidate follow-on phases surfaced during Discovery are recorded",
            "  here for a later change request — never silently added to scope.",
            "",
            "## Assumptions",
            *[f"- {line(a)}" for a in draft.get("assumptions", [])],
            "",
            "## Next Steps",
            *[f"- {line(n)}" for n in draft.get("next_steps", [])],
        ]
        return "\n".join(sections) + "\n"

    @staticmethod
    def _detect_scope(lowered: str) -> tuple[list[str], list[str]]:
        areas: list[str] = []
        scope: list[str] = []
        for area, keywords, items in _SCOPE_RULES:
            if any(kw in lowered for kw in keywords):
                areas.append(area)
                scope.extend(items)
        if not scope:
            areas.append("general engagement")
            scope = [
                "Clarify and document detailed requirements.",
                "Propose an approach for sign-off.",
                "Implement and validate against agreed criteria.",
            ]
        return areas, scope

    @staticmethod
    def _extract_objectives(text: str, *, limit: int = 5) -> list[str]:
        """Restate the needs text as discrete objective statements."""
        parts = [" ".join(p.split()) for p in _SENTENCE_SPLIT.split(text)]
        objectives = [p for p in parts if len(p) >= 8]
        if not objectives:
            objectives = [" ".join(text.split())]
        return objectives[:limit]

    @staticmethod
    def _summarize(text: str, *, limit: int = 200) -> str:
        collapsed = " ".join(text.split())
        return collapsed if len(collapsed) <= limit else collapsed[: limit - 1].rstrip() + "…"


if __name__ == "__main__":
    agent = BusinessProposalAgent()
    sample = (
        "The client needs a SOC automation pipeline to triage authentication logs and "
        "generate incident reports, plus a RAG knowledge base of security frameworks."
    )
    print(json.dumps(agent.draft_proposal(sample, client="Acme Corp"), indent=2))
