"""Legal/Compliance Research Agent.

Structures a legal or compliance inquiry into a reviewable intake: it classifies
the topic area, flags whether escalation to counsel is required, and produces a
*research checklist* of authority categories to verify — plus recommended next
steps and a mandatory disclaimer.

What this agent deliberately does NOT do (AGENTS.md §5, §9; governance rules):
- It does **not** provide legal advice or legal conclusions.
- It does **not** invent or assert statutes, case law, deadlines, or citations.
  The authority checklist names *categories to research and verify*, never a claim
  that a specific law applies to the user's facts.
- It does **not** send, file, or publish anything. Drafting only; humans act.

It is a drafting and triage aid whose output is meant to be handed to a qualified
attorney, not relied on directly.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from agents import versioned_agent_name


def _md_line(text: str) -> str:
    """Collapse untrusted text to one line so it cannot inject Markdown structure."""
    return " ".join(str(text).split())


# Mandatory, non-removable disclaimer attached to every assessment.
DISCLAIMER = (
    "This is an automated, non-authoritative drafting and triage aid. It does not "
    "constitute legal advice, does not create an attorney-client relationship, and "
    "does not replace review by a qualified attorney licensed in the relevant "
    "jurisdiction. Verify every authority and deadline with primary sources."
)

# Topic classification: ordered keyword rules -> (topic_area, authority checklist).
# Checklist items are RESEARCH POINTERS ("verify whether ..."), never assertions
# that a given law governs the user's situation.
_TOPIC_RULES: list[tuple[str, frozenset[str], tuple[str, ...]]] = [
    (
        "data protection / privacy",
        frozenset({"privacy", "gdpr", "ccpa", "personal data", "pii", "data breach", "consent"}),
        (
            "Verify which data-protection regimes apply (e.g. GDPR, CCPA/CPRA, state laws) "
            "based on data subjects, processing location, and sector.",
            "Verify breach-notification obligations and their timelines for each applicable "
            "regime.",
            "Verify contractual data-processing obligations (DPAs, sub-processor terms).",
        ),
    ),
    (
        "contracts",
        frozenset({"contract", "agreement", "nda", "breach of contract", "clause", "terms"}),
        (
            "Verify the governing-law and jurisdiction clauses of the agreement.",
            "Verify notice, cure, and termination provisions and any applicable deadlines.",
            "Verify limitation-of-liability, indemnity, and dispute-resolution terms.",
        ),
    ),
    (
        "employment / labor",
        frozenset({"employment", "employee", "termination", "harassment", "wage", "labor"}),
        (
            "Verify applicable federal, state, and local employment statutes for the worksite.",
            "Verify any administrative filing prerequisites and their deadlines.",
            "Verify employee-handbook, contract, and collective-bargaining obligations.",
        ),
    ),
    (
        "intellectual property",
        frozenset({"copyright", "trademark", "patent", "infringement", "license", "trade secret"}),
        (
            "Verify which IP rights are implicated and their registration status.",
            "Verify ownership, assignment, and licensing chains.",
            "Verify any infringement-notice or filing deadlines.",
        ),
    ),
    (
        "regulatory / compliance",
        frozenset({"regulation", "compliance", "regulator", "audit", "sanction", "license"}),
        (
            "Verify which regulators and frameworks have jurisdiction over the activity.",
            "Verify reporting, registration, and recordkeeping obligations and timelines.",
            "Verify whether any safe harbors or exemptions apply.",
        ),
    ),
    (
        "litigation / dispute",
        frozenset({"lawsuit", "litigation", "subpoena", "court", "complaint", "dispute", "claim"}),
        (
            "Verify the controlling statute of limitations for each potential claim.",
            "Verify court rules, response deadlines, and service requirements.",
            "Verify preservation/litigation-hold obligations for relevant evidence.",
        ),
    ),
]

# Signals that the matter is time-sensitive or adversarial and needs a human now.
_ESCALATION_TERMS: frozenset[str] = frozenset(
    {
        "subpoena",
        "lawsuit",
        "litigation",
        "court",
        "deadline",
        "statute of limitations",
        "regulator",
        "breach",
        "sanction",
        "complaint",
        "summons",
        "injunction",
    }
)


@dataclass(frozen=True)
class LegalAssessment:
    """Structured, non-authoritative legal/compliance intake.

    ``topic_area`` remains the primary (first-matched) area for backward
    compatibility; ``topic_areas`` lists **every** matched area — an inquiry
    that implicates several regimes (a subpoena for customer data is both
    litigation *and* data protection) gets every applicable checklist, not
    just the first rule that happened to match.
    """

    agent: str
    inquiry_summary: str
    topic_area: str
    topic_areas: list[str]
    jurisdiction: str
    authority_checklist: list[str]
    risk_flags: list[str]
    recommended_actions: list[str]
    escalation_required: bool
    disclaimer: str
    assumptions: list[str]
    kb_references: list[dict[str, Any]]


# Display name tracks the platform version — never hard-code a version here
# (drift-gated by tests/unit/test_agent_versioning.py).
_DEFAULT_NAME = versioned_agent_name("Legal/Compliance Research Agent")


class LegalComplianceAgent:
    """Classify and structure a legal/compliance inquiry for attorney review."""

    def __init__(self, name: str = _DEFAULT_NAME) -> None:
        self.name = name

    def assess_inquiry(self, text: str, *, jurisdiction: str | None = None) -> dict[str, Any]:
        """Return a structured, non-authoritative assessment of a legal inquiry.

        Args:
            text: Plain-language description of the legal/compliance question.
            jurisdiction: Optional jurisdiction hint. If omitted, the assessment
                records that jurisdiction is unspecified and must be confirmed.
        """
        if not isinstance(text, str):
            raise ValueError("text must be a string.")
        cleaned = text.strip()
        if not cleaned:
            raise ValueError("text cannot be empty.")

        lowered = cleaned.lower()
        topic_areas, checklist = self._classify_topics(lowered)
        risk_flags = self._risk_flags(lowered)
        escalation_required = bool(risk_flags)

        result = LegalAssessment(
            agent=self.name,
            inquiry_summary=self._summarize(cleaned),
            topic_area=topic_areas[0],
            topic_areas=topic_areas,
            jurisdiction=jurisdiction.strip()
            if jurisdiction and jurisdiction.strip()
            else "unspecified — confirm before relying on any authority",
            authority_checklist=list(checklist),
            risk_flags=risk_flags,
            recommended_actions=self._recommend_actions(topic_areas[0], escalation_required),
            escalation_required=escalation_required,
            disclaimer=DISCLAIMER,
            assumptions=[
                "Assessment is based only on the supplied description.",
                "No primary legal sources were retrieved, verified, or cited.",
                "Topic classification is heuristic and may be incomplete.",
            ],
            kb_references=self._kb_references(cleaned, topic_areas),
        )
        return asdict(result)

    @staticmethod
    def _classify_topics(lowered: str) -> tuple[list[str], tuple[str, ...]]:
        """Match **all** applicable topic rules; merge their checklists in order.

        First-match-wins classification silently dropped checklists when an
        inquiry crossed areas — e.g. a subpoena for customer data matched
        "data protection" and lost the litigation checklist with its
        preservation and response-deadline items. Every matched area now
        contributes; duplicates are removed preserving rule order.
        """
        areas: list[str] = []
        merged: list[str] = []
        seen: set[str] = set()
        for topic_area, keywords, checklist in _TOPIC_RULES:
            if any(kw in lowered for kw in keywords):
                areas.append(topic_area)
                for item in checklist:
                    if item not in seen:
                        seen.add(item)
                        merged.append(item)
        if areas:
            return areas, tuple(merged)
        return (
            ["general / unclassified"],
            (
                "Verify which area(s) of law the facts implicate.",
                "Verify the relevant jurisdiction(s) and governing authorities.",
                "Verify any applicable deadlines before taking action.",
            ),
        )

    @staticmethod
    def _kb_references(text: str, topic_areas: list[str]) -> list[dict[str, Any]]:
        """Ground compliance-adjacent inquiries in the local knowledge base.

        Uses the offline lexical retriever over the in-repo corpus (framework
        notes: NIST, MITRE, OWASP…) — local-only, deterministic, and fail-soft:
        retrieval problems yield an empty list, never an error. References are
        supporting context for the human researcher, not legal authority.
        """
        try:
            from agents.knowledge_base_agent import KnowledgeBaseAgent

            query = " ".join([text, *topic_areas])
            refs = KnowledgeBaseAgent().retrieve(query, k=3)
            return [asdict(r) for r in refs]
        except Exception:
            return []

    @staticmethod
    def _risk_flags(lowered: str) -> list[str]:
        flags = [term for term in sorted(_ESCALATION_TERMS) if term in lowered]
        return flags

    @staticmethod
    def _summarize(text: str, *, limit: int = 200) -> str:
        collapsed = " ".join(text.split())
        return collapsed if len(collapsed) <= limit else collapsed[: limit - 1].rstrip() + "…"

    def intake_memo(self, assessment: dict[str, Any]) -> str:
        """Render an assessment as a counsel-ready Markdown intake memo.

        Follows the governance rule that high-stakes outputs separate facts,
        assumptions, analysis, recommendations, and unknowns — and keeps the
        mandatory disclaimer at the top where it cannot be missed. Untrusted
        text is collapsed to single lines so it cannot inject structure.
        """
        line = _md_line
        sections = [
            "# Legal/Compliance Intake Memo",
            "",
            f"> {line(assessment.get('disclaimer', DISCLAIMER))}",
            "",
            "## Facts (as supplied)",
            f"- {line(assessment.get('inquiry_summary', ''))}",
            f"- Jurisdiction: {line(assessment.get('jurisdiction', 'unspecified'))}",
            "",
            "## Topic Areas",
            *[f"- {line(a)}" for a in assessment.get("topic_areas", [])],
            "",
            "## Authority Checklist (verify, do not assert)",
            *[f"- [ ] {line(i)}" for i in assessment.get("authority_checklist", [])],
            "",
            "## Risk Flags",
            *(
                [f"- {line(f)}" for f in assessment.get("risk_flags", [])]
                or ["- None detected in the supplied text"]
            ),
            "",
            "## Recommended Actions",
            *[f"- {line(a)}" for a in assessment.get("recommended_actions", [])],
            "",
            "## Assumptions & Unknowns",
            *[f"- {line(a)}" for a in assessment.get("assumptions", [])],
        ]
        refs = assessment.get("kb_references", [])
        if refs:
            sections += [
                "",
                "## Local Knowledge-Base Context (supporting, not authority)",
                *[
                    f"- **{line(str(r.get('source', '')))}** "
                    f"(relevance {float(r.get('score', 0)):.2f}) — "
                    f"{line(str(r.get('snippet', '')))}"
                    for r in refs
                ],
            ]
        return "\n".join(sections) + "\n"

    @staticmethod
    def _recommend_actions(topic_area: str, escalation_required: bool) -> list[str]:
        actions = [
            "Confirm the relevant jurisdiction(s) and effective dates.",
            "Research and verify each authority-checklist item against primary sources.",
            "Separate facts from assumptions before drafting any position.",
        ]
        if escalation_required:
            actions.insert(
                0,
                "Escalate to a qualified attorney promptly — time-sensitive or adversarial "
                "signals were detected.",
            )
        else:
            actions.append("Have a qualified attorney review before acting on the findings.")
        return actions


if __name__ == "__main__":
    agent = LegalComplianceAgent()
    sample = (
        "We received a subpoena requesting customer data and need to understand our "
        "privacy obligations and response deadline."
    )
    print(json.dumps(agent.assess_inquiry(sample), indent=2))
