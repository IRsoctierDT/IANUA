# Legal/Compliance Research Agent

## Purpose

Structure a legal or compliance inquiry into a reviewable intake for a qualified
attorney. It classifies the topic area, flags whether the matter is time-sensitive
or adversarial (escalation), and produces a **research checklist of authority
categories to verify** — never legal advice and never fabricated citations.

| | |
|---|---|
| **Risk level** | Medium — touches a regulated domain; mitigated by hard guardrails (no advice, no invented authority, mandatory disclaimer, escalation flags). |
| **Skill level required** | Analyst to run; the output is intended for attorney review. |
| **Deployment complexity** | Low — pure Python, deterministic, no external services. |

## Inputs

- `text` (str, required) — plain-language description of the legal/compliance question.
- `jurisdiction` (str, optional) — jurisdiction hint. When omitted, the assessment
  records jurisdiction as *unspecified* and requires confirmation.

## Outputs

A JSON-serializable dict (`LegalAssessment`) with:

- `topic_area` — heuristic classification (privacy, contracts, employment, IP,
  regulatory, litigation, or general).
- `authority_checklist` — research pointers, each phrased as "Verify whether …".
- `risk_flags` / `escalation_required` — adversarial/time-sensitive signals.
- `recommended_actions` — next steps (escalation surfaced first when triggered).
- `disclaimer` — mandatory, non-removable.
- `assumptions` — what was *not* done (no primary sources retrieved or cited).

## Dependencies

None beyond the Python standard library. Deterministic and network-free.

## Example Usage

```python
from agents.legal_compliance_agent import LegalComplianceAgent

agent = LegalComplianceAgent()
result = agent.assess_inquiry(
    "We received a subpoena requesting customer data and need to understand our "
    "privacy obligations and response deadline.",
    jurisdiction="California",
)
# -> topic_area "data protection / privacy", escalation_required True,
#    risk_flags ["deadline", "subpoena"], a verify-only authority checklist.
```

## Limitations

- **Not legal advice.** Output is a non-authoritative triage/drafting aid; it does
  not create an attorney-client relationship and must be reviewed by counsel.
- **No primary-source retrieval.** It does not look up or cite statutes, case law,
  or deadlines. The checklist only names categories to verify (AGENTS.md §9).
- **Heuristic classification.** Topic detection is keyword-based and may be
  incomplete; it never asserts that a specific law governs the user's facts.
- **No outbound actions.** It never sends, files, or publishes anything
  (governance rules; AGENTS.md §5.1).

## Future Improvements

- Optional, clearly-labeled retrieval from a curated, citable legal-reference corpus
  (same verify-don't-assert discipline as the cybersecurity knowledge base).
- Finer topic taxonomy and multi-topic detection.
- Per-jurisdiction checklist variants once a verified reference set exists.
