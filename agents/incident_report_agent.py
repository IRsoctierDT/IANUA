"""Incident Report Agent — composes the pipeline's results into Markdown.

Renders SOC, MITRE, threat-intel, knowledge-base, detection, and citation
results into a reviewable Markdown incident report (optional PDF export).
Deterministic and network-free; the only write is the report file itself.
Cell content is escaped so untrusted log text cannot break table structure,
and the "(verified)" citations heading renders only when the caller attests
verification (see ``generate_report``).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from agents.mitre_mapper_agent import MitreMapperAgent
from agents.soc_analyst_agent import SocAnalystAgent
from agents.tools.llm import Generator
from agents.tools.validation import ValidationError

_NARRATIVE_SYSTEM = (
    "You are a SOC analyst assistant. In 2-3 sentences, summarize ONLY the facts "
    "provided. Do not invent hosts, accounts, IPs, or conclusions not present in the "
    "input. Be precise and defensive."
)


# Upper bound on one rendered inline value. Log-derived text flows into
# evidence values and mapper output; an oversized value must not be able to
# balloon the report or the PDF renderer downstream.
_MAX_INLINE_LEN = 500

# C0 control characters (minus the newlines handled explicitly) and DEL:
# stripped rather than escaped — they have no legitimate place in a report and
# NUL in particular breaks downstream tooling.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize(text: str) -> str:
    """Flatten newlines, strip control characters, and cap the length."""
    text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    text = _CONTROL_CHARS_RE.sub("", text)
    if len(text) > _MAX_INLINE_LEN:
        text = text[:_MAX_INLINE_LEN] + " …[truncated]"
    return text


def _md_cell(text: str) -> str:
    """Escape untrusted text for a Markdown table cell or inline position.

    Pipes and backticks are backslash-escaped (a raw backtick would open a
    code span and swallow the rest of the line); newlines are flattened and
    control characters stripped via ``_sanitize``.
    """
    return _sanitize(text).replace("|", "\\|").replace("`", "\\`")


def _md_code(text: str) -> str:
    """Neutralize untrusted text destined for *inside* a Markdown code span.

    Backslash escapes do not work inside code spans, so a backtick in the
    value would terminate the span and let the remainder render as active
    Markdown. The backtick is replaced with an apostrophe — a visible,
    documented substitution rather than a structural break.
    """
    return _sanitize(text).replace("`", "'")


def _build_narrative(soc: dict, mitre: dict, generator: Generator | None) -> str:
    """Return an AI-generated narrative, or a clear note when it is off/unavailable.

    Opt-in and fail-soft: with no generator the deterministic report is unchanged;
    if the local model errors, the section records that rather than failing the report.
    """
    if generator is None:
        return "_AI narrative not enabled (no local model configured)._"
    facts = (
        f"event_type={soc.get('event_type')}; severity={soc.get('severity')} "
        f"({soc.get('severity_score')}/100); indicators={soc.get('indicators')}; "
        f"mitre={mitre.get('technique_id')} {mitre.get('technique')}."
    )
    # Prefer grammar-constrained JSON when the backend supports it (e.g. llama.cpp),
    # so the narrative is structured and parseable rather than free text.
    generate_json = getattr(generator, "generate_json", None)
    try:
        if callable(generate_json):
            return _render_structured(generate_json(facts, system=_NARRATIVE_SYSTEM))
        return generator.generate(facts, system=_NARRATIVE_SYSTEM).strip()
    except ValidationError as exc:
        # Analyst-facing taxonomy: a transport failure (model simply not
        # running — the generator chains URLError/TimeoutError/OSError as the
        # cause) gets an actionable message instead of a raw socket trace,
        # which reads as breakage in a client-deliverable report. Genuine
        # generator misbehavior (e.g. unparseable model output) stays verbatim
        # — that detail is the debugging signal.
        if isinstance(exc.__cause__, OSError):
            return (
                "_AI narrative unavailable — local LLM offline (model not "
                "reachable on loopback). Start Ollama or llama-server to enable "
                "this section; all findings above are deterministic and "
                "unaffected._"
            )
        return f"_AI narrative unavailable (generator error: {exc})._"


def _render_structured(data: dict) -> str:
    """Render a grammar-constrained narrative object as Markdown bullets."""
    fields = [
        ("Summary", "summary"),
        ("Assessment", "assessment"),
        ("Recommended next step", "recommended_next_step"),
    ]
    lines = [f"- **{label}:** {_md_cell(str(data[key]))}" for label, key in fields if data.get(key)]
    return "\n".join(lines) or "_AI narrative returned no content._"


def _render_sequence(
    sequence_result: dict | None,
    sequence_detections: list[dict] | None = None,
) -> str:
    """Render the multi-event correlation section (from ``analyze_sequence``).

    ``sequence_detections`` (from ``DetectionMatcherAgent.match_for_sequence``)
    lists the Sigma correlation rules covering the findings, closing the loop
    between sequence triage and detection content.
    """
    if sequence_result is None:
        return "- Single-event analysis (no sequence context)"
    findings = sequence_result.get("findings", [])
    lines = [
        f"- **Events analyzed:** {sequence_result.get('event_count', 'N/A')}",
        f"- **Overall severity:** {sequence_result.get('severity', 'N/A')} "
        f"({sequence_result.get('severity_score', 'N/A')}/100)",
        "",
        "### Correlated Findings",
    ]
    if findings:
        lines.extend(
            f"- **{_md_cell(str(f.get('pattern', '')))}** from `{_md_code(str(f.get('source', '')))}` "
            f"[{f.get('severity', 'N/A')}] — {_md_cell(str(f.get('description', '')))} "
            f"(events {f.get('event_indices', [])})"
            for f in findings
        )
    else:
        lines.append("- No multi-event patterns detected")
    if findings:
        lines.extend(["", "### Matching Detections"])
        if sequence_detections:
            lines.extend(
                f"- **{_md_cell(str(d.get('title', '')))}** [{d.get('level', 'unknown')}] — "
                f"`{_md_code(str(d.get('file', '')))}` "
                f"({d.get('technique', '')}, covers {_md_cell(str(d.get('pattern', '')))})"
                for d in sequence_detections
            )
        else:
            lines.append("- No correlation rule covers these patterns yet")
    return "\n".join(lines)


def _render_behaviors(behavior_matches: list[dict] | None) -> str:
    """Render behavioral (post-compromise TTP) coverage for the event.

    Each rule states whether the telemetry it needs is ingested today, so a
    rule that replays green against fixtures but cannot fire in production is
    labelled rather than counted as real coverage.
    """
    if not behavior_matches:
        return "- No behavioral rule covers this technique yet"
    lines = []
    for match in behavior_matches:
        validation = str(match.get("validation", "unknown"))
        flag = (
            "active"
            if validation == "telemetry-available"
            else "awaiting telemetry - not live in this deployment"
        )
        lines.append(
            f"- **{_md_cell(str(match.get('title', '')))}** "
            f"[{_md_cell(str(match.get('level', 'unknown')))}] — "
            f"`{_md_code(str(match.get('file', '')))}` "
            f"({_md_cell(str(match.get('technique', '')))}; {flag})"
        )
    return "\n".join(lines)


def _render_response_plan(response_plan: dict | None) -> str:
    """Render the draft containment plan — guidance for a human, never an act.

    The disclaimer, the per-action owner, and the explicit rollback are all
    load-bearing: a reader must never mistake this section for something the
    platform did. Irreversible and evidence-affecting steps are called out
    before the step list so the cost is visible before the instruction.
    """
    if not response_plan:
        return (
            "- No containment plan proposed — the attributed techniques do not warrant "
            "action on this evidence alone"
        )
    lines = [
        f"> **{_md_cell(str(response_plan.get('disclaimer', '')))}**",
        "",
        f"- **Plan:** `{_md_code(str(response_plan.get('plan_id', '')))}` "
        f"(state: {_md_cell(str(response_plan.get('execution_state', 'draft')))})",
        f"- **Targets:** {_md_cell(', '.join(map(str, response_plan.get('targets', []))))}",
    ]
    actions = response_plan.get("actions", [])
    irreversible = [a for a in actions if not a.get("reversible", True)]
    evidence = [a for a in actions if a.get("destroys_evidence", False)]
    if irreversible:
        lines.append(
            "- **Irreversible steps requiring explicit approval:** "
            + _md_cell(", ".join(str(a.get("title", "")) for a in irreversible))
        )
    if evidence:
        lines.append(
            "- **Evidence-affecting steps (capture first):** "
            + _md_cell(", ".join(str(a.get("title", "")) for a in evidence))
        )
    for action in actions:
        lines.extend(
            [
                "",
                f"### Tier {action.get('tier', '?')} — {_md_cell(str(action.get('title', '')))}",
                f"- **Target:** `{_md_code(str(action.get('target', '')))}`",
                f"- **Performed by:** {_md_cell(str(action.get('owner', '')))}",
                f"- **Why:** {_md_cell(str(action.get('rationale', '')))}",
                "- **Steps:**",
            ]
        )
        lines.extend(f"  1. {_md_cell(str(step))}" for step in action.get("steps", []))
        lines.append(f"- **Rollback:** {_md_cell(str(action.get('rollback', '')))}")
    return "\n".join(lines)


def _render_citations(citations: list[dict] | None) -> str:
    """Render verified passage-level citations with char-offset locators."""
    if not citations:
        return "- None captured"
    return "\n".join(
        f"{i}. **{_md_cell(str(c.get('source', '')))}** "
        f"(chars {c.get('char_start', '?')}-{c.get('char_end', '?')}, "
        f'relevance {c.get("score", 0.0):.2f}): "{_md_cell(str(c.get("quote", "")))}"'
        for i, c in enumerate(citations, 1)
    )


class IncidentReportAgent:
    def __init__(self) -> None:
        self.soc_agent = SocAnalystAgent()
        self.mitre_mapper = MitreMapperAgent()

    def generate_report(
        self,
        log_text: str,
        output_path: str,
        *,
        soc_result: dict | None = None,
        mitre_result: dict | None = None,
        kb_references: list[dict] | None = None,
        detection_matches: list[dict] | None = None,
        behavior_matches: list[dict] | None = None,
        response_plan: dict | None = None,
        sequence_result: dict | None = None,
        sequence_detections: list[dict] | None = None,
        citations: list[dict] | None = None,
        citations_verified: bool = False,
        generator: Generator | None = None,
        pdf_path: str | None = None,
    ) -> Path:
        """Write a markdown incident report.

        Pass pre-computed ``soc_result`` and ``mitre_result`` to avoid
        re-running analysis when the orchestrator has already done it.
        ``kb_references`` (from the Knowledge Base Agent) adds cited framework
        context; ``detection_matches`` (from the Detection Matcher Agent) lists
        the Sigma rules that cover the event's technique; ``behavior_matches``
        lists the post-compromise behavioral rules covering it, each flagged
        with whether its telemetry is actually ingested; ``sequence_result``
        (from ``SocAnalystAgent.analyze_sequence``) surfaces multi-event
        correlated findings; ``citations`` (passage-level citations from
        ``KnowledgeBaseAgent.cite``) quote the exact grounding passages with
        char-offset locators. When any is omitted, the report notes that none
        were attached.

        Security consideration: the section heading claims "(verified)" only
        when ``citations_verified=True`` — set it solely after
        ``KnowledgeBaseAgent.verify_citations`` has passed (as the orchestrator
        does). This report agent does not re-verify; the default (``False``)
        renders a neutral heading so a direct caller cannot mislabel
        unchecked citations as verified.
        """
        if not isinstance(log_text, str):
            raise ValueError("log_text must be a string.")
        if not isinstance(output_path, str) or not output_path.strip():
            raise ValueError("output_path must be a non-empty string.")
        if soc_result is None:
            soc_result = self.soc_agent.analyze_log(log_text)
        if mitre_result is None:
            mitre_result = self.mitre_mapper.map_event(
                soc_result["event_type"],
                log_text,
            )

        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        indicators = soc_result.get("indicators", [])
        narrative = _build_narrative(soc_result, mitre_result, generator)

        report = f"""# Incident Report

## Generated
{datetime.now(UTC).isoformat()}

## Summary
{_md_cell(str(soc_result["summary"]))}

## Analyst Narrative (AI-generated)
{narrative}

## Severity
{soc_result["severity"]}

## Event Type
{soc_result["event_type"]}

## MITRE ATT&CK Mapping

- **Tactic:** {mitre_result["tactic"]}
- **Technique:** {mitre_result["technique"]}
- **Technique ID:** {mitre_result["technique_id"]}
- **Confidence:** {mitre_result["confidence"]}

### MITRE Evidence
{chr(10).join(f"- {_md_cell(str(e))}" for e in mitre_result["evidence"])}

### MITRE Investigation Steps
{chr(10).join(f"- {_md_cell(str(s))}" for s in mitre_result["recommended_investigation"])}

## Evidence

| Field | Value | Significance |
|-------|-------|--------------|
{chr(10).join(f"| {_md_cell(e['field'])} | {_md_cell(e['value'])} | {_md_cell(e['significance'])} |" for e in soc_result.get("evidence", [])) or "| — | — | No structured evidence captured. |"}

## Severity Score

**{soc_result.get("severity_score", "N/A")} / 100**

## Indicators
{chr(10).join(f"- `{_md_code(str(i))}`" for i in indicators) if indicators else "- None detected"}

## Recommended Actions
{chr(10).join(f"- {_md_cell(str(a))}" for a in soc_result["recommended_actions"])}

## Sequence Correlation
{_render_sequence(sequence_result, sequence_detections)}

## Knowledge Base References
{chr(10).join(f"- **{_md_cell(r['source'])}** (relevance {r['score']:.2f}) — {_md_cell(r['snippet'])}" for r in kb_references) if kb_references else "- None captured"}

## Cited Passages{" (verified)" if citations_verified else ""}
{_render_citations(citations)}

## Detection Coverage
{chr(10).join(f"- **{_md_cell(str(d['title']))}** [{_md_cell(str(d['level']))}] — `{_md_code(str(d['file']))}` ({_md_cell(str(d['technique']))})" for d in detection_matches) if detection_matches else "- No Sigma rule covers this technique yet"}

## Behavioral Coverage (post-compromise)
{_render_behaviors(behavior_matches)}

## Response Plan (DRAFT — not executed)
{_render_response_plan(response_plan)}

## Assumptions
{chr(10).join(f"- {_md_cell(str(a))}" for a in soc_result["assumptions"])}
"""

        target.write_text(report, encoding="utf-8")

        if pdf_path is not None:
            # Optional PDF export (requires the '.[pdf]' extra). Imported lazily so
            # the Markdown report never depends on reportlab being installed.
            from agents.tools.pdf_report import render_markdown_to_pdf

            render_markdown_to_pdf(report, pdf_path)
        return target


if __name__ == "__main__":
    agent = IncidentReportAgent()
    agent.generate_report(
        "Failed password for root from 10.0.0.5 port 22 ssh2",
        "reports/markdown/sample_incident_report.md",
    )
    print("Generated reports/markdown/sample_incident_report.md")
