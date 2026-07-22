# Case Study — Incident Report Agent

> **Composes a portfolio-grade Markdown incident report from the pipeline's structured
> outputs — SOC triage, ATT&CK mapping, KB citations, and detection coverage — with an
> optional, clearly-labeled AI narrative that fails soft when no model is available.**

| | |
|---|---|
| **Component** | Incident Report Agent (`agents/incident_report_agent.py`) |
| **Domain** | Reporting · documentation · human-readable incident artifacts |
| **Purpose** | Render a structured, escalation-ready Markdown report from the agents' typed results |
| **Risk level** | Low — writes one Markdown file to a local path; no network required for the core report |
| **Skill level required** | Analyst to run; Python developer to extend sections |
| **Deployment complexity** | Low — pure Python core; optional local model for the narrative |

---

## 1. Executive Summary

The Incident Report Agent is where the pipeline's machine-readable outputs become a document a
human can act on. It takes the SOC Analyst's triage and the MITRE Mapper's technique mapping —
and, when supplied, Knowledge Base citations and Sigma detection matches — and renders a
structured Markdown report: summary, severity, ATT&CK mapping with evidence, an evidence table,
indicators, recommended actions, cited references, detection coverage, and assumptions.

Two properties make it safe to run against real, untrusted log content. First, **every table
cell is escaped** so a pipe or newline injected via a log field can't break the report layout
or smuggle formatting. Second, the optional **AI narrative is opt-in and fails soft**: with no
local model configured the deterministic report is unchanged, and if the model errors the
section records that rather than failing the whole report. The narrative is always clearly
labeled "AI-generated" and constrained to the supplied facts.

**Outcome:** a reproducible, escalation-ready incident artifact where the deterministic content
is trustworthy on its own and the AI summary is a clearly-marked convenience, never a
dependency.

---

## 2. Objectives

1. **Compose, don't recompute** — accept pre-computed SOC/MITRE results so the orchestrator's
   work isn't duplicated.
2. **Render untrusted content safely** — escape Markdown-significant characters so log fields
   can't break the table or inject formatting.
3. **Make enrichment optional** — KB citations and detection matches appear when supplied and
   degrade to a clear "none attached" note otherwise.
4. **Keep AI clearly labeled and non-load-bearing** — the narrative is opt-in, fact-constrained,
   and fails soft.
5. **Write to an explicit path** — the caller controls the output location; no hidden
   working-directory writes.

---

## 3. Architecture / Process

```
 soc_result ─┐
 mitre_result┤   (pre-computed, or the agent runs SOC+MITRE itself)
 kb_references┤
 detection_matches┤
 generator (optional)┘
        │
        ▼
 ┌──────────────────────────┐   escape cells → assemble sections
 │ IncidentReportAgent      │   summary · narrative · severity · ATT&CK · evidence table
 │  .generate_report(path)  │   · score · indicators · actions · KB refs · detection coverage
 └────────────┬─────────────┘   · assumptions
        │
        ▼
   reports/markdown/<name>.md   (human review & approval)
```

**Design invariants** (from [DESIGN.md](../../DESIGN.md)):

- Untrusted log content is escaped before it enters a Markdown table (`_md_cell`).
- The report writer is the only component that touches the filesystem, and only under a
  caller-supplied path.
- The AI narrative is opt-in, labeled, fact-constrained, and fails soft — never required for a
  valid report.

---

## 4. Implementation Steps

### 4.1 Compose from supplied results

`generate_report()` accepts optional `soc_result` and `mitre_result`; if omitted it runs the
SOC Analyst and MITRE Mapper itself. This lets the [Orchestrator](./detection-matcher-and-orchestrator.md)
pass results it already computed instead of paying for the analysis twice.

### 4.2 Safe Markdown rendering

`_md_cell()` replaces `|` with `\|` and collapses newlines to spaces so a crafted log field
can't break the evidence table or inject rows. Every value that lands in a table cell passes
through it — the report stays well-formed even on hostile input.

### 4.3 Optional, fail-soft AI narrative

`_build_narrative()` returns a clear "not enabled" note when no `generator` is passed. When one
is present, it builds a facts string (event type, severity, indicators, technique) and asks the
local model to summarize *only* those facts. If the backend supports grammar-constrained JSON
(e.g. llama.cpp), it renders a structured narrative; if the model errors, the section records
"AI narrative unavailable" rather than raising. The output is always headed "Analyst Narrative
(AI-generated)."

### 4.4 Graceful degradation of enrichment

KB references and detection matches render as their own sections when supplied and fall back to
"None captured" / "No Sigma rule covers this technique yet" when not — so a partial pipeline
still produces a complete, honest report.

---

## 5. Worked Example

**Command** (deterministic — no model needed):

```bash
python -m agents.incident_report_agent
# writes reports/markdown/sample_incident_report.md
```

For a structured SSH root-login event, the report includes a MITRE section and an escaped
evidence table:

```markdown
## MITRE ATT&CK Mapping

- **Tactic:** Initial Access
- **Technique:** Valid Accounts
- **Technique ID:** T1078
- **Confidence:** medium

## Evidence

| Field | Value | Significance |
|-------|-------|--------------|
| user  | root  | Privileged account referenced. |
| src_ip| 203.0.113.42 | External source address. |
```

When the orchestrator supplies detection matches, a **Detection Coverage** section is attached
automatically — for T1110 that's the three ranked Sigma rules from the
[Detection Matcher](./detection-matcher-and-orchestrator.md). With a local model configured
(`LLM_NARRATIVE=auto`), an **Analyst Narrative (AI-generated)** section is added, constrained to
the facts above; with no model, that section simply notes it isn't enabled and the rest of the
report is identical.

> The narrative is illustrative and AI-generated; it is constrained to the structured facts and
> never substitutes for analyst verification.

---

## 6. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Untrusted log content breaks or injects table formatting | Misleading report | `_md_cell()` escapes pipes/newlines on every cell |
| AI narrative fabricates hosts/IPs/conclusions | False incident detail | Narrative is constrained to supplied facts and clearly labeled AI-generated |
| Model outage fails the whole report | No artifact when it's needed most | Narrative fails soft; deterministic report is unaffected |
| Hidden filesystem writes | Surprised state / test pollution | Output path is an explicit caller argument |
| Missing enrichment silently omitted | Reader assumes full coverage | Absent KB/detection data renders an explicit "none" note |

---

## 7. Cost Considerations

The deterministic report is pure Python with zero external dependencies at runtime — no API
keys, no network, no cost, fully offline. The optional narrative uses a local model (Ollama or
llama.cpp, loopback-only, free); any remote inference would be an explicit, gated decision
(see [DESIGN.md](../../DESIGN.md) §9).

---

## 8. Future Enhancements

- **PDF export** — render the Markdown to a portfolio/client-ready PDF (noted as a roadmap item
  in `PROJECT_STATUS.md`).
- **Report templates** — selectable layouts for SOC vs. executive audiences.
- **Signed reports** — attach a hash/signature for tamper-evidence.
- **Batch reporting** — one report per event across a log file.

---

## 9. Reproduce It Yourself

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Deterministic report from a single log line:
python -c "
from agents.incident_report_agent import IncidentReportAgent
p = IncidentReportAgent().generate_report(
    'Accepted password for root from 203.0.113.42 port 22 ssh2',
    'reports/markdown/demo_incident.md')
print('wrote', p)
"

python -m pytest tests/test_incident_report_agent.py
```

---

*Part of the [IANUA](../../README.md). Security tooling here is
for defensive, authorized-lab use only — see [AGENTS.md](../../AGENTS.md) §5.*
