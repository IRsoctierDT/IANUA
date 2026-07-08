# Case Study — Detection Matcher & Orchestrator (the Capstone Pipeline)

> **Two components that close the loop: the Detection Matcher links a triaged technique to
> the Sigma rules that alert on it, and the Orchestrator chains all seven agents into one
> call that turns a raw log line into a cited, detection-mapped incident report.**

| | |
|---|---|
| **Components** | Detection Matcher Agent (`agents/detection_matcher_agent.py`) · Orchestrator Agent (`agents/orchestrator_agent.py`) |
| **Domain** | Detection engineering · multi-agent orchestration · end-to-end triage |
| **Purpose** | Map a technique to its covering Sigma rules, and coordinate the full agent pipeline into one reproducible workflow |
| **Risk level** | Low — read-only analysis + one local report write; no network required, no destructive actions |
| **Skill level required** | Analyst to run; Python developer to extend rules and wiring |
| **Deployment complexity** | Low — pure Python core; optional local model for the AI narrative |

---

## 1. Executive Summary

Triage tells you *what happened*; detection engineering tells you *what alerts on it*. The
**Detection Matcher** connects the two using the shared ATT&CK vocabulary: given the technique
the MITRE Mapper emitted, it returns the Sigma rules in `detections/sigma/` tagged with that
technique, ranked most-severe-first. It's read-only, deterministic, and **fails soft** — a
missing corpus or an absent PyYAML yields no matches rather than an error, keeping the package's
core dependency-free.

The **Orchestrator** is the capstone. In a single `process_log()` call it runs the SOC Analyst,
MITRE Mapper, Threat Intel, Knowledge Base, and Detection Matcher agents, then hands everything
to the Incident Report Agent to render a Markdown report — optionally with a fail-soft AI
narrative. The report destination is an explicit parameter, so the pipeline has no hidden
working-directory dependency and tests write to a temp path instead of mutating tracked files.

**Outcome:** one function turns a raw log line into a triaged, MITRE-mapped, IOC-enriched,
framework-cited, detection-covered incident report — every step deterministic by default and
each sub-agent independently testable.

---

## 2. Objectives

1. **Close the triage→detection loop** — map a technique to the Sigma rules that cover it, via
   shared ATT&CK tags.
2. **Rank by urgency** — order detection matches most-severe-first for the report.
3. **Coordinate, don't entangle** — the orchestrator wires single-responsibility agents without
   them depending on each other.
4. **Stay reproducible** — the whole pipeline is deterministic by default; the report path is
   explicit.
5. **Degrade gracefully** — every enrichment step (KB, detections, AI narrative) fails soft so a
   partial environment still yields a complete report.

---

## 3. Architecture / Process

```
 raw log line
      │
      ▼
 ┌──────────────┐  Orchestrator.process_log(log, report_path)
 │ SOC Analyst  │──▶ classify · score · evidence · indicators
 └──────┬───────┘
      │ event_type / result
      ▼
 ┌──────────────┐        ┌──────────────┐        ┌────────────────┐
 │ MITRE Mapper │──T1078▶│ Detection    │──rules▶│                │
 └──────┬───────┘  T1110 │ Matcher      │        │ Incident       │
      │                └──────────────┘        │ Report Agent   │──▶ reports/markdown/*.md
      ├── indicators ─▶ Threat Intel ─────────▶│ (+ fail-soft   │
      └── query ──────▶ Knowledge Base ───────▶│   AI narrative)│
                          (cited refs)          └────────────────┘
                                                     │
                                                     ▼
                                            human review & approval
```

**Design invariants** (from [DESIGN.md](../../DESIGN.md) §5, decision log 2026-06-17/20):

- Detection Matcher is read-only, network-free, and fails soft (missing corpus / no PyYAML → no
  matches).
- The orchestrator's `report_path` is explicit — no hidden CWD write; tests target a temp path.
- The AI narrative is on-by-default via env but fails soft to the deterministic report.

---

## 4. Implementation Steps

### 4.1 Detection Matcher — technique → Sigma rules

`match_for_technique()` normalizes the technique ID, builds the ATT&CK tag (`attack.t1110`), and
returns every Sigma rule whose `tags` include it, as typed `DetectionMatch` records
(`rule_id`, `title`, `level`, `technique`, `file`). Matches are sorted by Sigma severity
(critical → informational), ties broken by title. `match_for_event()` is the convenience that
reads the `technique_id` straight from a MITRE result.

### 4.2 Detection Matcher — safe, soft failure

Rules are loaded from `detections/sigma/*.yml` with `yaml.safe_load`; a malformed file is
skipped, and if PyYAML isn't installed or the directory is missing, the agent returns `[]`. The
core package stays dependency-free and the pipeline degrades to "no detection coverage" rather
than crashing.

### 4.3 Orchestrator — wire the agents

`OrchestratorAgent.__init__` constructs each single-responsibility agent and resolves an optional
LLM generator from the environment (`LLM_NARRATIVE=auto`). `process_log()` runs SOC → MITRE →
Threat Intel (per indicator) → Knowledge Base → Detection Matcher, then calls the Incident Report
Agent with all the pre-computed results so nothing is analyzed twice.

### 4.4 Orchestrator — explicit output, structured return

The report path defaults to the tracked sample location but is a parameter callers (and tests)
override. `process_log()` returns a dict of the `soc`, `mitre`, `threat_intel`, `knowledge_base`,
and `detections` results — the machine-readable twin of the Markdown report.

---

## 5. Worked Example

**Detection Matcher — technique T1110 to its covering Sigma rules:**

```bash
python -m agents.detection_matcher_agent
```

```json
[
  {"rule_id": "cb797ff0-...", "title": "SSH Brute Force Followed by Successful Root Login",
   "level": "critical", "technique": "T1110", "file": "ssh_bruteforce_then_success.yml"},
  {"rule_id": "61b25aa1-...", "title": "SSH Brute Force - Repeated Failed Passwords",
   "level": "high", "technique": "T1110", "file": "ssh_brute_force.yml"},
  {"rule_id": "dc593d6d-...", "title": "SSH Failed Password",
   "level": "low", "technique": "T1110", "file": "ssh_failed_password.yml"}
]
```

Three rules cover T1110, ranked critical → high → low — exactly the **Detection Coverage**
section the report attaches.

**Orchestrator — one call, full pipeline:**

```bash
python -m agents.orchestrator_agent
# runs SOC → MITRE → Threat Intel → KB → Detection Matcher → Incident Report
# writes reports/markdown/orchestrated_incident.md
```

For `Failed password for root from 10.0.0.5 port 22 ssh2`, the orchestrator produces a report
that classifies the event, maps it to **T1110 (Brute Force)**, triages `10.0.0.5` as a private
IP needing local context, cites the ATT&CK framework overview from the knowledge base, and
attaches the three Sigma rules above — deterministically, with no network required.

---

## 6. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Missing Sigma corpus or PyYAML | Pipeline crash | Detection Matcher fails soft → returns no matches |
| Malformed Sigma rule file | Skipped/incorrect coverage | Bad YAML is skipped; only well-formed dicts are considered |
| Hidden working-directory write | Test pollution / surprise state | `report_path` is an explicit parameter; tests use a temp path |
| One agent's failure breaks the chain | No report | Each enrichment step (KB, detections, narrative) fails soft independently |
| AI narrative required for a valid report | Model outage blocks output | Narrative is opt-in and fails soft to the deterministic report |

---

## 7. Cost Considerations

The entire pipeline is pure Python with zero external dependencies at runtime for its core path
— no API keys, no network, effectively zero marginal cost, fully offline. The optional AI
narrative uses a local model (Ollama/llama.cpp, loopback-only, free). Any remote inference or
paid enrichment is an explicit, human-gated decision ([DESIGN.md](../../DESIGN.md) §9).

---

## 8. Future Enhancements

- **Sub-technique matching** — resolve parent/child ATT&CK relationships (e.g. `T1110.001`).
- **Detection gap reporting** — flag mapped techniques with *no* covering Sigma rule as coverage
  gaps.
- **Streaming/batch orchestration** — process a log file or live tail, not just single events.
- **Correlation across events** — aggregate related events (e.g. brute force → success) into one
  incident.
- **Structured audit of each run** — record every orchestration through the
  [policy/audit layer](./policy-and-audit.md).

---

## 9. Reproduce It Yourself

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Detection Matcher — technique to Sigma rules:
python -c "
from agents.detection_matcher_agent import DetectionMatcherAgent
import json
print(json.dumps(DetectionMatcherAgent().match_for_technique('T1110'), indent=2))
"

# Full pipeline → writes reports/markdown/orchestrated_incident.md:
python -m agents.orchestrator_agent

python -m pytest tests/test_detection_matcher_agent.py tests/test_orchestrator_agent.py
```

---

*Part of the [AI Operator Cyber Command Center](../../README.md). Security tooling here is
for defensive, authorized-lab use only — see [AGENTS.md](../../AGENTS.md) §5.*
