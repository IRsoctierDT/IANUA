# Case Study — SOC Analyst Agent v0.2

> **Defensive security automation that turns a single log line into a triaged,
> MITRE-mapped, human-reviewable incident report — fully local, fully auditable.**

| | |
|---|---|
| **Component** | SOC Analyst Agent v0.2 (+ MITRE Mapper, Threat Intel, Incident Report, Orchestrator) |
| **Domain** | Defensive security automation · alert triage · detection engineering |
| **Purpose** | Classify a security log event, score its severity, surface evidence and indicators, map it to MITRE ATT&CK, and emit a Markdown incident report |
| **Risk level** | Low — read-only analysis; no scanning, no network egress, no destructive actions |
| **Skill level required** | Analyst / junior SOC engineer to run; Python developer to extend |
| **Deployment complexity** | Low — pure Python, no external services required for core flow |

---

## 1. Executive Summary

The SOC Analyst Agent ingests a security log event — as plain text **or** structured
JSON — and returns a typed analysis: event classification, a 0–100 severity score, an
evidence table, extracted indicators of compromise, and concrete recommended actions.
A small set of cooperating agents then enriches that result (ATT&CK mapping, indicator
triage) and renders a portfolio-grade Markdown incident report.

The entire pipeline runs **locally and deterministically**. It performs no network
activity, no scanning, and no external enrichment by default — every outward or
irreversible step is left to a human (see [AGENTS.md](../../AGENTS.md) §5). This makes it
safe to run against real logs in an air-gapped lab and reproducible enough to unit-test.

**Outcome:** an analyst goes from a raw log line to a structured, escalation-ready
incident artifact in a single function call, with the reasoning made explicit rather than
hidden in a model's head.

---

## 2. Objectives

1. **Accept both input shapes** — security tooling emits both unstructured syslog lines
   and structured JSON events; the agent must handle either without losing fidelity.
2. **Score severity numerically** — a coarse `low/medium/high` label is not enough for
   queue prioritization; produce a defensible 0–100 score with explainable modifiers.
3. **Surface evidence, not just verdicts** — every analysis must show *which fields drove
   the conclusion* so a human can audit it.
4. **Map to a shared vocabulary** — translate the event into MITRE ATT&CK tactics and
   techniques so findings are comparable across incidents.
5. **Stay safe-by-default** — no external calls, no destructive actions; escalation is a
   human decision the agent only *recommends*.
6. **Be portfolio-grade** — fully typed, unit-tested, and documented.

---

## 3. Architecture / Process

The agent layer is a set of single-responsibility components coordinated by an
orchestrator. None of them reach the network or filesystem except the report writer,
which writes only to the local `reports/` directory.

```
        raw log (text or JSON dict)
                  │
                  ▼
        ┌───────────────────┐
        │  SOC Analyst v0.2 │   classify · score · evidence · indicators
        └─────────┬─────────┘
                  │ structured result
        ┌─────────┼───────────────────────────┐
        ▼         ▼                           ▼
  ┌──────────┐ ┌──────────────┐        ┌──────────────────┐
  │  MITRE   │ │ Threat Intel │        │ Incident Report  │
  │  Mapper  │ │ (per IOC)    │        │ (Markdown writer)│
  └──────────┘ └──────────────┘        └──────────────────┘
   tactic/        IOC triage              reports/markdown/*.md
   technique
                  │
                  ▼
        human review & approval (escalation, external enrichment)
```

**Design invariants** (from [DESIGN.md](../../DESIGN.md)):

- Agents *recommend, classify, summarize, and structure*. Humans approve anything
  destructive, external, or escalation-worthy.
- Every component returns a frozen `@dataclass` serialized via `asdict()` — output is a
  plain, typed dict that is trivial to test and to render.
- Untrusted input (the log) never reaches a shell, file path, or query unsanitized.

---

## 4. Implementation Steps

### 4.1 Dual input normalization

`_normalize_input()` accepts a `str` or a `dict`. JSON strings are parsed; dicts are
flattened to `(flat_text, structured_fields)`. Both the human-readable `message` and the
structured fields are preserved so downstream scoring can use either.

### 4.2 Classification

`_classify_event()` keyword-matches the flattened text into event types:
`authentication failure`, `successful login`, `ids alert`, `firewall block`,
`network anomaly`, or `unknown security event`.

### 4.3 Severity — label *and* numeric score

`_estimate_severity()` returns a label, honoring an explicit `severity` field if present.
Critically, it inspects **both** the flat text **and** the structured `user`/`account`
fields — so a structured event whose `message` omits the username but whose `user` field
says `root` is still recognized as privileged.

`_score_severity()` converts the label to a base score and applies aggravating modifiers
(privileged account, repeated/brute-force signals, explicit "critical" markers), clamped
to 100.

> **Design note — a real bug this fixed.** An earlier version scanned only the flattened
> `message`. A structured event like `{"user": "root", "message": "Accepted password ..."}`
> was scored `low (20)` because "root" never appeared in `message`. The fix — reading the
> structured `user`/`account` fields in *both* the label and score functions — is what the
> worked example below demonstrates (`user=root` → `high`, score `80`).

### 4.4 Evidence table & indicators

`_build_evidence()` emits a typed `EvidenceEntry` per significant field (timestamp, host,
user, src_ip, severity, message), each with a plain-English significance string.
`_extract_indicators()` pulls IOCs from structured fields first (`src_ip`, `source_ip`,
…) and falls back to IPv4 token scanning of the text.

### 4.5 Enrichment & reporting

The orchestrator passes the SOC result to the MITRE Mapper (event → tactic/technique),
runs each indicator through the Threat Intel agent (public vs. private IP, domain, etc.),
and hands everything to the Incident Report agent, which renders Markdown — escaping
pipe/newline characters so untrusted log content can't break the table layout.

---

## 5. Worked Example

**Input** — a structured SSH event: a *successful* root login from a public IP, the kind
of event that follows a brute-force attempt.

```json
{
  "timestamp": "2025-06-15T03:14:22Z",
  "host": "edge-bastion-01",
  "user": "root",
  "src_ip": "203.0.113.42",
  "message": "Accepted password for root from 203.0.113.42 port 22 ssh2"
}
```

**SOC Analyst output** (abridged — this is real output, not illustrative):

```json
{
  "agent": "SOC Analyst Agent v0.2",
  "summary": "Detected probable successful login activity.",
  "severity": "high",
  "severity_score": 80,
  "event_type": "successful login",
  "indicators": ["203.0.113.42"],
  "recommended_actions": [
    "Preserve the original log evidence.",
    "Correlate with adjacent timestamps.",
    "Confirm whether the login was expected and authorised.",
    "Review follow-on commands or session activity.",
    "Escalate for immediate human review."
  ]
}
```

The score breaks down as **70 (base for `high`) + 10 (privileged `root` account) = 80**.
Because `user=root` lives in a structured field rather than in `message`, this is exactly
the case the v0.2 severity fix was built to handle.

**MITRE mapping:**

| Field | Value |
|---|---|
| Tactic | Initial Access |
| Technique | Valid Accounts (`T1078`) |
| Confidence | medium |

**Threat-intel triage of `203.0.113.42`:** classified as a **public IP**, risk `unknown`,
with the agent explicitly recommending external reputation enrichment *before*
classification — i.e. it declines to guess and defers to a human/feed. (`203.0.113.0/24`
is the IETF documentation range, used here as a safe stand-in for a real external IP.)

The orchestrator writes the combined result to
[`reports/markdown/orchestrated_incident.md`](../../reports/markdown/orchestrated_incident.md).

---

## 6. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Untrusted log content breaks report rendering | Misleading incident report | Pipe/newline escaping in the Markdown table writer |
| Structured fields ignored in scoring | Under-triaged critical events | Severity functions read both flat text and `user`/`account` fields |
| Over-trust of agent verdict | Analyst skips review | Output always includes evidence + assumptions; escalation is a *recommendation* only |
| Prompt-injection / malicious log fields | Unsafe downstream action | No log content reaches a shell, path, or query; analysis is read-only |
| Indicator misclassification | Wrong enrichment path | Threat-intel agent returns `unknown` + "enrich first" rather than guessing |

---

## 7. Cost Considerations

The core pipeline is **pure Python with zero external dependencies at runtime** — no API
keys, no paid inference, no cloud services. It runs on the existing workstation/lab at
effectively zero marginal cost and works fully offline. Optional RAG enrichment uses a
local Ollama model (also free, loopback-only). Any remote enrichment (paid threat-intel
feeds, external reputation APIs) is an explicit, human-gated decision — never a silent
default.

---

## 8. Future Enhancements

- **Repeated-attempt correlation** — aggregate multiple failed logins from one source IP
  into a single brute-force finding with an escalating score.
- **Expanded MITRE coverage** — more techniques and sub-techniques; confidence tuned by
  evidence strength.
- **Pluggable enrichment** — opt-in connectors for local threat-intel datasets (still
  default-deny on external egress).
- **Structured audit log** — tamper-evident record of each analysis for review.
- **Batch + streaming modes** — process a log file or a live tail, not just single events.

---

## 9. Reproduce It Yourself

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Single structured event:
python -c "
from agents.soc_analyst_agent import SocAnalystAgent
import json
print(json.dumps(SocAnalystAgent().analyze_log({
    'timestamp': '2025-06-15T03:14:22Z', 'host': 'edge-bastion-01',
    'user': 'root', 'src_ip': '203.0.113.42',
    'message': 'Accepted password for root from 203.0.113.42 port 22 ssh2'
}), indent=2))
"

# Full multi-agent pipeline → writes reports/markdown/orchestrated_incident.md:
python -m agents.orchestrator_agent

# Run the test suite (unit + integration + security, 85% coverage gate):
python -m pytest
```

---

*Part of the [AI Operator Cyber Command Center](../../README.md). Security tooling here is
for defensive, authorized-lab use only — see [AGENTS.md](../../AGENTS.md) §5.*
