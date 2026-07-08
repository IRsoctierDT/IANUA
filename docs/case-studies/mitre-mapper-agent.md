# Case Study — MITRE ATT&CK Mapper Agent

> **Deterministic translation of a security event into a shared ATT&CK vocabulary —
> tactic, technique, technique ID, and a confidence level — so findings are comparable
> across incidents and auditable by a human.**

| | |
|---|---|
| **Component** | MITRE Mapper Agent (`agents/mitre_mapper_agent.py`) |
| **Domain** | Detection engineering · threat modeling · MITRE ATT&CK |
| **Purpose** | Map an event type / log line to an ATT&CK tactic + technique with evidence and investigation steps |
| **Risk level** | Low — read-only classification; no network, no scanning, no destructive actions |
| **Skill level required** | Analyst to run; Python developer to add mapping rules |
| **Deployment complexity** | Low — pure Python, no external services |

---

## 1. Executive Summary

The MITRE Mapper takes an event type (and optionally the raw log text) and returns a typed
mapping to the MITRE ATT&CK framework: the tactic, the technique, its canonical ID, a
confidence level, the evidence that drove the mapping, and concrete investigation steps.

The deliberate choice here is **determinism first**. Mappings are rule-based and reproducible
rather than delegated to a model, which means the same event always produces the same
technique ID — a property that matters when findings feed dashboards, metrics, and
cross-incident correlation. When a pattern isn't recognized, the agent returns `UNKNOWN` with
low confidence and a prompt to add a rule, rather than guessing a plausible-looking technique.

**Outcome:** every triaged event carries a stable ATT&CK label an analyst can trust and audit,
and the mapping logic is transparent enough to unit-test technique by technique.

---

## 2. Objectives

1. **Speak the shared vocabulary** — translate events into ATT&CK tactics/techniques so they
   are comparable across incidents and tools.
2. **Be deterministic** — the same input maps to the same technique every time; no model
   nondeterminism in the core path.
3. **Show the evidence** — return *why* a mapping was chosen, not just the label.
4. **Decline gracefully** — an unrecognized event maps to `UNKNOWN`/low confidence with a
   next step, never a fabricated technique.
5. **Be extensible** — new mappings are added as small, individually testable rules.

---

## 3. Architecture / Process

```
event_type (+ optional log_text)
          │
          ▼
   ┌────────────────────┐   normalize → match rule
   │ MitreMapperAgent   │   • "authentication failure" → T1110 Brute Force (Credential Access)
   │  .map_event()      │   • SSH "accepted"            → T1078 Valid Accounts (Initial Access)
   └─────────┬──────────┘   • "ids alert"               → analyst review (UNKNOWN, low)
          │                • no match                  → UNKNOWN, low + "add a rule"
          ▼
   MitreMappingResult(tactic, technique, technique_id, confidence,
                      evidence[], recommended_investigation[])
```

**Design invariants** (from [DESIGN.md](../../DESIGN.md)):

- The result is a frozen `@dataclass` serialized via `asdict()` — a plain, typed dict that is
  trivial to test and render.
- Deterministic mappings precede any LLM inference (recorded in the engineering log,
  2026-06-02); model reasoning is a later, optional layer, not the source of truth.
- Unknown patterns fail toward analyst review, never toward a confident wrong answer.

---

## 4. Implementation Steps

### 4.1 Normalize the inputs

`map_event()` lowercases both the event type and the (optional) log text so matching is
case-insensitive and can key off either the classification or raw signal in the line.

### 4.2 Rule matching, most-specific first

The agent checks rules in order: an `authentication failure` maps to **T1110 Brute Force**
(Credential Access, medium confidence); an SSH line containing `accepted` maps to **T1078
Valid Accounts** (Initial Access, medium) — capturing a *successful* login worth a legitimacy
review; an `ids alert` maps to an explicit "requires analyst review" result (UNKNOWN, low)
because a signature alone doesn't determine a technique.

### 4.3 Evidence and investigation steps

Every branch returns an `evidence` list (the observations behind the mapping) and a
`recommended_investigation` list (e.g. "Check source IP frequency", "Verify whether MFA or
account lockout controls were triggered"). The mapping is a starting point for a human, with
the next actions spelled out.

### 4.4 Decline, don't guess

If no rule matches, the agent returns `UNKNOWN` tactic/technique at low confidence with the
advice to review the raw evidence and add a mapping rule if the pattern recurs. This keeps the
technique namespace honest — an `UNKNOWN` is a signal to extend the ruleset, not noise.

---

## 5. Worked Example

**Command:**

```bash
python -m agents.mitre_mapper_agent
```

**Output** (real output):

```python
{'event_type': 'authentication failure',
 'tactic': 'Credential Access',
 'technique': 'Brute Force',
 'technique_id': 'T1110',
 'confidence': 'medium',
 'evidence': ['Authentication failure event detected.',
              'Repeated failed login activity may indicate brute force behavior.'],
 'recommended_investigation': ['Check source IP frequency.',
                               'Review failed login count per account.',
                               'Verify whether MFA or account lockout controls were triggered.']}
```

The `authentication failure` event maps deterministically to **T1110 (Brute Force)** under the
**Credential Access** tactic. Feeding an SSH `Accepted password …` line instead yields **T1078
(Valid Accounts)** under **Initial Access** — the mapping that the
[Detection Matcher](./detection-matcher-and-orchestrator.md) and
[Incident Report](./incident-report-agent.md) agents then build on.

---

## 6. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| A plausible-but-wrong technique is guessed | Misleading metrics / correlation | Unmatched events return `UNKNOWN`/low confidence, never a fabricated ID |
| Over-trust in a medium-confidence mapping | Analyst skips verification | Confidence level + evidence + investigation steps are always returned |
| Rule set drifts from ATT&CK updates | Stale mappings | Rules are small and individually unit-tested; add/adjust deliberately |
| Non-determinism from a model in the core path | Unreproducible findings | Core mapping is rule-based and deterministic; LLM reasoning is an optional later layer |

---

## 7. Cost Considerations

Pure Python with no external dependencies at runtime — no API keys, no paid inference, no
network. Runs at effectively zero marginal cost and fully offline. An optional LLM refinement
layer would use a local model (also free, loopback-only) and remain an explicit, gated choice.

---

## 8. Future Enhancements

- **Expand technique coverage** — more tactics, techniques, and sub-techniques.
- **Confidence tuning by evidence strength** — raise/lower confidence based on corroborating
  signals rather than a fixed per-rule level.
- **ATT&CK data ingestion** — load technique metadata from the official ATT&CK dataset
  (recorded as future work in the engineering log).
- **Optional LLM refinement** — a local model proposes candidate mappings that the
  deterministic rules confirm, never the reverse.

---

## 9. Reproduce It Yourself

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

python -c "
from agents.mitre_mapper_agent import MitreMapperAgent
import json
m = MitreMapperAgent()
print(json.dumps(m.map_event('authentication failure', 'Failed password for root from 10.0.0.5 port 22 ssh2'), indent=2))
print(json.dumps(m.map_event('successful login', 'Accepted password for root from 203.0.113.42 port 22 ssh2'), indent=2))
"

python -m pytest tests/test_mitre_mapper_agent.py
```

---

*Part of the [AI Operator Cyber Command Center](../../README.md). Security tooling here is
for defensive, authorized-lab use only — see [AGENTS.md](../../AGENTS.md) §5.*
