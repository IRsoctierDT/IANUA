# Case Study — Threat Intelligence Agent

> **Indicator triage that classifies what it can and refuses to guess what it can't —
> returning `unknown` with an "enrich first" recommendation instead of an unverified
> reputation verdict.**

| | |
|---|---|
| **Component** | Threat Intel Agent (`agents/threat_intel_agent.py`) |
| **Domain** | Indicator triage · IOC classification · verify-don't-assert |
| **Purpose** | Classify an indicator (IP, domain, unknown), assess how much local context it needs, and recommend the right enrichment path |
| **Risk level** | Low — read-only classification; no external lookups, no network egress |
| **Skill level required** | Analyst to run; Python developer to extend classification rules |
| **Deployment complexity** | Low — pure Python, no external services |

---

## 1. Executive Summary

The Threat Intel Agent takes a single indicator of compromise and returns a typed triage: the
indicator type, a risk level, a confidence, a plain-English explanation, and the recommended
next actions. Its defining behavior is **epistemic honesty**. A private IP is classified with
high confidence as "internal, needs local context." A *public* IP is deliberately marked
`unknown` risk — because the agent performs no external reputation lookups by default — with an
explicit recommendation to enrich against threat feeds *before* classifying. It declines to
assert a verdict it hasn't earned.

This matters because the most dangerous failure mode in automated triage is a confident wrong
label. By defaulting to "enrich first" instead of guessing, the agent keeps a human's judgment
in the loop for exactly the indicators that require external data.

**Outcome:** analysts get instant, safe structure on every indicator, and the agent never
launders an unverified guess as a finding.

---

## 2. Objectives

1. **Classify indicator type** — private IP, public IP, domain, or unknown — from the raw
   string alone.
2. **Right-size the context needed** — say whether an indicator needs *local* correlation or
   *external* enrichment.
3. **Never assert an unverified verdict** — a public IP is `unknown` until enriched; the agent
   recommends the feed lookup rather than faking it.
4. **Recommend concrete next actions** — each result carries the specific investigation steps
   for that indicator type.
5. **Stay network-free by default** — no outbound calls; external enrichment is a human-gated
   step.

---

## 3. Architecture / Process

```
indicator string
      │
      ▼
 ┌──────────────────────┐   private IPv4 (10/8, 172.16/12, 192.168/16) → private_ip, high conf
 │  ThreatIntelAgent    │   other IPv4                                   → public_ip, risk unknown
 │  .analyze_indicator()│   contains "."                                 → domain, risk unknown
 └──────────┬───────────┘   otherwise                                    → unknown, low conf
      │
      ▼
 ThreatIntelResult(indicator_type, risk_level, confidence,
                   explanation, recommended_actions[])
```

**Design invariants** (from [DESIGN.md](../../DESIGN.md) §5):

- Public indicators return `unknown` + "enrich first" rather than a fabricated reputation.
- No external network egress by default; feed/API enrichment is an explicit, human-gated step.
- The result is a frozen `@dataclass` serialized via `asdict()` for clean composition with the
  rest of the pipeline.

---

## 4. Implementation Steps

### 4.1 Private-IP detection

`_is_private_ip()` first confirms a valid IPv4, then checks the RFC 1918 ranges (`10/8`,
`172.16–31`, `192.168/16`). A private IP is classified with **high** confidence as
`context-dependent` — it's internal, so the answer lives in the asset inventory and local
logs, and the agent says exactly that.

### 4.2 Public-IP restraint

A valid IPv4 that isn't private is `public_ip` with risk **`unknown`** and **medium**
confidence. The explanation is explicit: "Public IP requires external reputation enrichment
before classification." The recommended actions point to threat feeds, geolocation/ASN review,
and correlation with IDS/firewall/auth events — i.e. the enrichment a human runs next.

### 4.3 Domain and unknown handling

A string containing a `.` that isn't an IP is treated as a `domain` (risk `unknown`, medium)
with DNS/WHOIS/reputation next steps. Anything else is `unknown`/low confidence with advice to
review the original evidence and add a parsing rule if it recurs.

### 4.4 Fail loud on empty input

An empty indicator raises `ValueError` rather than returning a meaningless classification —
the caller passed nothing to analyze.

---

## 5. Worked Example

**Command:**

```bash
python -m agents.threat_intel_agent
```

**Output** (real output — a private IP):

```python
{'indicator': '192.168.1.50',
 'indicator_type': 'private_ip',
 'risk_level': 'context-dependent',
 'confidence': 'high',
 'explanation': 'Private IP addresses are internal and require local network context.',
 'recommended_actions': ['Correlate with asset inventory.',
                         'Check authentication and firewall logs.',
                         'Determine whether the host behavior is expected.']}
```

Contrast a **public** IP — the agent refuses to assert a verdict:

```python
{'indicator': '203.0.113.42',
 'indicator_type': 'public_ip',
 'risk_level': 'unknown',                # ← declines to guess
 'confidence': 'medium',
 'explanation': 'Public IP requires external reputation enrichment before classification.',
 'recommended_actions': ['Check threat intelligence feeds.',
                         'Review geolocation and ASN.',
                         'Correlate with IDS, firewall, and authentication events.']}
```

The private IP gets a confident, actionable local-context verdict; the public IP gets an honest
`unknown` and the enrichment path a human should run — never a fabricated reputation score.

---

## 6. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Fabricated reputation for a public IP | False confidence drives wrong response | Public IPs return `unknown` + "enrich first"; the agent never guesses |
| Silent external lookups | Data leak / egress dependency | No network calls by default; enrichment is a human-gated step |
| Indicator misparsed | Wrong enrichment path | Strict IPv4 validation; ambiguous strings fall to `unknown`/low confidence |
| Over-trust of a `context-dependent` label | Missed internal threat | Private-IP results still list local correlation actions to run |

---

## 7. Cost Considerations

Pure Python, zero external dependencies at runtime — no API keys, no paid feeds, no network.
Runs at effectively zero marginal cost and fully offline. Paid threat-intel feeds or reputation
APIs are an explicit, human-gated decision — never a silent default (see
[DESIGN.md](../../DESIGN.md) §9).

---

## 8. Future Enhancements

- **Pluggable local feeds** — opt-in connectors for local threat-intel datasets, still
  default-deny on external egress (AbuseIPDB / VirusTotal / OTX are noted as future work in the
  engineering log — all human-gated).
- **IPv6 and hash indicators** — extend classification beyond IPv4 and domains.
- **Confidence from corroboration** — raise confidence when multiple signals agree.
- **Caching of human-approved enrichments** — remember verdicts an analyst has confirmed.

---

## 9. Reproduce It Yourself

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

python -c "
from agents.threat_intel_agent import ThreatIntelAgent
import json
a = ThreatIntelAgent()
for ind in ['192.168.1.50', '203.0.113.42', 'suspicious-domain.example', 'not-an-indicator']:
    print(json.dumps(a.analyze_indicator(ind), indent=2))
"

python -m pytest tests/test_threat_intel_agent.py
```

---

*Part of the [AI Operator Cyber Command Center](../../README.md). Security tooling here is
for defensive, authorized-lab use only — see [AGENTS.md](../../AGENTS.md) §5.*
