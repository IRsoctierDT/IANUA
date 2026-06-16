# Case Study — SOC Analyst Agent v0.2

**Layer:** Agent Layer  
**Branch:** feat/soc-analyst-v0.2  
**Status:** Complete

---

## Problem

The v0.1 SOC Analyst Agent accepted only plain-text log strings and returned a flat
severity label with no numeric scoring. Analysts had no machine-readable evidence trail
and no way to feed structured log data (JSON events from SIEMs, cloud logging APIs)
without pre-processing.

---

## What Was Built

### Input Normalisation

`analyze_log()` now accepts three forms:

| Input form | Example |
|---|---|
| Plain-text string | `"Failed password for root from 203.0.113.42 port 22 ssh2"` |
| JSON string | `'{"host":"web-01","src_ip":"203.0.113.42","message":"..."}'` |
| Python dict | `{"host": "web-01", "src_ip": "203.0.113.42", "message": "..."}` |

Empty strings, empty dicts, and non-string/non-dict inputs are rejected with
`ValueError` at the boundary.

### Severity Scoring (0–100)

A numeric `severity_score` field is appended to every result. Base scores by label:

| Label | Base | Root/admin bonus | Brute-force bonus | Critical keyword |
|---|---|---|---|---|
| critical | 90 | +10 (cap 100) | +10 | +5 |
| high | 70 | +10 | — | — |
| medium | 45 | — | — | — |
| low | 20 | — | — | — |
| unknown | 0 | — | — | — |

Structured input that carries an explicit `severity` field honours it directly.

### Evidence Table

`_build_evidence()` maps structured input fields to an `EvidenceEntry` list:

```python
@dataclass(frozen=True)
class EvidenceEntry:
    field: str
    value: str
    significance: str
```

For plain-text input, privileged-account presence and event-signal keywords are
captured as evidence entries.

The `IncidentReportAgent` renders the evidence table as a markdown pipe table.

### New Event Types

`_classify_event()` gained two new patterns:

- `"successful login"` — `Accepted password` / `Accepted publickey`
- `"network anomaly"` — `connection refused` / `timeout`

### Sample Logs

`sample-logs/ssh_brute_force.log` — 5 plain-text SSH failure lines  
`sample-logs/structured_events.json` — 4 structured JSON events covering all event types

---

## Test Coverage

18 tests in `tests/test_soc_analyst_agent.py` (all passing):

- v0.1 backward-compatibility (auth failure, root high severity, empty/non-string rejection)
- JSON string parsing and explicit severity honour
- Dict input: src_ip extraction, evidence table population, empty dict rejection
- Severity score: range check, root > medium baseline, critical ≥ 90, unknown = 0
- Evidence: plain-text root entry, required keys present
- New event types: successful login, network anomaly, root successful login = high

Coverage gate: 85 % (enforced in CI).

---

## Facts / Assumptions / Analysis / Recommendations

**Facts**
- All 18 unit tests pass; mypy clean across 39 files; ruff lint + format clean.
- No external network calls are made; analysis is fully offline.

**Assumptions**
- Structured input uses one of the expected key names (`src_ip`, `source_ip`, `ip`, `remote_addr`).
- Severity labels from upstream systems match the five values in `_SEVERITY_SCORES`.

**Analysis**
- The cast-based `_estimate_severity` return eliminates the previous `type: ignore` workaround.
- Lazy init was not needed here; the agent has no module-level service clients.

**Recommendations**
- Add integration tests that drive `IncidentReportAgent.generate_report()` end-to-end with sample logs.
- Consider adding a `MITRE_TECHNIQUE_ID` field to `EvidenceEntry` once the MITRE mapper
  is wired into the evidence pipeline.
