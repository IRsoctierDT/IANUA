# Detection Intelligence Plan

> The tracked engineering plan for IANUA's ATT&CK mapping, threat-intelligence,
> behavioral-detection, and response layers. Adapted from the adversarially
> verified design of 2026-08-21 (13-agent research/verification workflow over
> the working tree; 72 claims refuted and corrected before a line was written).
> Statuses below are live — update this file as slices land.

## Executive Summary

IANUA gains a version-pinned, revocation-aware local MITRE ATT&CK corpus
(`attack/`), a data-driven event→technique mapping engine
(`agents/mapping/`), and a first-party behavioral threat-intelligence library
(`intel/`) — each committed, drift-gated, deterministic, offline, and
dependency-free. Containment ("shut down payloads") ships as an
evidence-linked **response plan** artifact whose security tests prove it
cannot execute; no host executor is built. The honest headline: IANUA can
*name*, *evidence*, and *plan against* resident-payload behavior with a
corpus that provably cannot go silently stale — it does not, and will not,
kill processes on hosts.

## Objectives

1. Real, reviewable ATT&CK technique mapping (data, not code ladders).
2. An "ongoing database": a pinned local ATT&CK corpus whose staleness is
   loud (merge-blocking reference gates) and whose refresh is one documented
   human command, ~2–4×/year.
3. A threat-intelligence library whose durable half is **behavioral**
   (Pyramid of Pain, encoded: atomic indicators decay on a clock; behavioral
   records age on review intervals and ATT&CK revisions).
4. Resident-payload detection content and a plan-only response layer that
   honors AGENTS.md §5/§5.1 by construction.

## Scope verdicts (what is deliberately not built)

| Not building | Reason |
|---|---|
| Any host executor (`kill_process`, `quarantine_file`, `isolate_host`) | The sandbox hard-codes `--network none`, `--cap-drop ALL`, `--read-only`; enabling execution means weakening an existing control (§2.6). The repo also has no per-invocation approval primitive — a policy allow-list entry is a permanent, unscoped grant. |
| Live third-party feed sync | Needs a secret + non-loopback egress (§5.1 gates) to buy atomic IoCs stale within days; committed real-world IoCs publish accusations that rot for every clone. |
| `yara-python`, `stix2`, `mitreattack-python`, `pydantic`, `numpy`, runtime PyYAML | Runtime `dependencies = []` is a deliberate, load-bearing property. Every candidate was rejected with a stdlib alternative; ~200 lines of owned STIX graph traversal beats feeding 54 MB of untrusted data to a third-party parser. |
| Statistical beaconing / exfil analytics | Requires flow telemetry no parser here produces; building the math without the sensor is coverage theater. Deferred with the prerequisite named. |
| ML/learned confidence scoring | Non-reproducible, unreviewable in a diff, breaks hermetic CI. |

## Architecture / Process

```
raw log ──► SOC classifier ──► agents/mapping (rules.json, first-match precedence)
                                     │  TechniqueAttribution[] (IDs validated against attack/)
                                     ▼
                               attack/  ◄─── the ONLY source of technique identity
                                     │       (pinned 19.2; revocation surfaced, never rewritten)
                                     ▼
                               intel/  ── behavioral match · atomic lookup with decay,
                                     │     never-flag suppression, 2-source corroboration
                                     ▼
                     risk engine · detections · incident reports
                        (every artifact stamps attack_version)
```

Invariants: `attack/` has zero first-party imports and is the only minter of
technique identity; every artifact naming a technique stamps the pinned
version; `intel/` and `agents/mapping/` consume `attack/` through narrow
typed surfaces; nothing in these packages reads a clock or opens a socket
(enforced by `tests/security/`).

## Implementation Steps (live status)

| Phase | Scope | Status |
|---|---|---|
| P1 | Sigma condition parser precedence + report Markdown hardening | **DONE** — PR #154 |
| P0 | Gate-scope reconciliation (`compliance/` into coverage, scripts mypy, parity meta-test) | **DONE** — PR #154 |
| P2 | `attack/` corpus: pin, shards, distiller, tombstones, freshness, SUP-03/MAN-03 | **DONE** — PR #154 (Enterprise ATT&CK 19.2) |
| P3 | Navigator rewire: version from pin; dead technique tags cannot merge | **DONE** — PR #154 |
| P4 | `agents/mapping/`: data-driven engine, multi-technique output, digest gate | **DONE** — PR #155 |
| P5 | `intel/`: behavioral library, synthetic seed, decay, corroboration, agent upgrade | **DONE** — this PR |
| P6 | `detections/behaviors/`: behavioral TTP corpus, reference-gated index, matcher + report wiring | **DONE** — this PR |
| P7 | `correlation/` wiring: scenario rules carry validated ATT&CK, incidents stamp coverage | Planned (waits on XDR-2; XDR-1 has landed) |
| P8 | `agents/response/`: plan-only containment; security tests prove no executor exists | **DONE** — this PR |
| P9 | Dashboard: Detection Intelligence tab — corpus health, intel freshness, behavioral telemetry split, maintenance debt, plan-only response notice | **DONE** — this PR |
| XDR-1 | `ingest/`: canonical `NormalizedEvent`, ten parsers across five domains, fail-closed source recognition, OCSF classification for structured events | **DONE** — this PR |
| XDR-2 | `correlation/`: entity resolution across domains, incident assembly, cross-source scoring | Planned (unblocks P7) |

## Trust boundaries added (DESIGN.md §5)

5. External ATT&CK STIX bundle → `attack/` store — human-staged, size ceiling
   → depth scan → SHA-256 → parse; Ed25519-signable pin; `.REJECTED`
   forensics; absence degrades soft, tampering hard-fails.
6. Third-party intel → `intel/` store — no live feed; license + TLP + source
   allow-lists; never-flag at ingest and query; corroboration caps.
7. Authored rules → committed stores — literal-only predicates, canonicalized
   digests, no programmatic writer; LLM output may never author a technique
   ID, predicate, target, or tier.
8. Indicator → containment → live host — **closed by construction** until an
   explicit, signed, expiring, per-target approval primitive is designed as
   its own reviewed change.
9. Third-party telemetry → canonical event → every downstream layer —
   recognize-never-guess (ambiguous records are attributed to no parser),
   degrade-visibly-never-drop, and no ambient authority (no clock, socket,
   subprocess, filesystem, or dynamic exec — asserted over the package AST).
   Email carries metadata only: there is no body field to hold one.

## Risks

Ranked, with mitigations, in DESIGN.md §8. The one that matters most:
**solo-maintainer decay of an "ongoing" database** — mitigated by scoping
content to what one person can re-review, making staleness visible
(version-distance freshness, expiring MAN-03 attestation, per-record review
intervals) and never letting freshness fail a build. If maintenance stops,
the dashboard says so — strictly better than claimed currency.

## Cost Considerations

Zero recurring infrastructure. Runtime dependency count: **0** (stdlib
only). The ongoing cost is human: ~1 focused hour per ATT&CK release
(2–4×/year) plus periodic review of committed intel records — the plan sizes
the corpus to that budget deliberately.

## Future Enhancements

- P7 and XDR-2 above: `correlation/` (entity resolution across domains,
  incident assembly), which is the remaining half of the XDR path.
- Unit 42 integration tiers: distill the MIT-licensed Adversary Playbooks
  (STIX 2.0, archived corpus) into `intel/behaviors/` via the human-staged
  pattern; `pan-unit42/iocs` snapshots stay gitignored under `data/intel/`;
  the commercial Cortex feed remains an unbuilt connector slot.
- Ed25519 pin signing ceremony (maintainer key; `attack/README.md`) — until
  performed, the integrity gate honestly claims corruption-detection only.
- Replace the `* @owner` CODEOWNERS placeholder so §8's mandatory-review
  rule enforces.
