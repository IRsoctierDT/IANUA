# `detections/behaviors/` — post-compromise behavioral detections

The TTP corpus aimed at payloads that are **already resident** on a host, as
opposed to `detections/sigma/`, which covers perimeter and authentication
events. Every rule is ATT&CK-anchored, fixture-replayed, and honest about
whether it can actually fire here.

## Purpose · Risk level · Skill level · Deployment complexity

- **Purpose:** name and evidence resident-implant behavior — defense
  impairment, LOLBin ingress, persistence installs, fileless execution.
- **Risk level:** low (detection content only; no payloads, no tooling).
- **Skill level required:** ATT&CK familiarity plus knowledge of the target
  telemetry to author; none to consume.
- **Deployment complexity:** none — the committed JSON index ships with the
  repository and the matcher reads it with stdlib `json`.

## The `validation:` marker — read this before trusting coverage

Every rule declares one of:

| Marker | Meaning |
|---|---|
| `telemetry-available` | The signal this rule needs is ingested today; it can fire in production. |
| `telemetry-required` | The rule replays green against fixtures but **cannot fire here** until the sensor exists (typically endpoint process telemetry: Sysmon EID 1, auditd `execve` with parent linkage, or an EDR feed). |

This platform currently ingests syslog-shaped text only, so most endpoint
rules are `telemetry-required` — and a security test asserts that any rule
keying on `command_line` / `parent_image` / `image` declares itself so.
Aspirational coverage stays visibly aspirational: the published ATT&CK
Navigator layer is deliberately sourced from `detections/sigma/` alone, so a
rule that cannot fire never inflates a public coverage claim.

**Answering "is real endpoint telemetry available?" is what promotes these
rules.** Until then they are validated logic waiting on a sensor, and they
say so in every report they appear in.

## Authoring a rule

1. Write the YAML in this directory. Required: `title`, `name`, `id` (UUID),
   `description`, `level`, `validation`, `tags` (with an `attack.tXXXX`
   technique tag), `logsource`, `detection`, `falsepositives`, `references`.
2. Add fixtures to `detections/fixtures/behavior_fixtures.json` — at least
   one `should_fire` and **at least three** `should_not_fire`. Behavioral
   rules fire on ordinary administrative tooling; the negatives are what
   prove the rule discriminates. Use RFC 5737/1918 addresses and invented
   hostnames only.
3. Regenerate the index in the same commit:
   `python scripts/build_behavior_index.py`.

The builder validates the whole corpus fail-closed and runs the **reference
gate**: an `attack.tXXXX` tag that does not resolve to an *active* technique
in the pinned corpus fails the build with the successor named. That is not
theoretical — `T1562.001` was revoked in ATT&CK 19 (superseded by `T1685`,
which moved into the new Defense Impairment tactic), and the gate caught it
during authoring of this very corpus.

## What this corpus is not

Detection rules describe attacker behavior — that is what makes them
detections. They are not attack tooling: a security suite asserts no rule
carries a payload, a shellcode blob, or prose that reads as a runnable
exploitation command (AGENTS.md §5). Matching *selections* legitimately
contain command fragments; prose fields do not.
