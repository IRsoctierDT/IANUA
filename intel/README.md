# `intel/` — the local threat-intelligence library

First-party, behavioral, expiring, and synthetic where atomic. See
DESIGN.md §5 boundary 6 and §11 (2026-08-21) for the full rationale.

## Purpose · Risk level · Skill level · Deployment complexity

- **Purpose:** ATT&CK-anchored behavioral indicators (the durable half of
  threat intelligence) plus a synthetic atomic seed exercising lookup,
  decay, and corroboration offline; consumed by the Threat Intel Agent.
- **Risk level:** low (committed, validated, read-only data; no egress).
- **Skill level required:** ATT&CK familiarity to author behavioral records.
- **Deployment complexity:** none — ships with the repository.

## Why behavioral outlives atomic (encoded, not asserted)

An adversary rotates an IP in minutes and a domain in hours; changing *how
they operate* — the login-spray rhythm, the history-clearing reflex, the
account-then-privilege chain — costs retraining and retooling. The schema
encodes that difference: atomic indicators carry a mandatory `expires` and
decay exponentially (per-type half-life: URL 14d, IP 30d, domain 90d,
hash 365d); behavioral records never decay on a clock — they age on a human
review interval and degrade to `stale-anchor` when their pinned ATT&CK
anchor is deprecated or revoked.

## Poisoning containment (structural, tested)

- Source allow-listing: an unregistered `source_id` rejects the record.
- License allow-list and **TLP:CLEAR-only** at ingest.
- The explicit never-flag CIDR list (RFC1918, loopback, link-local incl.
  169.254.169.254, CGNAT, multicast, ULA) is enforced at ingest **and**
  query — internal space can never be branded by a feed.
- Network-observable indicators need **two sources with distinct declared
  upstreams** for a `malicious` verdict; a single feed caps at `suspicious`.
- No atomic indicator can authorize any action anywhere in the platform.

## Adding real intel

Committed content stays first-party or synthetic. Vetted external corpora
(e.g. the MIT-licensed Unit 42 Adversary Playbooks) enter via the same
human-staged, pin-verified distill pattern as the ATT&CK bundle — a §5.1
human action, never a runtime fetch. Local, non-redistributable snapshots
belong in gitignored `data/intel/`.

Every data change regenerates the digest in the same PR:
`python scripts/check_intel_store.py --update`.
