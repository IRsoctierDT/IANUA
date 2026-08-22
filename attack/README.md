# `attack/` — the pinned local ATT&CK corpus

The shared MITRE ATT&CK® vocabulary for every layer of IANUA: distilled from a
version-pinned, hash-verified STIX 2.1 bundle into small committed shards, and
never fetched at runtime. `attack/` imports no first-party module and has no
third-party dependency (enforced by `tests/security/test_attack_no_network.py`).

## Purpose · Risk level · Skill level · Deployment complexity

- **Purpose:** deterministic technique lookup, revocation/deprecation
  surfacing, detection/data-component alignment, and group/software behavioral
  context — offline, reproducible, and drift-gated.
- **Risk level:** low (read-only committed data; fail-closed loaders).
- **Skill level required:** familiarity with ATT&CK IDs and STIX basics for
  refreshes; none for consumers.
- **Deployment complexity:** none at runtime; a refresh is one staged download
  plus one command, roughly twice a year.

## Refresh ceremony (human action — AGENTS.md §5.1)

1. Download the versioned enterprise bundle and collection index from
   <https://github.com/mitre-attack/attack-stix-data> into gitignored
   `data/attack/` (external-network action: a human performs it; no code in
   this repository fetches).
2. `python scripts/update_attack.py --build --bundle enterprise-attack-<v>.json`
   — verifies size ceiling and SHA-256 *before* parsing, distils the shards,
   merges the append-only tombstone ledger, rewrites the pin (unsigned).
3. Review the diff. Re-run the reference gates
   (`python scripts/build_attack_navigator.py --check` and the test suite):
   any Sigma tag or mapping rule pinned to a now-revoked/deprecated technique
   fails closed with the successor named — re-anchor it deliberately.
4. Sign the pin (see below) and commit shards + pin + snapshot together.

## Pin signing (corruption vs. tampering)

The per-shard SHA-256 hashes in the pin detect *corruption*. Because the pin
and the shards live in the same tree — writable by the same actor — only the
Ed25519 signature over the pin body upgrades the claim to detecting
*tampering*. The private key is held by the maintainer, outside any agent's
reach; only the public key enters the repository (inside the signed pin).

```bash
# one-time: generate a keypair (prints hex; store the private key in your
# password manager, never in the repo or .env)
python -c "from agents.policies.signing import generate_ed25519_keypair as g; \
priv, pub = g(); print('private:', priv.hex()); print('public: ', pub.hex())"

# each refresh: sign the freshly built pin
ATTACK_PIN_ED25519_PRIVATE_KEY=<hex> ATTACK_PIN_ED25519_PUBLIC_KEY=<hex> \
  python scripts/update_attack.py --sign
```

**Current state: the committed pin is unsigned.** `--check` therefore verifies
integrity (corruption) only and prints a note saying so; PR-review-evading
edits are out of scope until the maintainer signs. This is the honest weaker
claim, stated rather than implied away.

## Freshness (advisory, never a gate)

`freshness(today=...)` reports *version distance* against the committed
collection-index snapshot — how many known releases are newer than the pin —
plus pin age as context. It has no exit code and feeds no committed artifact:
a time-dependent gate would turn `main` red with no commit, and the reflexive
fix (bulk-extending dates) destroys the control. Staleness is surfaced in the
dashboard and the weekly advisory workflow instead.

## Licensing

MITRE ATT&CK® content is © The MITRE Corporation, used under MITRE's Terms of
Use (attribution required; not an OSI license and not part of this repository's
Apache-2.0 grant). See `attack/ATTRIBUTION.md`, `NOTICE`, and
`docs/IP_AND_LICENSING.md`.
