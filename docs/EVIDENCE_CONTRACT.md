# EVIDENCE_CONTRACT.md — IANUA ⇄ IANUA-Broker ⇄ Agent Trust Broker

> **The cross-repository data contract.** Three repositories exchange security evidence as
> files. This document is the single normative description of those files, so that a change
> on one side cannot silently break a reader on another. A copy of this file lives in each
> participating repository and the three copies must be byte-identical.
>
> | | |
> |---|---|
> | **Document** | Cross-Repository Evidence Contract |
> | **Status** | **Draft — not ratified.** No clause binds any repository until §13 is complete and the owner signs off. |
> | **Version** | `evidence-contract/0.1-draft` |
> | **Owner** | Repository maintainer (human) |
> | **Parties** | `IRsoctierDT/IANUA` · `IRsoctierDT/IANUA-Broker` (`mcpscan`) · `IRsoctierDT/agent-trust-broker` (ATB) |
> | **Companion docs** | [`AGENTS.md`](../AGENTS.md) §5 · [`DESIGN.md`](../DESIGN.md) §5 · IANUA-Broker `docs/proposals/ATB_POSTURE_CHECK.md` · IANUA-Broker ADR-17 |
> | **Review cadence** | On any change to a field, a digest algorithm, or a reader limit named below |

---

## 1. Executive Summary

Three repositories already exchange evidence, and until now nothing described the exchange
in one place. The result is the drift this document exists to stop: **two defects were found
by measurement while drafting it** (§11), one of which makes every honest Agent Trust Broker
deployment grade `HIGH` on a `mcpscan` governance finding, and one of which makes a routine
`mcpscan` minor release break IANUA's dashboard import outright.

The exchange is **files only**. No clause here licenses a socket, a listener, or egress to
any host. That is deliberate and it is a security boundary, not an implementation
convenience: see §12.4.

Three surfaces carry evidence. Their shipped status is uneven, and stating that plainly is
the point of the table:

| # | Surface | Producer | Consumer | Producer status | Consumer status |
|---|---|---|---|---|---|
| **1** | Scan report JSON | `mcpscan` | IANUA dashboard | **Shipped** | **Shipped** (`dashboard/scan_reports.py`) |
| **2** | `broker.json` posture manifest | ATB | `mcpscan` | **Not built** | **Shipped** (`src/mcpscan/checks/broker.py`) |
| **3** | Canonical tool-manifest digest | `mcpscan` | ATB, `mcpscan` | **Shipped** (`discovery/live_tools.py`) | ATB has no equivalent |

Surface 1 is the only bridge that works end to end today. Surface 2 has a reader and no
writer, and the reader cannot be satisfied (§11, D-1). Surface 3 is computed on one side only.

## 2. Objectives and Non-Goals

**Objectives**

1. Pin every field, type, bound and digest encoding that crosses a repository boundary.
2. Give both sides of each surface **the same test vectors**, run in both CIs, so agreement
   is proven by a test rather than asserted by a document.
3. Make a version bump on one side a *compatible* event for readers on the other.
4. Record what each file must never carry — secrets, raw evidence, personal identifiers.

**Non-Goals**

- **Not a transport.** No HTTP, no socket, no egress. §12.4.
- **Not a runtime coupling.** ADR-17 stands: `mcpscan` never imports ATB runtime code and
  never contacts a broker at runtime. IANUA never imports either.
- **Not an enforcement contract.** Every consumer here is read-only and assessment-only.

## 3. Parties and Dependency Direction

```
   agent-trust-broker                IANUA-Broker (mcpscan)              IANUA
   ──────────────────                ──────────────────────              ─────
   writes  broker.json  ──(2)──►  reads it, grades posture
                                  writes scan report JSON  ──(1)──►  reads it, renders
   must adopt tool digest ◄──(3)──  owns the digest algorithm
```

**`mcpscan` owns surfaces 2 and 3; ATB conforms to them.** That ordering is set by
IANUA-Broker's ADR-17 and restated in its `docs/proposals/ATB_POSTURE_CHECK.md` §1 — it keeps
the dependency direction correct, because the alternative has the scanner depending on the
runtime it is assessing. **IANUA owns no surface.** It is a read-only consumer of surface 1
and a prospective consumer of surface 2; it defines only the limits it applies to what it
reads (§7.3).

## 4. Normative Language

**MUST** / **MUST NOT** are binding on the named party once §13 is complete. **SHOULD**
carries a recorded reason to deviate. **MAY** is optional. Statements labelled
**(measured)** were verified against the shipped code at the commits in §9.1; statements
labelled **(proposed)** are not implemented anywhere and are the subject of §13.

## 5. Encoding Conventions (apply to every surface)

These exist because **the root cause of D-1 (§11) is an encoding disagreement, not a schema
disagreement.** Two repositories each had a defensible digest convention and no document
reconciled them.

### 5.1 Canonical JSON

Any value that is hashed or MAC'd MUST be serialized as:

```python
json.dumps(value, sort_keys=True, separators=(",", ":"))          # chain records, auth tags
json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))  # tool digests
```

The two forms differ in `ensure_ascii` and MUST NOT be interchanged: they produce different
bytes for any non-ASCII string, hence different digests. Each surface below names which form
it uses. Both are UTF-8 encoded before hashing.

### 5.2 Unicode normalization

Values feeding a **tool digest** MUST be NFC-normalized recursively, keys included
(`mcpscan`'s `_nfc`). Chain records and auth tags are **not** normalized — they hash
whatever was recorded. Do not add normalization to the chain: it would change historical
record hashes.

### 5.3 Digest encoding — the rule that D-1 broke

Every digest crossing a boundary is sha256. The two repositories disagree on how to spell
one, so **every field below declares its spelling explicitly**, and a reader MUST reject a
digest in the other spelling rather than coerce it:

| Field | Spelling | Length | Emitted by **(measured)** |
|---|---|---|---|
| ATB `record_hash`, `prev_hash` | `sha256:` + 64 lowercase hex | 71 | `atb.audit.digest()` |
| ATB chain `auth` tag | `hmac-sha256:` + 64 lowercase hex | 76 | `atb.lifecycle.seal_tag()` |
| `mcpscan` `tool_digest` | bare 64 lowercase hex | 64 | `mcpscan.discovery.live_tools.tool_digest()` |
| `broker.json` `evidence.expect_tip_hash` | **bare 64 lowercase hex** | 64 | nothing — see D-1 |

**Rule.** A producer MUST emit the spelling the table names for the field it is writing, and
MUST convert at the boundary rather than expecting the consumer to. Where a field carries a
value copied from another surface in a different spelling, the producer MUST strip or add the
prefix explicitly and the contract MUST say so at the field (§8.2 does).

## 6. Surface 1 — Scan Report JSON (`mcpscan` → IANUA)

**Status: shipped on both sides.** `mcpscan` writes it; IANUA reads it in
`dashboard/scan_reports.py` through a bounded allow-listed parser under the
"Imported scanner reports" trust boundary (`DESIGN.md` §5).

### 6.1 Fields the consumer requires **(measured)**

| Field | Type | Accepted values |
|---|---|---|
| `tool` | string | exactly `"ianua-broker"` |
| `schema_version` | string | `MAJOR.MINOR`, canonical ASCII digits; major MUST be `1`, any minor accepted (§6.2) |
| `overall_grade` | string | `A` `B` `C` `D` `F` |
| `generated_with_online` | bool | — |
| `dimension_grades` | object | MUST contain all of `{exposure, credential, tool_scope, pinning}`, each a grade; an **extra** key is ignored and not retained (§6.2) |
| `servers[]` | array | ≤ 200 entries |
| `servers[].id` | string | ≤ 256 chars, unique within the report |
| `servers[].state` | string | `running` or `declared` |
| `servers[].running` | bool | — |
| `servers[].grade` | string | a grade |
| `servers[].inspection_incomplete` | bool | — |
| `servers[].bind_addr` | string? | ≤ 256 chars; a **label**, never resolved or connected to |
| `servers[].port` | int? | 0–65535 |
| `servers[].findings[]` | array | ≤ 5000 per report |
| `servers[].findings[].dimension` | string | a known dimension, else retained under the consumer's own unknown-dimension sentinel — the finding is **kept**, never dropped (§6.2) |
| `servers[].findings[].severity`, `overall_grade`, `servers[].grade`, `servers[].state` | string | closed sets; an unknown value **refuses the report** (§6.2 residual) |

Unknown fields are discarded. Duplicate JSON keys, or duplicate finding identities, reject
the whole upload.

### 6.2 Forward compatibility — **R2 shipped; this records what it does**

The importer used to validate `schema_version` against a closed `{1.0, 1.1}` set and
`dimension_grades` by **exact set equality**, so a producer bumping its minor or adding a
dimension rejected the *whole* upload with the generic
`"Report format or limits are invalid."` — an operator saw a broken uploader, not a version
mismatch. That was defect D-2 (§10), and it was live rather than hypothetical, because
IANUA-Broker's `ATB_POSTURE_CHECK.md` §4 **recommends** adding a `Dimension.GOVERNANCE`
member in a deliberate minor with a schema bump.

Measured through the shipped parser, before and after:

| Report | Before | After |
|---|---|---|
| `1.1`, the four current dimensions | accepted | accepted |
| `1.1`, plus a `governance` dimension | **rejected** | accepted (extra ignored) |
| `1.2`, the four current dimensions | **rejected** | accepted (displays `1.2`) |
| `1.2`, plus a `governance` dimension | **rejected** | accepted |
| `2.0` — unknown **major** | rejected, generic message | **rejected**, names the supported major |
| `1.1`, **missing** a dimension | rejected, generic message | **rejected**, names the cause |

The rules now in force:

- **R1 stands, narrowed to majors.** `mcpscan` MUST NOT change a **major** without a
  coordinated IANUA change landing first or in the same wave. A minor bump or an added
  dimension no longer needs coordination, which is the point of R2: R1 was a convention a
  release could forget, and it is now load-bearing only where the consumer deliberately
  fails closed.
- **R2 — shipped.** An unknown **minor** inside the supported major is accepted and read
  with the newest known minor's field rules; an **extra** dimension is ignored like any
  other unknown key and is not retained; an unknown **major** is refused; a **missing**
  required dimension is refused. Both refusals name their cause without quoting the
  uploaded value.
- **R3 — shipped on the IANUA side**, as `tests/security/test_scan_report_import.py`: the
  six-row matrix above, the field-rule consequence (a `1.1`-only field is accepted at `1.2`
  and refused at `1.0`), the malformed-version set, and the finding-dimension cases below.
  `mcpscan` owes the producer half.

**The `dimension_grades` key alone was not enough, and review caught it.** A producer adds
a dimension *in order to tag findings with it*, and `_finding` validated each finding's
`dimension` against the same closed display set — so a report carrying the extra grade **and
a finding in that dimension** was still rejected whole. Measured: with the grade accepted, a
finding tagged `governance` rejected the report. D-2 was half fixed, and the matrix missed it
because its sample finding sat in an existing dimension.

A finding in an unknown dimension is now **kept**, under a sentinel the consumer owns rather
than the producer's string. Kept, because silently dropping a security finding is a worse
failure than either rejecting or mislabelling; the consumer's own constant, because the
display must not become a channel for producer-chosen text.

**The same trap exists in four more enums and is deliberately left closed.** Measured: an
unknown finding `severity`, `overall_grade`, `servers[].grade` or `servers[].state` each
reject the whole report. Those are not widened here, and the asymmetry is the reason — a
dimension is a grouping label this consumer does not even render, while each of those four is
read as **risk ordering**. An unknown severity shown under a sentinel reads as *less* urgent
than `critical`, not more, so a sentinel there could cause a mis-triage that a refusal cannot.
Refusing is the fail-closed answer, and widening any of them changes how risk is presented —
an owner's decision, not a consequence of this one. **Until it is taken, a producer adding a
severity, a grade or a state in a minor still breaks every import**, which is D-2's class
surviving in a narrower form and is recorded here rather than left to be rediscovered.

**R2's original wording said something this does not do, and §11 is why.** It read "an
unknown `schema_version` … degrades to a named, actionable error", which would keep
*refusing* a minor bump and merely explain itself better. That contradicts §11, which
requires refusing an unknown **major** and ignoring unknown fields **within** a known major
— and §11 is the normative versioning section, so it governs. Explaining the rejection more
clearly would also not have fixed D-2: the import would still fail, and the operator would
still have nothing to do about it but wait for a new IANUA release.

**The asymmetry is the control, not an oversight.** A minor only adds, so reading a `1.2`
report with `1.1`'s rules is safe — every field still passes the same allow-list and the
same bounds. A major is where a producer may change what an existing field *means*, and
there is no safe default for that, so it fails closed. Accepting unknown minors therefore
widens which *version strings* reach the parser and nothing else: no limit is relaxed, no
field skips validation, and an extra dimension's value is never read.

### 6.3 Consumer limits (IANUA, normative on the reader) **(measured)**

`MAX_REPORT_BYTES` 2 MiB · `MAX_DEPTH` 12 · `MAX_STRING_LENGTH` 8192 ·
`MAX_COLLECTION_ITEMS` 5000 · `MAX_NODES` 100 000 · `MAX_SERVERS` 200 · `MAX_FINDINGS` 5000.

A consumer MUST additionally: consult no file, URL, process or clock while parsing; treat
every string as untrusted plain text and render it through text/table widgets only, never
HTML or Markdown interpolation; never dereference a location or `bind_addr`; and never quote
uploaded values in an error message. A producer MUST NOT rely on any of these being relaxed.

## 7. Surface 2 — `broker.json` Posture Manifest (ATB → `mcpscan`)

**Status: reader shipped, writer absent, and the reader is currently unsatisfiable (D-1).**

Location, as the consumer searches for it **(measured,
`mcpscan.adapters.paths.ianua_broker_manifest_candidates`)**:
`$XDG_CONFIG_HOME/ianua/broker.json`, else `~/.config/ianua/broker.json` on POSIX;
`%APPDATA%\ianua\broker.json` on Windows. A missing manifest is the common, unbrokered case
and MUST NOT be an error.

### 7.1 v1 — the shape the shipped reader actually parses **(measured)**

```json
{
  "schema_version": "1.0",
  "fronts": ["~/.mcp.json#shell", "~/.mcp.json#db"],
  "allowlist": "least_privilege",
  "tool_manifests": "signed",
  "audit_log": "enabled",
  "evidence": {
    "expect_tip": "ATB-DEC-000001",
    "expect_tip_hash": "<bare 64 hex>",
    "chain_path": "/path/to/chain.jsonl"
  }
}
```

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | read and retained; **not currently validated against any set** |
| `fronts` | string[] | `location#name` subject ids, joined to discovered servers |
| `allowlist` | enum | `least_privilege` \| anything else ⇒ treated as `wildcard` |
| `tool_manifests` | enum | `signed` \| anything else ⇒ treated as `unverified` |
| `audit_log` | enum | `enabled` \| anything else ⇒ treated as `off` |
| `evidence` | object? | absent or malformed ⇒ `None` ⇒ `BROKER-EVIDENCE-MISSING` when posture is claimed |
| `evidence.expect_tip` | string | ATB `decision_id`, compared for exact equality |
| `evidence.expect_tip_hash` | string | **MUST be bare 64 lowercase hex**; a prefixed value silently voids the whole evidence block |
| `evidence.chain_path` | string? | a path the consumer may read to verify the tip |

The three enums **fail toward the bad value**: any unrecognized string normalizes to the
insecure reading. A producer MUST therefore write the exact good literals and MUST NOT
assume a typo degrades gracefully.

### 7.2 Findings the consumer emits **(measured — and not the names the research record predicted)**

Shipped ids, all on `Dimension.TOOL_SCOPE`: `BROKER-ABSENT` (High), `BROKER-MANIFEST-UNVERIFIED`
(High), `BROKER-EVIDENCE-MISSING` (High), `BROKER-EVIDENCE-MISMATCH` (High), `BROKER-NO-AUDIT`
(Medium), `BROKER-ALLOWLIST-PERMISSIVE` (Medium), `BROKER-PARSE-ERROR` (Low).

The 2026-10-09 research record (`research/2026-10-09-security-scanner-landscape.md`, feature
E) anticipated `BROKER-TIP-STALE`, `BROKER-HMAC-MISMATCH` and `BROKER-SERVER-UNPROTECTED`.
**Those are not the shipped names.** `BROKER-EVIDENCE-MISMATCH` already covers the stale tip
and `BROKER-ABSENT` already covers the unprotected server, so adding the predicted names
would duplicate two existing findings; and `BROKER-HMAC-MISMATCH` has no implementation
because **the shipped reader performs no HMAC verification at all**. Any v2 work MUST reuse
the shipped ids and MUST NOT introduce the research record's names as synonyms.

### 7.3 v2 — the delta **(proposed; nothing below is implemented)**

v2 adds integrity and runtime decision evidence. **A v1 consumer MUST refuse a
`schema_version` of `2.0`**, per §11's unknown-major rule.

An earlier draft of this section said the opposite — that v2 is "additive", so a v2 file
"MUST remain parseable by the v1 reader, which ignores unknown keys". Review was right that
this contradicts §11, and the contradiction is not merely editorial: **the shipped reader
does not validate `schema_version` at all (§7.1, measured) and ignores unknown keys**, so a
v2 manifest would be graded on its legacy enum fields by a consumer that never looks at
`auth`. A forged or absent auth tag would therefore grade as sound. Compatibility was the
wrong thing to optimize for against a fail-closed rule, which is the trade `AGENTS.md` §3
already settles.

Consequently **adopting v2 requires adding `schema_version` validation to the v1 reader
first**, as a precondition rather than a follow-up — a release-ordering constraint, recorded
in §13. Until that validation ships, no producer may write a `2.0` manifest, because the
readers in the field would silently accept it unverified.

| Field | Type | Purpose |
|---|---|---|
| `schema_version` | `"2.0"` | — |
| `auth` | string | `hmac-sha256:` + 64 hex over the canonical body minus `auth` (§7.4) |
| `generated_at` | RFC 3339 UTC string | staleness input; advisory only (§12.2) |
| `catalog_digest` | bare 64 hex | scope-catalog fingerprint |
| `bindings_digest` | bare 64 hex | role-binding fingerprint |
| `ruleset_digest` | bare 64 hex | screening-ruleset fingerprint |
| `decision_counts` | object | per-tool `{allow, deny, escalate}` integer counts |
| `pending_escalations` | integer | count only — never the escalation content |
| `protected_servers[]` | array | `{id, tool_map_digest}`; `id` matches a `fronts` entry |
| `protected_servers[].tool_map_digest` | bare 64 hex | §9.2 |

**`decision_counts` is a count, never a record.** A per-tool count is metadata; a decision
payload is evidence, and evidence does not cross (§12.3).

### 7.4 The v2 auth envelope **(proposed)**

Computed exactly as ATB's shipped `seal_tag` does, with **one deliberate change — a distinct
domain separator**:

```python
body    = {k: v for k, v in manifest.items() if k != "auth"}
message = b"atb-evidence-v2\n" + json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
auth    = "hmac-sha256:" + hmac.new(key, message, hashlib.sha256).hexdigest()
```

- The key MAY be the existing `ATB_CHAIN_SEAL_KEY` (hex-encoded, ≥ 32 bytes) **only because
  the domain differs.** ATB's chain seals use `b"atb-chain-seal-v1\n"`. Reusing that domain
  here would let a sealed lifecycle record and an evidence manifest be substituted for one
  another under the same key, which is the cross-protocol confusion ATB's own comment
  ("never reuse the identity signing key") already guards against elsewhere.
- Verification MUST use `hmac.compare_digest`.
- An absent key MUST mean **the export does not run**, never that it runs unsigned.
- A consumer that finds `auth` present and invalid MUST emit a finding and MUST NOT fall
  back to grading the body. A consumer that finds `auth` **absent** on a `schema_version`
  `2.0` file MUST treat it as invalid, not as a v1 file.

## 8. Surface 3 — Canonical Tool-Manifest Digest

**Status: shipped in `mcpscan` only.** ATB must adopt it verbatim to produce
`tool_map_digest`.

### 8.1 Per-tool digest **(measured, `mcpscan.discovery.live_tools.tool_digest`)**

```python
material  = _nfc({"name": name, "description": description, "inputSchema": input_schema,
                  "outputSchema": output_schema, "annotations": annotations})
canonical = json.dumps(material, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
digest    = hashlib.sha256(canonical.encode("utf-8")).hexdigest()     # bare 64 hex
```

`annotations` is **inside** the digest deliberately: a server that silently relaxes
`readOnlyHint` or `destructiveHint` changes the digest, which is the drift class the surface
exists to catch. Absent values are the JSON `null`, not an omitted key — omitting a key
changes the digest.

A separate `mcpseal_pin` covers `{name, description, inputSchema}` only, with **no NFC
normalization**, for `.mcp-lock.json` import compatibility. It MUST NOT be used where
`tool_digest` is specified.

### 8.2 `tool_map_digest` **(proposed)**

```python
material = "\n".join(sorted(per_tool_digests))          # bare hex, lexicographic
tool_map_digest = hashlib.sha256(("ianua-tool-map-v2\n" + material).encode("utf-8")).hexdigest()
```

Sorted, so tool order from `tools/list` does not affect it. Domain-separated, so it cannot
collide with a per-tool digest. Bare hex, per §5.3.

## 9. Test Vectors

### 9.1 Provenance

Computed from the shipped implementations at `agent-trust-broker@85cf4d4` and
`IANUA-Broker@2bfd3e0`, on CPython 3.13.17. Every value below is **measured**, not authored.

| # | Vector | Value |
|---|---|---|
| V1 | `tool_digest` of the §9.2 fixture | `8390c98015d8aeb1dae2ed1b93e3c459b6175453b0fa74d3e6030206f80fe446` |
| V1b | `mcpseal_pin` of the same fixture | `127564d2538a7cdb9e47a72ffd399a7ababc35abff369270e6738fad250e45a7` |
| V2 | same fixture, `inputSchema` keys reordered | **equals V1** (key-order independence) |
| V3 | same fixture with `readOnlyHint: false` | `b9a8cdc547e7a013af8a5cfb2d0042bb01a4fa552cff35a6a4efa4201fb6d7f8` (**≠ V1**) |
| V4 | `tool_map_digest` of `sorted([V1, V3])` | `2bbfceaa654be24954cc255307a612592e4555f93be087a477b58b35180e258a` |
| V5 | ATB `digest()` of the §9.3 record | `sha256:ff66a2ddf2bbc604766b4f4751e36ce1da1f865d4c24810bd355964bdb9a090a` |
| V6 | v2 `auth` over the §9.4 body | `hmac-sha256:9e30d4b9f261ebac208da2a0f50b9f1ac29d144bc9d274f603e1f4a43bab09a5` |

### 9.2 Tool fixture (V1–V4)

```json
{
  "name": "run_sql",
  "description": "Execute a read-only SQL query.",
  "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
  "outputSchema": null,
  "annotations": {"readOnlyHint": true}
}
```

### 9.3 Chain-record fixture (V5)

`prev_hash` = `sha256:` + sixty-four `0`; `decision_id` = `ATB-DEC-000001`;
`at` = `2026-01-01T00:00:00Z`; `payload` = `{"effect": "allow", "type": "test.decision"}`.

### 9.4 Envelope fixture (V6)

Key: the ASCII bytes `ianua-evidence-contract-test-key-do-not-deploy`. **This is a published
test string, not a credential; it MUST NOT be used by any deployment.** Body: the §7.3 fields
`schema_version` `"2.0"`, `allowlist` `"least_privilege"`, `audit_log` `"enabled"`,
`tool_manifests` `"signed"`, `fronts` `["~/.mcp.json#db"]`, and `evidence`
`{expect_tip: "ATB-DEC-000001", expect_tip_hash: <V5 bare form>}`.

### 9.5 Obligation

Each repository MUST carry these vectors as a test that runs in its own CI, asserting its own
side of each surface. A vector that cannot be reproduced from a repository's shipped code is
a contract violation in that repository, not a stale vector — the vectors are regenerated only
by a deliberate, reviewed contract version bump.

## 10. Defects Found While Drafting

Both were found by measurement against shipped code, and both are recorded here before any
fix so the contract's first act is honest about the state it inherits.

### D-1 — `broker.json` evidence cannot be satisfied by any value (P1)

`atb.audit.digest()` returns a `sha256:`-prefixed hash and `atb.persistence` writes that
string verbatim as `record_hash`. `mcpscan`'s `_parse_evidence` constrains `expect_tip_hash`
to `^[0-9a-f]{64}$`, then `verify_chain_tip` compares the chain's prefixed `record_hash`
against it. Measured, with a real one-record ATB chain:

| `expect_tip_hash` written as | Outcome **(measured)** |
|---|---|
| `sha256:ff66a2dd…` (copied verbatim from the chain) | evidence block parses to `None` ⇒ `BROKER-EVIDENCE-MISSING` (High) |
| `ff66a2dd…` (prefix stripped to satisfy the regex) | `verify_chain_tip` ⇒ `tip_hash_mismatch` ⇒ `BROKER-EVIDENCE-MISMATCH` (High) |

**There is no value that passes both gates**, so a correct ATB deployment grades `HIGH`
whichever way it writes the field. The fix belongs in `mcpscan` (it owns the surface): accept
either spelling at parse time, normalize to bare hex, and compare against the chain's
`record_hash` with its prefix stripped. The manifest spelling stays bare hex per §5.3. A
vector pinning both spellings MUST land with the fix.

**Status: FIXED.** `IRsoctierDT/IANUA-Broker#165` merged on 2026-11-05, taking that shape —
one `_normalize_tip_hash` used by the manifest side and the chain side alike, accepting bare
hex or an exact `sha256:` prefix and nothing else, so the widening is of the *spelling* and
never of the accepted value. A correct ATB deployment now grades clean, asserted end to end
(`findings == []`) rather than only at the parse boundary.

It also recorded why the defect survived nine months of a green suite: the repository's own
fixtures put bare hex into `record_hash`, a shape the ATB never emits, so both sides agreed
in the test and disagreed in production. **The lesson generalizes past this defect and is why
§9 exists:** a fixture written from one side's assumption about the other side is not a
cross-repository test, however green it is. The vectors in §9 are computed from the shipped
implementations for that reason, and §9.5 makes an irreproducible vector a defect in the
repository rather than a stale vector.

### D-2 — a `mcpscan` minor release breaks IANUA's importer (P2) — **FIXED**

A new `dimension_grades` key or any `schema_version` outside `{1.0, 1.1}` rejected the
entire upload with a generic message, and `ATB_POSTURE_CHECK.md` §4 recommends exactly that
change.

**Fixed by R2 in the consumer** (`dashboard/scan_reports.py`), measured before and after in
§6.2's six-row table: an unknown minor and an extra dimension are now accepted, while an
unknown major and a missing dimension are refused with messages that name the cause. R1
survives narrowed to majors, and R3's consumer half ships as
`tests/security/test_scan_report_import.py`.

Two things found while fixing it are worth carrying forward:

- **The version was never a label.** `_finding` gates the `acceptance` block on
  `schema != "1.1"`, so "accept unknown minors" had to decide which field rules apply.
  Reading a `1.2` report with `1.1`'s rules is the only answer consistent with minors being
  additive — and it means **adding a minor to `KNOWN_SCHEMA_VERSIONS` is what enables its
  new fields**, not a cosmetic bump.
- **The first fix was half of one.** Accepting the extra `dimension_grades` key left
  `_finding` rejecting any finding *tagged* with the new dimension — which is the only
  reason a producer adds one. Found by review, not by the matrix, whose sample finding sat
  in an existing dimension. The lesson is the same one §10 D-1 already records in a
  different costume: a test fixture that exercises the *shape* of a change without its
  *purpose* agrees with itself and misses the case that matters.
- **`str.isdigit` would have been a bypass.** It answers True for non-ASCII digits and
  `int` parses them, so `"1.\u0661"` (ARABIC-INDIC ONE) and `"\u00b9.2"` (SUPERSCRIPT ONE)
  would have validated as `1.1` and `1.2`. The accepted characters are named literally
  instead. This is the same defect class §5 of `AGENTS.md` records twice over — a rule
  written as a library property that answers differently than the author assumed — so it is
  pinned by test rather than left to the next reader.

## 11. Versioning

- Each surface carries its own `schema_version`, independent of any repository's release
  version and of this document's version.
- **Additive** changes (a new optional field) are a minor bump. **Any** change to a required
  field, an enum's accepted values, a digest algorithm, a domain separator or a reader limit
  is a major bump and requires a new §9 vector set.
- A consumer MUST refuse a **major** version it does not know, and MUST NOT silently ignore
  an unknown major. Within a known major it MUST ignore unknown fields.
- This document and the three copies of it are versioned together (`evidence-contract/X.Y`).
  A change lands in all three repositories in the same wave or not at all; the copies drifting
  apart is the failure mode the document exists to prevent, so a reviewer SHOULD diff them.

## 12. Security Considerations

### 12.1 What the auth tag proves, and what it does not

It proves the file was produced by a holder of the seal key and has not been altered since.
It does **not** prove the claims inside are true: `allowlist`, `tool_manifests` and
`audit_log` remain self-attested enums. That is precisely why the evidence block binds them
to an audit-chain tip the consumer can independently read — and why a posture claim without
evidence is a `HIGH` finding rather than a clean grade.

### 12.2 Staleness is not solved by a timestamp

`generated_at` is producer-asserted and an on-disk file carries no freshness guarantee. A
consumer MUST treat a tip that verifies against a readable chain as the authority and
`generated_at` as advisory. A stale file that still verifies is a *true statement about an
old state* — which is the same stale-truth failure mode an unsigned audit chain has, and the
reason the tip binding exists.

### 12.3 What MUST NOT appear in any file described here

No secret, token, key, password or key material. No decision payload, no escalation content,
no quarantined response, no raw log line, no `raw_excerpt`, no observable, no indicator, no
assembled incident. Counts, grades, enums, digests and timestamps cross; **evidence does
not.** This is `AGENTS.md` §5's exfiltration prohibition applied to a file, and it is the
rule most likely to erode — the plausible next addition is always "just the latest finding".

Personal identifiers MUST NOT be hard-coded into any fixture or vector in any of the three
repositories.

### 12.4 Files, not sockets

Every surface here is a file read from the local filesystem. This document licenses **no**
network activity, and no clause in it may be cited as authorization for one. In IANUA, an
inbound listener or egress destination is governed by `AGENTS.md` §5 and `DESIGN.md` §5
boundary 15, requires a committed entry in `agents/policies/egress.json` (which ships empty
and therefore denies) plus a named standing grant, and is a §5.1 boundary-crossing gate
requiring recorded human approval. Adding a transport to this contract is a separate,
amendment-first change.

### 12.5 Every read is untrusted

Each file is hostile input to its consumer, including one labelled redacted and one carrying
a valid auth tag — a valid tag proves provenance, not benignity. Malformed input MUST degrade
to a finding or a named error, never a crash, and never a partial application of a file's
claims. Consumers MUST bound size, depth and collection length (§6.3 is the reference set),
MUST reject duplicate JSON keys, and MUST NOT execute, connect to, or resolve anything named
in a file.

**Dereferencing is forbidden for display-only references and licensed for exactly one
field.** An earlier draft forbade dereferencing *any* path, URI or address, and review was
right that the absolute forbids the one read the evidence binding depends on: §7.1 licenses
reading `evidence.chain_path` to verify the tip, and the shipped `mcpscan` engine does
precisely that. An implementation obeying the absolute would have to skip the chain check,
which leaves the posture enums self-attested — the very thing the binding exists to fix. The
narrow rule, in the same shape `collect/` already uses for declared log sources:

- **Never dereferenced:** a finding `location`, a `servers[].bind_addr`, a `port`, a
  `fronts` entry, or any URI in any file. These are **labels**. They are rendered as text and
  never opened, resolved or connected to.
- **The single licensed read:** `evidence.chain_path`, read-only, to verify the declared tip.
  It MUST be an absolute path; it MUST NOT be a symlink; the read MUST be size-bounded and
  MUST NOT escalate to any other file; a failed or refused read MUST degrade to
  `BROKER-EVIDENCE-MISMATCH` with a reason, never to a clean grade. A consumer unwilling to
  take that read MUST emit the same finding rather than grade the enums as sound.

## 13. Ratification Checklist

This document binds nothing until every box is checked and the owner signs off. Each item
names the repository that owns it.

**IANUA-Broker (`mcpscan`)**
- [x] Confirm the §7.1 field table against the shipped reader, including that
      `schema_version` is genuinely unvalidated there. *(Confirmed while fixing D-1;
      `schema_version` is read into the manifest and validated against nothing, which is why
      the v2 precondition below is a precondition.)*
- [x] **Fix D-1 and land the two-spelling vector.** Merged as
      `IRsoctierDT/IANUA-Broker#165`. The vector is six tests in
      `tests/test_checks_broker.py`; three of them fail without the source change, verified
      by reverting it.
- [ ] State in `ATB_POSTURE_CHECK.md` §4 that R2 shipped on the consumer, so adding a
      `GOVERNANCE` dimension in a minor no longer breaks the IANUA import — and that R1
      still binds for a **major**.
- [ ] Carry R3's producer half: a test that the emitted report satisfies §6.1, so the
      consumer's matrix is pinned from both ends.
- [ ] **Precondition for v2:** validate `broker.json`'s `schema_version` and refuse an
      unknown major. This MUST ship **before** any producer writes a `2.0` manifest — the
      current reader validates no version and ignores unknown keys, so until it does, a `2.0`
      file would be graded on its legacy enums with its `auth` tag unread (§7.3).
- [ ] Confirm §7.2's shipped finding ids are complete, and that no `BROKER-*` id is planned
      under the research record's names.
- [ ] Carry §9's vectors in CI for surfaces 1 and 3.

**agent-trust-broker (ATB)**
- [ ] Confirm `ATB_CHAIN_SEAL_KEY` may be reused under the §7.4 domain, or name a separate
      variable.
- [ ] Confirm no `broker.json` writer exists today (drafting found none).
- [ ] Adopt §8.1 `tool_digest` verbatim; do not re-derive it.
- [ ] Confirm the §7.3 fields are all derivable from existing state without new collection.
- [ ] Carry §9's vectors in CI for surfaces 2 and 3.

**IANUA**
- [x] **Decide R2 (relax the importer) and scope it as its own change.** Decided by the
      owner and shipped: §6.2 and §10 D-2 record what it does, and the boundary's own
      `tests/security/test_scan_report_import.py` carries the matrix, the field-rule
      consequence and the malformed-version set.
- [x] Confirm §6.3's limits are current. *(Confirmed while shipping R2; the byte, depth,
      string, collection, node, server and finding bounds are unchanged by it — R2 widened
      which version strings reach the parser and nothing else.)*
- [ ] Record the surface-2 consumption decision. IANUA reading `broker.json` to show runtime
      protection beside static posture is a **new untrusted input format from a third-party
      producer** and needs explicit human scoping under `AGENTS.md` §6.3 before implementation.

**Owner**
- [ ] Ratify, promoting this document to `evidence-contract/1.0` and the three copies with it.

## 14. Risks, Cost, Future Enhancements

| Risk | Likelihood | Mitigation |
|---|---|---|
| The three copies drift | High — it is the default outcome | Byte-identical copies, diffed at review; §11 ties changes to one wave |
| A vector set is regenerated to make a failing test pass | Medium | §9.5: an irreproducible vector is a code defect, not a stale vector |
| v2 grows an evidence field | Medium | §12.3 names the erosion and the usual first request |
| A consumer coerces a digest spelling instead of rejecting it | Medium | §5.3 makes rejection the rule and names D-1 as the cost of coercion |
| This document is cited to justify a network transport | Low, high impact | §12.4 refuses in terms |

**Cost.** Documentation and tests only. No new dependency on any side — every algorithm here
is `hashlib`, `hmac`, `json` and `unicodedata`. IANUA's `dependencies = []` is untouched.

**Future enhancements**, each its own reviewed change: surface-2 consumption in the IANUA
dashboard (blocked on the §13 scoping item); a SARIF projection of `BROKER-*` findings; a
shared vector file loaded by all three CIs instead of three transcriptions.

## 15. Document Change Log

| Date | Version | Change |
|---|---|---|
| 2026-11-05 | `0.1-draft` rev 5 | Review of rev 4 found two defects, both confirmed. The D-2 fix was **half of one**: accepting an extra `dimension_grades` key still rejected any finding tagged with that dimension, which is the only reason a producer adds one — such a finding is now kept under a consumer-owned sentinel, never dropped and never carrying producer text. And §6.1's field row still said the key set was **exactly** the four, contradicting §6.2 one section later; it and two new rows now match. Also recorded, measured: the same forward-compatibility trap exists in `severity`, `overall_grade`, `servers[].grade` and `servers[].state`, and is deliberately left closed because each orders risk — widening them is the owner's call, and until it is taken D-2's class survives in that narrower form. |
| 2026-11-05 | `0.1-draft` rev 4 | D-2 is **fixed**: R2 shipped in `dashboard/scan_reports.py`, so an unknown minor and an extra dimension are accepted while an unknown major and a missing dimension still fail closed with named causes. §6.1's row and §6.2 are rewritten around the measured before/after, §10 records the two findings the fix turned up (the version gates a real field; `str.isdigit` would have been a bypass), and §13 checks off both IANUA items while handing `mcpscan` the producer half of R3. **R2's original wording contradicted §11** — it would have kept refusing minor bumps with a better message — and §11 governs, which §6.2 now states rather than leaving the two to disagree. |
| 2026-11-05 | `0.1-draft` rev 3 | D-1 is **fixed** — `IRsoctierDT/IANUA-Broker#165` merged. §10 records the merge and draws out the generalizable lesson (a fixture written from one side's assumption about the other is not a cross-repository test), and §13's first two IANUA-Broker items are checked off, one of them confirming that `broker.json`'s `schema_version` really is validated against nothing. D-2 remains open with no fix proposed, and ratification is still pending. |
| 2026-11-05 | `0.1-draft` rev 2 | Three defects found by automated review of rev 1, all confirmed, all in this document. **(a)** §7.3 promised a v2 file would stay parseable by a v1 reader, contradicting §11's unknown-major rule — and because the shipped reader validates no `schema_version` and ignores unknown keys, a v2 manifest with a forged or absent `auth` tag would have graded as sound; resolved fail-closed, with reader validation made a ratification precondition. **(b)** §12.5 forbade dereferencing any path, which forbids the `evidence.chain_path` read the tip binding depends on and the shipped engine performs; narrowed to display-only references plus one licensed, bounded read. **(c)** Eight cross-references had drifted (§14→§13, §13.2/.3/.4→§12.2/.3/.4, §10.1→§9.1) in a document whose value is being precisely referenceable. |
| 2026-11-05 | `0.1-draft` | First draft. Consolidates the three surfaces from shipped code in all three repositories; records defects D-1 and D-2, both measured; proposes the v2 delta, the auth envelope and `tool_map_digest`. Ratification pending §13. |
