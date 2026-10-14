# DESIGN.md — IANUA

> Architecture, trust boundaries, and decision record for this repository.
> Read this **before** any change (see [`AGENTS.md`](./AGENTS.md) §2). Update it whenever the
> architecture, a trust boundary, or a major dependency changes.

---

## 1. Executive Summary

IANUA is a **local-first, security-hardened platform** for
running AI/agent workloads, RAG pipelines, and defensive cybersecurity automation. It is
built so that the **safe configuration is the default configuration**: least privilege,
auditable actions, layered validation, and human approval for anything irreversible or
externally visible.

This document describes the intended architecture so that agents and humans make changes
that *fit the design* rather than eroding it.

---

## 2. Objectives

1. Serve and orchestrate **local LLMs** (e.g. via Ollama) with no dependence on external
   inference for core workflows.
2. Provide a **RAG subsystem** for grounding agents in trusted, local document corpora.
3. Expose capabilities to agents through **MCP servers** with strict, validated tool
   surfaces.
4. Support **defensive, lab-scoped** cybersecurity automation (detection content, log
   enrichment, triage helpers).
5. Keep every component **portfolio-grade**: typed, tested, documented, and reviewable.

**Non-objectives:** offensive tooling against unowned systems; any workflow that requires
hard-coded secrets or unaudited external network access (see `AGENTS.md` §5).

---

## 3. Architecture Overview

```
                        ┌──────────────────────────────────────────┐
                        │                 Human                     │
                        │  (approves gates, owns secrets, reviews)  │
                        └───────────────┬──────────────────────────┘
                                        │ approval gates (AGENTS.md §5.1)
                                        ▼
┌───────────────┐   plans/tasks   ┌──────────────────┐   validated tool calls
│   Planner /   │ ───────────────▶│   Orchestrator   │ ─────────────────────────┐
│   Reviewer    │◀─────────────── │  (agents/)       │                          │
└───────────────┘   findings      └────────┬─────────┘                          ▼
                                           │                              ┌─────────────┐
                          ┌────────────────┼──────────────────┐          │  MCP tools  │
                          ▼                ▼                  ▼          │  (mcp/)     │
                   ┌────────────┐   ┌────────────┐    ┌────────────┐     │ allow-listed│
                   │  Local LLM │   │    RAG     │    │ Detections │     └──────┬──────┘
                   │  (Ollama)  │   │  (rag/)    │    │(detections/)│            │
                   └────────────┘   └─────┬──────┘    └────────────┘            ▼
                                          │                              ┌─────────────┐
                                          ▼                              │  Filesystem │
                                   ┌────────────┐                        │  / lab data │
                                   │ Vector store│   ◀── trust boundary ─│  (data/)    │
                                   └────────────┘                        └─────────────┘
```

**Layers:**

- **Orchestration (`agents/`)** — role logic (planner/builder/reviewer/security), policy
  enforcement, and tool wiring. This is the control plane.
- **Capability surfaces (`mcp/`, `agents/tools/`)** — every tool validates its own input,
  enforces an allow-list, and is the *only* sanctioned way for an agent to reach the
  filesystem, network, or a model.
- **Knowledge (`rag/`)** — ingestion → chunking → embedding → retrieval over **trusted local
  corpora** only.
- **Inference** — local LLMs by default; any remote model is an explicit, gated decision.
- **Domain content (`detections/`)** — defensive, lab-scoped detection engineering.

---

## 4. Module Responsibilities

| Path | Responsibility | Key invariants |
|---|---|---|
| `agents/roles/` | Role definitions and their mandates | A role announces itself; honors its review priorities |
| `attack/` | Pinned local MITRE ATT&CK corpus (committed shards + pin) | Never fetched at runtime; zero first-party imports; integrity-verified fail-closed before parse; revocation surfaced, never rewritten |
| `intel/` | Local threat-intel library (first-party behavioral + synthetic atomic seed) | No live feed; TLP:CLEAR only; expiring, decaying, never-flag enforced at ingest and query; single-source network verdicts capped |
| `ingest/` | Multi-source telemetry normalization: endpoint, network, cloud, identity, email → one canonical event | Recognize-never-guess (an unclaimed record is labelled `unknown`, never routed to the closest parser); degrade visibly rather than drop; every field bounded and control-character stripped; no clock, filesystem, network, or subprocess; **no field exists for a message body** |
| `store/` | Durable, append-only event store over the canonical `NormalizedEvent` | Append-only enforced by engine triggers, not API discipline; rows content-addressed so a replay is a no-op and a tampered row fails on read; no clock (`ingested_at` injected); database confined to gitignored `data/events/`; every query bounded; retention keyed on ingestion time, never on source-reported time |
| `correlation/` | Entity resolution across domains + incident assembly | Entities merge only on declared exact rules — no fuzzy matching; connection endpoints never merged with each other, addresses never merged into hosts, host-scoped principals (uid 0, well-known SIDs, `root`) and display names never used as join keys, and a non-joinable value may not bridge two entities; over-common entities demoted to reported context rather than joined on; scoring is arithmetic from named constants with per-incident reasons; no clock, filesystem, network, subprocess, or storage driver |
| `pipeline/` | Continuous execution: one bounded, resumable cycle of store → correlation, invoked by a scheduler | At-least-once — the cursor advances only after a cycle succeeds, so a crash re-reads rather than skips; the cursor is a composite `(ingested_at, event_id)` keyset because one ingestion timestamp spans a whole batch; the cycle persists nothing, which is what makes a replay free; no clock, no socket, no subprocess, no executor (AST-asserted); the cursor is owner-only, confined to gitignored `data/pipeline/`, and written atomically
| `agents/policies/principal.py` | Caller identity carried in the audit chain | Rides in the already-hashed `actor` field, so no record-schema change and no migration; alphabet cannot express the preimage delimiter; no environment read, no module-level default, no `default_factory` identity (AST-asserted); immutable; records what the caller claimed, never verifies it |
| `agents/tools/` | Adapters from agent intent → real capability | Each adapter validates input and enforces least privilege; containment primitives are policy-gated per invocation, reversible by design, and audited |
| `agents/policies/` | Guardrails, allow/deny lists, approval logic | Default deny; gates fail closed |
| `agents/response/` | Draft containment plans (plan-only; no executor exists) | Every plan is `draft`; every action is human-owned, restrict-only, with rollback; capture precedes disruption |
| `rag/` | Document ingestion and retrieval | Only trusted local sources; no PII/client data |
| `mcp/` | MCP servers exposed to agents | Minimal, typed, validated tool surface; sandboxed execution |
| `dashboard/` | Streamlit command center over the agent pipeline | Local-only backends; fails soft with honest degradation labels — an unavailable layer reports *unavailable*, never empty-and-healthy; staleness and telemetry gaps are surfaced as status, not hidden |
| `compliance/` | Control registry, framework mappings, evidence engine | Checks are read-only/offline and fail closed; evidence carries no secrets; manual controls surface as attestations, never silent passes |
| `knowledge-base/` | Local retrieval corpus (NIST/MITRE/OWASP notes) | Trusted local content only; grounds citations |
| `security/sbom/` | CycloneDX SBOMs + exported hash-pinned locks | Derived from `uv.lock`; CI drift gates verify, never auto-commit |
| `detections/` | Defensive detection content (base Sigma + behavioral TTP corpus) | Lab-scoped; no offensive payloads; behavioral rules declare whether their telemetry is ingested, and every ATT&CK anchor must resolve active in the pinned corpus |
| `scripts/` | Operational CLI entrypoints | Idempotent; dry-run for destructive ops |
| `infra/` | IaC / containers / deploy manifests | No real secrets; deploy behind approval gate |
| `tests/security/` | Authz, validation, injection, secret-leak tests | Must pass before any boundary change merges |

---

## 5. Trust Boundaries & Data Flows

A **trust boundary** is any point where data or control crosses from a less-trusted zone to
a more-trusted one. Crossing one requires validation and (often) an approval gate.

1. **Human → Orchestrator** — the human is the root of trust; only the human owns secrets
   and approves gates.
2. **Orchestrator → Tools/MCP** — agent intent is *untrusted input*. Tools validate
   arguments, enforce allow-lists, and sandbox execution. Never pass LLM-generated strings
   to a shell, file path, or query without sanitization.
3. **External/LLM data → RAG/Logic** — model output and ingested documents are untrusted.
   Validate schemas; never deserialize untrusted data unsafely; guard against prompt
   injection influencing tool calls.
4. **System → Filesystem/Network** — filesystem reach is scoped to the project and lab
   `data/`; network egress is default-deny and limited to lab hosts. Any other egress is a
   gated action.

5. **External ATT&CK STIX bundle → local `attack/` store** — the upstream bundle is
   untrusted third-party data. A human stages it (no code egress, AGENTS.md §5.1);
   `scripts/update_attack.py --build` enforces a size ceiling and a nesting-depth scan,
   verifies the streaming SHA-256 against the committed pin, and only then parses with
   `RecursionError` handled explicitly. The pin is Ed25519-signable; `--check` verifies
   signature (when present), per-shard hashes, canonical rendering, and the
   revocation/successor invariants. A rejected bundle gets a `.REJECTED` forensic
   marker and an audit record; previously committed shards stay authoritative.
   Tampering hard-fails (`AttackIntegrityError`); absence degrades soft to an explicit
   `AttackUnavailableError` — never a guess.

6. **Third-party intel feed → `intel/` indicator store** — no live feed ships; committed
   content is first-party or synthetic only, and any future vendored snapshot lands in
   gitignored `data/intel/`. Whole-store fail-closed validation: unlisted `source_id` or
   non-allow-listed license rejects; TLP above CLEAR is refused at ingest (an intel hit's
   restricted datum IS the indicator value, and reports are tracked); every atomic
   indicator carries a mandatory expiry with per-type exponential decay; the explicit
   never-flag CIDR list (never `ipaddress.is_private`, which is wrong in both directions)
   is enforced at ingest AND query; network-observable indicators need two sources with
   distinct declared upstreams for a `malicious` verdict — one poisoned feed caps at
   `suspicious`. `as_of` is always injected (no module reads a clock); ATT&CK anchors on
   behavioral records degrade to `stale-anchor` on deprecation/revocation rather than
   letting an external taxonomy switch off a working local detection.

7. **Analyst/LLM-authored rule → committed store (write path)** — poisoning a *store*
   poisons every future detection, so no programmatic writer exists: mapping rules,
   intel records, behavioral rules, and the response catalogue change only through a
   reviewed PR, each guarded by a committed canonicalized digest or index gate.
   Predicates are literal-only by schema (no regex ⇒ no ReDoS over attacker-influenced
   text). LLM output may enrich narrative prose; it may **never** author a technique ID,
   a predicate, a target, or a response tier.

8. **Indicator/attribution → containment action → live host** — **closed by
   construction.** `agents/response/` emits a `draft` plan and nothing else; no executor
   ships, and security tests fail the build if one appears (no module outside the
   planning set, no import path to `subprocess`/`socket`/`mcp.sandbox`, no dynamic-exec
   call, no clock read, no writer). Recorded honestly: the boundary is closed because
   the repository has **no per-invocation approval primitive** — the policy allow-list
   is a standing grant, `guarded.enforce(report_only=True)` bypasses the raise, the
   audit record has no payload slot to bind an approval to, the sandbox cannot perform
   host actions without weakening an existing control, and there is no caller identity.
   Opening it requires designing an explicit, signed, expiring, per-target approval
   primitive as its own reviewed change.

   **Amended 2026-08-21 (owner direction — see the containment decision in §11):** a
   *direct-invocation* containment path now exists **outside** this boundary:
   `agents/tools/containment.py`, policy-gated per call under the dedicated
   `containment` action class (not the allow-list), input-validated, reversible by
   design, deny-listable per capability, with decision **and** outcome recorded to
   the hash-chained audit trail. The plan→execution half of this boundary is
   unchanged: no code path consumes a `ResponsePlan` and executes it,
   `agents/response/` still ships no executor, and its security tests continue to
   enforce that.

9. **Third-party telemetry → canonical event → every downstream layer** — `ingest/` is
   the platform's largest untrusted-input surface: a hostname is whatever the endpoint
   claimed, a command line whatever the adversary typed, a mail subject whatever the
   sender chose. Three properties keep it from becoming a liability. **Recognition is
   never a guess**: a record is parsed only when one parser signature claims it on
   distinctive keys, and a record claimed by two signatures is attributed to neither —
   mis-attributing a CloudTrail record to an endpoint parser would produce a confident,
   wrong analysis, which is worse than an explicit "not recognized". **Nothing is
   dropped**: oversized, over-nested, undecodable, and type-confused records still yield
   an event, with `parse_status` demoted and a note saying what happened, because
   silently discarding telemetry is how a blind spot is manufactured. **Nothing derived
   is ambient**: no clock (a substituted "now" would fabricate the ordering the
   correlator depends on), no filesystem, no network, no subprocess, no dynamic exec —
   asserted over the package's AST, so a future contributor cannot quietly add one. A
   command line from a compromised host is evidence to be carried and rendered, never a
   string to be run. Email is held to a stricter rule still: `EmailContext` has **no body
   field**, and a security test parses every parser's AST to prove none reads one — the
   detection value in mail telemetry is in the metadata, and the body adds liability
   without adding signal (AGENTS.md §5). Serialization is an allow-list projection over
   frozen dataclasses, so no attacker-controlled key can ride along into a downstream
   artifact, and match-view keys come from the schema rather than from record content.

10. **Normalized events → durable `store/`** — the first boundary this platform crosses
    *into persistence*, and the asymmetry matters: `ingest/` is a pure function that can be
    re-run, while a stored event is evidence that something else will later rely on. Three
    controls carry it. **Integrity:** rows are content-addressed (SHA-256 of the canonical
    projection), so a replayed batch stores nothing new and a row edited outside the
    platform fails its hash on read rather than returning a plausible event; SQLite triggers
    refuse `UPDATE` outright, because append-only enforced only in the Python API is not a
    control when anything holding the file could rewrite history. **Containment:** the
    database lives under gitignored `data/events/`, a filename that escapes it is refused
    rather than normalized, and the package imports no socket, subprocess, or dynamic
    execution — asserted over its AST like `ingest/` and `intel/`. **Honesty:** `ingested_at`
    is injected rather than read from a clock, so the storage timeline is reproducible;
    retention prunes on it rather than on source-reported time, so a host with a wrong clock
    cannot control its own retention; and an event carrying no source timestamp is excluded
    from every time window rather than treated as in-range, because an unknown position in
    time silently counted as "inside" would place that event in every window a caller asks
    about. Reads are bounded by a hard ceiling applied even when the caller asks for more.
    The no-message-body rule is re-enforced here on the *read* path: `from_dict` rejects
    undeclared keys, so a body smuggled into a row refuses to reconstruct instead of being
    quietly dropped.

11. **Stored events → assembled incidents (`correlation/`)** — the boundary where data becomes
    an *accusation*, which makes its security property attribution correctness rather than
    containment. Every field this layer reads is attacker-influenced: a hostname is whatever the
    endpoint claimed, a username whatever was typed. If two principals resolve to one entity the
    resulting incident names the wrong person with full confidence, and every artifact drawn from
    it — a containment plan, an escalation, a report — inherits that error. So merging is
    permitted only on declared exact rules, never on resemblance, and the generic over-merge
    vectors are closed individually: a placeholder (`-`, `unknown`, `localhost`) yields no
    reference at all; a host-scoped principal (numeric POSIX uid, well-known SID, `root`,
    `administrator`) is kept as an alias but never joins, judged on the value rather than the
    field because the auditd parser carries `auid` in `actor.user_name`; a display name
    (whitespace-bearing) never joins, because the Entra parser carries `userDisplayName` there and
    two people share "John Smith"; the two endpoints of a connection are never merged with each
    other, and an address is never merged into a host since DHCP and NAT reuse addresses; and a
    non-joinable value is excluded from the union entirely, not merely from the join keys, because
    a shared unusable value otherwise *bridges* two entities into one. Fan-out suppression closes
    the structural version: an entity appearing in more events than the configured threshold is
    demoted to reported context, since grouping transitively on a shared gateway or CI service
    account collapses a whole window into one false incident — the failure that most resembles a
    finding. Corroboration is required (a lone event is not an incident, mirroring the response
    layer's refusal to plan on weak signal), every bound is re-asserted, output is deterministic
    under input permutation so an incident is replayable as evidence, and scoring is arithmetic
    from named constants with its reasons attached — the detection plan's rejection of learned
    confidence scoring applies here. The package imports no storage driver, so the layer deciding
    attribution cannot also rewrite the evidence.

12. **Caller → policy decision and audit record (`agents/policies/principal.py`)** — the
    boundary that had nothing on it: the Decision Log's 2026-08-21 entry gave "the repository
    has no caller identity at all" as one of three reasons the plan→execution boundary stays
    closed. A `Principal` now carries *which component* and *on whose behalf*, and it rides in
    the existing `actor` field **because that field is already inside the hash preimage**.
    Anything recorded outside the preimage — an unhashed JSON key, a side file — is editable on
    disk without breaking the chain or the head signature (which covers only
    `f"{seq}|{head_hash}"`), so it would not be attributable at all. Reusing a hashed field also
    avoids a record-schema change, which matters more than it first appears:
    `AuditEvent(**json.loads(line))` raises on a missing *and* on an unexpected key, so a new
    field breaks reading in both directions, and that exception escapes through `record()` →
    `enforce()` → every `ToolRegistry.dispatch` — in containment reaching `_record_outcome`
    *after* the effect. **Fixing the delimiter was the prerequisite.** The preimage is an
    unescaped `"|".join` over eight fields, so a value carrying `|` shifts where one field ends
    and the next begins: a `deny` record can be made to hash identically to an `allow` record,
    which `tests/security/test_audit_field_delimiter.py` demonstrates against the production
    hash function rather than asserting. Reachability was established by reading the call sites:
    `actor` was caller-supplied and unvalidated everywhere; a filename carrying `|` reaches
    `action` through `quarantine_file`/`release_file`, since `_resolve_no_symlink` confines the
    path but not its alphabet; the `pid: int` and regex-validated capabilities are not
    reachable. Two controls close it, split by what the field *means*. **Identity is rejected:**
    the principal alphabet cannot express `|`, and `record()` refuses any hashed field
    containing it — silently rewriting who did something is not a repair. **Description is
    escaped:** `target` and `detail` are percent-encoded before they enter `action`/`reason`,
    because a filename may legitimately contain `|` and that record is written after the file
    has already moved, so rejecting there would leave the effect done and the trail missing. A
    backslash escape would not do — `\|` still *contains* the delimiter, so the preimage would
    stay ambiguous and the guard would refuse the escaped form. There is deliberately **no
    ambient path to an identity**: no `principal_from_env`, no module-level default, no
    `field(default_factory=...)` reading the process environment, asserted over the module's AST
    — the repository already contains that idiom four times in `agents/tools/llm.py`, so an
    `IANUA_PRINCIPAL` key would read as idiomatic while being an unauthenticated claim. A
    principal records what the caller *said*; nothing here verifies it, and the docstring says
    so rather than letting a reader assume authentication.

13. **Scheduler → unattended cycle (`pipeline/`, `scripts/run_pipeline.py`)** — the boundary
    where this platform starts running with nobody watching, which changes which failures
    matter. Every layer before it is invoked by a human reading the output; this one is invoked
    by cron at 03:00, so a silent failure stays silent until someone asks why there were no
    alerts. The governing choice is therefore **at-least-once**: `run_cycle` returns the new
    cursor and does not persist it, the caller advances only after the cycle succeeded, and a
    crash re-reads the same window. Events can be processed twice and cannot be processed zero
    times — a duplicate incident is noise an analyst dismisses, while a skipped window is a
    blind spot nobody is told about. That trade is only free because **the cycle persists
    nothing**: `correlation.assemble` is pure, so a replay recomputes rather than duplicating,
    which `tests/security/test_pipeline_hardening.py` asserts by comparing the whole tree before
    and after. **The cursor is composite, not a timestamp**, because `append_many` stamps one
    `ingested_at` across a whole batch: ties are the normal case, so a timestamp-only cursor
    must either skip the rest of a tied batch (`>`) or re-read it on every run forever (`>=`) —
    a `(ingested_at, event_id)` keyset paired with a total `ORDER BY` has neither failure, and
    needed no schema version bump because it adds a filter rather than an index. **No clock in
    the package at all**, asserted over the AST: the window is the cursor, never "the last five
    minutes", so a slow run cannot silently widen its window and clock skew cannot silently
    narrow it. **One cycle per invocation, not a daemon** — the operating system's scheduler is
    more reliable than a hand-rolled loop and leaves nothing to supervise, the same shape
    `scripts/audit_maintenance.py` already uses. The CLI is the only place a clock is read, a
    path comes from an operator, or a cycle is authorized: it runs through `enforce` as
    `read_only` against the declarative policy bundle, so a deployment that re-gates that class
    stops the pipeline rather than having it quietly keep reading, and a missing or malformed
    bundle fails closed. **The audit record is written before the cursor advances**, because the
    reverse order has a failure with no recovery — a saved cursor plus a failed audit write
    means a window was consumed with no record that it was, while a failure in this order simply
    re-reads a window the record already described. Identity is explicit: `--caller` is passed
    or absent, never inherited from whichever account owns the timer, asserted over the CLI's
    AST because `field(default_factory=lambda: os.environ.get(...))` already appears four times
    in `agents/tools/llm.py` and a `$USER` fallback would put an unauthenticated name into a
    hash-chained, signed record. The cursor itself is treated as evidence metadata: 0o600 in a
    0o700 directory under gitignored `data/pipeline/`, written to a content-keyed temporary file
    that is chmodded *before* the rename so it never exists at its real path in a wider mode,
    and confined by resolving the root then appending — so a symlink planted where the pipeline
    directory should be is refused rather than followed.

**Sensitive data** (logs, legal docs, client info, credentials, PII) never crosses outward
across these boundaries and is never committed.

---

### Imported scanner reports

The dashboard accepts IANUA-Broker JSON snapshots through a bounded,
allowlisted parser. Imported files are untrusted data, even when labelled
redacted: no report path is opened, no command is executed, and no external
request is made by this feature. Only normalized fields reach plain-text/table
rendering; arbitrary secret and unknown fields are not retained. The report
viewer keeps data in the current session, with explicit upload consent, and
clears stale results when an upload is removed or invalid. It cannot certify
that free text is secret-free. Comparisons preserve incomplete-inspection
signals and never infer resolution from an incomplete current report.

### Release publication

Publishing a release crosses from CI into externally visible state (a git tag, a
GitHub Release with signed assets), so it sits behind a human boundary:

```
release PR merged ──► CI green (push, main) ──► release-on-merge.yml
                                                  detect  (contents: read)
                                                    │ untagged, or tagged-but-unreleased,
                                                    │ and check_version_sync --tag passes
                                                  publish (environment: release)
                                                    │ ◄── HUMAN APPROVAL (required reviewer,
                                                    │      verified at runtime; fails closed)
                                                    ├─ tag vX.Y.Z → CI-verified commit (create-only)
                                                    └─ dispatch release.yml (rebuild, test, sign, publish)
```

Invariants: a tag is created only at the `head_sha` of a successful CI push run on
`main` and is never moved (an existing tag is accepted only if it already names
that commit, which makes a failed dispatch resumable, and a resumed tag must itself
have a successful CI push run, with the version chain re-verified at that commit); `detect` holds read-only
permissions, and write scopes (`contents`, `actions`) exist only in the approved
job; inputs reach shell steps through `env`, never inline expressions;
`release.yml` re-verifies the version chain and rebuilds from the tag instead of
trusting artifacts from the gating workflow. Pages publication keeps its own
`github-pages` approval. Runbook: `docs/RELEASING.md`.

## 6. Security Architecture

- **Least privilege** at every layer — tools request the minimum scope; processes run with
  the minimum permissions.
- **Defense in depth** — input validation *and* allow-lists *and* sandboxing *and*
  monitoring; no single point of trust.
- **Secure defaults** — safe behavior with zero flags; opting into risk is explicit and
  logged.
- **Auditability** — security-relevant actions emit structured logs suitable for review.
- **Secret management** — secrets live in environment/secret stores, documented as keys only
  in `.env.example`; never in source, tests, or logs.
- **Encryption** — in transit (TLS for any network call) and at rest for any sensitive
  store.
- **Fail closed** — on ambiguity, missing config, or failed validation, deny and halt rather
  than proceed.

---

## 7. Implementation Notes

- Python is the baseline, fully type-annotated and `mypy`-clean. Bash for glue; Swift only
  for macOS-specific targets.
- All configuration is environment-driven and documented in `.env.example`.
- Use the shared structured logger; never `print()` security events.
- New dependencies are pinned and justified (purpose, maintenance, license, risk) per
  `AGENTS.md` §4.
- Quality gates (`compileall`, `pytest`, `ruff`, `mypy`, `bandit`, plus SCA and secret
  scanning) run locally and in CI per `AGENTS.md` §7–§8.

---

## 8. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Prompt injection steering tool calls | Unauthorized action | Allow-listed tools, input validation, human gates |
| Secret leakage in code/logs | Credential compromise | Secret scanning in pre-commit + CI; `.env.example` only |
| Unsafe shell/exec from LLM output | RCE / data loss | Sanitize inputs; avoid shell where possible; sandbox |
| Dependency vulnerability | Supply-chain compromise | `pip-audit` SCA; pinned, justified deps |
| Scope creep into offensive tooling | Legal/ethical exposure | Lawful-lab boundary (§5); escalate ambiguous cases |
| Auto-containment misfire (false positive contained) | Benign file/process/host/account disrupted | Containment primitives are reversible by design with rollback counterparts (the opt-in force kill is separately deny-listable); every action audited; operators can re-gate the class or deny-list capabilities in the policy bundle |
| Architectural drift | Erosion of trust boundaries | This doc is authoritative; reviewers enforce it |
| Poisoned/tampered ATT&CK corpus drives wrong mappings | Confidently incorrect SOC output | Boundary 5 control stack: size ceiling → depth scan → SHA-256 → parse; signable pin; stdlib `json` only; nothing executed |
| Silent ATT&CK staleness — dead techniques persist in content | Coverage claims drift from reality | Revoked/deprecated retained with successors; append-only tombstone ledger; merge-blocking reference gate in the Navigator builder; expiring MAN-03 attestation |
| Solo-maintainer decay of the "ongoing" corpus | Currency claim becomes false | Version-distance freshness (advisory, never a gate); expiring attestation flips to "attestation due"; refresh is one documented human command ~2×/year — and if it stops, the dashboard says so |
| Intel-feed poisoning causes analyst DoS or whitewashing | Alert flood, or attacker infrastructure branded clean | Never-flag denylist at ingest and query; two-source corroboration with declared upstream independence; per-type decay with hard expiry; no atomic indicator can authorize any action; no live feed at all |
| Telemetry mis-attributed to the wrong domain parser | Confident, wrong analysis on a real intrusion | Signature recognition on distinctive keys only; a record claimed by two signatures is attributed to neither; unclaimed records are labelled `unknown` and carried, never routed to the closest match; every fixture asserted claimed by exactly one signature |
| Hostile telemetry exhausts memory or smuggles content | Ingest outage, or forged fields in a client-facing report | Per-field, per-record, per-collection ceilings; iterative (non-recursive) depth check; control characters stripped at the single coercion helper; allow-list projection on serialization; match-view keys come from the schema, never from record content |
| Message bodies enter the corpus through an email parser | Sensitive-content liability with no detection gain | `EmailContext` has no body field to hold one; a security test walks every parser's AST and fails the build if any lookup names a body-shaped field, across all five domains |

---

## 9. Cost Considerations

Local-first and open-source by default keeps recurring cost near zero (compute is the
existing workstation/lab). Remote inference, paid APIs, or cloud infrastructure are
**explicit, gated decisions** with documented cost justification — never an unannounced
default.

---

## 10. Future Enhancements

- Formalize a policy-as-code layer in `agents/policies/` (e.g. OPA-style allow/deny).
- Add signed, tamper-evident audit logging with retention policy.
- Expand `tests/security/` with property-based fuzzing on tool input validators.
- Container-level sandboxing (rootless, seccomp/AppArmor) for MCP tool execution.
- Optional SBOM generation and dependency provenance attestation in CI.

---

## 11. Decision Log

| Date | Decision | Rationale |
|---|---|---|
| _initial_ | Local-first inference (Ollama) as default | Cost, privacy, no external dependency for core flows |
| _initial_ | Default-deny network egress | Minimize attack surface and data-exfil risk |
| _initial_ | Allow-listed, self-validating tool surfaces | Contain prompt-injection blast radius |
| _initial_ | `AGENTS.md` as platform-neutral charter | One rule set across Codex/Claude/other agents |
| 2026-06-17 | KnowledgeBaseAgent uses deterministic term-overlap retrieval, not the vector RAG pipeline | Incident-report grounding must be reproducible, network-free, and CI-testable. The vector pipeline (`rag/`) remains the path for semantic search via a local model; the two are complementary, not redundant. Both load the corpus through `rag.ingest` for shared path-traversal safety. |
| 2026-06-17 | Advisory agents (Legal/Compliance, Business Proposal, Knowledge Curator) are deterministic, network-free, and *draft-only* | These agents touch higher-stakes domains (legal, client-facing, knowledge-base content). Each classifies/structures input and returns a reviewable artifact, but never fabricates authority, invents pricing, or publishes/writes — humans own those actions (AGENTS.md §5.1). Each ships a mandatory disclaimer and a per-agent doc under `docs/agents/`. |
| 2026-06-17 | `OrchestratorAgent.process_log` takes a `report_path` parameter | Removes a hidden CWD dependency: the report destination is explicit, so tests write to a temp path instead of mutating the tracked sample report. |
| 2026-06-18 | KnowledgeBaseAgent gains an opt-in `semantic` mode with lexical fallback | Semantic (local-embedding cosine) retrieval improves relevance, but must not compromise the default. `lexical` stays the default — deterministic and CI-safe; `semantic` is opt-in and **falls back to lexical** if the loopback-only, fail-closed `OllamaEmbedder` is unreachable, so the agent pipeline never breaks. The embedder is injectable for deterministic tests. |
| 2026-06-19 | Policy/audit layer (`agents/policies/`) codifies §5/§5.1; MCP `ToolRegistry` enforces it | Approval gates and auditability were documentation only. The PolicyEngine (default-deny, fail-closed; §5 prohibitions non-negotiable) and a hash-chained AuditLogger make them executable. `ToolRegistry.dispatch` now gates every tool by its declared `action_class`: only `allow` runs, `require_approval`/`deny` fail closed, and decisions are auditable — making the control load-bearing at the capability surface, not just available. |
| 2026-06-20 | Opt-in local LLM generation (`agents/tools/llm.py`, default `qwen3.5:9b`) | Agents are deterministic by default; LLM use is opt-in so the core pipeline stays reproducible and network-free (CI uses an injected fake transport). `OllamaGenerator` mirrors `OllamaEmbedder`'s posture (loopback-only allow-list, bounded timeout, fail-closed). The incident report's "Analyst Narrative" is clearly labeled AI-generated, constrained to the supplied facts, and **fails soft** if the model is unreachable. Default model `qwen3.5:9b` (Apache-2.0); `LLM_MODEL` reconciled across `.env.example` and dashboard. |
| 2026-06-20 | LLM narrative on-by-default (`LLM_NARRATIVE=auto`) + pluggable backend (`LLM_BACKEND`) | A `Generator` protocol with two adapters — `OllamaGenerator` and `LlamaCppGenerator` (llama-server OpenAI-compatible `/v1`) — keeps the backend swappable; both enforce the same loopback/fail-closed posture. `resolve_generator()` reads env and returns a generator (auto/on) or `None` (off / invalid host → degrade to deterministic). The orchestrator enables it by default; tests force `LLM_NARRATIVE=off` (conftest) to stay hermetic. |

| 2026-07-24 | Compliance layer (`compliance/`) with dashboard tab and published trust page | Vanta-style continuous posture monitoring, self-hosted: a registry of deterministic, offline controls evaluates the repository's own security posture, maps results to NIST CSF 2.0 / SOC 2 / ISO 27001 (labeled *indicative* — not an audit), and records evidence to the gitignored `data/compliance/` through the existing hash-chained `AuditLogger` so history tampering is detectable. Properties that cannot be verified offline (branch protection, Pages approval gate) are explicit **manual attestation** controls — they hold framework coverage below 100% rather than silently passing. The public trust page follows the status-page pattern exactly: committed snapshot (`docs/trust.data.json`, schema with no field for check details, so internals cannot leak), deterministic renderer, `--check` drift gate in CI and pre-commit, publishing behind the human-gated Pages deploy. |

| 2026-07-24 | Attestations for manual controls are committed, expiring, and fail-closed | A manual control passes only via a reviewable entry in `compliance/attestations.json` (validated fail-closed; duplicates, bad dates, or extra fields reject the whole store). Attestations expire and revert the control to "attestation due" — no stale claim passes forever. Attested controls count in framework rollups but never in the automated posture score, and attestor names never reach the public trust page. Posture trend history derives purely from the recorded evidence trail. |

| 2026-08-21 | ATT&CK is a committed, pruned, pinned index (`attack/`) — never a fetched bundle, never a code ladder | The enterprise STIX bundle is ~54 MB against a ~6 MiB repo pack, so committing it is out and fetching at analysis time would violate default-deny egress and make the suite network-dependent. A human stages the versioned file in gitignored `data/attack/`; `scripts/update_attack.py --build` verifies size and SHA-256 against the pin *before* parsing, then distils sub-1 MB shards plus an append-only tombstone ledger. There is **no `--fetch` mode**: routing one through `guarded.enforce()` cannot express per-invocation human approval — the only paths to success (an allow-list label, `report_only=True`) are permanent unscoped downgrades of the control. CI does not have the bundle, so `--check` is an integrity/invariant gate, not regenerate-and-diff: pin signature (when present), per-shard hashes, canonical rendering, tombstone invariants, size ceilings. Freshness is *version distance* against a committed collection-index snapshot — advisory only, never an exit code (a time-dependent gate turns `main` red with no commit and invites bulk-extended expiry dates, which destroys the control). The pin is Ed25519-signable via `agents/policies/signing.py` from the gate script (never from `attack/`, which has zero first-party imports); a hash-only pin honestly claims corruption-detection, not tamper-detection. |
| 2026-08-21 | Revocation is surfaced, never silently rewritten — and a stale reference cannot merge | The index retains every technique the pinned bundle knows, including revoked and deprecated objects, so `lookup("T1064")` answers "deprecated, no replacement" instead of the indistinguishable-from-a-typo `None`. Revoked objects resolve successors through the `revoked-by` STIX relationship; deprecated objects carry no replacement pointer and the invariant check tolerates that asymmetry (it is MITRE's, not ours). The teeth: `scripts/build_attack_navigator.py` previously hard-coded `"attack": "16"` in a *published* artifact and validated tags by regex shape only (accepting `T9999` and every dead ID). It now reads the version from the pin and fails closed on any unresolvable, revoked, or deprecated Sigma tag — a rule pinned to a dead technique cannot merge. ATT&CK v19's restructures (Defense Evasion split into Stealth/Defense Impairment; detection prose moved from `x_mitre_detection` to detection-strategy/analytic objects) landed via the distiller with zero code assumptions broken — the validation of pinning the vocabulary instead of hard-coding it. |

| 2026-08-21 | Event-to-technique mapping moves from Python control flow into a reviewed data store under `agents/mapping/` | `MitreMapperAgent` becomes a thin facade over a committed, ordered ruleset; `map_event()` keeps its exact signature and legacy dict shape (additive keys: `techniques`, `matched_rules`, `attack_version`). The predicate language is literal-only by schema — no regex operator exists, so ReDoS over attacker-influenced log text is structurally impossible — with bounded rule/clause/value counts, validated fail-closed in the attestations style; every output string is a store- or corpus-declared constant, so log text can never transit into a result. The ruleset lives under `agents/mapping/` (not `detections/`) so the engine parsing untrusted text sits inside the bandit and coverage scopes by construction and a built wheel ships its rules (`detections` is absent from `packages.find.include`). Rules resolve against `attack/` at load: unknown → reject; revoked → reject naming the successor; deprecated → reject (operational content re-anchors deliberately); each rule declares its tactic, validated as a member of the technique's tactics, because techniques are multi-tactic and deriving would drift on version bumps. Integrity is a committed canonicalized digest (`rules.sha256`) verified by `scripts/check_mapping_rules.py --check` in CI and pre-commit — not per-event audit writes, which would give a pure function a clock and unbounded chain growth. Deliberate visible consequences of sourcing names from the pinned corpus: T1557 reads "Adversary-in-the-Middle" (the old compound label belonged to T1557.002) and T1070.003 sits under "Stealth" (v19 split Defense Evasion). |

| 2026-08-21 | Threat intelligence is first-party, behavioral, expiring, and synthetic where atomic (`intel/`) | The durable asset is a small, ATT&CK-anchored, fixture-backed behavioral library IANUA authors — no licensing exposure, no decay clock — plus a synthetic atomic seed built only from RFC 5737/3849/2606 values and clearly fabricated hashes, so lookup/decay/corroboration are exercisable from a clean clone without publishing accusations about real third-party infrastructure. No live feed ships: a useful atomic corpus needs an API key (§5.1 secret gate) and non-loopback egress (§5.1 network gate) to buy indicators stale within days. Aging differs in kind by Pyramid-of-Pain level: atomic indicators decay exponentially (per-type half-life; URL 14d → hash 365d) with a hard expiry; behavioral records age on a human review interval and on ATT&CK revisions — a deprecated/revoked anchor degrades the record to `stale-anchor`, never rejects it. `as_of` is injected everywhere (the store's newest retrieval date is the deterministic fallback); no module in `intel/` reads a clock or opens a socket, enforced by security tests. `ThreatIntelAgent` now classifies with stdlib `ipaddress` (explicit internal CIDRs, deliberately not `is_private`, which returns True for the RFC 5737 documentation ranges the seed occupies) and consults the library fail-soft. |

| 2026-08-21 | Behavioral detection content is authored in YAML, consumed as a committed JSON projection, and reference-gated | `detections/behaviors/` holds the post-compromise TTP corpus aimed at payloads already resident on a host. Rules are authored in Sigma YAML (what detection engineers actually write) but consumed through `detections/behaviors.index.json`, built by `scripts/build_behavior_index.py`: the matcher reads coverage with stdlib `json`, so PyYAML stays off the runtime import path and no third fail-soft `ModuleNotFoundError` branch appears — a detection engine silently loading zero rules is a fail-*open*, not fail-soft. The builder is the reference gate: every `attack.tXXXX` tag must resolve to an **active** technique in the pinned corpus, so a rule anchored to a technique a later release retires fails the build with its successor named. This caught a real case during authoring — `T1562.001` is revoked in 19.2 (superseded by `T1685`, which v19 moved into the new Defense Impairment tactic). Every rule carries a mandatory `validation:` marker (`telemetry-available` vs `telemetry-required`) and at least one stated false-positive source, and the marker is asserted against the rule's own selection fields: a rule keying on process-creation telemetry the platform does not ingest **must** declare itself aspirational. That honesty is why the published Navigator layer stays a pure function of `detections/sigma/` — folding telemetry-required rules into a coverage heatmap would inflate a public claim with detections that cannot fire. Fixtures follow the base-corpus pattern with a raised bar: at least three negatives per rule, because behavioral rules key on ordinary administrative tooling and must prove they discriminate — which only works now that the evaluator honors parentheses and precedence. |

| 2026-08-21 | Containment is a plan, not a capability — and the boundary is closed because the approval primitive does not exist yet | `agents/response/` produces an evidence-linked, ATT&CK-anchored `ResponsePlan` in `draft` state, serialized by allow-list projection so nothing from raw incident text or the process environment can transit into it. **No executor ships and there is no arming flag.** This is not caution for its own sake: `SandboxRunner` hard-codes `--network none`, `--cap-drop ALL`, `--read-only` and no PID namespace, so it cannot perform any host action and making it able to would weaken an existing control; `PolicyEngine`'s allow-list resolves before the policy table, making it a permanent unscoped standing grant rather than per-invocation approval; `guarded.enforce(report_only=True)` bypasses the raise entirely; `AuditLogger.record` has no structured payload slot to bind an approval to; and the repository has no caller identity at all. Security tests enumerate the package and fail the build if an executor appears, if any module gains an import path to `subprocess`/`socket`/`mcp.sandbox`, if a dynamic-exec call or clock read appears, or if a plan reaches any state other than `draft`. The action catalogue is committed, reviewed data validated fail-closed: verbs come from a closed **restrict-only** allow-list (collect/revoke/isolate/block/reset/quarantine/terminate — the schema cannot express gaining access, moving laterally, or acting on a third party), every action names a **human** owner and carries a rollback, irreversible actions must state their finality in words, and anything evidence-affecting must declare a prerequisite. Plan ordering is a safety property: tier 0 collection always precedes reversible containment, which always precedes irreversible action, because terminating a process destroys the volatile memory that is often the only readable copy of the implant. Weak signal produces **no plan at all** — a port scan or unattributed IDS alert yields `None` rather than a proposal, since acting on weak evidence is how false positives become outages. The restraint is the artifact: a containment layer whose security tests prove it cannot execute is a stronger claim than a half-working remote-kill path, and the latter would be a §5 liability. |
| 2026-08-21 | Multi-source ingest is a recognizer, not a router — an unclaimed record is labelled, never handed to the closest-looking parser | The keyword classifier works for syslog-shaped text and fails for everything else: a CloudTrail `AssumeRole` record or an Entra sign-in has no `src_ip`, no flat message, and nothing a keyword ladder can grip. `ingest/` translates ten formats across five domains (Sysmon, auditd; Zeek, Suricata EVE; AWS CloudTrail, Azure Activity; Entra sign-in, Okta System Log; Defender for O365, Google Workspace) into one `NormalizedEvent`. Each parser declares a *signature* that claims records on distinctive keys; `detect_source` refuses on ambiguity, because two signatures overlapping is a corpus bug to fix at the signature rather than paper over by taking whichever registered first, and a mis-attributed record yields a confident wrong analysis — strictly worse than an honest "not recognized". Degradation is visible, never silent: oversized, over-nested, undecodable, and type-confused records still produce an event with `parse_status` demoted and a note, since dropping telemetry manufactures the blind spot the layer exists to close. `timestamp` is never back-filled with "now" — fabricated ordering would corrupt every correlation built on it — and the package reads no clock at all, asserted over its AST alongside the no-subprocess/no-socket/no-dynamic-exec checks. `EmailContext` deliberately has no body field, and a security test proves no parser in any domain reads one. Two packages, not one: `ingest/` normalizes and `correlation/` will resolve entities, so the parsing surface can be reasoned about (and bandit-scanned) without the stateful half. |
| 2026-08-21 | OCSF classification for normalized events keys off `(source_type, activity)`, and defaults are reported as defaults | The existing table maps the text classifier's `event_type`; multi-source records arrive already structured with a vendor-stable `activity`, which is a far better basis than re-deriving one from prose. `normalize_source_event()` reports `mapped: True` only for an explicit table entry or prefix rule — a domain default (cloud → API Activity, email → Email Activity) or a Base Event fallback reports `False`, so "we classified this" is never confused with "we defaulted". Endpoint, network, and identity get no domain default at all: their records span several OCSF classes, so an unmapped activity yields Base Event rather than a plausible-looking wrong answer. Parser `activity` values are therefore held to an enumerable vocabulary — a Suricata alert's signature name is carried verbatim in the message and *not* promoted into `activity`, which would make the field unbounded and the table meaningless. Two corrections shipped with it: OCSF 1008 is Event Log Activity (1001 is File System Activity — the uid was always right, the label was not), and `sigma_eval` gained `endswith`, the modifier nearly all published endpoint Sigma content is written against and whose absence made such a rule raise rather than match. |

| 2026-08-21 | Defensive `containment` action class (auto-allowed, audited) + lab-scoped containment toolkit with MITRE ATT&CK mapping | The agents could not stop an active payload: containment actions classified as `destructive`/`unknown` and stalled at a human gate, which defeats the control against ransomware/extortion (encryption completes in minutes). On the repository owner's direction (recorded here as the standing human authorization, AGENTS.md §5.1), `agents/policies/` gains a `containment` class that is auto-allowed by default under three compensating controls: (1) the class covers only **reversible-by-design, lab-scoped** primitives in `agents/tools/containment.py` — quarantine⇄release (symlink-refusing path validation), suspend⇄resume, isolate⇄restore, block⇄unblock, disable⇄enable — with one narrow, labeled exception: `stop_process(force=True)` sends SIGKILL to halt active encryption (process-level, never data-destructive, separately deny-listable under its own `stop_process_force` label); irreversible eradication stays `destructive` and keeps its gate, and host/network/account actions run only through an injectable lab-scoped executor that fails closed when absent or unconfirmed; (2) classification order checks containment **after every gated class** (boundary/secret/destructive/deployment/dependency/external-network keywords), so hybrid phrasing ("quarantine and delete the backups", "quarantine the sample and upload it") keeps the more restrictive class and §5 denies are untouched — free-text keyword classification is best-effort by design, so unmatched text still fails closed to `unknown`, and the enforced surface at tool dispatch uses declared action classes; (3) every policy decision **and** execution outcome is recorded to the hash-chained audit trail through the toolkit's audit logger, and operators can re-gate the class or deny-list individual capabilities in `policy.json`. Each capability is mapped to the ATT&CK techniques it counters — resolved and validated **against the pinned corpus** (`attack/`, 19.2 at time of writing), failing closed on unknown/revoked/deprecated anchors — plus a curated mitigation reference, with descriptions (`agents/tools/attack_mapping.py`, complementing the detection-side Navigator layer); ransomware (T1486 + T1490) and extortion (T1657) rules land in the reviewed mapping store (`agents/mapping/rules/core.json`, digest-gated) with response steps that lead with the toolkit. **Relation to the plan-only decision above (same date):** this deliberately opens the *direct-invocation* half of the execution boundary that decision recorded as closed — by the owner's explicit direction, and with a different control design than the one that entry rejects: not an allow-list standing grant, but a dedicated action class decided and audited per invocation, per-capability deny-list labels, reversible primitives, and fail-closed executors. The plan→execution half **stays closed**: `agents/response/` still ships no executor, no code path consumes a `ResponsePlan` and executes it, and its security tests continue to enforce exactly that (§5 boundary 8 records the amended posture). |

| 2026-10-09 | Releases publish from a merged release PR through a human-gated, create-only tagging workflow | Hand-cut releases touched a dozen version surfaces and drifted. `scripts/prepare_release.py` edits them atomically (full rollback on any failure, including partially written generator output), and `release-on-merge.yml` turns the merged PR into a tag + dispatch of the existing `release.yml` only after approval on the `release` environment, whose required-reviewer rule is checked at runtime because GitHub would otherwise auto-create the environment unprotected. Tags are create-only at the CI-verified commit; a tag that exists without a Release is offered for resumption at its own commit, so a transient dispatch failure cannot strand a version, and a tag naming any other commit fails closed. Rejected: release-please (cannot maintain this repository's Changelog format, SECURITY.md support table or status page), and automatic publication without approval (AGENTS.md §5.1). |

| 2026-10-14 | The SOC gains a memory: `store/`, an append-only event store on stdlib `sqlite3` | Stage 1 of the production-SOC program (`docs/PRODUCTION_SOC_PLAN.md`), begun on the owner's direction to make IANUA a deployable own-infrastructure SOC rather than a lab-only analysis platform. `ingest/` normalizes ten formats into one shape and then **holds nothing** — its invariant is no clock, no filesystem, no network, no subprocess — which is correct for a parser and insufficient for a SOC, where the first question after an alert is what else that host did in the preceding hour. A separate package, not an extension of `ingest/`: persistence needs a filesystem and an ingestion clock, so folding it in would break an AST-asserted invariant, and the platform already made this exact split once (`ingest/` normalizes, `correlation/` resolves). **stdlib `sqlite3`, deliberately:** runtime `dependencies = []` is a load-bearing property, and the compose file's Postgres has sat unused since it was provisioned; a driver for a networked database is a §5.1 dependency decision with its own review, not a default taken quietly, and WAL-mode SQLite serves a single-node deployment that does not need one. **Append-only lives in the engine, not the API:** triggers raise on `UPDATE`, because an API without an update method is not a control when anything holding the file can rewrite history — deletion exists only as counted retention pruning. **Rows are content-addressed** (SHA-256 of the canonical projection) so collection retries, replayed queues, and re-read rotated files store nothing new; a store that counted those separately would inflate every rate and correlation drawn from it, and the same hash makes a row edited outside the platform fail loudly on read instead of returning a plausible event. **No ambient clock:** `ingested_at` is injected in the `as_of` style `intel/` established, so the storage timeline is reproducible in CI; retention prunes on it rather than on source time, so a host with a wrong clock cannot keep its events forever or have them pruned on arrival. **An undated event is excluded from every time window** rather than treated as in-range — `ingest/` never back-fills "now", and an unknown position in time silently counted as "inside" would place the event in every window a caller ever asks about. Queries are a fixed set of correlator pivots rather than a predicate language: nothing above needs arbitrary SQL, and accepting it would put this layer one bug away from arbitrary SQL. Every statement is assembled only from literals declared in the module with values bound, asserted over the AST for f-string/`%`/`.format()` interpolation, since "we used parameters" is a property of today's code and the test is what keeps it true. `NormalizedEvent.from_dict` is added as the sole inverse of `to_dict` — a second hand-rolled reader beside the writer is how two definitions of one shape drift apart — and it validates fail-closed rather than degrading, because a projection is a record this platform wrote itself: a missing key, an undeclared one, or a field past its bound means the row was damaged, and the no-message-body invariant therefore holds on read as well as on parse. Charter crossings in this stage: **none** — the store is lab-scoped data under gitignored `data/`, which is why it is first. |

| 2026-10-14 | `correlation/` resolves entities across domains and assembles incidents (XDR-2) | Stage 2 of the production-SOC program; crosses no §5 boundary, so it ships against the charter as written. Closes the gap the detection plan tracked as XDR-2 and unblocks P7. `store/` answers "what happened before"; this answers "which of those were the same event seen in different telemetry", which is the function a SOC actually performs. **The governing rule is that a mis-attribution is worse than an honest non-match:** a missed link costs an analyst a query, while a false link produces a confident incident naming the wrong principal that every downstream artifact inherits. So merges happen only on declared exact rules — intra-event co-occurrence for co-referring kinds, exact normalized equality, and one user-principal↔username rule — with no fuzzy matching, edit distance, or similarity threshold anywhere. Four over-merge vectors are closed individually, three of them found by tests rather than by reading: **connection endpoints are two addresses** (the intra-event co-occurrence rule is right for `actor` and `device` and catastrophically wrong for endpoints — merging them made every source equal its destination and transitively collapsed thirteen addresses into one entity, so one shared gateway produced a meaningless window-wide incident); **host-scoped principals never join**, judged on the value and not the field, because the auditd parser carries `auid` in `actor.user_name` and a field-based rule let POSIX uid 0 through as an ordinary username and merged root on every Linux host; **display names never join**, because the Entra parser carries `userDisplayName` in the same field and two people share "John Smith"; and **a non-joinable value may not bridge** — marking a value unusable for joining is insufficient unless it is also excluded from the union, which two sign-ins sharing a display name proved by merging into one entity through it. Addresses are never merged into hosts because DHCP and NAT reuse them. Structurally, fan-out suppression demotes an entity appearing in more events than the threshold to reported context rather than dropping it, since transitive grouping on a shared gateway or CI service account collapses a window into one false incident; corroboration is required, mirroring the response layer's refusal to plan on weak signal. Scoring is arithmetic from named constants with per-incident reasons, not learned weights — the detection plan's verdict on ML confidence scoring ("non-reproducible, unreviewable in a diff, breaks hermetic CI") applies. Output is deterministic under input permutation, including member order within an incident, because an incident is evidence and must replay. ATT&CK stamping is deliberately absent: that is P7 and belongs to the mapping engine, and a second mapping path here would be unreviewed. Host-qualified principals (`root@web-01`) would recover the links the host-scoping rule conservatively drops and are deferred rather than approximated. |

| 2026-10-14 | Caller identity (`Principal`) rides in the audit chain's existing `actor` field; the unescaped preimage delimiter is closed first | Stage 3 of the production-SOC programme, scoped by the owner to the three paths where enforcement actually exists (`containment.py:161`, `guarded.py:90`, `mcp/server.py:103`) — a survey established that only those three `enforce()` call sites exist outside tests. **The delimiter had to be fixed before identity could mean anything.** `_compute_hash` joins eight fields with an unescaped `\|`, so a value containing it shifts the field boundaries and a `deny` record can be made to hash identically to an `allow` record; this was demonstrated against the production function, not argued. It was reachable: `actor` was caller-supplied and unvalidated at every site, and a filename containing `\|` reaches `action` via `quarantine_file`/`release_file` (`_resolve_no_symlink` confines the path, not its alphabet). Not reachable through `stop_process`/`resume_process` (`pid: int`) or the regex-validated host/account/hash capabilities. **The fix splits by what a field means.** Identity is *rejected* — the principal alphabet cannot express the delimiter and `record()` refuses any hashed field carrying it, because silently rewriting who did something is not a repair. Description is *escaped* — `target` and `detail` are percent-encoded before entering `action`/`reason`, since a filename may legitimately contain the character and that record is written *after* the file has moved; rejecting there would leave the effect done and the trail missing. Percent-encoding rather than a backslash escape, because `\\|` still contains the delimiter: the preimage would stay ambiguous and the guard would refuse the escaped form — a flaw found by the end-to-end test, not by reading. **Identity reuses `actor` rather than gaining a field**, because that field is already in the hash preimage (so it is attributable) and because a schema change breaks `AuditEvent(**json.loads(line))` in both directions, with the exception escaping through `record()` → `enforce()` → every dispatch, post-effect in containment. A component-only principal renders byte-identical to the bare string the field carried before, so old and new records stay comparable and this is a non-migration. The survey reported `actor` as "a construction-time constant at every call site"; that was wrong — it is a threaded parameter at all three chokepoints and `guarded.py` already compounds it (`f"{actor}[report-only]"`), which is what made this cheap. **No ambient authority, asserted over the AST:** no env read, no module default, no `default_factory` identity. The repository already contains that idiom four times in `agents/tools/llm.py` plus env-reading helpers in `audit.py` and `signing.py`, so an `IANUA_PRINCIPAL` key would have looked idiomatic and been an unauthenticated claim. A rendered-length runtime check was written and then **removed**: the alphabet caps each part at 64, so two parts plus a separator can never exceed the bound and the guard could not fire — the bound is asserted as arithmetic in the tests instead. Deliberately out of scope: this does not authenticate the claim, and it does not touch the ungated `cli/` → orchestrator → ten agents → `agents/tools/llm.py` egress path the survey found (only three `enforce()` sites exist; `llm.py` performs real `urlopen` egress and imports no policy engine). Gating that path is enforcement work, not identity work, and is recorded in `docs/PRODUCTION_SOC_PLAN.md` rather than smuggled in here. |
| 2026-10-14 | `pipeline/` makes the platform continuous: one bounded, resumable, at-least-once cycle invoked by the operating system's scheduler | Stage 4 of the production-SOC program (`docs/PRODUCTION_SOC_PLAN.md`); crosses no §5 boundary, so it ships against the charter as written. `store/` holds what happened and `correlation/` decides which events were one story, but until now nothing ran either of them except a human at a dashboard — a SOC that only works while someone is looking at it is a lab, which is the gap this closes. **At-least-once, deliberately, and the asymmetry is the whole argument:** `run_cycle` returns the new cursor and does not persist it, so a crash between the cycle and the save re-reads rather than steps over. A duplicate incident is noise an analyst dismisses; a skipped window is a blind spot nobody is told about, and nothing in the system would report it. The trade is free only because the cycle **persists nothing** — `assemble` is pure — which a security test asserts by comparing the whole tree before and after a cycle rather than by trusting the claim. **The cursor had to be composite, and finding out why required reading my own Stage 1 code adversarially:** `append_many` stamps one `ingested_at` across an entire batch, so equal timestamps are the *normal* case, not an edge case, and a timestamp-only cursor has only bad options — `>` skips the rest of a tied batch, `>=` re-reads it on every run forever. A `(ingested_at, event_id)` keyset with a matching total `ORDER BY` has neither failure; `Query` gained `ingested_after` and the `event_id` tie-break, and deliberately **no composite index**, since that would change the schema and `SchemaVersionError` refuses a differing version. The trap was demonstrated empirically before it was fixed. **One cycle per invocation, not a daemon:** cron or a systemd timer is more reliable than a hand-rolled loop, leaves nothing to supervise, and is the shape `scripts/audit_maintenance.py` already uses; `Persistent=true` on a timer also runs a missed window on boot, which a daemon would simply have lost. **No clock in the package at all** (AST-asserted, like `ingest/` and `store/`): the window is the cursor, never "the last five minutes", which makes a slow run that silently widens its window unrepresentable rather than merely unlikely. Time, operator paths, and authorization all enter at `scripts/run_pipeline.py`, which is also the platform's **fourth `enforce()` site** — it gates the cycle as `read_only` against the declarative policy bundle, so a deployment that re-gates that class stops the pipeline instead of quietly continuing, and a missing bundle fails closed. **The audit record precedes the cursor advancing**, because the reverse ordering has an unrecoverable failure: a saved cursor plus a failed audit write means a window was consumed with no record of it, whereas a failure in this order re-reads a window the record already described. Identity is explicit — `--caller` or nothing, never `$USER` — asserted over the CLI's AST for the same reason `principal.py` is: the environment-reading idiom already appears four times in `agents/tools/llm.py`, so the unsafe version is the one that would look idiomatic. Two findings came out of writing the tests rather than the code: the cursor was being written **0o644** while every other evidence-writing module in the repository uses 0o600, now fixed by chmodding the temporary file *before* the rename so the cursor never exists at its real path in a wider mode; and the temp file had a **fixed name**, so two overlapping runs could interleave writes and rename a half-written cursor into place, now keyed to a digest of the content. `Incident` still carries no identifier — `assemble` invents no state — so `pipeline.reference()` derives a stable digest over the sorted event ids, which is what makes an at-least-once duplicate recognizable as one; it is documented as unkeyed and explicitly **not** a security claim, since attribution belongs to the hash-chained audit log. Finally, `tests/unit/test_gate_scope_parity.py` gained an assertion that every top-level directory holding Python is either in a gate scope or in a named exclusion with a reason: the six parity assertions were all conditional on someone having remembered to add the directory in the first place, which is exactly how `cli/` came to sit in **no** gate scope at all while every gate stayed green. `cli/` is now recorded as a known exclusion pointing at its own stage, rather than being an omission. |

> Append new architectural decisions here (date, decision, rationale) so the history stays
> auditable.
