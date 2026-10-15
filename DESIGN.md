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
| `ingest/` | Multi-source telemetry normalization: endpoint, network, cloud, identity, email → one canonical event | Recognize-never-guess (an unclaimed record is labelled `unknown`, never routed to the closest parser); degrade visibly rather than drop; every field bounded and control-character stripped; no clock, filesystem, network, or subprocess; **no field exists for a message body**, and `raw_excerpt` is rebuilt from each signature's declared paths so no un-modelled field is retained either |
| `store/` | Durable, append-only event store over the canonical `NormalizedEvent` | Append-only enforced by engine triggers, not API discipline; rows content-addressed so a replay is a no-op and a tampered row fails on read; no clock (`ingested_at` injected); database confined to gitignored `data/events/`; every query bounded; retention keyed on ingestion time, never on source-reported time |
| `correlation/` | Entity resolution across domains + incident assembly | Entities merge only on declared exact rules — no fuzzy matching; connection endpoints never merged with each other, addresses never merged into hosts, host-scoped principals (uid 0, well-known SIDs, `root`) and display names never used as join keys, and a non-joinable value may not bridge two entities; over-common entities demoted to reported context rather than joined on; scoring is arithmetic from named constants with per-incident reasons; no clock, filesystem, network, subprocess, or storage driver |
| `pipeline/` | Continuous execution: one bounded, resumable cycle of store → correlation, invoked by a scheduler | **Two windows, never one** — the cursor advances over the new events, while correlation sees those plus a trailing `lookback` of already-consumed history, because a cursor *partitions* the stream and cross-domain correlation is *windowed*; at-least-once — the cursor advances only after a cycle succeeds, so a crash re-reads rather than skips; the cursor is a composite `(ingested_at, event_id)` keyset because one ingestion timestamp spans a whole batch; the cycle persists nothing, which is what makes a replay free and what lets "already reported" be derived from event ids rather than remembered; reads never exceed what `assemble` will examine, so the cursor cannot cross an event nothing looked at; one cycle at a time, because two concurrent appenders fork the audit chain; no clock, no socket, no subprocess, no executor (AST-asserted, recursively); every path component between the lab root and the cursor is checked for a symlink |
| `collect/` | Local log collection: declared files on this node → `ingest/` → `store/` | **The one package that reaches outside the project** (§5 boundary 14) — declared sources only, never discovered: no glob, no directory walk, no heuristic; absolute paths only; a symlink at the log file is refused when the paths are validated (which catches a stale or mistyped source, not an adversary racing the read — winning that race needs write access to the log's directory, with which the same false evidence can be written into the log directly); two spellings of one file collapse to one source, so a pass cannot read the same region twice and then misreport what it did; credential-shaped paths are refused outright — matched on **both** the declared and the resolved spelling, because a symlinked ancestor resolves a positional rule away while a symlinked ancestor pointing *into* a key directory hides it from the declared one; sources are opened read-only and a security test asserts no write mode reaches one; rotation and truncation are detected by `(device, inode)` plus a digest of the last bytes consumed, not guessed — `copytruncate` regrowth and inode reuse both pass an identity-and-size check while holding different content; a first run reads from the *beginning*, since the conventional tail-the-end default would skip the history a SOC most wants on day one; offsets advance only after the events are durable; bounded per source per run; no clock, no socket, no subprocess, no executor (AST-asserted, recursively) — which is why journald is out of scope, as reading it means spawning `journalctl` |
| `store/paths.py` | One confinement check for every writer under the lab-data root | Walks **every** component from the resolved root to the file, not just the leaf; tests `is_symlink()` rather than `exists() and resolve() != path`, because a dangling link is what a planted attack looks like before `mkdir` materializes it; raises the caller's own error type so each package keeps its taxonomy. Extracted after `store/` and `pipeline/` were found wrong in the *same two ways* |
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
   `data/`, **with one licensed exception**: `collect/` reads log files on the node it runs
   on, read-only and declared-only, which is boundary 14 below and the `AGENTS.md` §5
   amendment it records. This boundary was not updated when stage 5 amended the charter, so
   it contradicted boundary 14 on the same page until a stage 6 survey caught it — the exact
   drift the "amend per crossing" rule exists to prevent, in the document that records the
   crossings. Network egress is unchanged: default-deny, limited to lab hosts, and any other
   egress is a gated action.

   Reports are also a filesystem destination, and the one that leaked. An incident report
   carries event content, and its default destination was a **tracked** file
   (`reports/markdown/orchestrated_incident.md`) that both shipped CLIs wrote to with no
   path argument — so a real log line put real telemetry into the working tree, one
   `git add -A` from being published, against the §5 prohibition on committing logs.
   `agents/incident_report_agent.py` now refuses any destination inside the repository but
   outside the gitignored `data/`, judged on the resolved path, and both defaults point
   under `data/reports/`.

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
   sender chose. Four properties keep it from becoming a liability. **Recognition is
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
   without adding signal (AGENTS.md §5). **Nothing un-modelled is retained**: every
   signature declares the payload paths its parser reads, and `raw_excerpt` is
   re-serialized from those paths alone (`ingest/_coerce.py::project`), so a field no
   parser models — a mail `Body`, a column a vendor added last week, a key an attacker
   chose — has no route into a stored event. This closes a real gap rather than restating
   an existing claim: the excerpt used to be a copy of the whole decoded record, so a
   Defender export's `Body` reached `raw_excerpt` and survived `to_dict()` *even though*
   `EmailContext` has no body field and no parser reads one. Both halves of the control
   were real and neither covered the excerpt. Serialization is now an allow-list
   projection over frozen dataclasses across the whole event — `raw_excerpt` included,
   where before it had to be excluded from that claim by name — so no attacker-controlled
   key can ride along into a downstream artifact, and match-view keys come from the
   schema rather than from record content. A record *no* signature claims is projected
   through the union of every parser's declared paths, with a note naming the keys whose
   values were withheld, because recognition breaking upstream is the likeliest route by
   which a body would otherwise reach a store that cannot be redacted. Free-form text
   that never decoded into a record is still carried verbatim: there is no structure
   there to project, and dropping it would manufacture the blind spot this layer exists
   to close. Indicators are extracted from the full text of an unclaimed record and then
   the text is discarded, so narrowing the evidence does not blind `correlation/`.

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
    alerts. The first design question is *what a cycle may see*, and the obvious answer is
    wrong: correlating exactly the events since the cursor **partitions** the stream, while
    cross-domain correlation is **windowed**. An attack landing at 10:02, 10:07 and 10:12 is
    then three one-event cycles that each assemble nothing, and once the cursor passes them no
    later cycle can recover the story — reported as `exit 0` and "0 incident(s)", precisely the
    silent blind spot this boundary exists to refuse. Measured rather than reasoned about: the
    same store correlated in one pass yields a three-domain score-52 incident, and through
    disjoint cycles yields none. So a cycle keeps **two** windows — the cursor advances over the
    new events, and `assemble` sees those plus a trailing `lookback` of already-consumed
    history. Whether an incident is *news* is derived from its event ids (does it involve any
    event this cycle had not consumed?) rather than remembered, which keeps the overlap from
    re-alerting every cycle while leaving the cycle stateless. The limit is stated rather than
    hidden: an incident spanning longer than the lookback is still cut, which is inherent to any
    stateless window and is why persisted, mergeable incidents remain the end state. The widened
    read is bounded above by the cursor being saved, because the store grows continuously under
    a collector and correlating past it would report a story built partly from events the cycle
    never consumed. The governing choice is otherwise **at-least-once**: `run_cycle` returns the new
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
    that is chmodded *before* the rename, so the cursor never exists **at its real
    path** in a wider mode (the temporary file itself is created at the umask default
    and tightened before the rename; it is unreadable to other users throughout
    because the enclosing directory is `0o700`, which is where that guarantee actually
    comes from),
    and confined by walking **every** component between the resolved root and the file — not
    only the leaf directory, because `data/pipeline` is two deep and a link planted at `data`
    was otherwise never examined while `mkdir(parents=True)` created the leaf straight through
    it; and by testing `is_symlink()` rather than `exists() and resolve() != path`, because a
    link whose target does not exist yet reports `exists() is False`, skipping exactly the case
    mkdir goes on to create. `store/` carried the identical defect, where it relocated the whole
    evidence database, and both are now pinned by one test so they cannot drift.

    **One cycle at a time, as a correctness control.** The CLI holds an exclusive lock for a
    whole cycle, because `AuditLogger` derives each record's `seq` and `prev_hash` by reading
    the last line and appending — a read-modify-write with no lock. Six concurrent invocations
    produced a duplicate `seq`, a forked chain, and `verify()` returning `False` for every
    future reader, with all six exiting `0`. That is worse than losing records: it puts a false
    positive into a tamper detector, so an operator can no longer distinguish overlapping timer
    firings from someone editing the log. A declined lock exits `0` and says so — the timer
    outrunning the cycle is expected on a tight schedule, and failing would mail the operator
    every five minutes until they learned to ignore it.

14. **This node's log files → the event store (`collect/`)** — the boundary where IANUA
    stops being fed and starts reaching. Every other package keeps its filesystem reach inside
    the project and the gitignored lab-data root; this one reads `/var/log`, which is the §5
    crossing the owner approved for stage 5 specifically. The crossing is *outward and
    read-only*, and the controls follow from what could go wrong rather than from a general
    principle.

    **Why not the network.** The obvious collector pulls from hosts or exposes a listener, and
    the repository has twice refused outbound egress — the ATT&CK bundle and the threat-intel
    feed — because `guarded.enforce()` cannot express per-invocation human approval, so the only
    ways to make a fetch pass are an allow-list label or `report_only`, both permanent unscoped
    downgrades of default-deny. Reading this node's own logs needs no network at all, so it does
    not reopen that argument. A listener is not egress either, but it adds an unauthenticated
    inbound surface the charter does not yet describe; that is a later stage with its own
    boundary.

    **What an attacker who can write a log gets.** Everything this layer reads becomes stored
    evidence, so the failure mode is *fabricated telemetry* — an attacker who controls a log line
    controls what the SOC believes happened. That cannot be fully prevented by the reader (if you
    can write the log, you can lie in it), so the controls target what the reader must not make
    *worse*: it must not be redirected to a file nobody declared, and it must not promote prose
    into structured evidence. Hence a symlink at the final component is refused, and hence
    `ingest/keyvalue.py` claims a line only when at least two pairs cover 60% of it, so a
    sentence containing an equals sign is carried as text rather than attributed a source type it
    did not earn.

    **Be exact about what the symlink check buys**, because the first version of this section was
    not. It runs once, when the operator's paths are validated, and the reader then opens the same
    *path* — so it catches a source that is a link at declare time (a stale or mistyped path, a
    layout nobody intended), not an adversary who swaps a link between validation and the read.
    Review was right to call that claim: whoever can win that race already has write access to the
    log's directory, and with it can write chosen content into the log itself for the same
    fabricated-evidence outcome without racing anything. What the reader *does* guarantee is that
    every byte of one pass — the continuity digest and the data — comes from a single descriptor,
    so a fingerprint match is about the bytes that were actually consumed. Closing the remaining
    stat/open window needs `os.fstat`, and `os` is on this package's banned-import list for
    reasons (no spawn, no clock, no environment) that outweigh a race with that precondition; the
    window is recorded here rather than papered over.

    **Credential paths are refused, not warned about.** A collector pointed at a private key
    would copy that key into `data/`, and §5 names credentials sensitive by default. The
    deny-list is not a complete defence and is not presented as one; it stops the plausible
    accident. The *pattern* and the *wiring* are tested separately, because deleting the
    `if _DENIED.search(...)` branch left a pattern-only test passing — a regex nobody consults
    still matches.

    **Positioning is the correctness problem, not the security one, and it is the harder half.**
    A rotated log keeps its name and changes its `(device, inode)`, so an offset applied to the
    new file skips its first `offset` bytes — silently, in the moment volume made rotation
    happen. Truncation in place keeps the identity and resets the size, and an offset-only reader
    then seeks past the end and reports "nothing new" forever. A partial final line consumed
    costs both the fragment and the remainder. Each is detected rather than guessed, and each has
    a test naming the loss it holds closed. One gap remains stated rather than fixed: the tail of
    a file rotated away *between* runs is unreachable by name, because a one-shot process holds
    no descriptor across invocations. It is bounded by how often the collector runs, which is why
    the documented schedule is minutely.

    **Ingestion order became a control here.** Stage 4 documented it as a contract on whoever
    wrote events; stage 5 is that writer, and a contract with one reader is just a comment. The
    store now *refuses* an `ingested_at` behind its high-water mark, because the pipeline pages
    by a `(ingested_at, event_id)` keyset and an earlier-stamped event sits behind a cursor that
    has already passed it — never read, by any cycle. The mark is a row in the existing `meta`
    table, so the DDL is unchanged and no `SCHEMA_VERSION` bump is provoked; it is *stored*
    rather than derived from `MAX(ingested_at)` precisely because retention deletes rows and a
    derived mark would reset when a window aged out. The CLI stamps `max(now, mark)`, so a clock
    that steps backwards clamps instead of failing — `occurred_at` still carries the source's own
    time. The cost is honest and recorded in the plan: a clock that jumps *forward* raises the
    mark permanently and delays retention for everything after it.

    **Its own policy class.** Collection is gated `collection`, not `read_only`. The pipeline is
    `read_only`, and sharing a switch would mean that stopping the thing which reads host files
    also stops the thing which correlates what was already read. `allow` by default, so the gate
    is a kill switch rather than a restriction — said plainly, because what actually constrains
    collection is which sources were declared.

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
| 2026-10-14 | A cycle keeps **two** windows: the cursor advances over new events, correlation sees a trailing `lookback` as well — plus six defects found reviewing Stage 4 against itself | The stage shipped CI-green and did not do its job. Correlating exactly the events since the cursor **partitions** the event stream, but cross-domain correlation is **windowed**: an attack landing at 10:02, 10:07 and 10:12 became three one-event cycles that each assembled nothing, and once the cursor passed them no later cycle could recover the story — output `exit 0`, `0 incident(s)`, the exact silent blind spot §5 boundary 13 refuses. Measured, not argued: the same store in one pass yields a three-domain score-52 incident, through disjoint cycles none. Every test had hidden it by seeding a whole batch *before* the first cycle, so the whole story always sat inside one window; the regression test now interleaves append-and-cycle, which is the only way this runs in production. **Lookback over the alternatives, with its limit stated:** persisted mergeable incidents are what a real SOC does and remain the end state, but they are a new persistence layer with a schema, a close/expiry lifecycle and an idempotent merge — a stage, not a fix; a fixed trailing window with no cursor re-reports every incident every run. The overlap is the smallest change that makes the stage work, and *an incident spanning longer than the lookback is still cut* — inherent to any stateless window, asserted by a test so nobody later reads the overlap as a complete solution. Two properties make it safe: whether an incident is **news** is derived from its event ids rather than remembered, so the cycle still persists nothing and the overlap does not re-alert every firing; and the widened read is bounded above by the cursor being saved, since the store grows continuously under a collector and correlating past it would report a story built partly from events the cycle never consumed. `Query` gained `ingested_from` (inclusive, additive, no schema change) as the deliberate counterpart to `ingested_after`: one *excludes* the cursor so the pipeline makes progress, the other *includes* a trailing region so a story can be seen whole. **The same review found four failures in controls this PR claimed to establish.** A symlinked *ancestor* escaped the lab-data root: the check examined the leaf directory and the file but never `data`, and `mkdir(parents=True)` created the leaf through the link — and it was existence-gated, so a link whose target did not exist yet (precisely what mkdir then creates) was skipped. `store/` carried the identical bug, where it relocated the whole evidence database; fixed in both, pinned by one test, per the owner's standing call to fix pre-existing defects in place and flag them. Two concurrent cycles corrupted the audit chain **permanently** — `AuditLogger` reads the last line for `seq`/`prev_hash` then appends, with no lock, so six concurrent invocations gave a duplicate `seq`, a forked chain and `verify()` `False` for every future reader, all exiting `0`; worse than losing records, because it puts a false positive into a tamper detector, and reachable from the `*/5` schedule this PR itself documented. `run_cycle` advanced the cursor past events `assemble` never examined, since it truncates silently at `max_events`. An audit record asserted "cursor advanced" *before* the save that decides it, so a failed save left a false claim in a tamper-evident chain; it now states intent. Three failure paths reached an unattended operator as tracebacks rather than exit codes. And nothing asserted the CLI applies the cursor it loads — deleting `cursor=cursor`, which makes the pipeline re-read the entire store forever while still reporting success, left all 70 tests green. Seven test weaknesses were fixed the same way they were found: by planting the defect each claimed to catch and watching it fail. The AST invariants scanned the package non-recursively, so a subpackage could import `socket` unchecked; the no-ambient-identity test checked a list of variable names, so `os.environ.get("IANUA_OPERATOR")` passed and it now bans reaching the environment at all; two gate-ordering tests were `source.index(...)` comparisons, brittle to a reformat and vacuous against a real reordering, now replaced by behaviour. The lesson worth keeping: every one of these was green in CI, and the ones that mattered most were found by *running* the code in the shape it actually deploys rather than by reading it. |
| 2026-10-14 | `collect/` reads this node's own logs — the first §5 boundary crossing — and ingestion order becomes a control rather than a contract | Stage 5 of the production-SOC programme. **Nothing in the repository wrote an event anybody had not typed**: `ingest/` normalizes what a caller hands it, so the platform had four stages of memory, correlation and scheduling over a store only a test ever filled. Three models were put to the owner with their boundaries priced separately, because they differ in kind rather than degree: an outbound poller crosses default-deny egress, which this repository has refused **twice** (the ATT&CK bundle, the intel feed) on the grounds that `guarded.enforce()` cannot express per-invocation human approval — the only ways to pass are an allow-list label or `report_only`, both permanent unscoped downgrades; an inbound listener is not egress but adds an unauthenticated network surface the charter does not describe; reading local files crosses only filesystem reach, outward and read-only. The owner chose local-first, so the egress argument stays closed and a listener remains a later stage with its own boundary. **Declared, never discovered** is the central control: no glob, no directory walk, no heuristic, because a collector that searches for sources eventually finds one nobody meant it to read, and everything it reads becomes stored evidence. A symlink at the final component is refused at declare time (which catches a stale or mistyped source; the adversarial reading of this claim was overstated and is corrected in the row below) while ancestors are deliberately *not* walked — `/var/log` is legitimately a symlink on several distributions, and refusing the normal case gets a control switched off. That asymmetry against `store.paths.confine`, which walks every component under the lab root, is reasoned rather than sloppy: inside the lab root every component is ours. Credential-shaped paths are refused outright, since pointing a collector at a private key copies it into `data/`; the pattern and its *wiring* are tested separately after deleting the `if _DENIED.search(...)` branch left a pattern-only test green — a regex nobody consults still matches, which is the same class of decorative test this programme has now found three times. **Positioning turned out to be the harder half, and it is correctness not security.** A rotated log keeps its name and changes its `(device, inode)`, so an offset applied to the new file skips its first `offset` bytes silently, in the moment volume caused the rotation; truncation in place keeps the identity and resets the size, so an offset-only reader seeks past the end and reports "nothing new" forever; a partial final line consumed loses both the fragment and the remainder. Each is detected rather than guessed and each has a test naming its loss, verified by planting the defect. A first run reads from the **beginning**, not the end: the conventional tailer default would skip exactly the history a SOC wants on the day it is switched on. One gap is stated rather than fixed — the tail of a file rotated away *between* runs is unreachable by name, since a one-shot process holds no descriptor across invocations — which is why the documented schedule is minutely. **Ingestion order stopped being a comment.** Stage 4 recorded it as a contract on whoever wrote events; stage 5 is that writer, and a contract with one reader is a comment. `append_many` now refuses an `ingested_at` behind a stored high-water mark, because the pipeline pages by a `(ingested_at, event_id)` keyset and an earlier-stamped event sits behind a cursor that has already passed — never read, by any cycle. The mark is a **row in the existing `meta` table**, so the DDL is unchanged and `SchemaVersionError` is never provoked, and it is *stored* rather than derived from `MAX(ingested_at)` precisely because retention deletes rows and a derived mark would reset when a window aged out — pinned by a test that prunes everything and still refuses. It cost **zero** existing tests, which says the invariant matched how the store was already used. The CLI stamps `max(now, mark)` so a backwards clock clamps rather than fails, with the forward-jump cost recorded. **`ingest/` gained a decoder, not a parser.** Measured first: JSON-lines sources (Suricata EVE, Zeek, CloudTrail, Entra, Okta, Defender, Workspace) parsed and correlated fully, while auditd `key=value` and syslog text came out `unknown`/`text` with no fields — collectable and not correlatable, and on a Linux node those are the two most valuable local sources. `ingest/keyvalue.py` adds **no signature and no parser**: the auditd recognizer already claimed `{type, node, auid, comm}` and already read auditd's clock out of `msg=audit(...)`; it was written expecting a mapping nothing produced. The risk it introduces is not a crash but **manufactured telemetry**, so its thresholds are the control — at least two pairs covering 60% of the line, because one pair matches ordinary log text and two incidental pairs appear in prose and in URLs. Freeform syslog stays out of scope: extracting it means regex patterns against unversioned vendor message strings, the most defect-prone code in any log pipeline, and it belongs in its own reviewed change. **`store/paths.py` removes duplication rather than adding it.** Three packages now write under the lab-data root and two of them had grown copies of one check that were wrong in the *same two ways* — leaf-only, and gated on `exists()` so a dangling link was skipped. One implementation, in `store/` because it owns the root and both other callers already import it, with a security test asserting all three refuse the same escape so they cannot drift apart again. Collection is gated as its own `collection` action class rather than `read_only`: it is the one action reaching outside the project, and sharing the pipeline's switch would mean stopping host reads also stops correlation of what was already read. Charter amended in this change per the owner's standing instruction to amend as each boundary is crossed. |
| 2026-10-14 | Stage 5 reviewed against itself: nine production defects and eleven test weaknesses, every one of them green in CI | Reviewed the way stage 4 was, and the result was the same in kind: the stage passed every gate and did not hold. **Three defects lost log data outright.** A line longer than `max_bytes` with no newline inside the budget wedged its source **permanently** — the `cut == -1` branch returned the unchanged offset, the next run computed the same budget over the same bytes, and the operator was told "nothing new" with exit 0; reproduced over five consecutive passes at offset 0, and reachable with the shipped defaults on any single line past 8 MiB as well as with any `--max-bytes` below the 64 KiB line cap, which the flag's help text did not warn against. `logrotate copytruncate` — the prescribed mode for a writer that holds a descriptor — preserves the inode and resets the size, so a file truncated and regrown *past* the old offset passed identity and size both and the reader resumed mid-stream: 31 of 40 brute-force lines silently skipped through the real CLI, with no reset reported. Delete-and-recreate rotation defeated `(device, inode)` whenever the kernel reused the freed inode, which it strongly prefers to do. One continuity fingerprint — a digest of the last 64 bytes consumed, re-read and compared on resume — closes the latter two, and `Position.size`, documented as the truncation discriminator, turned out to be read by no decision at all. **Two defects made events unreachable rather than lost**, which is worse because the store looks complete. The high-water mark permits equality, correctly, since one `append_many` stamps one time across a batch — but the pipeline's keyset is *strictly* after `(ingested_at, event_id)`, so an event stamped exactly at the mark with a lower id sits behind a cursor that has already passed it: four stored, three ever seen, measured. `max(now, mark)` in the CLI walked straight into that on every backwards clock step, so the store now owns the arithmetic (`EventStore.next_stamp`, `math.nextafter`) because the mark and the cursor contract are both its own. And the mark was never bootstrapped: `SCHEMA_VERSION` is deliberately unchanged, so every database written by stages 1-4 opens with rows and no `meta` entry, and returning `None` there left the control inert precisely where there was already history to get behind — it now derives from the rows once, with the stored row still winning when it exists, since retention prunes and a derived mark would move backwards. A non-finite `ingested_at` is refused outright: NaN compares false against every bound, which disables the control rather than tripping it, and `inf` wedges the store forever. **Two defects fabricated or misstated evidence.** `_execve_command` matched `a0`/`a1`… on every record type, so a `SYSCALL` record's syscall *argument registers* were reassembled into a plausible `actor.command_line` — a command no one ran, on the most frequent auditd record type, reachable for the first time the moment the key=value decoder existed. Real auditd auth records carry `msg=` **twice** (the clock form and a payload form), and last-wins clobbered the clock, so every SSH authentication and every sudo invocation landed undated; first-occurrence-wins is also the defensive reading, since a later pair cannot restate what the head of the line declared. **The rest were operational**: one unreadable source returned before `save_offsets` and so starved every healthy source's progress *forever* under a persistent failure; `sqlite3.Error` is neither `OSError` nor `StoreError` and escaped as a traceback in cron mail; the lock's own `mkdir`/`open`/`chmod` ran at `__enter__`, outside every `try`, and the first operator to hit it is the one following the runbook; and `--source X --source X` read one file twice from one stored position and then recorded "1 of 2 sources" in a hash-chained log. **Eleven test weaknesses, found by planting each defect and watching the suite stay green.** Four were discovered *by the plants themselves*, after the fixes: the deny-list ancestor test passed on the resolved spelling alone because its fixture matched both ways, and nothing isolated the resolved direction either — both now assert that the *other* spelling does not match, so the fixture cannot prove the wrong thing; no test held the "report before advancing" ordering, so swapping the two blocks — which consumes lines nobody was told about — stayed green; and the three-caller containment parity test asserted a *dangling* link in its docstring while every fixture used an existing target, the one shape that any check at all catches. The bound tests scaled their inputs from the constants under test, so `MAX_PAIRS`, `MAX_VALUE_LEN` and `MAX_KEY_LEN` could each be raised arbitrarily with the suite green; they are pinned to literals now, and a 512 MiB plant caught the same tautology in a cap test that sized its own fixture from the cap. The read-only and discovery invariants parsed one hard-coded file and only attribute calls, so `from glob import glob` plus a bare call satisfied all three, and `scripts/run_collector.py` — where operator paths actually enter — was in none of them. **Three overstated claims were corrected rather than defended**, which is the part a reviewer cannot do for you: the symlink check was documented as stopping an adversary and does not (see boundary 14); `ingest/keyvalue.py` claimed truncation left "the record marked degraded by `ingest/`'s existing machinery" and nothing marks anything; and §8's "full scope" mypy list had drifted to six of fourteen packages while §8 opens by claiming §7 is mirrored exactly — now pinned by the parity test, which had covered the §7 command block but not the prose. The lesson is the same one stage 4 recorded and is now recorded twice on purpose: the defects that mattered were found by **running** the code in its deployed shape, and the tests that mattered were proved by **breaking** the code they claim to protect. |
| 2026-10-14 | Three defects a stage 6 survey found in merged code: an unreadable store, a world-readable store, and a report default that wrote telemetry into the working tree | Surveying the repository to price the stage 6 PII posture turned up defects rather than design questions, all three reproduced before being acted on. **A line of 2049-4096 characters was writable and then permanently unreadable.** `_unrecognized` bounded `message` at `MAX_RAW_EXCERPT` (4096) while `from_dict` validates it at `MAX_FIELD_LEN` (2048) — one constant, in the one field written at the wider bound — so `append` accepted the event and every later `query` raised `MalformedProjectionError`. `run_cycle` does not catch it, so **every subsequent detection cycle on that store failed**: one long log line, a padded username in a brute force or a URL in an application log, stopped the SOC. Only `raw_excerpt` may carry the wider bound, because it is validated there on both sides. Observables are now read from the excerpt rather than the truncated message so detection is unchanged — and the first draft of that docstring claimed the fix *widened* extraction, which was false (`observables()` coerces each input at `MAX_FIELD_LEN` itself) and is corrected rather than shipped. **The event database was the only state file under the lab-data root created at the process umask**: measured at 0o644 inside 0o755, while a byte offset in `data/pipeline/` was deliberately 0o600 inside 0o700 with a docstring explaining that it is evidence. The asymmetry ran the wrong way round — bookkeeping protected, the telemetry itself readable by every local account — and it matters more the moment the data is real. Narrowed on open, including an existing wide store, so a deployed database corrects itself rather than waiting for someone to read a release note; the 0o700 directory is the control and the file modes are defence in depth, stated the way `pipeline/cursor.py` already states the same trade, because SQLite creates its sidecars at the umask and may recreate them on any write. **An incident report's default destination was a tracked file.** `reports/markdown/orchestrated_incident.md` is in git, `generate_report` applied none of the confinement `store.paths.confine` exists for, and all four shipped entry points call `process_log` with no path — so running the documented command over a real log line wrote the hostname, the account, the source address and the raw message into the working tree, against §5's prohibition on committing logs. Nothing currently committed holds event data (checked: the committed report has no indicators at all), so this was preventive. The defaults move under `data/reports/` and the writer refuses any destination inside the repository but outside `data/`, on the resolved path so a traversal is refused too; the dashboard and CLI that read the old path moved with it. The test that pins it is self-cleaning, because running it against the guard removed left a real 1996-byte incident report in `docs/` and poisoned every later run — a test that fails must not also leave behind the artifact whose absence it asserts. |
| 2026-10-14 | A completeness critic over the *fix* commit found three more defects, two of them introduced by the fixes themselves | The stage 5 review's dimensions all read the parent commit; the critic read the merged head and found what the fixes had left or created. **One stamp per pass stranded whole sources.** `append_many` is one transaction per call, so hoisting `next_stamp` out of the per-source loop gave every source's separate commit the same `ingested_at` — and the collector and pipeline hold *different* locks by design, each existing to stop its own concurrent invocations forking the audit chain, so nothing prevents a cycle firing between two commits. That cycle saved a cursor **inside** the tie group, and the keyset is strictly after `(ingested_at, event_id)`, so every later-source event whose content hash sorted below the cursor's id was behind a cursor that had already passed it. Reproduced at 30 of 60 collected events permanently invisible with the pipeline reporting `events_read: 0` — which is exactly the loss `next_stamp` was added to prevent, reintroduced one layer up by the call that was supposed to prevent it. Stamping per commit means a cursor can only land between tie groups. The first test written for it drove the store API directly and so passed with the defect planted back; it now fires the cycle from inside `append_many`, which is the only place the defect is reachable. **The over-long-line fix traded a stall for silent bulk loss.** Advancing by `len(chunk)` while emitting `max_line` passed over the difference — up to 8 MiB minus 64 KiB per pass, measured at 4505 of 5410 bytes — while reporting `truncated: 1`, and the test written with it asserted `offset == 100` after emitting 20 bytes, blessing an 80% loss as correct. Advancing by what was emitted makes the module's own claim ("the remainder may arrive as further truncated records") true for the first time; the consequence, recorded rather than hidden, is that one pathological record becomes several events. **auditd's nested payload was swallowed whole.** Real `USER_AUTH`/`USER_CMD`/`CRED_*` records — every SSH authentication and every sudo invocation — carry everything an analyst needs inside a second, single-quoted `msg`, which the pattern matched as one value, so `finditer` resumed past it and `acct`/`addr`/`res` were never produced as keys. The record reached the parser with only `type/msg/pid/uid/auid/ses`, so the actor fell back to `auid` = `4294967295` (the unset sentinel every pre-auth sshd record carries), with no address, no result and no observables — while still stamped `structured` with no note. The numeric user is not host-joinable, so the event carried *zero* joinable references and could never enter an incident: a brute force collected from `audit.log` produced **zero** incidents, confirmed A/B through the real CLIs against byte-identical flattened records that produced one. The merge runs only after the thresholds pass, so scavenging inside a quote can never promote prose, and first-occurrence-wins holds across levels so an influenced payload cannot restate the `type` or `exe` the record's head declared. **And that fix introduced a false-merge, caught before it shipped.** Decoding the payload exposed `hostname=?`, auditd's placeholder on every pre-authentication record, which `NEVER_JOIN` did not list: two unrelated attacks on different accounts from different addresses assembled into one 12-event incident scored 40 instead of two correct 6-event ones. `?` and `(none)` join the committed deny set, which is where the repository already keeps `-`, `unknown` and `localhost` for exactly this reason. The lesson this round adds to the two already recorded: a fix is a change like any other, and the review that matters most is the one aimed at the fix rather than at the original. |
| 2026-10-15 | Retention becomes a caller, not a method: report by default, delete only on an exact-match grant | `EventStore.prune` shipped in stage 1 and had **no caller** outside tests — a retention mechanism with no retention policy, which a stage 6 survey found while pricing the PII posture. `scripts/run_retention.py` is the caller, and the shape follows from a tension the survey surfaced: the repository's own generated `05_Governance_Rules.md` puts "Deleting data" under "Human Approval Required Before", while retention wants to run on a schedule. **The two modes are different action classes because they are different actions.** A dry run deletes nothing, so it is gated `read_only` and runs freely; `--apply` deletes, so it is gated `destructive`, which the shipped bundle sets to `require_approval` and therefore *refuses*. That refusal is the design. `guarded.enforce()` cannot express a per-invocation prompt — the 2026-08-21 decision established that and declined to add one — but it can express a standing grant for one named label in a committed, reviewable file, so permitting deletion is an operator adding `retain_events:apply` to their allow list. The allow list is **exact-match**, and that is load-bearing: a grant of the bare `retain_events` is what an operator would plausibly write thinking it permits "retention", and under a prefix or substring match it would permit the destructive half too. Pinned by a parametrised test over four partial grants — written only because planting a prefix match did **not** fail the first test for it, since neither full label is a prefix of the other. **Deletion is irreversible in a way nothing else here is**, and the survey's critic found the interaction nobody had looked at: the retention dimension examined prune-versus-cursor and prune-versus-high-water-mark and never prune-versus-collector-offsets. Offsets live in their own file and nothing rewinds them, so pruned content cannot be recovered by re-collecting a source that still holds every line — measured by purging a store and re-running the same collector invocation, which reported "nothing new" and stored zero. The CLI says so in its own output, the runbook says so, and a test pins it as a property so the warning cannot quietly become false. `count_before` is added to the store as a `COUNT` rather than a `query`, so reporting what would be deleted does not depend on every projection in range parsing cleanly — the operator most needs that number when something is wrong with the data. The runbook also states what keeping costs (~1.7 KB/event measured, ~507 MB/day and ~15 GB/month at the documented cadence), because a window is a number nobody can choose without it, and records that four audit chains now grow under `data/` while the only shipped audit-retention tool documents a fifth path that no writer creates. **The PII posture half of stage 6 remains open**, and the survey settled what the decision actually is: not a handling policy applied later but what `ingest/` writes, because `event_id` is `sha256(projection)` and both tables carry append-only triggers, so redaction in place is refused by the schema and only whole-row deletion works. |
| 2026-10-15 | The PII posture is an **allow-list on what `ingest/` writes**, because redaction after the fact is structurally foreclosed | Stage 6's second half, and the question it answers is not "how do we handle personal data" but "what do we write", because the store makes those the same question. Measured before deciding: `UPDATE events` raises `IntegrityError: events is append-only`, `event_id` is a sha256 over the projection, and `DELETE` exists only as whole-row pruning — so there is no redaction pass to defer to, and a field written today is kept until its row is pruned. **Reproduced first:** a Defender for O365 record carrying a `Body` with an IBAN and an auth code reached `raw_excerpt` and survived `to_dict()` on all three entry paths, *even though* `EmailContext` has no body field and an AST test proves no parser in any domain reads one. Both controls were real; neither covered the excerpt, which was a verbatim copy of the decoded record (`json.dumps(payload)[:4096]`). **The fix is structural, not a deny-list:** `Signature` gains a required `fields` tuple of payload paths — one component per mapping level, so Zeek's literally-dotted `id.orig_h` is unambiguous — and the excerpt is re-serialized from those paths alone. Three rules make an over-broad declaration safe rather than merely discouraged: absent paths are omitted rather than nulled; a declared path landing on an object contributes its key *names* and never its values, so declaring a container by mistake degrades to shape; and every value, key name, container length and walk depth is bounded. A deny-list was rejected — `FORBIDDEN_CONTENT_FIELDS` enumerates six spellings of "body" and the seventh ships in a vendor's next release. **The unrecognized path was the decision that mattered:** filtering only claimed records would have left the likeliest route open, since the way a body actually reaches a store is a vendor renaming the key a signature recognizes, not a parser that reads one. An unclaimed record is therefore projected through the union of all ten declared lists — so a renamed Defender export still yields sender, recipient, subject, verdict and timestamp — with a note naming the withheld keys, which is also the diagnostic an operator needs to fix the signature. **Stated costs, measured not asserted:** five of fifteen fixtures lose a top-level field (`zeek` `duration`/`orig_bytes`/`qtype_name`/`rcode_name`, `suricata` `proto`, `cloudtrail` `eventVersion`; auditd's `a0`/`a1`/`a2` drop from the excerpt but the reassembled argv is retained in `Actor.command_line`). Those are fields no parser models, and the remedy is to model them, which the allow-list now makes visible instead of leaving as an invisible accident. An unclaimed JSON record no longer feeds its raw text to the legacy keyword classifier through `message`; its indicators survive, because an unclaimed record is still *scanned* in full for URLs, hashes and addresses — typed, bounded fields with their own join deny-list — and only its modelled paths are *retained*. Free-form syslog prose is unchanged: there is no structure there to project. **Two existing tests got stronger rather than being left alone:** `test_serialization_is_an_allow_list_projection` excluded `raw_excerpt` from its own claim by name, and `test_json_string_and_mapping_inputs_agree` neutralized the field because the mapping path re-serialized while the JSON-text path copied, so one record produced two excerpts; both exclusions are gone. Twelve plants were run against the new tests and two escaped — a depth guard that only mattered past CPython's recursion limit, and a second guard on the walk rather than the leaf — so both tests were retargeted at the mechanism until the plants failed. The charter is amended (§5, "What is retained") rather than left claiming `data/` holds no personal identifiers, which a platform that ingests sign-in and mail telemetry cannot honestly claim. |
| 2026-10-15 | `message` is bounded on the **write** side beside the read-side validation it mirrors — the #206 defect had a sibling on every recognized record | Found while writing a bound for the withheld-keys note, by asking what else was assembled from several bounded parts and never re-bounded. Every individual field a parser writes passes `text()` at `MAX_FIELD_LEN`. **`message` is not a field** — it is `" ".join(...)` over several of them — and `from_dict` validates it at `MAX_FIELD_LEN` like any other, so `append` accepted an over-long summary and every later `query` raised `MalformedProjectionError` for the whole result set. `run_cycle` does not catch it: **one record stopped every subsequent detection cycle on that store, permanently.** The reproducing record is not hostile in shape — an encoded-PowerShell process creation, the most common malicious artifact in endpoint telemetry and the thing the Sysmon parser exists to capture, whose command line alone produced a 2168-character message. Measured end to end (`append` returned an event id, `query` then raised); nine of the fifteen ingest fixtures reproduce it under `MAX_FIELD_LEN`-length values, across eight of the ten vendors. **This is the same defect `#206` fixed**, and the reason it survived is instructive: that fix bounded `message` in `_unrecognized` and its tests covered only the unrecognized path, so the structured path — every recognized record, which is to say the whole product — kept the bug with a green suite. The remedy is placement, not another truncation: `NormalizedEvent.bounded()` applies every read-time bound and sits directly beside `from_dict`, which asserts them, on the argument the store layer already made for `to_dict`/`from_dict` — a bound asserted in one place and applied in another drifts, and when this one drifted the symptom was not a rejected record but a stored one that could never be read. `ingest.normalize` applies it to every parsed event, so a parser cannot forget it and a new parser inherits it. Truncation is **not** silent: `parse_status` is demoted and a note says the summary may be shorter than the source, because a cut summary can drop the only copy of a value that lives on no field (a CloudTrail `mfaAuthenticated`, a Defender `ThreatTypes`). `_unrecognized` deliberately keeps its own bounds and is not routed through the finalizer — there `message` is the carried evidence rather than an assembled summary, so its truncation is the documented normal case; the round-trip property is asserted on both paths regardless. The test that would have caught it builds a maximal event by reflection over the dataclass rather than from a hand-written field list, so adding a field to `NormalizedEvent` and forgetting to bound it fails without anyone editing the test; each of the thirteen fields was removed from `bounded()` in turn to confirm the test bites on every one. |
| 2026-10-15 | Backup/DR is a verified copy plus a runbook, and the store gains the completeness control it never had | Stage 9's first half, taken on the owner's direction to build the operational envelope, with backup/DR first. A survey of the repository established the premise by running it rather than reading it: **nothing backed up anything**, which `docs/PRODUCTION_SOC_PLAN.md` already said, and the exposure was sharper than the absence suggests. **A file copy is not a backup.** With a writer holding the store open, the main `.sqlite3` file held 4 KiB of a 548 KiB database and the rest sat in the `-wal`; a copy of that file alone passes `PRAGMA integrity_check`, opens through `EventStore.open()` without raising, and reports a plausible 353 of 400 events — the loss is invisible. So the CLI uses SQLite's online backup API (stdlib, correct under concurrent writes, no new dependency) and **attests the copy it made rather than the source it read**, because attesting the source describes a database that has since moved on. A completeness control had to be added to do that: deleting 100 of 400 rows leaves `integrity_check`, `count()`, `query()` and `high_water_mark()` all silent, since content addressing proves each row is what was written and nothing about whether all of them are there. `EventStore.attest()` digests every `event_id` in sorted order with the row count in the preimage, streamed so a 15-million-row store costs no memory; it is explicitly **not** a tamper control (anyone who can rewrite rows can recompute a digest) — the append-only triggers and the hash chains are that, and this catches *loss*. **The decisive finding was an asymmetry, and it is why positions are excluded by construction.** Of the four store/position skew directions, exactly one is unrecoverable: offsets newer than the store, where the collector reports `events_stored: 0, lines_read: 0, offsets_advancing: true` and exits 0 while every unread line still sits in the source, and offsets are never rewound. A cursor is safe in either direction (`next_stamp` reads the current clock, so re-collected events land above a stale one) and discarding both positions is a **complete** recovery, measured at 600 of 600 events with zero duplication — so a backup that cannot restore a position cannot restore a bad one, and the recovery procedure needs no new code at all. That made the runbook the deliverable the mechanism exists to serve, which is why `docs/RESTORE.md` leads with the ordering rule rather than the command. Gated `read_only`: nothing existing is changed, no network is reached, and a destination outside the lab root is refused — an off-node copy would be §5.1's external-network gate, which egress has twice been refused, and that is an operator's decision rather than something the platform reaches for. The backup's own integrity is anchored by putting the manifest's sha256 into the hash-chained audit record, reusing the tamper evidence that already exists instead of adding a second signing path. Residuals are named in the runbook rather than left implicit: an unsigned chain cannot detect end truncation and `AUDIT_HMAC_KEY` ships blank; `data/` itself is created at the process umask (measured 0o755) and the CLI warns rather than silently chmod'ing a directory it does not own; nothing prunes old backups, because that is a `destructive` decision in the shape retention already established. The drill test destroys the whole lab root and recovers it, from a deliberately **stale** backup, because a backup current at the moment of loss is the easy case and not the one an operator gets. Five plants were run against it — a file copy instead of the online API, a verifier that stops comparing the attestation, a dropped narrowing sweep, an empty backup instead of an error, and positions included after all — and all five are caught. |

> Append new architectural decisions here (date, decision, rationale) so the history stays
> auditable.
