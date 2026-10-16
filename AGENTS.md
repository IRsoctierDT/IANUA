# AGENTS.md — IANUA

> **Platform-neutral agent operating charter.** This file is the single source of truth for
> any autonomous or semi-autonomous coding agent operating in this repository — Codex,
> Claude Code, Cursor, Aider, or a custom orchestrator. Where a platform looks for a
> differently named file (e.g. `CLAUDE.md`), symlink or copy this file so the rules stay
> identical across agents.
>
> | | |
> |---|---|
> | **Document** | Agent Operating Charter |
> | **Status** | Authoritative — supersedes ad-hoc instructions |
> | **Owner** | Repository maintainer (human) |
> | **Companion docs** | [`DESIGN.md`](./DESIGN.md), `SECURITY.md`, `CONTRIBUTING.md` |
> | **Review cadence** | Re-read on every session start; revise on architecture change |

---

## 1. Repository Mission

This repository is the **IANUA**: a portfolio-grade environment
for **AI operations, cybersecurity automation, retrieval-augmented generation (RAG)
systems, and agentic workflows**.

It exists to demonstrate, and to operate, production-quality engineering across four
domains:

1. **Defensive security automation** — detection engineering, log enrichment, alert
   triage, and lab-scoped tooling that improves a defender's posture.
2. **AI/agent infrastructure** — local-LLM serving, MCP servers, RAG pipelines, and
   orchestrated multi-agent workflows.
3. **Secure-by-default systems engineering** — every component ships with least privilege,
   auditability, and defense in depth as first-class requirements, not afterthoughts.
4. **Professional, reviewable artifacts** — code, tests, and documentation suitable for a
   portfolio, a client engagement, an investor, a grantor, or a regulator.

Every change an agent makes must serve this mission **and** leave the repository in a state
that a senior security engineer would sign off on.

---

## 2. Mandatory Pre-Flight (read before touching anything)

Before modifying **any** code or documentation, an agent **must** complete this sequence and
state, in its working notes, that it has done so:

1. **Inspect repository structure** — enumerate the tree, identify the affected module(s),
   and confirm the change belongs where you intend to put it (see §4).
2. **Read [`DESIGN.md`](./DESIGN.md)** — understand the intended architecture, data flows,
   and the trust boundaries you may be crossing.
3. **Read this file (`AGENTS.md`) in full** — the rules below are binding.
4. **Read the nearest local context** — any `README.md`, module docstring, or `AGENTS.md`
   override in the subdirectory you are editing. **Deeper files win** on conflicts.
5. **Preserve existing naming conventions** — match file, module, function, and variable
   naming already present. Do not introduce a competing style.
6. **Keep security controls visible** — never remove, weaken, comment out, or bypass an
   existing control (auth check, validation, sandbox, rate limit, audit log) to make a test
   pass or a feature work. If a control is genuinely wrong, fix it openly and flag it.
7. **Confirm scope** — if the requested change is ambiguous, exceeds the stated task, or
   would touch a security boundary (§5), **stop and ask the human** before proceeding.

> **Fail-closed rule:** if any pre-flight step cannot be completed (missing `DESIGN.md`,
> unreadable module, unclear ownership), **do not guess** — halt and report.

---

## 3. Operating Principles (how every decision is weighed)

When more than one valid implementation exists, prefer them in this order, and make the
trade-off explicit in your summary:

1. **Most secure** — least privilege, smallest attack surface, fail-closed.
2. **Most scalable / maintainable** — clear interfaces, testable units, low coupling.
3. **Most cost-effective** — open-source and local-first where practical.

Cross-cutting principles that apply to **every** change:

- **Least privilege** — request the minimum scope, the minimum filesystem reach, the
  minimum network access. Default deny.
- **Defense in depth** — never rely on a single control; layer validation, authz, sandbox,
  and monitoring.
- **Secure defaults** — the safe configuration must be the one you get with no flags set.
- **Auditability** — security-relevant actions emit structured, tamper-evident logs.
- **Determinism & idempotence** — re-running a task must not corrupt state.
- **Human-in-the-loop for irreversibility** — see §5 approval gates.
- **Long-term maintainability over short-term convenience** — no clever hacks that the next
  engineer (or agent) cannot safely modify.

---

## 4. Repository Structure & Conventions

The repository follows a predictable layout so that both humans and agents can locate
responsibility quickly. Treat this as the canonical map; `DESIGN.md` holds the detailed
rationale.

```
ianua/
├── AGENTS.md                  # This charter (source of truth for agents)
├── CLAUDE.md                  # Symlink to AGENTS.md for Claude-based agents
├── DESIGN.md                  # Architecture, data flows, trust boundaries, decisions
├── SECURITY.md                # Vulnerability reporting & security policy
├── CONTRIBUTING.md            # Human + agent contribution workflow
├── README.md                  # Project overview & quickstart
├── pyproject.toml             # Version source of truth + ruff/mypy/pytest/bandit config
├── uv.lock                    # Dependency source of truth (locks/SBOM derive from it)
├── .pre-commit-config.yaml    # Local quality gates (mirror of CI)
├── .env.example               # Documented config keys — NEVER real secrets
├── .devcontainer/             # One-click Codespaces test environment (dashboard)
├── .github/                   # CI pipeline, drift gates, Pages deploy (human-gated)
├── agents/                    # Agent implementations, orchestration, versioning
│   ├── roles/                 # Role specs (planner, builder, reviewer, security)
│   ├── tools/                 # Tool adapters; each validates its own input
│   ├── policies/              # Policy engine, audit chain, signing, approval logic
│   ├── mapping/               # Event→technique engine + committed ruleset
│   └── response/              # Draft containment plans (plan-only; no executor)
├── attack/                    # Pinned local MITRE ATT&CK corpus (committed shards + signed pin)
│   ├── data/                  # Distilled technique/detection/relationship shards (drift-gated)
│   └── pins/                  # Version pin manifest (sha256 per shard; Ed25519-signable)
├── compliance/                # Control registry, framework mappings, evidence engine
├── intel/                     # Local threat-intel library (first-party behavioral + synthetic seed)
├── ingest/                    # Multi-source telemetry normalization (XDR front door)
│   └── parsers/               # One module per domain: endpoint, network, cloud, identity, email
├── store/                     # Durable append-only event store (SOC memory; stdlib sqlite3)
├── correlation/               # Entity resolution across domains + incident assembly
├── pipeline/                  # Scheduled detection cycle (at-least-once, resumable cursor)
├── sli/                       # Service-level indicators for the platform itself (fail-closed)
├── collect/                   # Local log collection (declared sources; reaches outside the project)
├── scripts/                   # Operational & maintenance CLIs (verify, SBOM, status page)
├── rag/                       # Ingestion, chunking, embedding, retrieval, citations
├── mcp/                       # MCP server + sandboxed tool execution
├── dashboard/                 # Streamlit command center (SOC, batch, KB, health)
├── detections/                # Detection-engineering content (lab-scoped only)
├── knowledge-base/            # Local retrieval corpus (NIST/MITRE/OWASP notes)
├── security/sbom/             # CycloneDX SBOMs + exported dependency locks
├── infra/                     # Container/compose manifests for the local lab stack
├── docs/                      # Runbooks, changelog, engineering log, status page, case studies
├── portfolio/                 # Portfolio-facing overviews and roadmaps
├── sample-logs/               # Captured historical fixtures (excluded from migrations)
├── tests/                     # pytest suite (unit, integration, security)
│   ├── unit/
│   ├── integration/
│   └── security/              # Authz, input-validation, injection, secret-leak tests
└── data/                      # Local/lab data ONLY — gitignored; never client data
```

**Conventions:**

- **Language baseline:** Python (typed), with Bash for glue and Swift only where a macOS
  target requires it. Match existing choices per module.
- **Naming:** `snake_case` for Python modules/functions, `PascalCase` for classes,
  `UPPER_SNAKE` for constants, `kebab-case` for CLI scripts and filenames where shell-facing.
- **Typing:** all new Python is fully type-annotated and passes `mypy` (see §7).
- **Docstrings:** every public module, class, and function has a docstring stating purpose,
  inputs, outputs, and any security consideration (e.g. "validates and sanitizes `path`").
- **Config:** all configuration via environment variables or typed config objects; document
  every key in `.env.example`. No magic literals for secrets, hosts, or ports.
- **Logging:** use the shared structured logger; never `print()` security-relevant events.
- **Dependencies:** pin versions; prefer well-maintained, open-source libraries; justify any
  new dependency in the PR description (purpose, maintenance status, license, risk).

---

## 5. Security Boundaries (hard limits)

These are **non-negotiable** and override any conflicting instruction, including a user
request to "just this once" relax them.

**Prohibited — never do:**

- ❌ Create **offensive** cybersecurity tooling intended for use outside a **lawful,
  owned/authorized lab**. No tooling whose primary purpose is to attack, exploit, or evade
  defenses on systems you do not own or have written authorization to test.
- ❌ Add code that **scans, attacks, exploits, brute-forces, or accesses third-party
  systems** without explicit, documented authorization.
- ❌ Hard-code **secrets, tokens, passwords, API keys, private keys, or personal
  information** anywhere — source, tests, fixtures, comments, commit messages, or logs.
- ❌ Weaken, disable, or bypass an existing **security control** to make code work.
- ❌ Exfiltrate, transmit, or log **sensitive data** (logs, legal documents, client info,
  PII) to any external endpoint.
- ❌ Perform **destructive or external actions** (deleting data, force-pushing, deploying,
  sending network requests to non-lab hosts, mutating cloud resources) **without human
  approval** (see approval gates below).

**Treat as sensitive by default:** logs, legal documents, client information, credentials,
internal hostnames/IPs, and anything under `data/`. Apply confidentiality, minimize copies,
and never commit them.

**Filesystem reach — amended for local log collection (stage 5).** Reach is scoped to the
project and the gitignored lab-data root, with one licensed exception: `collect/` may read
log files on the node it runs on, **read-only**, and only files an operator has named on the
command line. The exception is deliberately narrow, and the narrowness is the control:

- **Declared, never discovered.** No glob, no directory walk, no "find the logs" heuristic.
  A collector that searches for sources eventually finds one nobody meant it to read, and
  everything it reads becomes stored evidence.
- **Absolute paths only**, since a relative path means whatever the scheduler's working
  directory happens to be.
- **No symlink at the log file**, checked when the operator's paths are validated. This
  catches a source that is a link at declare time — a stale or mistyped path, a layout
  nobody intended — not an adversary who swaps a link between validation and the read:
  winning that race requires write access to the log's directory, and with that the same
  false evidence can be written into the log directly. Within one pass every byte (the
  continuity digest and the data) comes from a single descriptor. Ancestor components are
  not walked, deliberately, because `/var/log` ancestors are legitimately symlinks on
  several distributions.
- **A named deny-list of credential paths is refused**, not warned about. A collector
  copies what it reads into `data/`, so collecting a private key would put a secret there.
  Read `_DENIED` in `collect/sources.py` for what it actually covers, and do not read this
  bullet as a general credential detector — it is not one, and the code's own comment says
  why ("a broader list would start refusing real logs, and a collector that refuses real
  logs gets switched off"). Measured through `collect.declare`: `id_rsa`, `id_ed25519`,
  `server.key` and `.env` are refused; `credentials.json`, `secrets.yaml` and
  `api_token.txt` are **accepted**. An earlier version of this bullet said
  "credential-shaped paths are refused", which an operator could reasonably read as a
  guarantee the list does not provide. The control that actually bounds this is the
  declared-paths rule above — a human types every source — and this list catches the
  common mistakes, not an adversary and not every spelling.
- **Read-only, always.** Sources are opened `"rb"`; a security test asserts no write mode
  reaches a source path. A collector that could modify the logs it reads could destroy the
  evidence it exists to preserve.
- **No subprocess**, which is why `journald` is out of scope: reading it means running
  `journalctl`.

This amendment covers **inbound reads of this node's own files only**. It does not license
outbound network egress and it does not license an inbound listener. Both are licensed
separately and much more narrowly by the stage 7 amendment below, which supersedes this
sentence and nothing else in this bullet list. See `DESIGN.md` §5 boundary 14 and
boundary 15.

**The network — amended for the active/passive peer channel (stage 7).** The owner approved
an inbound listener and egress to a declared peer. Both were previously refused, and the
refusals are not being waved away: this amendment is narrower than either thing it permits,
and the narrowness is again the control.

**What the prior refusals actually said, because the answer has to meet it.** Egress was
refused twice — the ATT&CK bundle and the threat-intel feed — on the ground that
`guarded.enforce()` cannot express *per-invocation* human approval, so the only ways to make
a fetch pass were an allow-list label or `report_only`, both permanent and unscoped. That
objection stands and is not answered by an approval. It is answered the way
`run_retention.py --apply` answered the same shape: a **standing grant for one named label
in a committed, reviewable file**, scoped to this one action, which a reviewer can see in a
diff. Paired with a committed host allow-list that is **empty by default and therefore
denies**, the grant names the action and the allow-list names the destination, and neither
alone is sufficient. The listener was refused for a different reason — that it "adds an
**unauthenticated** network surface" — and that word is the whole of it: the surface
licensed here authenticates every request before it does anything.

- **Read-only, and health/state only.** The listener serves a projection of state the node
  has already computed: the `attest()` digest, the event count, the high-water mark, each
  chain's verdict, and when the last backup and last promotion verification ran. It accepts
  **no** mutation, **no** file upload, and **no** command.

  **No *application or store* mutation — and audit writes are required, not merely
  permitted.** The first version of this bullet forbade any "code path from a request to a
  write" at all, and review was right that the absolute conflicts with §3's auditability
  principle: a failed HMAC verification *is* a security-relevant action, so a listener that
  cannot record one lets an attacker probe it indefinitely and invisibly. The narrow rule is
  that a request may reach **the audit chain and nothing else** — never the event store,
  never a position file, never any other file. Both outcomes are recorded: an accepted
  request and a rejected one, since only the rejections reveal probing.

  **Bounded on *both* outcomes, because an audit write per request is a denial-of-service
  amplifier.** `AuditLogger.record` is a lock-serialised append to a hash chain, so a flood
  would otherwise convert cheap requests into contended disk writes on the active node — and
  #53 exists because that chain is fragile under concurrency. Accepted and rejected requests
  are therefore both aggregated or rate-limited rather than written one-for-one, and the
  implementation PR owes a measured figure for the bound rather than a claim that one exists.
  A security test asserts the store and the positions are unreachable from a request, rather
  than a docstring claiming it.

  The first version of this paragraph bounded **rejections only**, and review was right that
  this leaves the amplifier open on the path that is not bounded. Three ways in, and the
  third needs no key at all: an authorized passive node polling faster than its schedule; a
  compromised one, which holds the key and can poll without limit; and a **replayed** valid
  request, which has a valid MAC and so takes the *accepted* path. An on-path attacker who
  captures one valid request can therefore flood the active node's audit chain without ever
  knowing the key.

  **Request freshness is therefore server-enforced, not merely echoed.** The nonce above was
  specified as binding the *response*, which does nothing for the request: the listener must
  **reject** a nonce it has seen, or one outside a bounded freshness window, before the
  request reaches the audit chain at all. That is the third time on this amendment that the
  first draft protected the direction that does not matter — request MAC without response
  MAC, and now response freshness without request freshness — and it is recorded as a
  pattern because the next reviewer should expect to find a fourth.
- **A versioned, committed allow-list of named fields — not a category.** The first
  version of this bullet licensed "aggregates and digests", and review was right that a
  *category* is the wrong enforcement point: it would make a digest of a low-entropy
  observable look licensed when it is dictionary-testable, and a per-identity count look
  licensed when a small domain discloses the identity. A category cannot distinguish those
  from a row count, so the rule is an allow-list of **exact fields, committed and
  versioned**, and any field not on it requires another boundary review rather than an
  argument that it belongs to a permitted kind.

  Licensed by name, each with the reason it is safe: the `attest()` digest **as a
  comparison and not as a value, and only above a declared cardinality floor** (see
  below); the total event count; the ingestion high-water mark; each chain's
  present/intact/entry-count verdict; and the timestamps of the last backup and last
  promotion verification. **Explicitly not licensed**, and named because they are the
  plausible next additions: a digest or count scoped to any subset an adversary can choose
  or guess, anything per-identity, per-host or per-source, and any field derived from a
  single event. The distinction is entropy, not aggregation — "it's only a hash" and "it's
  only a count" are both how this erodes.

  **The digest's safety was asserted and is now a condition, because at low cardinality it
  is a presence oracle.** The first version of this bullet licensed it on the grounds that
  it is "a fingerprint of the whole, not of any member, and the set is large" — and review
  was right that the parenthesis is not guaranteed by anything. `event_id` is a sha256 over
  the canonical projection with **no store-injected entropy** (`ingested_at` is a separate
  column), `DIGEST_PREFIX` is a public constant, and `attest()` hashes the count followed by
  the sorted ids. So the whole preimage is known except the ids themselves.

  Measured, through the shipped code, with the attacker computing the id offline from a raw
  log line and no access to the store: **at `count == 1` a guess alone reproduces the served
  digest exactly** (a wrong guess does not, so the oracle discriminates), and at `count` of
  2, 5 and 40 a guess alone fails while a guess plus every *other* id succeeds. Two
  consequences, and the second is the sharper one:

  - The forging work is **multiplicative in cardinality** against an attacker who knows
    nothing else, which is why a floor helps at all.
  - It collapses to **one guess** for an attacker who already knows the other events. For a
    real store holding every source's telemetry that means they already hold the evidence,
    which is why the floor is still worth having — but it is a bound and not an
    elimination, and saying otherwise is how the first version of this bullet went wrong.

  It also **contradicted the not-licensed list three lines above it**: at `count == 1` the
  digest *is* "a field derived from a single event", which that list already forbids. The
  document disagreed with itself, and the mechanism followed the permissive half.

  So: the digest crosses as a **comparison**. The passive node puts its own locally computed
  digest in the (already authenticated) request and the active node answers match or differ,
  which discloses one bit instead of a preimage and removes the on-path offline oracle
  entirely at no operational cost — the passive already knows its own digest. And the
  comparison is **withheld below a declared minimum cardinality of at least 1000 events**,
  below which only the count crosses. That floor is deliberately generous: withholding costs
  almost nothing (a store that small is a freshly restored or near-empty node, where the
  count alone answers the operator's question) while being wrong costs a presence oracle, and
  an asymmetric cost is a reason to err high rather than to tune.

  **The residual, stated rather than implied.** Against an *authorized* peer — or anyone
  holding its key — the comparison is an **interactive** oracle: guess, send, read match.
  Rate-limiting bounds that and does not remove it, and nothing here defends against a
  compromised holder of the channel key, which is equally true of everything else the
  channel serves.

  This is §5's exfiltration prohibition applied to a socket. An event, a `raw_excerpt`, an
  observable, an indicator or an assembled incident is **evidence**, and evidence does not
  leave the node over this channel. The stage 6 amendment's reasoning carries over
  unchanged: what a parser modelled is what the store holds, and none of it is what this
  serves.
- **Authenticated in both directions, and the response is the direction that matters.**
  Every request carries an HMAC over its body, keyed from the environment and verified with
  `hmac.compare_digest`. **And so does every response**, bound to a fresh nonce the request
  supplies.

  The first version of this bullet authenticated the request only, and review found the
  hole: a request MAC proves the caller knew the key and says nothing about whether the
  *answer* is genuine. But the answer is the entire point of this channel — it is what
  informs a promotion decision. An on-path attacker who cannot forge a request can still
  forge "peer is dead", or alter the digest and chain verdicts the operator is reading, and
  either one corrupts exactly the decision the channel exists to support. Authenticating
  the request protected the direction that does not matter. The nonce is not decoration
  either: without it a captured valid response replays later, presenting an hour-old
  "healthy" as current, which is the same stale-truth failure an unsigned audit chain has.

  **No key configured means the listener refuses to start**, never that it serves openly —
  the same fail-closed shape as the rest of the platform, and the opposite of the default
  that made an unsigned audit chain verify as intact. The key is never committed, never
  logged and never in an error message, exactly as `AUDIT_HMAC_KEY` already is.
- **Bound to a declared address, never discovered — and the refusal is on the *parsed*
  value.** The operator names the interface and port on the command line; there is no
  default that listens everywhere. Any address that parses as **unspecified, in either
  family**, is refused outright rather than warned about, for the same reason `collect/`
  refuses a glob: a surface that binds to whatever it finds eventually binds to something
  nobody meant to expose.

  The first version of this bullet refused the literal string `0.0.0.0`, and review found
  the bypass. Measured with `ipaddress.ip_address(x).is_unspecified`, **six spellings are
  unspecified and a literal rule catches one of them**: `0.0.0.0`, `::`, `::0`,
  `0:0:0:0:0:0:0:0`, the fully expanded `0000:…:0000`, and the IPv4-mapped
  `::ffff:0.0.0.0`. `::` binds every IPv6 interface and, depending on `IPV6_V6ONLY`, accepts
  IPv4-mapped connections too — so the literal rule was satisfiable while exposing precisely
  the all-interface surface it existed to prevent. This is the defect class this repository
  keeps finding in its own controls: a rule written as a string that the thing it means to
  stop can simply spell differently.
- **The active node listens; the passive node reaches out.** So the node that will be
  *promoted* — the one whose integrity matters most at the moment it matters — has no
  inbound surface at all. Egress is therefore from the passive node only, to a single host
  that appears in its committed allow-list.
- **Still no automatic promotion, and this changes nothing about the fence.** The channel
  tells an operator what the other node holds. It cannot promote, and the puller cannot
  promote. Promotion stays procedural because nothing here can verify that the former
  active's timers were stopped, which `DESIGN.md`'s active/passive row establishes and
  `scripts/run_backup.py --verify-restore` says on every success. A health response that
  reads "peer is dead" is an input to a human decision, never a trigger.
- **No subprocess, no shell, and stdlib only.** `http.server`, `ssl`, `hmac`, `hashlib`,
  `socket` — `dependencies = []` stands, and **five** security test files assert it — `test_collect_hardening.py`, `test_correlation_hardening.py`, `test_ingest_hardening.py`, `test_pipeline_hardening.py`, `test_store_hardening.py`, each asserting `config["project"]["dependencies"] == []`. An earlier version of this bullet said six; the number is named here so it is checkable rather than asserted. A consensus
  system would have been the one candidate needing a package, and it is not what was
  approved.

**What this still does not license**, stated because an amendment is read by whoever wants
the next thing: shipping the store over this channel (an operator's existing transport moves
the file, which `DESIGN.md`'s active/passive row already decided); any egress to a host not
in the committed allow-list; any third-party fetch, which the two prior refusals still
govern; automatic failover; and a listener on the passive node.

**What is retained — amended for real telemetry (stage 6).** Real logs describe people:
a sign-in record *is* a username, a mail record *is* two addresses, a process record *is*
whoever was at the keyboard. A platform that ingests them and claims to hold no personal
identifiers would be claiming not to work. So the posture is not "no personal data under
`data/`" — it is **retain only what a parser modelled**, and say plainly what that means:

- **The excerpt is rebuilt, never copied.** Each signature in `ingest/parsers/` declares
  the payload paths it reads, and `raw_excerpt` is re-serialized from those paths alone
  (`ingest/_coerce.py::project`). **For any record that decodes to a mapping**, a field
  no parser models — a mail `Body`, a column a vendor added last week, a key an attacker
  chose — has no route into a stored event. That qualifier is load-bearing and was missing
  from the first version of this amendment: see the residual below, which is wider than
  that version said. A declared path that lands on an object contributes its key *names*
  and not its values, so an over-broad declaration degrades to shape rather than to
  content — for an object. A declared path landing on a *list* contributes its values, up
  to the entry bound.
- **Because redaction is not available.** The store refuses `UPDATE` and `event_id` is a
  sha256 over the projection, so a stored event cannot be edited — only the whole row can
  be pruned. That is deliberate (evidence integrity), and its consequence is that
  *what `ingest/` writes is the whole of the retention posture*. There is no later
  redaction pass to rely on, and no agent should write code that assumes one.
- **An unclaimed record is projected, not quoted.** A record no signature claims is
  rebuilt from the union of every parser's declared paths, with a note naming the keys
  whose values were withheld. Recognition breaking upstream is the likeliest route by
  which a body would otherwise reach an append-only store, so this path carries the same
  rule as the recognized one rather than falling back to the raw text. **Anything that
  never decoded into a mapping is still carried verbatim**, and that is not only prose:
  measured on merged code, a JSON record with a trailing comma, a JSON *array* rather
  than an object, and a record over the `MAX_RAW_BYTES` ceiling each carried an
  un-modelled mail body into both `message` and `raw_excerpt`. A log line truncated
  mid-write by rotation is a realistic instance, not a contrived one. There is no mapping
  to project in those cases and dropping the text would manufacture the blind spot rule 2
  exists to close, so the behaviour stands — but it is a residual of the control, not an
  exception for prose, and the earlier wording here understated it.
- **Indicators come from modelled content wherever a mapping was decoded**, and this
  replaces an earlier rule that said the opposite. An earlier version of this bullet said
  "on every path", and an audit measured that false: where nothing decodes to a mapping —
  the three regimes the residual above names, and bare non-JSON prose — the retained
  evidence *is* the verbatim record, extraction reads the retained evidence, and so the
  charter's own worked example below is extracted in full. Measured on merged code, all
  four regimes yield all five of its names. That is a consequence of the residual above
  and not a second defect (retaining the text while refusing to scan it would be the
  inconsistent posture), but the word "every" was wrong, and the security test that
  pinned the rule was named for the wrong scope while exercising only the two mapping
  paths. Both are corrected, and
  `test_prose_indicators_survive_where_no_mapping_was_decoded` in
  `tests/security/test_ingest_hardening.py` now pins the residual across all four
  regimes, so changing it is deliberate. **Whether that residual should be closed is an open decision for the
  owner**, and closing it means accepting a further detection cost on records that never
  parsed. An unclaimed record used to be *scanned* in full
  for indicators while only its modelled paths were retained, on the reasoning that "the
  indicator survives the narrowing; the sentence around it does not". **The sentence
  survived too.** `_DOMAIN` matches any `word.Word` with no plausibility check, so an
  un-modelled `Body` reading "Dear Mr.Jones, please urgently.Reply … invoice 44.Smith at
  acct-7781.Watson" produced a `raw_excerpt` of `{}` — the withholding worked — and five
  observables: `Mr.Jones`, `urgently.Reply`, `44.Smith`, `acct-7781.Watson`,
  `Ms.Delacroix`. Personal names, in a table that is indexed, append-only and clearable
  only by deleting whole rows, and false correlation join keys besides. Measured on merged
  code, not argued.

  Extraction now reads the *retained* evidence, so there is no wider string to read and the
  separate one that existed for it is gone. **The cost is real and is the trade:** an
  indicator appearing only in an un-modelled field is no longer extracted, which is exactly
  the route the previous rule cared about — a vendor renaming the key a signature matches.
  What compensates is the withheld-key note, which names what was dropped so an operator
  can write the signature; what does not compensate is anything automatic. A
  plausible-TLD check was weighed and refused: a public-suffix list is a third-party
  dependency that goes stale, and a hand-kept allow-list would silently drop legitimate
  internal domains like `host.corp`. Indicators remain typed, bounded fields with their own
  join deny-list in `correlation/entities.py`, and the `MAX_FIELD_LEN` bound still applies —
  an indicator past character 2048 of one field is not extracted.
- **Volume is bounded by a gated pass, not by hope.** `scripts/run_retention.py` reports
  by default and deletes only under a committed `destructive` grant. Measured at roughly
  1.8 KB per event, a `*/5` schedule at the default batch size is ~15 GB/month, so a
  retention decision is an operational requirement and not a tidiness preference.

  **What "bounded" means, precisely, because a pass returns no disk.** `prune` is a
  `DELETE`, which moves pages onto SQLite's free list without truncating the file, and the
  store runs at `auto_vacuum=0` — measured on a store `EventStore.open` just created, and
  it is SQLite's *default*, not a pragma this repository sets: `auto_vacuum` appears
  nowhere in `store/`, so nothing pins it and a future migration could change it without
  touching this bullet. Measured through the shipped CLI with the grant: a
  20,889,600-byte store, `events_removed: 10200` of 12000, exit 0 — and the file was
  **20,889,600 bytes afterwards**, same inode, `page_count` unchanged, `freelist_count`
  0 → 4247. The report has no byte, size or disk field, so nothing in the output says so.
  What a pass buys is a **plateau**: freed pages are reused by later appends and the file
  grows only when they run out (measured — 15,000 further events moved it not one byte
  while the free list drained to 87), so the store settles at the largest live set it has
  ever held. That is a real bound and the sentence above stands, but it bounds the *live
  set*, not the filesystem. Returning bytes is a manual `VACUUM` which this repository does
  not ship — no `vacuum` in any tracked *code* file (`docs/RETENTION.md`, `docs/RESTORE.md`
  and this charter now document the procedure, so the `grep -rni vacuum .` an earlier
  version of this bullet offered as the check returns five files and not zero; scope it to
  code), `EventStore` exposes no vacuum method and its connection is private (`_conn`;
  measured, its public surface is append/append_many/attest/close/count/count_before/
  high_water_mark/next_stamp/open/path/prune/query/verify_integrity) — and which an
  operator runs themselves against the
  database (measured: -84.9% on a pruned store in 21.9 ms, inode, mode, `attest()` digest,
  `event_id`s, `meta`, indexes and both append-only triggers all preserved). An agent
  should not write code that *assumes* a pass reclaims disk, and should not read this
  bullet as a claim that it does; `docs/RETENTION.md` carries the procedure and its costs.
- **And a pass never deletes past the detection cycle, which is a second grant.** The
  threshold is clamped to the pipeline cursor, because the two used to be mutually
  invisible: measured, 40 events with only the oldest 5 processed and `--keep-days 3
  --apply` destroyed **24 events the cycle had never looked at**, exit 0. An absent cursor
  (step 3 of `docs/RESTORE.md` deletes one by design) and a cursor ahead of the newest
  stored event both clamp to *nothing*. The honest shape of the trade is that clamping
  does **not** bound the disk — measured over a 40-day stall, clamping and refusing grow
  the store at the same rate and only deleting unprocessed evidence holds it flat — so
  nothing bounds the disk during a detection stall except destroying evidence nobody has
  analysed. That cannot be engineered away; it is *authorized*, by
  `--include-unprocessed` under its own `retain_events:apply-unprocessed` grant, which
  `retain_events:apply` deliberately does not confer.
- **And it stops short of the cursor, because the cycle reads back into it.** The clamp
  above bounds a pass to *processed* events; the detection cycle's lookback exists to
  re-read *processed* events as correlation context. Those are the same rows. Measured
  with no concurrency, no unusual flag and no short window: a three-step story straddling
  the 90-day boundary, all three steps inside one default 900s lookback, was reported by
  the cycle at **score 52 over three domains** before the documented retention pass and
  **score 30 over two** after it. The damage is not an error an operator sees — what they
  read is still an incident, only smaller and quieter, which is indistinguishable from a
  quieter attack. A pass therefore leaves `--lookback-margin` seconds of processed history
  behind the cursor, defaulting to `pipeline.DEFAULT_LOOKBACK` (imported, not restated, so
  the two cannot drift apart). An operator who raises the pipeline's `--lookback` **must**
  raise this to match: the cycle's flag is not recorded anywhere this pass can read, so
  the mismatch is undetectable by design rather than by omission. The margin is 900
  seconds and not an amnesty — a 200-day-old event is still reclaimed — and
  `--include-unprocessed` bypasses it, since that flag is where an operator says they mean
  it.

  An agent should note what this is *instead of*: the hazard was first written down as a
  locking problem ("retention and the cycle hold different locks, so a prune can run
  mid-cycle") and that framing is **refuted by measurement**. Driving a prune
  deterministically between the cycle's two queries produced the same degraded score as
  running the passes strictly in sequence, so a lock would have serialised them and
  changed nothing. The margin makes the two passes touch disjoint row ranges, which is a
  stronger guarantee than mutual exclusion precisely because it does not depend on every
  future writer remembering to take a lock. Do not add one here on the theory that
  concurrent passes are the risk.

This amendment changes **nothing** about secrets: a credential, token, key or password is
never written to source, tests, fixtures, comments, commit messages, or logs, and
credential-shaped source paths are still refused outright by `collect/`.

**Lawful-lab scope:** security tooling in this repo is for **defensive purposes and
authorized lab exercises only**. Detection content, parsers, and analysis tooling are
welcome; weaponized exploit chains aimed at unowned targets are not. When in doubt about
whether something is offensive vs. defensive, **ask the human and document the
authorization basis**.

### 5.1 Approval Gates (human-in-the-loop)

An agent must **pause and obtain explicit human approval** before any action that is
irreversible, externally visible, or security-sensitive:

| Action class | Examples | Gate |
|---|---|---|
| **Destructive** | `rm -rf`, dropping tables, history rewrite, `git push --force` | Human approval, dry-run first |
| **External network** | requests to any non-lab host, publishing packages, webhooks | Human approval + URL shown in full |
| **Deployment / infra mutation** | applying IaC, restarting prod services, cloud changes | Human approval, plan/diff shown |
| **Dependency addition** | new third-party package | Justification in PR; human review |
| **Secret / credential handling** | reading/rotating keys, touching `.env` | Human performs; agent never stores |
| **Boundary-crossing** | anything touching §5 prohibitions | Stop; do not proceed |

When a gate is hit, the agent presents: *what* it intends to do, *why*, the *blast radius*,
and a *rollback plan* — then waits.

---

## 6. Agent Roles & Workflow

Work in this repository is organized around four cooperating roles. A single agent may play
several roles in sequence, but it must **announce which role it is in** and honor that
role's responsibilities.

| Role | Mandate | Must produce |
|---|---|---|
| **Planner** | Decompose the request; map it to modules; identify trust boundaries crossed; surface risks, assumptions, dependencies. | A short plan + task list before code. |
| **Builder** | Implement the smallest correct change; follow conventions (§4); keep controls visible (§5). | Working, typed, documented code. |
| **Reviewer** | Apply the review priorities (§6.1); run required checks (§7); reject anything that fails. | Pass/fail with specific findings. |
| **Security** | Independent pass focused only on the security boundaries (§5) and `tests/security`. | Sign-off or blocking findings. |

### 6.1 Review Priorities (in order)

When reviewing any change — your own or another agent's — evaluate in this order and stop to
fix before moving on:

1. **Security defects** — broken authz, injection, secret leakage, unsafe deserialization,
   SSRF, path traversal, weakened controls.
2. **Logic errors** — incorrect behavior, wrong results, race conditions.
3. **Unhandled edge cases** — empty/oversized/malformed inputs, partial failures, timeouts.
4. **Unsafe tool execution** — shell/exec with unsanitized input, unsandboxed agent tools,
   missing allow-lists.
5. **Poor input validation** — untyped boundaries, missing schema validation, trust of
   external/LLM-supplied data.
6. **Broken tests** — failing, flaky, skipped, or missing coverage for new logic.
7. **Incomplete documentation** — undocumented public surface, stale README/DESIGN.
8. **Violations of `DESIGN.md`** — architectural drift, boundary erosion, naming breakage.

### 6.2 Task Lifecycle & Definition of Done

`pending → in_progress → in_review → done` (or `blocked`).

A task is **done** only when **all** of the following hold:

- [ ] Change is scoped to the request; no unrelated edits.
- [ ] Existing security controls preserved or improved (none weakened).
- [ ] New/changed logic has tests, including a `tests/security` case where a boundary is
      involved.
- [ ] **All required checks (§7) pass locally.**
- [ ] Public surface is documented; `DESIGN.md` updated if architecture changed.
- [ ] No secrets, credentials, or client data added anywhere — and no personal identifier
      hard-coded into source, tests, or fixtures. Telemetry under `data/` describes people
      by its nature; the control there is what `ingest/` retains (§5, stage 6 amendment),
      not a claim that the data is anonymous.
- [ ] Summary states what changed, why, residual risks, and rollback.
- [ ] Any approval gate (§5.1) that was hit has a recorded human approval.

If a task cannot reach this bar, it stays `in_progress` or moves to `blocked` with a clear
note — **never** marked done.

### 6.3 Escalation

Escalate to the human (do not improvise) when: a security boundary is implicated; the plan
requires an approval gate; `DESIGN.md` is missing or contradicts the request; required
checks reveal a defect you cannot safely fix within scope; or the request itself appears to
ask for prohibited behavior.

---

## 7. Required Checks (quality gates)

Every change must pass the full gate **locally before review**, and again in CI. These are
the minimum bar — green is required, not optional.

```bash
# 1. Everything compiles
python -m compileall .

# 2. Full test suite (unit, integration, security) — CI adds an 85% coverage gate
python -m pytest

# 3. Lint & style (formatting is CI-enforced too: ruff format --check .)
ruff check .

# 4. Static type checking (full CI scope)
#    The interpreter flag is NOT decoration: mypy resolves imports against its
#    own interpreter, so a standalone install does not share one with the
#    project. Measured without it on a fresh container: 134 errors in 132
#    files, 132 of them a missing `pytest` stub. CI carries it too.
mypy --python-executable "$(command -v python)" agents attack intel ingest store correlation pipeline collect scripts tests dashboard mcp rag compliance sli

# 5. Security static analysis (SAST) — same config and scope as CI
bandit -c pyproject.toml -r agents attack intel ingest store correlation pipeline collect scripts mcp sli

# 6. Drift gates — derived artifacts must match their sources
python scripts/check_locks.py           # exported pip locks ↔ uv.lock
python scripts/build_status_page.py --check   # status page ↔ status.data.json
python scripts/build_trust_page.py --check    # trust page ↔ trust.data.json
python scripts/build_readme.py --check        # README generated sections ↔ their sources
python scripts/rename_to_ianua.py --check     # no legacy pre-IANUA identifiers
python scripts/build_attack_navigator.py --check  # Navigator layer ↔ Sigma corpus + attack/ pin
python scripts/update_attack.py --check       # ATT&CK shards ↔ signed pin; revocation invariants
python scripts/check_mapping_rules.py --check # mapping ruleset ↔ digest; techniques resolve in the pin
python scripts/check_intel_store.py --check   # intel library ↔ digest; licenses, TLP, anchors validate
python scripts/build_behavior_index.py --check # behavioral index ↔ corpus; anchors resolve active
```

### 7.1 Extended gate (run when the change warrants it)

```bash
# Auto-formatting (must produce no diff in CI)
ruff format --check .

# Coverage threshold — new logic must not lower it
python -m pytest --cov=agents --cov=scripts --cov-report=term-missing --cov-fail-under=85

# Dependency vulnerability scan (SCA)
pip-audit

# Secret scanning — fail the build on any detected credential.
#
# `detect-secrets-hook`, NOT `detect-secrets scan`. Measured: `scan --baseline`
# rescans and *rewrites* the tracked baseline in place — bumping
# `generated_at`, shifting line numbers, and silently absorbing any NEW finding
# as an accepted entry — and it exits 0 either way. So the command this block
# used to give could not fail the build on a detected credential, which is the
# one thing the line above claims it does, and it dirtied a tracked file as a
# side effect. `detect-secrets-hook` exits 1 on a secret not in the baseline
# and 0 when clean. It is also what `.pre-commit-config.yaml` already runs,
# so the charter was the only place disagreeing with the repo.
#
# It does NOT always leave the baseline alone, and an earlier version of this
# block claimed it did ("untouched in both cases, measured, both directions").
# Measured since, in a third case that version did not test: when an accepted
# finding's LINE NUMBER has shifted — any edit above it in the same file — the
# hook rewrites the baseline to refresh it, prints "The baseline file was
# updated. Probably to keep line numbers of secrets up-to-date. Please `git
# add .secrets.baseline`", and exits **3**. That is not a finding and not the
# `scan --baseline` hazard above: the entry count, the digests and the plugin
# set are unchanged (verify those three, then stage it). An earlier version of
# this block said the FILTER set was unchanged too, and that is false —
# measured on detect-secrets 1.5.0, the first such rewrite ADDS
# `detect_secrets.filters.common.is_baseline_file` pinned to
# `.secrets.baseline` and bumps `generated_at`. An agent told to verify an
# unchanged filter set would refuse to stage a legitimate rewrite. The
# difference that matters is that `scan` can absorb a NEW finding silently
# while this only ever moves a line number of one already reviewed.
#
# NUL-delimited, and that is not style. An unquoted `$(git ls-files)` here —
# which is what this block gave until measured — word-splits the 58 tracked
# paths that contain spaces under `sample-logs/github log debugging/`. One of
# them is `5_Run python -m build.txt`, so argparse receives a bare `-m` and
# the command dies with `error: unrecognized arguments: -m build.txt ...` at
# **exit 2, having scanned nothing**. A gate that cannot run cannot "fail the
# build on any detected credential", which is the one thing the line above
# claims it does, so the previous form was a second way of saying the same
# defect this block already records.
#
# The trailing `--` is the same defect's third route, and it is the worst of
# the three because it exits **0**. `xargs` appends the paths as plain
# arguments, so one tracked file whose name begins with a dash is read as a
# flag: measured in a throwaway repo holding one AWS-access-key-shaped
# literal and a file named `--help`, the form without a terminator printed
# usage and exited 0 with that key unscanned — a secret-scanning gate
# reporting green over a committed credential. With `--` the same repo names
# `AWS Access Key` at `planted.py:1` and exits **123** — not 1, which an
# earlier version of this block claimed: the hook exits 1 and `xargs` reports
# any child exit in 1..125 as its own 123. Check for non-zero, not for 1. (The literal itself is
# deliberately not reproduced here: this gate flags it, correctly, and §5
# forbids a key in a comment as much as in source.) A dash-led name is legal
# and `git add -- --help` commits it, so this is reachable from any pull
# request. Found by review, not by us.
git ls-files -z | xargs -0 detect-secrets-hook --baseline .secrets.baseline --
#
# If this prints "Your baseline file (.secrets.baseline) is unstaged", that is
# not a finding — the hook refuses to run against a baseline with uncommitted
# edits, so `git add .secrets.baseline` first. It is the state you are in
# immediately after accepting a finding below. It exits **1**, not 3 as an
# earlier version of this block said, which is the SAME code as a real
# finding: tell the two apart by the message, never by the exit code. The
# refusal fires only when the baseline is tracked and dirty — an untracked
# baseline, or a tracked clean one, does not trigger it.
#
# `gitleaks detect --no-banner` is NOT an equivalent — an earlier version of
# this block offered it as "or:", and the two demonstrably disagree. CI runs
# gitleaks; §7.1 runs detect-secrets. Measured on one tree: gitleaks green
# while detect-secrets was red on two findings that had been unbaselined since
# `2496c2e` (#217) — three merges with a §7.1 gate red and a green pipeline,
# because nothing in CI ran this one. Both now run in CI (`ci.yml` stage 2) and
# both are required; treat them as two gates that catch different things.
#
# To ACCEPT a new finding, updating the baseline is a deliberate, reviewable
# act: `detect-secrets scan --baseline .secrets.baseline`, then read the diff
# and commit it. Read **all** of that diff — the same `scan --baseline`
# rewrite-in-place described above will absorb anything else that has drifted
# in the same opaque write, so the review is the control, not the command.

# Optional: type-strictness on new modules
mypy --python-executable "$(command -v python)" --strict <changed_module>
```

> If a tool above is not yet wired into the repo, the **first** task is to add it to
> `pyproject.toml` / `.pre-commit-config.yaml` rather than skipping the check.

---

## 8. CI/CD & Branch Policy

Local checks (§7) are mirrored exactly in CI so that "passes on my machine" equals "passes
in the pipeline."

**Pipeline stages (fail-fast, ordered):**

1. **Setup** — pinned toolchain, cached deps, reproducible install.
2. **Static analysis** — `ruff check`, `ruff format --check`, `mypy` over the same
   fifteen packages §7 names (`agents attack intel ingest store correlation pipeline
   collect scripts tests dashboard mcp rag compliance sli`). §8 claims §7 is mirrored
   exactly, so this list is part of that claim: it had drifted to six of the fourteen,
   and `tests/unit/test_gate_scope_parity.py` now pins this prose as well as the §7
   block. Keep the two in step — the parity test is what caught `sli` missing here.
3. **Security** — `bandit` (SAST), `pip-audit` (SCA), **both** secret scanners
   (`detect-secrets` against the reviewed baseline, and `gitleaks`), CodeQL.
   The two are not interchangeable and both are required: measured on one tree,
   `gitleaks` was green while `detect-secrets` was red on two findings — which
   is how a red §7.1 gate sat behind a green pipeline for three merges while
   CI ran only `gitleaks`.
   Any finding above the agreed severity threshold **blocks merge**.
4. **Tests** — `pytest` on 3.11 and 3.12 with coverage gate (`--cov-fail-under=85`);
   `tests/security` must be green; sandbox enforcement runs in a Linux container.
5. **Drift gates** — derived artifacts are regenerated and diffed read-only, never
   auto-committed: SBOM + exported pip locks ↔ `uv.lock`; status page ↔ its source
   data; the IANUA-rename guard checks the ref under test.
6. **Build / package** — only on a fully green pipeline.
7. **Deploy (GitHub Pages)** — **human approval gate on the `github-pages`
   environment, kept by design**; deploys are never automatic, and the gate is
   never to be weakened or bypassed.
8. **Release** — after a `release: prepare` PR (built by `scripts/prepare_release.py`)
   merges and CI is green, `release-on-merge.yml` tags the CI-verified commit and
   dispatches `release.yml` — **only after human approval on the `release`
   environment**; tags are never moved. Runbook: `docs/RELEASING.md`.

**Branch protection (recommended):**

- No direct commits to `main`; changes land via reviewed pull request.
- Required status checks: all of stages 2–4 above.
- At least one human review on any change touching `agents/`, `mcp/`, `infra/`, or §5
  boundaries.
- Signed commits where supported; linear history; no force-push to protected branches.
- **Owner attribution (required):** every commit an agent makes is **authored as the
  owner** (`git config user.name/user.email` = `IDRozenblad <44316408+IRsoctierDT@users.noreply.github.com>`, GitHub's private noreply
  address, never a personal email), so the owner appears as the commit author on GitHub.
  The agent is credited only through its own `Co-Authored-By:` trailer.
- Secrets live only in the CI secret store — never in the repo, never echoed in logs.

**Pre-commit** (`.pre-commit-config.yaml`) runs the fast subset (ruff, mypy on changed
files, secret scan) so problems are caught before they reach CI.

---

## 9. Documentation Standards

Deliverables (runbooks, design notes, client/portfolio docs) follow a consistent,
review-ready structure:

**Executive Summary · Objectives · Architecture/Process · Implementation Steps · Risks ·
Cost Considerations · Future Enhancements**

For tool or component documentation, also state: **Purpose · Risk level · Skill level
required · Deployment complexity.** Use professional formatting suitable for client
delivery, distinguish **facts from assumptions**, and **cite authoritative sources** for any
legal, regulatory, compliance, or grant claim — never invent statutes, deadlines, or
requirements, and flag when professional legal/financial review is advisable.

---

## 10. Quick Reference Card

```
BEFORE YOU EDIT:   inspect tree → read DESIGN.md → read AGENTS.md → read local context
WHILE YOU EDIT:    least privilege · secure defaults · controls stay visible · types + docs
NEVER:             hard-code secrets · weaken controls · attack 3rd parties · exfiltrate data
ASK FIRST (gate):  destructive · external network · deploy · new dependency · secrets
BEFORE DONE:       compileall · pytest · ruff · mypy · bandit  (all green)
WHEN UNSURE:       stop and ask the human — fail closed, never guess
```

---

*This charter is intentionally strict. Its purpose is to make the safe path the default
path, so that every contribution — human or agent — leaves IANUA more secure, more maintainable, and more credible than it was before.*
