# Security Scanner Landscape 2026 — IANUA Feature Research

| | |
|---|---|
| **Date** | 2026-10-09 |
| **Author** | Ivan Rozenblad |
| **Status** | Research record: recommendations, not commitments |
| **Scope** | MCP / agent / skill scanners, red-team harnesses, runtime gateways, MCP spec 2026-07-28 |
| **Repos affected** | IANUA-Broker, agent-trust-broker (ATB), IANUA (this repo, feature F only) |

> **Evidence note.** Facts below are as gathered by the research council on 2026-10-09.
> Star counts are as rendered that day; vendor marketing figures are unrated. This record has
> not been re-verified since. Re-check any number before you quote it externally
> (AGENTS.md §9).

---

## 1. Executive Summary

Build two things, fuse one, integrate three, and publish honest numbers. The council
reached that verdict after a scout pass reported surveying 61 tools; §4 lists the
ones that drove the analysis. The Skeptic also broke the original
"nobody covers it all" thesis.

1. **The MCP/agent scanner market saturated in 2026.** Cisco (mcp-scanner, skill-scanner),
   NVIDIA (SkillSpector, 14.8k stars in two months), Snyk (ex-Invariant Agent Scan) and
   Tencent (AI-Infra-Guard) now cover description-poisoning detection, skill malware
   signatures and server-code SAST. A solo maintainer loses any head-on race there.
2. **IANUA-Broker's real moat is packaging and trust, not detection breadth.** It ships as
   one stdlib binary with zero egress, a signed posture baseline, SARIF to GitHub code
   scanning and a named-human risk ledger. The competitors with comparable coverage (Cisco,
   Snyk) all route through a cloud API or an LLM.
3. **Two whitespace areas survive adversarial review:**
   - No one ships an offline, deterministic toxic-flow analysis across servers. Snyk does
     it, but only behind `SNYK_TOKEN`.
   - No scanner checks a server against the MCP 2026-07-28 authorization MUSTs (RFC 9728
     PRM, RFC 8707 resource, audience validation, token-passthrough refusal). No scanner
     treats tool annotations as untrusted either.
4. **Tool-manifest pinning is no longer unique** (mcpseal, rugsnare, Trail of Bits). Fusing
   it into IANUA's existing signed baseline/diff is still a two-week feature worth building.
   It adds rug-pull regression classes and a `.mcp-lock.json` importer, and it reproduces
   the Cursor CVE-2025-54136 and postmark-mcp incidents in CI.
5. **Three traps to refuse:**
   - Building a detection benchmark. SkillTrustBench, MCPTox and MCPSecBench already exist,
     so run against them instead.
   - Importing Cedar/OPA into the Agent Trust Broker. ToolHive, AgentCore and agentgateway
     own that space, and an import would dilute ATB's fail-closed invariants.
   - Any LLM-judged detection. It breaks the offline/deterministic moat.

**Recommended order:** live-tool drift (B) → toxic flow (C) → ATB evidence export (E) →
spec conformance (A) → benchmark run (D). That is about 31 focused days, and each phase ends
in a publishable case study.

---

## 2. Method

Six agents ran in three adversarial rounds. Every fact traces to a page an agent actually
opened. Claims that failed verification were corrected or dropped.

| Round | Agent | Mandate | Output |
|---|---|---|---|
| 1 | Scout A | MCP server, tool-manifest and agent-skill scanners | 16 tools, 10 incidents/CVEs |
| 1 | Scout B | LLM/agent red-team scanners; OWASP LLM Top 10 2025 and Agentic Top 10 2026 coverage | 23 tools, 20-row standards map |
| 1 | Scout C | Runtime gateways, guardrails, agent identity; MCP spec 2026-07-28 | 22 products, spec and IETF digest |
| 2 | Skeptic | Re-open the 18 highest-stakes claims; attack the gap thesis; give verdicts on 8 candidate features | 16 corrections, 3 omissions found, 8 verdicts |
| 3 | Architect | Buildable designs for the surviving candidates, inside IANUA's stdlib/offline/fail-closed constraints | CLI, check ids, test rows, effort |
| 3 | Strategist | Weighted ranking and 90-day plan | Backlog, phases, open questions |

**Evidence standard:**
- GitHub star counts are as rendered on the day.
- Where GitHub omits a release year, the year is inferred and marked as inferred.
- Vendor marketing pages count as unrated.
- The IANUA repos were read live from GitHub (READMEs, roadmaps, open issues). The backlog
  therefore excludes anything that already ships or is fenced by an ADR.

---

## 3. IANUA Current State

Three public repos already cover static posture, runtime enforcement and SOC tooling. The
backlog only adds what they lack. Read live from GitHub on 2026-10-09.

| Repo | What ships today | Roadmap / fences that constrain new work |
|---|---|---|
| **IANUA-Broker** (`mcpscan`, v1.6, PyPI, Apache-2.0, stdlib + psutil) | Local MCP discovery with reachability tiers. Static audit of 7 host adapters (Claude, Cursor, Windsurf, Cline, VS Code, Zed, Continue) for plaintext secrets, auto-approval, over-broad scopes, unpinned packages, reused credentials and tool-poisoning signals. A–F scoring. Terminal/HTML/JSON/SARIF 2.1.0 output. `inventory`, `trust` (risk relationships), `graph` (cross-server attack paths), signed `baseline`/`diff` drift gate, `schedule`, `atlas` (ATT&CK, ATLAS, OWASP LLM, NIST AI RMF, CIS v8). Opt-in `--online` OSV, token-store and process-env inspection, `--inspect-broker`, `selftest`, signed data-pack, gated `lan` assessment. Adversarial test battery; 0 FP / 0 FN dogfood corpus | **Queue:** R-LIVE-TOOLS (P1, opt-in loopback `tools/list`), R-ATB-TIP-EXPORT (P0 follow). **Fenced:** merging scanner with ATB runtime (ADR-17), silent egress, auto-fix of credentials/pinning |
| **agent-trust-broker** (ATB, v0.2, stdlib only) | Closed-world scope catalog and least-privilege role bindings. Short-lived identities with depth-1 attenuating delegation and cascade revocation. Deterministic allow/deny/escalate decisions. Hash-chained JSONL audit with segment rotation and seals. Persistent escalation queue with one-shot triple-bound approvals. ATB-03 enforcement gateway (MCP stdio PEP). ATB-04 response screening with content-addressed quarantine and no off-switch. Conformance matrices T1–T12, E1–E6, S1–S19, L1–L25 | **P0:** durable revocation (R-ATB06-IDREV), seal key required in prod (R-ATB05-SEALDEF), key lifecycle (R-ATB06-M6). **Fenced:** ML screener, automatic rotation, Cedar-style policy import, `cryptography` dependency without an AGENTS.md §5.1 decision |
| **IANUA** (platform, this repo) | 12 defensive agents, pinned ATT&CK 19.x corpus, Sigma detection loop, local RAG, policy-gated MCP server, default-deny policy engine with hash-chained audit. The Streamlit dashboard's Scan Reports tab already imports IANUA-Broker JSON for before/after review | README states all agent blueprints are built; further work is enhancement |
| **IANUA-Marketplace** (private, created 2026-09-20) | Unknown | Open question (§10): its purpose changes the priority of skill/plugin checks |

**Design constraints every recommendation respects:**
- stdlib-first;
- offline and zero-egress by default, with disclosed opt-ins;
- deterministic over probabilistic;
- fail-closed;
- human approval for anything destructive;
- scanner and runtime stay in separate repos and talk only through versioned file contracts.

---

## 4. Landscape

The council's scouts reported 61 tools surveyed (16 + 23 + 22, §2). **This record does
not reproduce that full inventory**: the source output named only the tools below, so
treat §4 as the tools that drove the analysis, not the complete population.

- §4.1 lists the 16 entries the scouts grouped as scanners and adjacent analysis tools.
  Two are not live scanners and are rated accordingly: MCPSafetyScanner is a paper
  artifact, and Promptfoo ModelAudit scans model files only.
- §4.2 names red-team harnesses, runtime gateways and standards. These sit outside the
  capability matrix (§5).

Maturity is the Skeptic-corrected rating (1–5). Star counts are as rendered on
2026-10-09.

### 4.1 Static and live scanners (closest to IANUA-Broker)

| Tool | Maintainer | License | Scans | Strengths | Limits | Maturity |
|---|---|---|---|---|---|---|
| Cisco AI Defense MCP Scanner | Cisco | Apache-2.0 | Live tools/prompts/resources (remote or stdio); server source in 10 languages; pip-audit, VirusTotal, PyPI/npm in a sandbox | Broadest artifact coverage; YARA runs with no API key; Cisco AITech taxonomy | No SARIF, no baseline/diff; LLM analyzers need keys; ~1.1k stars | 4 |
| Cisco skill-scanner | Cisco | Apache-2.0 | Agent skills: YARA-X, AST taint, `.pyc` integrity, shell-pipeline taint; `.claude/commands/*.md` via `--lenient` | SARIF/HTML/JSON; 2.5k stars | Plugins, `.claude/agents`, hooks and MCP configs not covered | 4 |
| NVIDIA SkillSpector | NVIDIA | Apache-2.0 | Skills (dir, zip, git URL, `SKILL.md`); never executes | 69 patterns / 17 categories, Python AST taint, OSV lookup, SARIF 2.1.0, baseline fingerprints; 14.8k stars since the 2026-08-03 launch | Skills only; does not connect to MCP servers; optional LLM stage; unauthenticated MCP mode | 4 |
| Snyk Agent Scan (ex-Invariant mcp-scan) | Snyk | Apache-2.0 | Installed harnesses, MCP servers and skills across 13 clients | Toxic-flow lineage from Invariant; `--ci`, MDM mode; 3.1k stars | Requires `SNYK_TOKEN` and the hosted analysis API; rug-pull and cross-origin not named in v0.6 | 4 |
| Tencent AI-Infra-Guard | Tencent | Apache-2.0 | AI infra fingerprinting (146 components, 2000+ CVE rules); MCP and skill scan in 14 categories | 6.8k stars, v4.6.2 (2026-09-17) | Skill scan is LLM-based (`LLM_API_KEY`); no SARIF; web UI unauthenticated | 4 |
| Trail of Bits mcp-context-protector | Trail of Bits | Apache-2.0 | Runtime wrapper: TOFU pin of instructions, descriptions and schemas; blocks on drift; re-checks on `list_changed` | Best-documented rug-pull defense; ANSI sanitization; response quarantine | 226 stars, no releases, no report format | 3 |
| mcpseal | individual | MIT | `.mcp-lock.json` of name + description + inputSchema; proxy blocks on mismatch | Local-first; pins `sha256` over canonical `{name, description, inputSchema}` | 0.1.4 (2026-08-22); annotations and outputSchema not in the hash; stores last-approved description text in plaintext; 3 runtime deps (`canonicaljson`, `keyring`, `cryptography`) plus opt-in event upload to a control plane when logged in (corrected 2026-10-09, see §6.3); single maintainer | 2 |
| rugsnare | individual | Apache-2.0 | scan/diff baseline, exit 1 on drift, optional proxy | CI-ready | 3 stars | 1 |
| mcp-shield | individual | MIT | Client configs, plus connects to servers: hidden instructions, shadowing, cross-origin | `--identify-as` client-dependent behavior check | 15 commits, no releases | 2 |
| Lasso MCP Gateway `--scan` | Lasso | MIT | Reputation (Smithery/npm/GitHub) + description scan; auto-blocks under score 30 | Presidio PII masking | Cloud guardrails need an API key; 40 commits | 2 |
| claude-skill-antivirus | individual | MIT | Claude Code skills; 9 engines incl. SSRF, typosquat, sub-agent abuse | Scanned 71,577 SkillsMP skills (self-reported) | 78 stars; JSON output undocumented | 2 |
| clawscan | OpenClaw | MIT | Meta-harness running several skill scanners, plus a judge and benchmark compare | v0.2.0 (2026-09-22) | Harness, not a detector | 2 |
| MCPSafetyScanner | academic | MPL-2.0 | LLM multi-agent audit of a config | arXiv 2504.03767 | 2 commits; paper artifact | 1 |
| Promptfoo ModelAudit | Promptfoo | MIT | Model files (Pickle, SafeTensors, GGUF, ONNX and more) | SARIF, CycloneDX SBOM | Model files only | 4 |
| Palo Alto Prisma AIRS | Palo Alto | Commercial | Runtime API scan of tool definitions, inputs and outputs | Enterprise integration | No public benchmark or technical detail | 3 |
| Semgrep | Semgrep | — | No MCP ruleset found; cheatsheet and shadowing demo only | — | — | n/a |

### 4.2 Adjacent categories

- **Red-team harnesses with agentic/MCP targets.** These test a live app; they do no static
  scanning.
  - Promptfoo: 157 plugins, including `mcp`, `tool-discovery` and
    `agentic:memory-poisoning`, plus an OWASP agentic preset; 24.2k stars.
  - DeepTeam: per-ASI mapping.
  - garak and PyRIT: model-level only, with no tool targets.
  - Agentic Radar and Agent-Wiz: static framework-graph extraction.
  - Commercial: Cisco AI Defense, Mindgard, Lakera Red (Check Point), HiddenLayer, Straiker,
    Pillar, Repello, Adversa and SPLX (Zscaler). The counts on their pages are vendor
    figures and were left unrated.
- **Runtime gateways and policy points.** This is where static scanning ends.
  - ToolHive: Cedar, OIDC, OTel.
  - Docker MCP Gateway: signed catalog, per-profile tool enable.
  - agentgateway (Linux Foundation): CEL.
  - IBM ContextForge.
  - AWS Bedrock AgentCore Policy: Cedar/Dogwood on every tool call.
  - Google Model Armor: screens `tools/call`, not `tools/list`.
  - Microsoft Entra Agent ID / Agent 365.
  - Cloudflare MCP Server Portals.
  - NeMo Guardrails.
  - No longer available: Invariant's hosted Explorer shut down in January 2026 after the
    Snyk acquisition, and Protect AI's LLM Guard is archived.
- **Standards that define the target.**
  - MCP spec 2026-07-28 removed protocol sessions and deprecated Dynamic Client Registration
    in favor of Client ID Metadata Documents.
  - In its authorization section, the same spec made four things MUSTs: RFC 9728 PRM,
    RFC 8707 resource, audience validation and token-passthrough refusal.
  - In its tools section, tool annotations are "untrusted unless from trusted servers."
  - The OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10) was published on
    2025-12-09.
  - On 2026-09-15 the IETF WIMSE working group adopted `draft-ietf-wimse-aims-00` for agent
    identity.

---

## 5. Capability Matrix

IANUA-Broker already matches or beats the field on packaging (offline, SARIF, signed
baseline), and it is the only tool with cross-server attack paths. It is behind on live
tool-manifest inspection, skill content and server-source analysis.

**Legend:** Y = documented · P = partial or heuristic · — = absent · $ = needs a vendor
account or API key.

| Capability | IANUA-Broker | Cisco mcp-scanner | Cisco skill-scanner | SkillSpector | Snyk Agent Scan | AI-Infra-Guard | ToB context-protector | mcpseal |
|---|---|---|---|---|---|---|---|---|
| Tool-description poisoning / hidden instructions | P (config-level signals) | Y (YARA + LLM$) | Y (skills) | Y (skills) | Y$ | Y (LLM$) | P (response guard) | — |
| Live `tools/list` capture | — (roadmap R-LIVE-TOOLS) | Y (remote + stdio) | — | — | Y | Y | Y (proxy) | Y (proxy) |
| Rug-pull: manifest pin and drift over time | — | — | — | P (skill fingerprints) | — | — | Y (TOFU, blocks) | Y (lockfile) |
| Cross-server shadowing / cross-origin | — | P | — | — | Y$ (v0.5 labels) | P | — | — |
| Toxic flow / cross-server attack path | Y (graph, credential chaining) | — | — | — | Y$ (hosted) | — | — | — |
| Tool-level data flow (private read → public write) | — | — | — | — | Y$ | — | — | — |
| Excessive scope / auto-approve / dangerous tools | Y (7 host adapters, trust) | P | P (allowed-tools) | Y (least-privilege category) | Y$ | P | — | — |
| Plaintext secrets in configs / env / token stores | Y (+ process env, token stores) | — | Y (skills) | Y | Y$ | P | — | — |
| Unpinned packages / dependency CVEs | Y (OSV opt-in) | Y (pip-audit, VirusTotal) | — | Y (OSV) | Y$ | Y (2000+ rules) | — | — |
| Server source SAST | — | Y (10 languages) | n/a | n/a | P | P | — | — |
| Skill / plugin content (`SKILL.md`, scripts) | — | Y | Y | Y | Y$ | Y | — | — |
| `.claude/agents`, plugin manifests, hooks | — | — | P (`--lenient` commands) | — | — | — | — | — |
| **MCP 2026-07-28 auth conformance (PRM, audience, passthrough)** | — | — | — | — | — | — | — | — |
| **Tool annotations treated as untrusted** | — | — | — | — | — | — | — | — (not hashed) |
| Network exposure of local servers | Y (reachability tiers) | — | — | — | — | Y (fingerprinting) | — | — |
| AI asset inventory (model servers, vector DBs, gateways) | Y | — | — | — | P | Y | — | — |
| Framework mapping (ATT&CK, ATLAS, OWASP, NIST, CIS) | Y (OWASP LLM; no ASI yet) | Y (Cisco AITech) | — | P | — | — | — | — |
| SARIF 2.1.0 | Y | — | Y | Y | — | — | — | — |
| Signed posture baseline + drift gate + risk-acceptance ledger | Y | — | — | P | — | — | — | P |
| Runtime enforcement evidence consumed by the scanner | P (`--inspect-broker`) | — | — | — | — | — | — | — |
| Offline, zero egress, no account | Y | P (YARA only) | Y | Y (`--no-llm`) | — | — | Y | Y |
| Scanner-as-target adversarial test battery | Y | — | — | — | — | — | — | — |

**Sources:** each column's repository README (linked from §4), opened 2026-10-09.

**How to read the matrix:**
- The two all-dash rows (auth conformance, untrusted annotations) are the **whitespace**.
- In three rows IANUA alone is "—" while a free offline tool is "Y": live tools, manifest
  pinning and skill content. These are the **integration or fusion targets**.

---

## 6. Adversarial Critique

The Skeptic re-opened 18 claims and found three tools the Scouts missed. It also killed the
original gap thesis as a statement about the whole stack. Cisco mcp-scanner + Cisco
skill-scanner + mcpseal already cover description scanning, manifest pinning, server SAST and
skill malware. All three are Apache or MIT licensed and mostly offline.

### 6.1 Corrections that changed the analysis

| Scout claim | Verdict | Correction |
|---|---|---|
| No head-to-head detection benchmark exists | False | SkillTrustBench (Tencent Zhuque + CUHK-SZ, 5,520 samples, 9 categories, leaderboard); MCPTox (arXiv 2508.14925); MCPSecBench (arXiv 2508.13220) |
| No offline manifest-pinning CLI besides Trail of Bits | False | mcpseal (zero deps, lockfile), rugsnare (scan/diff), Minibridge (tool-definition change prevention) |
| Skill scanning field = SkillSpector + one hobby project | Omission | Cisco skill-scanner (2.5k stars, SARIF, AST taint) and clawscan were missed; the field saturated within 60 days of SkillSpector's launch |
| SkillSpector scans MCP servers | Overstated | It scans skill directories only; "MCP least-privilege" is a category inside skill content |
| Snyk dropped tool-poisoning detection | Misread | Labels moved into a hosted API taxonomy; capability loss is unproven, but `SNYK_TOKEN` is mandatory |
| CVE-2025-54136 published 2025-09-16, CVSS 7.2 | Wrong | NVD published it 2025-08-01; CNA score 7.2, NVD score 8.8; fixed in Cursor 1.3 (NVD) |
| `Mcp-Param-*` header name in spec 2026-07-28 | Unverified | The changelog only says custom headers go via `x-mcp-header`; **do not build a check on the header name** |
| Maturity by star count | Wrong axis | Trail of Bits (226 stars, 139 commits, Trail of Bits engineering) outranks mcp-shield (554 stars, 15 commits); commercial "98.1% detection" and "15M+ patterns" claims are unrated marketing |

**Category errors removed:**
- ToolHive, Docker Gateway, Lasso Gateway and EQTY Guardian had been scored as scanners.
  They are runtime proxies and now sit in their own group.
- MCPSafetyScanner is a paper, not a tool.
- garak and PyRIT are model-level red-team harnesses with no tool or MCP target, so they do
  not bear on IANUA's gap.

### 6.3 Post-publication correction (2026-10-09)

The mcpseal row originally said "zero runtime deps, offline". That claim came
from the project's marketing copy. Reading the published v0.1.4 source (PyPI
sdist, sha256 `1b0b99e7…b468`, verified against PyPI's published digest)
shows:
- three runtime dependencies: `canonicaljson`, `keyring` and `cryptography`;
- an opt-in path that uploads events to a control plane, active only after a
  user logs in;
- a lockfile that stores each approved tool's description text in plaintext,
  next to its hash.

The core pinning is local, so the "partial" verdict below stands. The
"zero-dependency" contrast with IANUA-Broker is overstated.

### 6.2 Verdicts on the eight candidate directions

| Candidate | Verdict | One-line reason |
|---|---|---|
| Offline manifest pin + drift fused into baseline/diff | Partial | Pinning is commoditized. The only new part is the fusion with a signed baseline, SARIF before/after and the risk ledger. A feature, not a thesis |
| Offline tool-level toxic-flow analysis | **Real whitespace (narrow)** | Only Snyk does flow analysis, and it needs a hosted API. `graph` already exists to extend |
| Skill / plugin / `.claude/agents` scanner | Commoditized for `SKILL.md`; partial for agents, plugin manifests, hooks | Cisco and NVIDIA own `SKILL.md`. The uncovered surface is small, and Cisco is one PR away from it |
| MCP 2026-07-28 auth and annotation conformance | **Real whitespace** | No scanner checks RFC 9728 PRM, resource, audience, passthrough refusal or annotation trust. Deterministic and loopback-testable; spec churn is the risk |
| CycloneDX agent BOM | Partial | No standard component types for tools or skills yet. Low effort, modest value |
| Build a benchmark corpus | **Trap** | Three public corpora exist, and a solo corpus would be smaller and contested. Run against theirs |
| ATB as Cedar/OPA policy point | **Trap** | ToolHive, AgentCore, agentgateway and Minibridge own policy languages. Importing one dilutes ATB's fail-closed invariants (ADR-17). Export decisions as evidence instead |
| OWASP ASI01–ASI10 mapping in `atlas` | Commoditized | Promptfoo and DeepTeam publish it. Half a day of work for portfolio legibility; cite the OWASP PDF |

> **Skeptic's standing warning:** the "auditable stdlib" moat exists only while every
> network touch stays opt-in and disclosed. The original five-scanner thesis is a
> scope-creep tell.

---

## 7. Gap Analysis

The incidents of 2025–2026 define what a scanner must catch. Mapping them against the matrix
leaves five buildable gaps. The Architect designed each one to stay stdlib, offline and
fail-closed.

### 7.1 Incidents that define "good detection"

| Date | Incident | Class | Caught today by | IANUA feature that would catch it |
|---|---|---|---|---|
| 2025-05-26 | GitHub MCP toxic flow: public issue → private repo read → leak in PR | Indirect injection + flow | Snyk (hosted) | C: toxic flow `FLOW-UNTRUSTED-PRIVATE-PUBLIC` |
| 2025-06-13 | CVE-2025-49596 MCP Inspector RCE, no auth between client and proxy | Dev-tool RCE | OSV lookup | A: `CONF-401-WWW-AUTH` (unauthenticated `initialize` accepted) |
| 2025-07-08 | Supabase MCP: ticket text → `service_role` reads tokens → writes back | Injection + excessive scope | None statically | C + existing `trust`; E (was a PEP in front?) |
| 2025-07-09 | CVE-2025-6514 mcp-remote command injection from a malicious server | Malicious server → client RCE | OSV, Cisco | Existing `--online` OSV; B pins the server version |
| 2025-08-01 | CVE-2025-54136 Cursor trusts an edited MCP config after one approval | Config rug pull | Trail of Bits (runtime) | B: `TOOL-*` drift against the signed baseline |
| 2025-09-25 | postmark-mcp 1.0.16 adds a BCC to the attacker | Version rug pull / supply chain | mcpseal, ToB | B: `TOOL-DESC-CHANGED` + `PIN-UNPINNED`; D regression fixture |
| 2025-10-08 | CVE-2025-53967 Figma MCP shell injection | Server code vuln | Cisco SAST, OSV | OSV only (SAST is out of scope: commoditized) |
| 2025-12-17 | CVE-2025-68143/4/5 Anthropic mcp-server-git path bypass, arg injection | Server code vuln | OSV | OSV; C flags filesystem+git EXEC chains |
| 2026-01-20 | MarkItDown MCP SSRF | SSRF | Cisco | A: `CONF-REDIRECT-OFFHOST`; C sink classification |
| 2026-02-02 | ClawHavoc: 341 of 2,857 ClawHub skills malicious | Skill-marketplace malware | Cisco, NVIDIA, Tencent | F: ingest their SARIF; G: hooks and agents adapter |

### 7.2 The five designs

All five are stdlib only. `--tools-json FILE` is the shared offline fixture format.

| ID | Feature | Repo | Surface | Core logic | Egress | Effort |
|---|---|---|---|---|---|---|
| **A** | `mcpscan conformance` | IANUA-Broker | `conformance --target URL [--allow-host] [--bearer-env] [--follow-as-metadata] [--upstream-canary]` | 14 checks with a four-state status (`pass` / `fail` / `not_observable` / `not_evaluated`). Black-box observable: `CONF-401-WWW-AUTH`, `CONF-PRM-MISSING/MALFORMED/RESOURCE-MISMATCH/INSECURE-URL`, `CONF-TOKEN-ACCEPT-ANY` (negative probe), `CONF-REDIRECT-OFFHOST`, `CONF-PROTO-VERSION`, `ANNOT-MISSING/CONTRADICT/NAME-MISMATCH/UNTRUSTED-ORIGIN`. Reported honestly as `not_observable`: RFC 9207 `iss` and RFC 8707 resource (client duties). Passthrough is tested only via the opt-in loopback canary | Loopback unless `--allow-host` names the exact host; printed in the report header | 7 days |
| **B** | `--inspect-live-tools` + manifest drift | IANUA-Broker | `scan\|baseline\|diff --inspect-live-tools`, `diff --fail-on-tool-drift`, `baseline --import-mcp-lock`, `--repin SERVER:TOOL`, `--spawn-stdio NAME` (opt-in, executes) | Per-tool `sha256(canon(name, description, inputSchema, outputSchema, annotations))`, NFC-normalized. Drift classes: `TOOL-ADDED/REMOVED/DESC-CHANGED/DESC-POISON-NEW/SCHEMA-CHANGED/ANNOT-RELAXED/ANNOT-TIGHTENED/SHADOW/MANIFEST-UNPINNED/DUPLICATE-NAME`. The digest lives inside the signed baseline. The accept ledger is keyed `server:tool:new_digest`. The mcpseal import recomputes mcpseal's algorithm, refuses unknown lock versions and marks entries `provenance: imported` | Loopback `tools/list`; stdio spawn disclosed per server | 6 days |
| **C** | `graph --data-flow` | IANUA-Broker | `graph --data-flow [--tools-json] [--dot]` | Three signal layers: annotations, a signed name/schema lexicon, and server type from inventory. Confidence is tier A/B/C. When signals disagree, the more dangerous class wins. Flow rules: `FLOW-UNTRUSTED-PRIVATE-PUBLIC` (critical), `FLOW-PRIVATE-PUBLIC-XSERVER`, `FLOW-UNTRUSTED-EXEC`, `FLOW-SECRET-HOLDER-SINK`. Score adjustments: +1 auto-approve, −1 behind ATB, −1 tier C. Every flow carries refutable evidence | None | 7 days |
| **D** | `atlas` ASI map + `mcpscan bench` | IANUA-Broker | `bench --corpus DIR --adapter mcptox\|mcpsecbench\|skilltrustbench\|incidents --expected FILE` | Adapters normalize samples into `--tools-json` and run the normal scan path (no bench-only logic). Rows are TP / FN / FP / NA; NA covers out-of-scope categories and is reported, not hidden. The corpus sha256 is recorded. Always exits 0, with an optional `--min-recall` | None (corpora fetched by hand) | 0.5 + 4 days |
| **E** | ATB decision-evidence export | agent-trust-broker (writer), IANUA-Broker (reader) | `atb evidence export --out broker.json [--sarif] [--otel-ndjson]`; atomic write runs automatically on segment seal | `broker.json` v2 holds the chain tip, catalog/bindings/ruleset digests, decision counts by tool, pending escalations and `protected_servers[].tool_map_digest` (= B's manifest digest), HMAC'd with the seal key. ATB SARIF rules: `ATB-CHAIN-VERIFIED`, `ATB-SEAL-MISSING`, `ATB-ESCALATION-PENDING`, `ATB-DENY-OBSERVED`. `mcpscan` adds `BROKER-TIP-STALE`, `BROKER-HMAC-MISMATCH`, `BROKER-SERVER-UNPROTECTED` | None (files only) | 4 + 2 days |

**Shared hardening across A–E:**
- Body cap of 1 MiB, JSON depth 32, 2,000 tools per server, 64 KiB per description.
- Terminal-escape stripping.
- No redirect following.
- `ProxyHandler({})`, so an `HTTPS_PROXY` variable can never cause silent egress.
- New check ids ship through the signed data-pack.
- The one cross-repo contract (`broker.json` v2 plus the canonical manifest hash) is
  documented in both repos, with shared test vectors.

---

## 8. Ranked IANUA Feature Backlog

Toxic-flow analysis (C) ranks first on value. Live-tool drift (B) still ships first, because
C, A and D all consume the `--tools-json` capture that B introduces.

Scores are 1–5, where 5 is best (so Effort 5 = smallest). Weights: Security 30%,
Differentiation 25%, Portfolio 20%, Effort 15%, Risk 10%. Every total below was recomputed
from the component scores and weights when this record was written.

| Rank | ID | Item | Repo | Sec | Diff | Port | Eff | Risk | Total | Incident it reproduces |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | C | Tool-level toxic flow in `mcpscan graph --data-flow` | IANUA-Broker | 5 | 5 | 5 | 2 | 2 | 4.25 | GitHub MCP (2025-05-26), Supabase (2025-07-08) |
| 2 | A | `mcpscan conformance` against MCP 2026-07-28 auth and annotation MUSTs | IANUA-Broker | 4 | 5 | 5 | 3 | 3 | 4.20 | Inspector CVE-2025-49596; confused-deputy and passthrough classes |
| 3 | B | `--inspect-live-tools` manifest pin/drift fused into signed baseline/diff, mcpseal import | IANUA-Broker | 5 | 3 | 4 | 4 | 4 | 4.05 | Cursor CVE-2025-54136, postmark-mcp 1.0.16 |
| 4 | E | ATB decision-evidence export to `broker.json` v2 / SARIF (closes R-ATB-TIP-EXPORT) | ATB + Broker | 3 | 4 | 4 | 4 | 4 | 3.70 | Supabase excessive scope (proves a PEP mediated the call) |
| 5 | D2 | `mcpscan bench`: publish results against MCPTox, MCPSecBench, SkillTrustBench and the 10 incident configs, false negatives admitted | IANUA-Broker | 3 | 4 | 5 | 3 | 3 | 3.65 | All ten, as a permanent CI regression corpus |
| 6 | ATB-P0 | Durable chained revocation, seal key required in prod posture, key lifecycle (R-ATB06-IDREV, R-ATB05-SEALDEF, R-ATB06-M6) | ATB | 4 | 3 | 4 | 3 | 4 | 3.60 | Long-lived privileged identity; tamperable unsealed evidence |
| 7 | G | `.claude/agents`, plugin manifests and hooks adapter checks (the surface Cisco and NVIDIA leave uncovered) | IANUA-Broker | 3 | 3 | 3 | 4 | 3 | 3.15 | ClawHavoc class: hooks are shell at event time |
| 8 | F | Ingest Cisco skill-scanner and SkillSpector SARIF into the dashboard Scan Reports tab | **IANUA** | 3 | 2 | 3 | 4 | 5 | 3.10 | ClawHavoc, via partners rather than a rebuild |
| 9 | EVADE | R-ATB04-EVADE homoglyph, chunk-split and short-encoding vectors in the screening ruleset | ATB | 3 | 2 | 3 | 4 | 3 | 2.90 | Cisco's Unicode and homoglyph injection vectors |
| 10 | D1 | OWASP ASI01–ASI10 column in `mcpscan atlas` (data-pack lookup, cite the OWASP PDF) | IANUA-Broker | 2 | 1 | 3 | 5 | 5 | 2.70 | None; taxonomy legibility |
| 11 | H | CycloneDX-style agent BOM export | IANUA-Broker | 2 | 2 | 3 | 4 | 3 | 2.60 | Postmark supply chain, inventory only; wait for component-type standardization |

### 8.1 Why the top five

- **C** is the only offline whitespace the Skeptic left standing. Snyk's flow analysis
  needs a hosted API, and `graph` already models cross-server credential chaining, so this
  extends an existing module instead of starting a new product.
  - The cost: tool annotations are optional and usually absent, so the classifier must
    report tier-C confidence and "unknown" loudly instead of guessing.
  - The payoff: a DOT diagram of the GitHub incident, found by a zero-dependency CLI, is the
    most legible case study in the backlog.
- **A** is standards work nobody has done. Every check cites an RFC or a spec section. The
  four-state status, including `not_observable` for client-side MUSTs, is itself the
  differentiator against vendors who would over-claim.
  - Spec churn is the risk. Version the check set with `--spec 2026-07-28`, and keep each
    check to one function with one citation.
- **B** has the highest raw security value (two named incidents) and is already P1 on the
  roadmap. mcpseal and rugsnare pin manifests too, so the differentiation is the fusion:
  - the manifest digest lives inside the signed baseline;
  - `diff --fail-on-regression` gates it;
  - the accept ledger can waive one specific drift, with an expiry and a reason;
  - SARIF carries before/after.

  Importing `.mcp-lock.json` turns mcpseal users into an upgrade path instead of
  competitors.
- **E** is the cheapest way to make the two repos tell one story, and it answers the Cedar
  trap: export decisions as evidence, never import policy.
  `protected_servers[].tool_map_digest` equals B's manifest digest. Static posture and
  runtime enforcement are therefore cryptographically linked in one GitHub code-scanning
  view.
- **D2** is the Skeptic's "boring but valuable" first item. A detection table against three
  public corpora and ten reproduced incidents, with false negatives admitted, is worth more
  to a hiring manager than any single feature. It also turns the incidents into a permanent
  regression corpus for C, A and B.
  - Expect poor SkillTrustBench numbers, because `mcpscan` is not a skill scanner. Say so,
    and show F routing those findings to Cisco and NVIDIA.

### 8.2 Explicitly excluded

| Direction | Reason |
|---|---|
| Building a benchmark corpus | SkillTrustBench (5,520 samples), MCPTox and MCPSecBench exist; a solo corpus would be smaller and contested, and vendors dispute every false negative |
| Cedar / OPA / CEL import into ATB | ToolHive, AgentCore, agentgateway and Minibridge own policy languages; an import dilutes ATB's deterministic fail-closed invariants and breaches ADR-17 |
| LLM-judged detection | Needs API keys and egress, is non-deterministic, and Cisco and AI-Infra-Guard already do it with more compute; it would destroy the auditable-stdlib moat |
| Generic `SKILL.md` malware scanner | Saturated within 60 days: Cisco skill-scanner, SkillSpector, clawscan, claude-skill-antivirus. Ingest their SARIF instead (F) |

---

## 9. Risks, Assumptions, and Open Questions

The plan's two biggest exposures are spec churn under feature A and heuristic false
positives under feature C. Both have a mitigation that costs less than the feature itself.

| Risk | Likelihood | Mitigation |
|---|---|---|
| MCP spec moves the 2026-07-28 MUSTs again (sessions and DCR were removed in one revision) | High | Each `CONF-*` row carries `spec_version` and an `applies_to` range in the data-pack; `CONF-PROTO-VERSION` gates which rows run |
| Name-lexicon false positives in `graph --data-flow` | Medium | Tiered confidence on every finding; tier C never above high; FP-guard corpus held at 0 FP in CI; the lexicon is signed data, editable without a release |
| Over-claiming conformance | Medium | Four-state status; negative probes labelled as such; the README lists the non-observable MUSTs up front |
| Scope creep toward a runtime proxy (stdio spawn in B, canary in A) | Medium | Per-server opt-in, loopback only, disclosed in output; no interception path; ADR-17 restated in each module docstring |
| Contract drift between ATB and Broker (`broker.json` v2, manifest digest) | Medium | One `docs/EVIDENCE_CONTRACT.md` in both repos, with shared test vectors run in both CIs |
| Cisco or NVIDIA cover `.claude/agents` and hooks before G ships | High | Keep G an adapter extension (days, not weeks); drop it if either ships first |
| Benchmark numbers look poor on skill corpora | Certain | Report NA for categories `mcpscan` does not claim; route them to partner scanners via F |

**Assumptions made by the council:**
- IANUA-Broker's dogfood corpus and SARIF pipeline are stable enough to extend. The README
  claims 0 FP / 0 FN and semver-covered check ids.
- ATB's seal key can double as the HMAC key for the evidence export.
- The `--tools-json` capture format is acceptable as the fixture format for all adversarial
  tests.
- The user will keep the stdlib-only rule for ATB.

## 10. Open Questions (owner: Ivan)

Answers recorded 2026-10-09.

- [x] **What is IANUA-Marketplace?** *Answer:* a scaffold for an eBay-style
  marketplace website or app, not a skill or plugin distribution channel.
  *Effect:* F and G stay where they are and are **not** pulled into Phase 1. The
  agent BOM (H) gains nothing from it, and the benchmark framing is unchanged.
- [ ] **Is a `cryptography` dependency acceptable for ATB under AGENTS.md §5.1?**
  Still open. Without it, key lifecycle (R-ATB06-M6) and evidence export stay
  HMAC-only, which limits how far third parties can verify the evidence.
- [x] **Will a loopback MCP server run in CI?** *Answer:* yes. *Effect:* A and C
  keep their full definitions of done. A stdlib loopback fixture server now
  ships in IANUA-Broker's test suite (`tests/_live_mcp_server.py`, PR
  IRsoctierDT/IANUA-Broker#123).
- [ ] **Which incident configs may be reproduced as fixtures?** Still open. The
  postmark-mcp rug pull is already reproduced in the fixture server.
- [x] **Are job applications planned within 90 days?** *Answer:* yes, starting in
  early January 2027 (about 12 weeks from 2026-10-09). *Effect:* publish the D2
  benchmark table by **mid-to-late November 2026**, so it is live and polished
  before applications start. Then land C.

### 10.1 Owner direction (2026-10-09)

The owner set the build direction to **live tool-manifest inspection, skill
content analysis and server-source analysis**: the three capability rows where
IANUA-Broker is "—" while a free offline tool is "Y" (§5).

This deliberately goes further than the council's verdicts. The Skeptic rated
generic `SKILL.md` scanning as commoditized and server SAST as out of scope
(§6.2, §8.2). The constraint that follows: each new surface must still meet the
moat conditions (stdlib, offline by default, deterministic, fail-closed), so
that IANUA-Broker offers the audited, zero-egress version of each check rather
than a smaller copy of Cisco or NVIDIA. The resulting IANUA-Broker sequence is
in that repository's `docs/ROADMAP.md`:

1. R-LIVE-TOOLS: landed in IRsoctierDT/IANUA-Broker#123.
2. R-LIVE-TOOL-DRIFT.
3. R-LIVE-TOOLS-JSON.
4. R-LIVE-STDIO: gated, because spawning a server runs its code.
5. R-SKILL-CONTENT.
6. R-SERVER-SOURCE.

---

## 11. Next Actions

Start with the two-week foundation. It is low-risk and already on the roadmap, and every
later feature consumes the `--tools-json` capture it introduces.

1. **Week 1: ship `--inspect-live-tools` and the manifest digest inside the signed baseline
   (B).** Definition of done:
   - A Postmark-style description mutation and a Cursor-style post-approval config edit both
     fail `mcpscan diff --fail-on-tool-drift` in the dogfood corpus and appear in SARIF with
     before/after.
   - `baseline --import-mcp-lock` reads an mcpseal lockfile.
   - There are 0 new false positives on the existing corpus.
2. **Week 2: close R-ATB-TIP-EXPORT with `broker.json` v2 (E) and add the ASI column to
   `atlas` (D1).** Definition of done:
   - ATB writes the HMAC'd evidence file on every seal.
   - `mcpscan --inspect-broker` emits `BROKER-SERVER-UNPROTECTED` for a privileged server
     missing from `protected_servers`.
   - One shared test vector proves both repos compute the same manifest digest.
3. **Publish the first case study** ("Catching the postmark-mcp rug pull offline in CI")
   with the SARIF screenshot. Then open the Phase 2 branches for A and C, in that order.
   Answer the open questions in §10 before Phase 2 starts, because the loopback-server-in-CI
   decision changes A's scope.

Each phase is gated: a phase is done only when its case study is publishable.
- If Phase 2 slips, drop the ATB key-lifecycle work, never C.
- If applications are due within 90 days, pull D2 forward to week 6.

---

## 12. Implications for this repository (IANUA platform)

*This section was added when the research was committed. It is not part of the council
output.*

- **Only F lands here.** All other backlog items belong to IANUA-Broker or
  agent-trust-broker and must be tracked in those repos.
- **F extends an existing trust boundary.** The Scan Reports tab
  (`dashboard/scan_reports.py`) already parses untrusted IANUA-Broker JSON under strict
  limits: size, depth, node count, duplicate keys, control characters and masked-secret
  rejection. Its output is rendered as plain text only. A SARIF importer for third-party
  scanners would be a **new untrusted input format from a third-party producer**. It should
  follow the same pattern:
  - a separate allowlisted projection;
  - the same limits;
  - no dereferencing of `artifactLocation` URIs;
  - no rendering of `message.markdown`;
  - a `tests/security` case for each limit.

  Under AGENTS.md §2.7 / §6.3, that boundary change needs explicit human scoping before
  implementation.
- **E and B are dependencies for later dashboard work.** Once `broker.json` v2 and the
  manifest digest exist, the dashboard can show runtime protection status next to static
  posture. That should wait until the cross-repo `EVIDENCE_CONTRACT.md` is published.

---

## 13. Sources

All pages were opened on 2026-10-09. Tools are cited by their repository or documentation
page. Primary references by group:

- **IANUA repos (read live):** IANUA-Broker README and ROADMAP · agent-trust-broker README
  and ROADMAP · IANUA README
- **Specifications and standards:** MCP 2026-07-28 changelog · MCP authorization · MCP tools
  and annotations · MCP security best practices (draft) · MCP ext-auth enterprise-managed
  authorization · OWASP Top 10 for Agentic Applications 2026 · OWASP LLM Top 10 2025 ·
  NIST AI RMF · draft-ietf-wimse-aims · draft-ietf-oauth-identity-assertion-authz-grant ·
  A2A 1.0 specification
- **Scanners (Skeptic-verified):** Cisco mcp-scanner · Cisco skill-scanner · NVIDIA
  SkillSpector · Snyk Agent Scan · Tencent AI-Infra-Guard · Trail of Bits
  mcp-context-protector · mcpseal · rugsnare · mcp-shield · Lasso MCP Gateway ·
  claude-skill-antivirus · clawscan · Promptfoo red-team plugins · Promptfoo ModelAudit ·
  DeepTeam · garak · PyRIT · Agentic Radar · Prisma AIRS October 2025 notes · Semgrep MCP
  guide
- **Benchmarks:** SkillTrustBench · MCPTox (arXiv 2508.14925) · MCPSecBench
  (arXiv 2508.13220)
- **Runtime gateways and platforms:** ToolHive and auth docs · Docker MCP Gateway ·
  agentgateway · IBM ContextForge · Invariant Gateway and Explorer shutdown · AWS AgentCore
  Policy · Google Model Armor MCP · Microsoft Agent 365 and Entra Agent ID · Cloudflare MCP
  Server Portals · NeMo Guardrails · GitHub MCP allowlists · Microsoft securing AI agents
  blog
- **Incidents and CVEs:** GitHub MCP toxic flow · CVE-2025-49596 · Supabase MCP ·
  CVE-2025-6514 mcp-remote · CVE-2025-54136 Cursor · postmark-mcp · CVE-2025-53967 Figma
  MCP · mcp-server-git CVEs · MarkItDown SSRF · ClawHavoc
- **Corporate moves affecting the field:** Snyk acquires Invariant · Palo Alto completes
  Protect AI · Zscaler acquires SPLX · SentinelOne to acquire Prompt Security · Cato acquires
  Aim Security · Linux Foundation Agentic AI Foundation

> **Link gap:** the source document named these references but did not carry their URLs.
> Add the URLs here before citing this record externally.

**Not verified and excluded from conclusions:**
- vendor marketing figures (Straiker, Repello, Pillar, Adversa);
- the `Mcp-Param-*` header name;
- Docker MCP Gateway interceptors;
- GA status of AgentCore Policy and of Model Armor's MCP integration;
- the exact year on GitHub release pages that omit it.
