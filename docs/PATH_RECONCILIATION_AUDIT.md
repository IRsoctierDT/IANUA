# Path & Assertion Reconciliation Audit

> **Status** — Findings confirmed 2026-10-13 against `main` @ `b7de847`. Remediation not
> started. Update the status column as stages land.
> **Scope** — Drift between what this repository *asserts* and what is *actually true*: a path,
> URL, handle, directory, count, or stated guarantee that leads nowhere, points somewhere other
> than a reader would conclude, or describes a state that has since changed.
> **Method** — Seven-dimension parallel survey (212 agents), three adversarial verifiers per
> candidate finding (evidence survives re-read / deliberate-by-design / would actually mislead),
> then a completeness critic over the survivors. 68 candidates, 65 survived, clustering to 38
> distinct issues; the critic added 5 the survey missed and reinstated 2 wrongly killed.

---

## 0. Remediation Status

Update the Status cell as each stage lands; keep the PR or commit in Evidence so the claim is
checkable. `—` means not started. A stage is only `done` when every item under it has landed.

| Stage | Scope | Status | Evidence |
|---|---|---|---|
| 0 | Maintainer-only: repo settings, externally visible deletes, secrets, account routines | **partial** | `.github/SECURITY.md` deleted (PR #190); repo settings still open |
| 1.1 | Attestation-expiry gate compares against the current date | **done** | PR #190 |
| 1.2 | Pre-commit hook versions reconciled with the project toolchain | **done** | 2026-10-23, not as the plan below prescribes. The ruff, mypy, bandit and detect-secrets hooks became `repo: local` hooks on the project interpreter instead of bumped pins. That also closes G2's isolated-environment half, which a bump would have kept, and a bandit drift (1.7.10 against 1.9.4) this audit did not list. Pinned by `test_precommit_runs_the_locked_toolchain_not_a_second_pin` |
| 1.3 | §7 ↔ CI gate-list reconciliation + parity test covers the gate list | — | |
| 1.4 | MAN-01's false attestation note | — | |
| 1.5 | `ALLOWED_EGRESS_HOSTS` wired or marked documentation-only | — | |
| 2 | Public landing-page claims (version, test count, agent count, gate block) | — | |
| 3 | Stale one-liners, batched | — | |
| 4 | `generate_docs_from_design.py` fixed, then regenerated; `--check` added | — | |
| 5 | Structure map + `cli/` into the gates + §8 scope pointer | — | |
| 6 | Lower-consequence prose | — | |
| — | Orphaned dashboard mockups: document, move, or delete | — | |

---

## 1. Executive Summary

The repository's **content** is in good shape. Every relative Markdown link in every non-
`sample-logs` document resolves; all `github.com` URLs on the published site name
`IRsoctierDT/IANUA` correctly; `main` is genuinely branch-protected; `CLAUDE.md` is a real
symlink to `AGENTS.md`; and the legacy repository name survives in exactly two deliberate,
documented places.

What has drifted is the repository's **claims about itself** — and in three cases a claim is a
guarantee that is not in force. A fourth, CodeQL, turned out on review to be unverifiable
rather than untrue; it is recorded below as such. The most urgent is a compliance gate documented as having
"teeth in CI" that cannot fire, with a nine-day fuse.

The causal story is simple and worth stating plainly: this repository invested heavily in drift
gates for *derived artifacts* (ten `--check` scripts) and almost nothing in gates for
*self-description*. So the files that describe the system — the charter's structure map, the
security-control inventory, the public landing page, the governance docs — drifted freely while
every generated artifact stayed pinned. Roughly a third of the findings trace to one generator,
`scripts/generate_docs_from_design.py`, which overwrites sixteen files unconditionally and has
no `--check` gate.

### The guarantees not in force

| # | Guarantee as written | Reality | Where |
|---|---|---|---|
| ~~G1~~ *(fixed, PR #190)* | "This assertion is MAN-0x's teeth in CI — an expired attestation fails the gate until the human re-attests" | The comparison is `attestation.expires < report.as_of`, where `as_of` is the **frozen committed snapshot date** (`2026-08-21`). MAN-01/MAN-02 expire `2026-10-22`, so the test is `"2026-10-22" < "2026-08-21"` → `False`. It stays `False` after expiry, because `as_of` only moves when a human runs `--snapshot`. The codebase already has the right predicate — `Attestation.valid_on(day)`, `self.date <= day <= self.expires` — and `compliance/engine.py:101` calls it correctly against `today`. This gate simply never does. | `scripts/build_trust_page.py:417-430`; `compliance/attestations.py:49`; `compliance/engine.py:101` |
| G2 | `.pre-commit-config.yaml` annotates its ruff hooks "mirrors `ruff check .`" and "mirrors `ruff format --check .`", and its header claims it mirrors the CI pipeline | Pre-commit pins `ruff` **v0.6.9** and `mypy` **v1.11.2** as *remote hook repos*, built in pre-commit's own isolated environments — they never see the project venv. CI installs `ruff==0.16.10` and a `mypy>=2.4.0` floor. Across that gap the formatter's output changed and mypy took a major version, so the `ruff-format` hook can rewrite a file that `ruff format --check .` in CI then rejects. **Scoped deliberately**: AGENTS.md:365-366 licenses pre-commit as "the fast subset", so this falsifies the hooks' own mirror comments — not §7-vs-CI parity, which runs in the project environment and is a separate question (G3). | `.pre-commit-config.yaml:3,36,38,40,44`; `pyproject.toml:40-41`; `.github/workflows/ci.yml:53,57` |
| G3 | §7 is the complete required-check list | CI's `static-analysis` job — a required status check — also runs `uv lock --check` and `python scripts/check_version_sync.py`. Neither string appears anywhere in `AGENTS.md`, `README.md`, or `.pre-commit-config.yaml`. Conversely §7 step 1, `python -m compileall .`, runs in **zero** workflows. A contributor can run all of §7 green and still be blocked. | `.github/workflows/ci.yml:46,48`; `AGENTS.md:273-274` |
| ~~G4~~ | *Withdrawn. See "CodeQL — unverified, not absent" immediately below.* | |

#### CodeQL — unverified, not absent

The first draft of this audit called CodeQL a control that had been **removed** without updating
its documentation. That was wrong, and the repository's own history says so:
commit `b05139f` (2026-06-18, *"ci(codeql): remove custom workflow — default setup supersedes
it"*) removed `.github/workflows/codeql.yml` **because** GitHub's CodeQL *default setup* had been
enabled, and GitHub rejects SARIF from an advanced-configuration workflow while default setup is
on. Default setup deliberately has no in-repo workflow file, so `grep -rniI codeql .github/`
returning zero is exactly what a correctly-migrated repository looks like. It proves nothing.

What can be said from outside the settings page, stated as observation rather than conclusion:

- CodeQL default setup **was** running as recently as 2026-08-21 — PR #159's check list
  included both `CodeQL` and `Analyze (actions)`.
- It does **not** appear on recent pull requests: neither PR #185 (merged 2026-10-09) nor
  PR #187 shows a `CodeQL` or `Analyze` check among its eleven.

That gap is worth a look, but it is not evidence of a false claim — default setup can be scoped
by path or event, and a draft PR may be treated differently. **SECURITY.md:59 is therefore
presumed accurate and is not a finding.** Resolving it needs the Settings → Code security page,
or the `code-scanning/default-setup` API with a `security_events`-scoped token (this session's
token gets 403). Stage 0 carries it as a question, not a defect.

What *does* survive, much narrower: AGENTS.md:336 lists CodeQL inside §8's CI Security stage
under the heading that local §7 checks are "mirrored exactly in CI", while §7's own gate list
never mentions it — and it cannot, because default setup has nothing to run locally. That is a
G3-shaped documentation gap, not a missing control.

### The public landing page is two minor versions stale and understates the suite by 50×

`docs/index.html` is the GitHub Pages site — the most-read artifact in the project.

| Claim | Line | Actual |
|---|---|---|
| `v1.9.0 · All systems operational` | 654 | `2.1.0` (`pyproject.toml:26`) |
| `v1.9.0` — "Latest Release" | 690 | `2.1.0` |
| `18` — "Tests Passing" | 682 | **914** test functions across 106 files |
| `12` — "Agents" | 678 | 13 agent modules |

Nothing gates the published page against the repository it describes.

---

## 2. Objectives

1. Retire every claim that is not in force, or make it true — guarantees first, cosmetics last.
2. Fix the generator before its outputs, so edits do not self-revert.
3. Close the *class* of drift with the smallest gates that fit this repo's existing idiom, so
   this audit does not need repeating.
4. Separate what a commit here can fix from what requires the maintainer (repo settings,
   account-level routines, sibling repos, a private key).

---

## 3. Process — why the gates did not catch this

Two structural blind spots, both verified:

**Eligibility.** `scripts/rename_to_ianua.py` only scans files whose suffix is in
`TEXT_SUFFIXES`. `.gitignore` has suffix `''`, so it is never scanned — which is why
`.claude/ai-command-center.code-workspace` (`.gitignore:21`) survives while the gate reports
clean. **Nine** tracked paths are suffixless and therefore invisible to it, six of them
content-bearing — `.github/CODEOWNERS`, `.gitignore`, `.gitleaksignore`, `LICENSE`, `NOTICE`,
`mcp/sandbox/profiles/apparmor-mcp-tool` — plus three empty markers (`detections/.gitkeep`,
`docs/.gitkeep`, `docs/.nojekyll`). Note that Python treats a leading-dot name as having no
suffix, which is why every dotfile here is ineligible. That line is also a case mismatch: the
`REPLACEMENTS` table carries the capitalised hyphenated spelling of one legacy identifier while
the file uses the all-lowercase spelling, and the comparison is case-sensitive. So the line is
doubly invisible — ineligible by suffix *and* unmatched by case.

**Coverage.** No gate compares a *description* against the thing described. There is no check
that AGENTS.md §4's "canonical map" matches the tree, that SECURITY.md's control inventory
matches `.github/workflows/`, that §7's gate list matches CI's steps, or that
`docs/index.html`'s stat strip matches `pyproject.toml` and the test suite.

**A live legacy identifier reaches the wire.** `mcp/transport.py:32` is
`SERVER_INFO = {"name": "ai-operator-mcp-stub", "version": "0.1.0"}` — sent in the MCP
`initialize` handshake to every host that connects. It advertises the pre-IANUA name, calls
itself a stub, and reports `0.1.0` against a platform at `2.1.0`. Do **not** fix this with
`rename_to_ianua.py --apply`: the table would mechanically yield `ianua-mcp-stub`, keeping the
"stub". Set the name deliberately and source the version from `agents.__version__`.

---

## 4. Implementation Steps (sequenced by consequence, not effort)

### Stage 0 — not autonomously fixable. Listed first so it is not skipped.

AGENTS.md §5.1 approval gates, or outside this repository entirely:

- **Repo settings** (maintainer): confirm or enable CodeQL default setup (needs a
  `security_events`-scoped token); enable **private vulnerability reporting**, without which the
  `OWNER/REPO` fix below produces a working-looking link to a disabled feature; **Issues are
  currently disabled**, which makes all four issue templates inert regardless; branch-protection
  required-reviewer count.
- **Externally visible**: ~~deleting `.github/SECURITY.md` changes what GitHub serves in the
  Security tab. Propose, do not do.~~ **Done on maintainer instruction (PR #190).** The stub
  held nothing the root policy lacks — every substantive item in it (no public issue, private
  advisory preferred, the contact address, the 5-business-day acknowledgement, the 30-day
  coordinated-disclosure window) also appears in `SECURITY.md`, so it was a partial copy rather
  than the pointer it claimed to be. GitHub now serves the 83-line root policy. Verified
  beforehand: no generator emits the path, nothing links into it, and the two gates that read
  `SECURITY.md` resolve the repository root — `compliance/controls.py:286` via
  `_resolve_inside(root, …)` and `scripts/check_version_sync.py:76` via `ROOT / "SECURITY.md"`.
- **Secrets**: the Ed25519 pin-signing ceremony (`attack/README.md`) — maintainer only.
- **Dependency addition**: a `dashboard-min` extra would need §5.1 justification.
- **Account-level routines**: the Pages-deploy watcher whose prompt names the
  **pre-IANUA repository name** while its WebFetch fallback names `IANUA`. That old name no
  longer exists as a repository and nothing has claimed it, so GitHub's rename redirect still
  resolves it — the routine works *by redirect*, which is fragile, not broken. Not committable
  here.
- **Migration, not a rename** (human decision): rewriting `aiocc` would change Docker
  `container_name` values plus the Postgres role and database, orphaning named volumes for anyone
  who has run the lab stack.

### Stage 1 — guarantees not in force. One reviewed change each.

| # | Change | Why its own commit |
|---|---|---|
| 1.1 | **G1**: have the trust-page check call `Attestation.valid_on(current_day)` instead of comparing against `report.as_of`; add a test that fails on a lapsed attestation | Compliance control behaviour. **Nine-day fuse** — MAN-01/MAN-02 lapse 2026-10-22 |
| 1.2 | **G2**: bump `.pre-commit-config.yaml:36,44` to the `pyproject.toml` pins, then run `pre-commit run --all-files` in the same change | A formatter bump will itself produce a wide diff |
| 1.3 | **G3**: add `uv lock --check` and `check_version_sync.py` to §7; either wire `compileall` into CI or drop the §7 claim; extend `tests/unit/test_gate_scope_parity.py` to assert the gate **list**, not only scopes | Changes the contributor contract |
| 1.4 | MAN-01 passes on an attestation whose own note records half the control unmet (`compliance/controls.py:509`) | Pairs with 1.1 |
| 1.5 | `ALLOWED_EGRESS_HOSTS` (`.env.example:31`) reads as a security control's config surface; the allow-list is hardcoded in `agents/tools/llm.py:31` and `rag/embeddings.py:27`. Wire it, or mark it documentation-only | Either branch changes a control's configurability or amends a security claim |

### Stage 2 — public-facing falsehoods. One or two commits.

`docs/index.html` `:654`, `:690` → `2.1.0`; `:682` → a real, honestly labelled test figure (and
the upstream copy at `portfolio/case_study_soc_analyst_v0.2.md:80`); `:678` agent count;
`:891-895` quality-gate block (omits four of ten steps) and `:849` "7-stage" vs eight jobs.
`.github/ISSUE_TEMPLATE/config.yml:4` → `IRsoctierDT/IANUA`. The string edits are trivial; the
point is adding these surfaces to `check_version_sync.py` / `prepare_release.py` so they do not
recur next release.

### Stage 3 — stale one-liners, safe to batch into a single commit.

Pure comment/doc deletions, no behavioural effect. `.github/CODEOWNERS:2,4-6` together with
`docs/DETECTION_INTELLIGENCE_PLAN.md:128-129` (must land together; closing check is
`git grep -n '@owner'` returning zero) · `docs/USAGE_GUIDE.md:5` `venv/` → `.venv/` ·
`.pre-commit-config.yaml:2` ("Rename to … at the repo root" — already there) ·
`.github/PULL_REQUEST_TEMPLATE.md:23` STITCHES → STICHES ·
`docs/DETECTION_INTELLIGENCE_PLAN.md:75-80` "this PR" → #156/#157/#158/#158/#159 ·
`security/sbom/README.md` counts at L16/44/45/47/49/127 (wrong by 5-6) · `AGENTS.md:293` ·
the five dead `.env.example` keys, including `:50`'s false "`update_attack.py --build` reads
from here" (it hardcodes `STAGING_DIR` at `scripts/update_attack.py:58`).

### Stage 4 — the generator. Root cause of roughly a third of the audit.

`scripts/generate_docs_from_design.py` must be fixed **before** any of its sixteen outputs:
`write()` at `:17` overwrites unconditionally, so file-only edits self-revert. It also asserts it
derives docs from `DESIGN.md` and reads nothing from it.

Group: the `STICHES/DESIGN.md` dead path — including the separate `# STICHES / DESIGN.md`
spelling at `:536` a literal find/replace will miss · stale mypy/bandit scopes at `:218-219` ·
the agent-blueprint partition at `:128-178` · the DESIGN.md-tokens falsehood at `:544-548` ·
v2.0.0 completeness claims at `:53-87`, `:356-396`. Then one regeneration run.

**4.x — add `--check` to this generator and wire it into §7.** This is the single highest-leverage
structural fix in the plan: it is what makes Stage 4 stick.

Also `package.json:8-9`: the shell `>` redirect truncates `theme.css` and
`tailwind.theme.json` before `npx` runs, so a failed export leaves an empty committed artifact.
These two scripts are **not** spurious — `docs/DESIGN_MD_IMPLEMENTATION.md:28-32` documents
exactly this export mechanism — so do not delete them. Wrap each in a write-to-temp-then-rename
so a failure leaves the previous artifact intact.

### Stage 5 — map and scope reconciliation. One commit each; mechanical but wide.

AGENTS.md §4 tree, DESIGN.md §4 table, and the README Layout block each publish a *different*
layout, and §4 calls itself "the canonical map" while omitting seven of the 24 non-hidden
real tracked top-level
directories: `architecture/`, `cli/`, `dashboards/`, `prompts/`, `reports/`, `research/`,
`workflows/`. Consequence is concrete — AGENTS.md §2 pre-flight tells an agent to "confirm the
change belongs where you intend to put it" against this map.

Disambiguate the two near-homograph pairs explicitly: `dashboard/` (the real Streamlit package)
vs `dashboards/` (one concept doc), and `.github/workflows/` (CI) vs `workflows/` (one operator
doc). Also drop the mapped-but-absent `data/` entry.

`cli/` holds documented user entry points yet sits outside mypy, bandit, coverage and
`packages.find` — annotate both `def main() -> None:`, decide `__init__.py` vs
`[project.scripts]`, and add smoke tests **in the same commit** as any `COVERAGE_SCOPE` change or
the 85% floor fails.

Then AGENTS.md §8 stage 2: replace its restated six-package "full scope" with a pointer to §7 —
**after** 1.3, so §7 is correct before anything defers to it.

### Stage 6 — lower-consequence prose.

`ingest/README.md:19` claims four downstream consumers read `NormalizedEvent`; none import it
(the package's own PR recorded this honestly as residual risk — the README overstates it).
`ingest/schema.py:3` "Today the platform…" · `DESIGN.md:303-307` (§10 lists five shipped controls
as "Future Enhancements") · `DESIGN.md:327` with `compliance/engine.py:73-75` (the published
trust page claims 100% / 16-of-16 coverage, which DESIGN.md says manual attestations hold below
100%) · `knowledge-base/mitre/enterprise_attack_overview.md:38-46` (RAG corpus still describes
the pre-`agents/mapping/` two-technique mapper — a stale *retrieval* source, so it can be cited
back as current) · `detections/behaviors/README.md:27` (asserts syslog-only ingest that
`ingest/` superseded) · sibling-repo labelling in `README.md:154` and
`docs/dashboard/STREAMLIT_DASHBOARD.md:21` (tells the reader to run `mcpscan`, which ships in
another repo) · `mcp/transport.py:32` via `agents.__version__` · `MCP_ROOT` into `.env.example` ·
`.gitignore:21` plus rename-gate eligibility · `docs/case-studies/agent-trust-broker-gate.md:37`
(cites EAODS / PAT-0001 / EAODS-CTRL-000184 / THR-0002, none of which exist here) ·
`.devcontainer/devcontainer.json:4`.

### Three orphaned dashboard mockups — decide, do not leave

`dashboard/activity_timeline.html` (480 lines), `dashboard/agent_roster.html` (374) and
`dashboard/mission_control.html` (605) are referenced by **no** `.py`, `.md`, `.toml`, `.yml` or
`.json` in the repo, yet sit in the directory AGENTS.md §4 maps as the Streamlit command center.
They assert live operational state — `agent_roster.html:252` reads
`12 agents · 9 active · 3 idle`, with hardcoded rows including `Scanning prod-cluster` and
`Enriching IOCs across 14 feeds` — and brand themselves `SENTINEL` with no IANUA, outside the
carve-out `docs/Changelog.md:342` records ("SENTINEL remains the landing page's design wordmark
only"). They fetch external resources at render time (`fonts.googleapis.com`,
`fonts.gstatic.com`) — though **not uniquely**: `docs/index.html`, `docs/status.html` and
`docs/trust.html` load the same hosts, and unlike these mockups those three are actually
published. If third-party font fetching from the Pages site matters, it is those three that
matter.

Two accuracy notes so this is not overstated: they do **not** ship in the wheel
(`[tool.setuptools.package-data]` declares no dashboard HTML), and nothing serves them. Options:
document them as mockups, move them out of `dashboard/`, or delete them.

---

## 5. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| G1 left unfixed past 2026-10-22 | Two manual compliance controls lapse and **nothing goes red**; the trust page keeps publishing them as attested | Stage 1.1, inside nine days |
| A reader trusts the security-control inventory | SECURITY.md promises CodeQL alongside bandit. In-repo evidence says it was migrated to GitHub default setup and was running in August; it is absent from recent PR check lists. Bandit itself covers 6 of 24 non-hidden top-level dirs | Stage 0: confirm default setup in Settings. Do **not** restate the claim either way until then |
| A vulnerability reporter follows the issue chooser | Lands on a 404 (`OWNER/REPO`); even once fixed, private reporting is off and Issues are disabled | Stage 0 + 2.x together, never separately |
| An agent trusts AGENTS.md §4 during pre-flight | Writes code into the wrong directory, or into one of the four single-file dirs that look like packages. Seven of the 24 non-hidden tracked top-level directories are unmapped (27 including `.devcontainer/`, `.github/`, `.streamlit/`) | Stage 5 |
| Generated files edited before the generator | Edits silently self-revert on the next run; reviewers see a correct diff that does not survive | Stage 4 ordering is mandatory |
| `REPLACEMENTS` entries added without their content fixes | `--check` fails immediately; CI goes red | Each table entry and its edits in the **same** commit |
| Fixing by `rename_to_ianua.py --apply` | Produces `ianua-mcp-stub` — keeps "stub", changes only the prefix | Edit `mcp/transport.py:32` by hand |

---

## 6. Cost Considerations

Zero infrastructure. Stages 2, 3 and 6 are string edits. Stage 1 is five small reviewed changes.
Stage 4 is the real work — the generator plus one regeneration. Stage 5 is mechanical but wide.

The recurring cost is what the new gates add to CI: four `--check`-style assertions
(self-description ↔ reality, gate list ↔ CI, published stats ↔ sources, generator ↔ outputs),
each a few seconds, all in the existing read-only drift-gate idiom.

---

## 7. Future Enhancements

1. **A self-description gate.** One script asserting: the §4 tree matches the real top level;
   SECURITY.md's control inventory matches `.github/workflows/`; §7's gate list matches CI's
   steps; `docs/index.html`'s stat strip matches `pyproject.toml` and the test count. This is the
   gate class the repository is missing entirely, and it would have caught most of this audit.
2. **Widen rename-gate eligibility** past `TEXT_SUFFIXES` to cover tracked suffixless files.
3. **A dated-assertion convention.** Every `NOTE (date):` carries an expiry, and a gate fails
   when one is past due — the generalisation of the CODEOWNERS case, where a *fixed* problem kept
   advertising itself as broken.

---

## Appendix — audit provenance

68 candidate findings from 7 parallel dimensions (placeholders · identity · structure ·
duplication · stale assertions · gate gaps · cross-repo), each adversarially verified by three
independent lenses; 65 survived, clustering to 38 distinct issues. Convergence is corroboration:
the AGENTS.md §4 map and the §8 mypy scope were each surfaced independently by 7 of 7 dimensions,
SECURITY.md precedence by 6.

The verification pass earned its cost twice. It **disproved the headline** of the CodeQL finding
("no CodeQL configuration has ever existed") using a Dependabot branch name inside the finding's
own cited CI log — the honest framing is a *removed* control, not an absent one. And the
completeness critic **reinstated two findings the verifiers wrongly killed**, one of them G1, the
most consequential item in the audit.

Recorded clean, so nobody re-spends the effort: zero broken relative Markdown links repo-wide;
all `github.com` URLs on the published site correct; no `.sh`, Dockerfile, `.cjs` or `.mjs` files
exist; `.streamlit/config.toml` and `.gitleaks.toml` clean; every `scripts/*.py` named in §7
exists; `main` is branch-protected; `CLAUDE.md` is a genuine symlink; `IANUA-Broker` references
point at a public repo, and the private `IANUA-Marketplace` appears only inside `research/`.

---

## Appendix B — why this document does not quote the legacy identifiers

Two findings above concern literal pre-IANUA strings. This document describes them rather than
reproducing them, because `scripts/rename_to_ianua.py --check` is a merge-blocking gate and
AGENTS.md §5 forbids weakening an existing control so that new code — or a new document — passes.
Excluding this file from the gate was the easier option and the wrong one.

That is not a workaround; it is the finding demonstrating itself. On first draft the gate caught
exactly two of the four legacy identifiers in this file. It missed the other two for precisely
the reasons documented in §3: one is absent from the `REPLACEMENTS` table, and the other sits in
a suffixless file **and** differs in case. The gate works, within a scope narrower than its own
summary line in AGENTS.md §7 claims.

To inspect the literals, read the cited lines directly: `mcp/transport.py:32` and
`.gitignore:21`.

---

## Appendix C — corrections after review

An audit's only value is that its claims hold, so the review round that corrected it belongs in
it. Codex reviewed commit `a2a4148` and raised eight findings; seven were correct and are fixed
above. Recorded because the pattern is instructive — most were *overreach*, not invention: a
real defect described one notch more strongly than the evidence supported.

| # | Claim as first written | Correction |
|---|---|---|
| 1 | CodeQL is a **removed** control with stale docs (P1) | Wrong. Commit `b05139f` shows it was *migrated* to GitHub default setup, which deliberately has no in-repo file. Reclassified to unverifiable-from-a-clone; SECURITY.md:59 presumed accurate |
| 2 | `Attestation.is_current(day)` exists and is called nowhere | Wrong on both counts. The predicate is `valid_on(day)`, and `compliance/engine.py:101` plus four tests call it. The frozen-`as_of` defect itself stands |
| 3 | The toolchain gap disproves §8's "mirrored exactly in CI" | Overreach. AGENTS.md:365-366 licenses pre-commit as "the fast subset", so it falsifies the hooks' own mirror comments, not §7-vs-CI parity. `mypy>=2.4.0` is also a floor, not a pin |
| 4 | "Four tracked files are suffixless" | Wrong, and internally inconsistent — it then listed five. There are **nine**, six content-bearing, and `.gitleaksignore` was missed entirely |
| 5 | The mockups are the **only** files fetching external resources | False. `docs/index.html`, `docs/status.html` and `docs/trust.html` load the same font hosts and are actually published — the more consequential instances |
| 6 | Seven of **23** top-level directories unmapped | Wrong denominator: 24 non-hidden tracked, 27 including dotted. The seven named were correct |
| 7 | Delete `package.json:8-9` | Wrong prescription. `docs/DESIGN_MD_IMPLEMENTATION.md:28-32` documents those `>` redirects as the intended export mechanism. The real defect is the empty artifact a failed `npx` leaves; fix is write-to-temp-then-rename |
| 8 | (no status column) | Correct — the header promised one and none existed. Added as §0 |

Two of these were self-inflicted in a way worth naming. The predicate name came from a survey
agent and was never checked against the `def` line, even though the surrounding lines were read.
And the CodeQL conclusion was reached despite this same session having earlier observed a green
check literally named `CodeQL` on PR #159 — evidence already in hand and not reconciled. The
adversarial pass that caught the finding's *other* overstatement did not catch either, which is
the honest limit of three verifiers who share the finding's framing.
