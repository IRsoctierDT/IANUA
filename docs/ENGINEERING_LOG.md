# Engineering Log

Newest entries first. Each entry records what was built, what was learned, and
what it points to next — the working notes behind the polished
[Changelog](./Changelog.md) and [case studies](./case-studies/README.md).

## 2026-07-22

### v2.0.0 — Master v2 STICHES Edition (release cut)

Platform version 1.9.0 → 2.0.0; edition identity Master v1 → v2. One line in
`pyproject.toml` re-versioned every agent because agent names derive from the
project version; locks, SBOM, and status page regenerated through their drift
gates.

Lessons Learned:

- Single-source versioning pays for itself at release time: zero per-agent
  edits, and the drift-gate test guarantees it stays that way.
- Drift gates (locks/SBOM/status-page `--check` jobs) turn "regenerate
  everything" from a risky chore into a mechanical, verifiable step.

Future Work:

- Tag `v2.0.0` on the merge commit (Changelog convention: versions ↔ tags).

---

### IANUA rename completed; migration tooling repaired

The rename workflow could never pass: running the migration with `--apply`
rewrote the script's own `REPLACEMENTS` table into identity mappings, after
which `--check` flagged every occurrence of the *new* name. Fixed by making
the script exclude itself, completing the rename in-tree, and converting the
workflow into a read-only guard (`contents: read`, checks the ref under test).

Lessons Learned:

- A migration script whose data tables contain the strings being migrated
  **must exclude its own source file** — otherwise `--apply` corrupts the tool
  and `--check` can never pass while the tool exists.
- Line-based find/replace misses identifiers wrapped across line breaks; a
  multiline scan is the only honest completeness check.
- A squash-merge captures the PR head at merge time — a commit pushed moments
  before can miss the train. Verify merged *content*, not just merge status,
  before restarting branches.
- CI that checks out a fixed side branch judges every PR by unrelated code;
  guards must always test the ref under review.

---

### Dashboard: correlated batch pipeline + interactive test enablement

Batch tab now runs one `process_sequence` over the uploaded log (correlated
findings, verified citations, sequence incident report) instead of N isolated
per-line analyses. Added a Codespaces devcontainer (one click from the repo
page → live dashboard on port 8501), bundled sample scenarios from
`sample-logs/` (fixed allow-list), and fail-soft knowledge-base search that
degrades from Qdrant semantic to the offline lexical corpus with the serving
backend labelled.

Lessons Learned:

- GitHub Pages is static hosting; "try it from the GitHub website" means
  Codespaces, not Pages.
- Degraded results must be labelled as degraded — silent fallback would pass
  lexical results off as semantic ones.
- Fail-closed engines need fail-soft UIs: catch the pipeline's validation
  errors at the edge and show a message, never a traceback.

Future Work:

- Qdrant embedded mode (`QdrantClient(path=...)`) to make semantic search
  service-free everywhere — the last piece of the $0 architecture.

---

### CI/supply-chain interrupts (fixed in passing)

`pip-audit` gate caught gitpython 3.1.50 (3 GHSAs; bumped to 3.1.54 at the
lock level, SBOM regenerated). Dependabot aborted its runs over labels that
did not exist in the repo; label references removed from `dependabot.yml`
(nothing keyed off them).

Lessons Learned:

- SCA gates fail on advisories that move underneath a *pinned, unchanged*
  lock — that is the gate working as designed, not a regression.
- Dependabot fails the whole run on a missing label; configure labels only
  after creating them.

## 2026-06-02

### Local AI Stack

Completed local AI stack with:

- Ollama
- Qwen3:4B
- Qdrant
- Sentence Transformers

Lessons Learned:

- Virtual environments must be explicitly activated.
- VS Code interpreter selection matters.
- Qdrant collections should be versioned.

---

### MITRE Mapper Agent

Implemented ATT&CK mapping. Unit tests created for T1110 and T1078 mappings.

Lessons Learned:

- Deterministic mappings should precede LLM inference.
- LLM reasoning can be added later.
- Confidence scoring is necessary.

Future Work:

- Add ATT&CK data ingestion.
- Add confidence scoring.

---

### Threat Intelligence Agent

Implemented indicator classification.

Future Work:

- AbuseIPDB integration
- VirusTotal integration
- AlienVault OTX integration
