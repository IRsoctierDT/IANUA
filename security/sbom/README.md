# Software Bill of Materials (SBOM)

> **Purpose:** Machine-readable inventory of every third-party component shipped
> or built into the AI Operator Cyber Command Center, with provenance and known
> vulnerability data — for supply-chain transparency, audit, and SCA gating.
> **Risk level:** Low (read-only inventory; contains no secrets or PII).
> **Skill level required:** Intermediate (CycloneDX / SCA familiarity).
> **Deployment complexity:** Low (single script, no services).

---

## Executive Summary

This directory holds a [CycloneDX](https://cyclonedx.org/) SBOM covering the
repository's **two package ecosystems** — Python and npm. The merged document
(`sbom.cdx.json`) inventories **259 components** (116 Python + 143 npm) and, at
generation time, **0 known vulnerabilities** per the public PyPI/OSV advisory
databases.

The canonical SBOM is generated from a **pinned lockfile of the declared
dependency closure** ([`requirements.lock`](./requirements.lock) —
`pip install -e ".[dev,dashboard]"`: Streamlit, qdrant-client,
sentence-transformers and their transitive stack). Generation is **byte-for-byte
reproducible** for a fixed timestamp. All 143 npm components are `dev` build
tooling (none ship at runtime); declared Python *runtime* dependencies are empty.

> A `pip-audit` run against the maintainer's **shared** pyenv environment
> reported 168 vulnerabilities — every one traced to stale/ambient packages
> **not** in this project's declared closure. See [`VULN_TRIAGE.md`](./VULN_TRIAGE.md).

## Objectives

1. Provide an auditor-ready, standards-based component inventory.
2. Attach known-vulnerability data so the SBOM doubles as an SCA snapshot.
3. Keep generation **deterministic, offline (for npm), and reproducible**.

## Artifacts

| File | Format | Scope | Source |
|---|---|---|---|
| `requirements.lock` | pip requirements | 117 pinned Python deps | `pip freeze` (clean closure) |
| `python.cdx.json` | CycloneDX 1.4 | 116 Python components | `pip-audit -r requirements.lock` |
| `npm.cdx.json` | CycloneDX 1.5 | 143 npm components | `package-lock.json` (offline) |
| `sbom.cdx.json` | CycloneDX 1.5 | **Merged** 259 components | both, via `generate_sbom.py` |

`sbom.cdx.json` is the canonical artifact. **Every** component carries a
[purl](https://github.com/package-url/purl-spec) — `generate_sbom.py` backfills
`pkg:pypi/...` purls that `pip-audit` omits (PEP 503 normalised). For
reproducibility it also rewrites `pip-audit`'s random `bom-ref` values to the
stable purl (remapping vulnerability `affects` refs so linkage is preserved), so
the output is **byte-identical across runs** for a fixed `--timestamp`. npm
components include SHA-512 hashes decoded from lockfile integrity strings for
provenance verification.

## Process / Architecture

```
package-lock.json ─┐                            (offline, deterministic)
                   ├─► scripts/generate_sbom.py ─► npm.cdx.json
pip-audit ─► python.cdx.json ─────────┘         └─► sbom.cdx.json (merged)
   ▲
   └── queries public PyPI/OSV advisory DB (network; sanctioned SCA gate, AGENTS.md §7)
```

The npm half is built **entirely from the committed lockfile** — no network, no
new dependency. The Python half reuses `pip-audit`, already wired into the
required checks (AGENTS.md §7), which is the **only** step that touches the
network (to enrich with advisories).

## Implementation Steps (regeneration)

Run from the repository root, using the project interpreter (pyenv 3.12.4):

```bash
# 0. (Only if dependencies changed) refresh the lock from a CLEAN venv:
python -m venv /tmp/sbomenv && /tmp/sbomenv/bin/pip install -e ".[dev,dashboard]"
/tmp/sbomenv/bin/pip freeze | grep -v '^-e ' | sort -f >> security/sbom/requirements.lock
#   ...then restore the header comment block at the top of the file.

# 1. Audit + emit the Python SBOM from the pinned lock (advisory lookup):
python -m pip_audit -r security/sbom/requirements.lock \
  -f cyclonedx-json -o security/sbom/python.cdx.json --progress-spinner off

# 2. Build the npm SBOM and merge (offline, deterministic):
python scripts/generate_sbom.py --timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

> `pip-audit` exits non-zero when vulnerabilities are found; this is expected
> and does **not** indicate SBOM generation failure — `python.cdx.json` is still
> written. CI uses the same lock as a **gate** (see `.github/workflows/ci.yml`):
> a non-zero exit there blocks the merge.

## Risks

- **Fact vs. snapshot:** the 0-vulnerability result reflects advisory data *at
  generation time* against a clean declared-closure install; regenerate to
  refresh. Auditing a stale or shared environment will report more (see
  `VULN_TRIAGE.md`).
- **Network egress:** Step 1 sends installed package names/versions to the
  public advisory service (PyPI/OSV). No secrets or source are transmitted. The
  npm step has no network access.
- **Lock drift:** `requirements.lock` is a `pip freeze` snapshot, not a
  hash-pinned resolution. It must be regenerated from a clean venv whenever the
  `[dev,dashboard]` extras change, or the SBOM and the installed code diverge.
  Hash-pinning (`--require-hashes`) is the next hardening step (see below).

## Cost Considerations

Zero added cost: no new third-party dependency was introduced. `pip-audit` was
already a required SCA gate; the npm path uses only the standard library.

## Future Enhancements

1. **Hash-pin** the lock (`pip-compile --generate-hashes` / `uv pip compile`) and
   add `--require-hashes` so installs are tamper-evident, not just version-pinned.
2. Automate lock/SBOM refresh on dependency-PRs (Dependabot/Renovate) so the
   committed SBOM never drifts from `pyproject.toml`.
3. Attest the SBOM (in-toto / Sigstore) for end-to-end provenance.

> **Done in this change:** lockfile pinning (`requirements.lock`),
> byte-reproducible generation, and a CI gate that fails on newly introduced
> advisories against the pinned closure.
