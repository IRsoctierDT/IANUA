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
(`sbom.cdx.json`) inventories **281 components** (138 Python + 143 npm) and, at
generation time, **0 known vulnerabilities** per the public PyPI/OSV advisory
databases.

The canonical SBOM is generated from a **hash-pinned lockfile resolved for the
Linux deployment target on Python 3.12** ([`requirements.lock`](./requirements.lock),
the Linux/3.12 subset of [`uv.lock`](../../uv.lock)). It therefore includes the
NVIDIA CUDA runtime stack that `torch` pulls in on Linux (`nvidia-*`, `triton`) —
real, shipped, security-relevant components a macOS resolution would omit. The
SBOM is generated with `pip-audit --disable-pip`, which reads the pinned file
directly (no resolver), so generation is **deterministic and platform-independent**
and byte-for-byte reproducible for a fixed timestamp. All 143 npm components are
`dev` build tooling (none ship at runtime); declared Python *runtime* deps are empty.

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
| `../../uv.lock` | uv lock (TOML) | **source of truth** — universal, hashed, all extras (144 pkgs) | `uv lock` from `pyproject.toml` |
| `requirements.lock` | pip requirements (hashed) | 138 Linux/3.12 deps (full `[dev,dashboard]`, incl. CUDA) | `uv pip compile --python-platform linux` |
| `requirements-dev.lock` | pip requirements (hashed) | 52 SHA-256 hash-pinned `[dev]` tools | `uv export --extra dev` (from `uv.lock`) |
| `python.cdx.json` | CycloneDX 1.4 | 138 Python components | `pip-audit --disable-pip -r requirements.lock` |
| `npm.cdx.json` | CycloneDX 1.5 | 143 npm components | `package-lock.json` (offline) |
| `sbom.cdx.json` | CycloneDX 1.5 | **Merged** 281 components | both, via `generate_sbom.py` |

**`uv.lock` (repo root) is the dependency source of truth.** It is the universal,
hashed resolution of `pyproject.toml`; CI fails closed via `uv lock --check` if
`pyproject.toml` changes without re-locking. `requirements-dev.lock` is exported
from it; `requirements.lock` remains a platform-resolved snapshot for the SBOM/SCA
(see [Future Enhancements](#future-enhancements) for migrating it to a uv export).

The CI **Security job** installs its own tools from `requirements-dev.lock` under
`pip install --require-hashes`, so the toolchain that runs with repository access
is tamper-evident, not just version-pinned.

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
# 0. (Only if dependencies changed) refresh uv.lock and the exported pip locks:
uv lock                                                    # source of truth
uv pip compile pyproject.toml --all-extras --generate-hashes \
  --python-platform x86_64-unknown-linux-gnu --python-version 3.12 \
  --no-header --no-annotate -o security/sbom/requirements.lock   # re-add header
uv export --extra dev --no-emit-project --no-annotate --no-header \
  -o security/sbom/requirements-dev.lock                  # re-add header

# 1. Emit the Python SBOM from the pinned lock. --disable-pip reads the hashed
#    file directly (no resolver), so this is platform-independent — the Linux
#    CUDA packages don't need to be installable on the machine generating it:
python -m pip_audit --disable-pip -r security/sbom/requirements.lock \
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
- **Target platform:** `requirements.lock` and the SBOM represent the **Linux /
  Python 3.12** deployment target (its package+version set is the Linux/3.12
  subset of `uv.lock`). A macOS resolution would drop the ~22 CUDA components; a
  Windows one would swap them for `pywin32`/`colorama`. Regenerate for the chosen
  target if the deployment platform changes.
- **Generation uses `--disable-pip`:** the SBOM/SCA reads the fully-hashed lock
  directly rather than resolving it, so it never tries to install the Linux-only
  CUDA wheels — the audit runs anywhere (including macOS) and is deterministic.
  This *requires* the lock to stay fully pinned **and** hashed; an unhashed entry
  makes `pip-audit --disable-pip` fail closed.

## Cost Considerations

Zero added cost: no new third-party dependency was introduced. `pip-audit` was
already a required SCA gate; the npm path uses only the standard library.

## Future Enhancements

1. **Attest the SBOM** (in-toto / Sigstore) for end-to-end provenance.
2. **Auto-regenerate the SBOM on Dependabot lock bumps** (a workflow that reruns
   the export + `generate_sbom.py` and commits to the PR), so the committed SBOM
   never lags `uv.lock`. Deferred for the security review of an auto-committing,
   write-scoped workflow.

> **Done:** `uv.lock` as the dependency source of truth (`uv lock --check` gate);
> `requirements.lock` hash-pinned and resolved for the **Linux/3.12 deployment
> target** (SBOM includes the CUDA stack); SBOM generated with
> `pip-audit --disable-pip` (platform-independent, byte-reproducible); a CI gate
> that fails on newly introduced advisories; **hash-pinned `[dev]` toolchain**
> installed under `--require-hashes`; and Dependabot (`uv` + `npm` +
> `github-actions`) routing every update PR through the full supply-chain gate.
