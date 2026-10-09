# Releasing IANUA

> **Purpose:** cut a versioned IANUA release, from version bump to signed GitHub Release and
> refreshed GitHub Pages site. · **Risk level:** medium (externally visible) · **Skill level:**
> maintainer · **Deployment complexity:** low (one command, one PR, two approvals)

## Executive Summary

A release used to be a manual edit of about a dozen files: the v2.1.0 release (#178) took sixteen
commits. It is now one local command plus one pull request. Everything after the merge is
automated, and every externally visible step still waits for a named human approval
(AGENTS.md §5.1).

## Objectives

- Every version surface moves together, or nothing moves (atomic, fail-closed).
- The tag points at the exact commit CI proved green, and existing tags are never moved.
- Publishing (tag, GitHub Release, Pages) never happens without a human approving it.

## Process

```
prepare_release.py ──► PR "release: prepare IANUA vX.Y.Z" ──► review + merge
                                                                    │
                                     CI green on main ◄─────────────┘
                                       │                      │
                     release-on-merge.yml                pages.yml
                     detect: untagged version?           (approval: github-pages)
                     publish (approval: release)              │
                       ├─ tag vX.Y.Z at the CI commit         ▼
                       └─ dispatch release.yml          GitHub Pages refreshed
                            build · validate · sign ·
                            GitHub Release + assets
```

| Stage | Automation | Human gate |
|---|---|---|
| Bump all version surfaces | `scripts/prepare_release.py` | PR review |
| Detect the new version | `release-on-merge.yml` (`detect`) | — |
| Tag + GitHub Release with dists, SBOM, attestations, `SHA256SUMS` | `release-on-merge.yml` (`publish`) → `release.yml` | `release` environment |
| Publish `docs/` to GitHub Pages | `pages.yml` | `github-pages` environment |

## Implementation Steps

1. **Collect changes under `## Unreleased`** in [`docs/Changelog.md`](./Changelog.md) as you merge
   work. The release script refuses to run if that section is empty.
2. **Prepare the release** on a branch:

   ```bash
   python scripts/prepare_release.py 2.2.0 --title "Live Tool Inspection" --dry-run   # list files
   python scripts/prepare_release.py 2.2.0 --title "Live Tool Inspection"
   ```

   This updates `pyproject.toml`, `uv.lock`, `package.json`, `package-lock.json`, both SBOM roots,
   `docs/status.data.json`, `docs/Changelog.md`, `docs/PROJECT_STATUS.md`, `SECURITY.md` (minor and
   major bumps only) and the version-sync test pin. It then regenerates the status page and README
   and runs `check_version_sync`. Any failure restores every file to its original bytes.
3. **Run the full gate** (AGENTS.md §7), then open the PR titled `release: prepare IANUA v2.2.0`.
4. **Merge** once CI and review pass.
5. **Approve two deployments** when they appear in the Actions tab:
   - *Release on version bump → Tag and publish* (`release` environment) creates tag `v2.2.0` at the
     merge commit and dispatches **Release assets**, which rebuilds, re-runs the full test gate,
     signs, and creates the GitHub Release.
   - *Deploy GitHub Pages* (`github-pages` environment) publishes the updated site.
6. **Verify** the release page lists the wheel, sdist, `sbom.cdx.json`, the attestation bundles
   and `SHA256SUMS`.

### One-time setup

Go to **Settings → Environments → New environment**, name it `release`, and add yourself under
**Required reviewers**. Set **Deployment branches** to `main` only. The `publish` job checks for a
required reviewer before it tags anything and refuses to run without one. GitHub would otherwise
auto-create an unprotected environment.

## Risks

| Risk | Control |
|---|---|
| Version surfaces drift | One atomic script; `check_version_sync` in CI, in `detect`, and again in `release.yml` |
| Tag on an unverified commit | Tag created only at the `head_sha` of a successful CI push run on `main` |
| Tag moved or overwritten | Git refs API create-only; `release.yml` never force-updates |
| Unapproved publication | `release` environment with required reviewer, checked at runtime (fails closed) |
| Malformed release title | Allowlisted characters; no Markdown control characters or parentheses |
| A later commit lands before approval | The tag still pins the detected commit, not the branch head |

## Cost Considerations

Free on GitHub-hosted runners. A release adds about two short jobs plus the existing
`release.yml` build. No secrets or third-party services are used, only `GITHUB_TOKEN`.

## Future Enhancements

- Generate release notes from the promoted Changelog section instead of `--generate-notes`.
- Signed tags, once a signing identity is available to Actions.
