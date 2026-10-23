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

   **Then rewrite the prose it could not.** The script substitutes the version and title in
   `docs/PROJECT_STATUS.md`'s current-version line and leaves the editorial sentences after it, so
   they still describe the *previous* release. It prints an `ACTION NEEDED` notice naming the file
   for exactly this reason — v2.2.0 shipped with a "Release Automation & Control Integrity" heading
   above a paragraph about the v2.0 rename era, caught only because a human read the diff. Check
   the same for any hand-written release summary.

   Also confirm `## Unreleased` actually covers everything merged since the last tag. Promotion is
   one-way: whatever is in that section becomes the permanent `## vX.Y.Z` record **and** the
   published release body (step 5).
3. **Run the full gate** (AGENTS.md §7), then open the PR titled `release: prepare IANUA v2.2.0`.
4. **Merge** once CI and review pass.
5. **Approve two deployments** when they appear in the Actions tab:
   - *Release on version bump → Tag and publish* (`release` environment) creates tag `v2.2.0` at the
     merge commit and dispatches **Release assets**, which rebuilds, re-runs the full test gate,
     signs, and creates the GitHub Release.
   - *Deploy GitHub Pages* (`github-pages` environment) publishes the updated site.

   **Never publish a release from the web page.** Release immutability is enabled (see
   one-time setup), so a release locks the moment it is published. A release published from the
   web page locks before **Release assets** can attach anything. The workflow then fails and
   names every asset that is missing, and nothing can be added afterwards. The way out is the
   next patch version, released through steps 1–5.
6. **Verify** the release page lists the wheel, sdist, `sbom.cdx.json`, the attestation bundles
   and `SHA256SUMS`. A release published since immutability was enabled should also carry the
   **Immutable** label, and `gh release verify vX.Y.Z --repo IRsoctierDT/IANUA` checks the
   attestation GitHub signs for an immutable release. No release has been checked that way yet,
   because v2.3.0 was published before the setting.

### One-time setup

Go to **Settings → Environments → New environment**, name it `release`, and add yourself under
**Required reviewers**. Set **Deployment branches** to `main` only. The `publish` job checks for a
required reviewer before it tags anything and refuses to run without one. GitHub would otherwise
auto-create an unprotected environment.

Then go to **Settings → General → Releases** and tick **Enable release immutability**. The owner
enabled it on 2026-10-23. From then on a published release's tag cannot be moved or deleted, and
its assets cannot be added, replaced or removed. Its title and notes can still be edited
([GitHub Docs](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)).
GitHub fixes this per release when the release is published, so v2.3.0 and every earlier release stay
mutable. The flow above is unaffected: `gh release create` attaches every asset to a draft and
publishes last (its own `--help` says so). `release.yml` reads each release's immutability before
a repair. It re-uploads only to a mutable release, only checks that an immutable one has all its
assets, and fails when it cannot tell which kind it has. Unticking the setting affects only
releases published afterwards. A release published while it was on stays locked.

## Risks

| Risk | Control |
|---|---|
| Version surfaces drift | One atomic script (partially generated output is rolled back too); `check_version_sync` in CI, in `detect`, and again in `release.yml` |
| Tag on an unverified commit | Tag created only at the `head_sha` of a successful CI push run on `main` |
| Tag moved or overwritten | Git refs API create-only; a re-run accepts an existing tag only if it names the same commit; `release.yml` never force-updates. Since 2026-10-23, release immutability also has GitHub refuse to move or delete the tag of a published release |
| Published assets replaced after release | Release immutability (repository setting): a release's assets lock when it is published. `gh release create` attaches them all to a draft before publishing |
| A release published from the web page | It locks with no assets. `release.yml` never uploads to an immutable release: it fails and names each missing asset (`tests/security/test_release_immutability.py`). The remedy is the next patch version, never a repair |
| Repair of a release that predates immutability | `release.yml` reads `isImmutable` for each release. It re-uploads only on `false` and refuses to guess on anything else, including a `gh` too old to know the field |
| Dispatch fails after tagging | `detect` re-offers a tagged version that has no GitHub Release, at the tagged commit, behind the same approval |
| Unapproved publication | `release` environment with required reviewer, checked at runtime (fails closed) |
| Malformed release title | Allowlisted characters; no Markdown control characters or parentheses |
| Release notes that ignore the curated changelog | `scripts/release_notes.py` composes the body from the promoted `## vX.Y.Z` section; a missing or empty section fails the publish rather than shipping blank notes |
| A later commit lands before approval | The tag still pins the detected commit, not the branch head |

## Cost Considerations

Free on GitHub-hosted runners. A release adds about two short jobs plus the existing
`release.yml` build. No secrets or third-party services are used, only `GITHUB_TOKEN`.

## Future Enhancements

- Signed tags, once a signing identity is available to Actions.
- Restore merged-PR attribution alongside the curated notes (the compare link carries the full
  commit record today, but not the contributor list `--generate-notes` used to produce).
