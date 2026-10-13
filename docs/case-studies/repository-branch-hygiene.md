# Case Study — Repository Branch Hygiene & Safe Bulk Pruning

> **Diagnosing a "25 branches, 17 tags" repository and safely pruning 24 stale merged
> branches — with a reusable, fail-closed method that survives the trap where squash-merges
> defeat Git's own merge detection.**

| | |
|---|---|
| **Component** | Repository operations (`git` / GitHub, no application code) |
| **Domain** | Source-control hygiene · release management · safe destructive operations |
| **Purpose** | Restore a clean branch topology (one long-lived branch + tagged releases) without losing any un-merged work |
| **Risk level** | Medium — deleting remote refs is a mutating, outward-facing action; mitigated by content verification and a fail-closed guard (AGENTS.md §5.1) |
| **Skill level required** | Developer comfortable with Git plumbing and the `gh` CLI |
| **Deployment complexity** | Low — read-only diagnosis, then a single guarded deletion pass |

---

## 1. Executive Summary

A maintainer noticed the repository carried **25 branches against only 17 tags** and asked
whether that was expected. It was not. Tags and branches are orthogonal — tags mark
releases, branches track work — so the counts are unrelated, but **25 branches was the real
signal: merged feature branches had never been deleted.**

Diagnosis confirmed that **every one of the 24 non-`main` branches was already merged** and
that **zero pull requests were open**. The branches fell into two groups: 15 older
`feature/*` branches that Git recognized as merged, and 9 branches from the current work
cycle that had been **squash-merged** — their content was fully on `main`, but Git's
content-based merge detection could not see it.

That second group is the core finding. **Squash-merge collapses a branch into a single new
commit with a fresh patch identity, so `git branch --merged`, `git cherry`, and even
`git diff main <branch>` all give misleading answers.** The authoritative signal is the pull
request's `MERGED` state, not any local Git heuristic.

**Outcome:** 24 remote branches and 30 local branches were removed after verification;
`main` plus the release tags were left untouched; nothing un-merged was deleted; and the
repository returned to the conventional, tidy state of **one long-lived branch + tagged
releases**.

---

## 2. Objectives

1. Explain the "25 vs 17" observation truthfully (branch/tag counts are unrelated).
2. Establish, before deleting anything, that each branch is **safe** — its work already on
   `main` and no open PR depending on it.
3. Delete stale branches **fail-closed**: verify first, exclude `main`, abort if any PR is open.
4. Avoid the squash-merge trap that makes merged branches look un-merged.
5. Leave a **repeatable method** and a durable prevention so the drift does not recur.

---

## 3. Architecture / Process

```
                 ┌─────────────────────────────────────────────────────┐
                 │ 1. DIAGNOSE  (read-only)                             │
                 │    git fetch --prune                                │
                 │    git branch -r                → 25 branches        │
                 │    git branch -r --merged main  → 15 confirmed merged│
                 └───────────────────────┬─────────────────────────────┘
                                         ▼
                 ┌─────────────────────────────────────────────────────┐
                 │ 2. CLASSIFY the other 9                             │
                 │    gh pr list --head <b> --state all --json state   │
                 │    squash-merged → PR state = MERGED (authoritative) │
                 └───────────────────────┬─────────────────────────────┘
                                         ▼
                 ┌─────────────────────────────────────────────────────┐
                 │ 3. GUARD  (fail closed)                             │
                 │    open_prs == 0 ?  else ABORT                       │
                 │    delete-list = all remote branches EXCEPT main     │
                 └───────────────────────┬─────────────────────────────┘
                                         ▼
                 ┌─────────────────────────────────────────────────────┐
                 │ 4. DELETE  (mutating, one pass)                     │
                 │    git push origin --delete <list>                  │
                 │    then prune local: -d where safe, -D where a       │
                 │    MERGED PR confirms squash-equivalence             │
                 └─────────────────────────────────────────────────────┘
```

**Design invariants:**

- **Diagnosis is read-only** and repeatable; nothing is deleted until every branch is
  accounted for.
- **PR state is the source of truth** for "is this work on `main`?" — local Git heuristics
  are advisory only.
- **Fail closed:** any open PR aborts the run; `main` is always excluded; deleted merged
  branches remain recoverable from their squash commit if ever needed.

---

## 4. Implementation Steps

### 4.1 Diagnose (read-only)

```bash
git fetch --prune origin
git branch -r | grep -v HEAD                       # 25 remote branches
git branch -r --merged origin/main | grep -v HEAD  # only 15 report as merged
gh pr list --state open --json number -q 'length'  # 0 open PRs
```

The gap between "25 total" and "15 merged" is the whole puzzle: 9 branches were merged but
did not *look* merged to Git.

### 4.2 Classify the branches Git couldn't confirm

For each remaining branch, the pull request's terminal state settles it:

```bash
gh pr list --repo <owner>/<repo> --state all --head "$b" --json number,state \
  -q '.[0] | "PR #\(.number) \(.state)"'
# → PR #43 MERGED   (squash-merged: content on main, new commit identity)
```

All nine returned `MERGED`. Combined with the 15 Git-confirmed, **all 24 non-`main`
branches were safe.**

### 4.3 Guard, then delete the remote branches (one pass)

```bash
# Fail closed: abort if any PR is open; build the list as "everything except main".
[ "$(gh pr list --state open --json number -q 'length')" = "0" ] || { echo ABORT; exit 1; }
git branch -r | grep -v HEAD | grep -v 'origin/main$' | sed 's# *origin/##' > /tmp/del.txt

git push origin --delete $(tr '\n' ' ' < /tmp/del.txt)   # 24 branches deleted
```

### 4.4 Prune local branches — the two-pass verification

The first local pass used a content heuristic and it **misfired on exactly the squash-merged
branches**, which is the lesson worth keeping:

```bash
# Pass 1 — delete only branches whose commits are already on main.
for b in $(git branch | sed 's/[* ]//g' | grep -v '^main$'); do
  if [ -z "$(git cherry main "$b" | grep '^+')" ]; then
    git branch -D "$b"          # 25 deleted safely
  else
    echo "KEPT $b"              # 5 flagged as 'has commits not on main' — FALSE POSITIVE
  fi
done
```

`git cherry` (and `git diff main <branch>`) flagged the 5 squash-merged branches as
un-merged. They were not — their work was on `main` as a single squash commit. **Pass 2
re-checked them against the authoritative signal and finished the cleanup:**

```bash
# Pass 2 — a MERGED pull request is proof the work landed; then force-delete.
for b in <the 5 flagged branches>; do
  gh pr list --state all --head "$b" --json state -q '.[0].state'   # MERGED
  git branch -D "$b"
done
```

Final state: **`main` only**, locally and remotely, with all release tags intact.

---

## 5. The Core Finding — Squash-Merge Defeats Content-Based Merge Detection

A squash-merge replays a branch's changes as **one new commit** on `main`. That commit has a
different SHA and a different patch-id than any of the branch's original commits, so every
Git heuristic that reasons about *reachability* or *patch equivalence* concludes the branch
is not merged:

| Signal | On a real (fast-forward/merge) branch | On a **squash-merged** branch |
|---|---|---|
| `git branch --merged main` | ✅ lists it | ❌ omits it (tip not an ancestor of `main`) |
| `git cherry main <branch>` | ✅ all lines `-` (equivalent) | ❌ shows `+` lines (no matching patch-id) |
| `git diff main <branch>` | ~empty if not diverged | ❌ non-empty — but mostly because **`main` moved on**, not because the branch has new work |
| **PR state = `MERGED`** | ✅ authoritative | ✅ **authoritative** |

**Takeaway:** when a repository squash-merges (as this one does — see the
[merge-strategy note](#7-cost-considerations)), judge "is this branch merged?" by the pull
request's `MERGED` state, not by local Git content heuristics. Use `git branch --merged` /
`git cherry` only as a fast first pass, and always reconcile the leftovers against PR state
before deleting.

---

## 6. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Deleting a branch with un-merged work | Permanent loss of commits | Verify **PR = MERGED** (or Git-confirmed merged) before deleting; squash-merged branches recoverable from their squash commit |
| Deleting a branch backing an open PR | Breaks review in flight | Fail-closed guard: **abort if any PR is open**; delete-list is built as "everything except `main`" |
| `git cherry` / `git diff` false "un-merged" | Good branches wrongly kept — or, if trusted blindly, wrongly deleted | Treat content heuristics as advisory; reconcile against PR state (§5) |
| Force-delete (`-D`) hides a genuinely un-merged branch | Silent data loss | `-D` used **only** after a `MERGED` PR confirms the work landed |
| Deleting `main` or a release branch | Repository breakage | `main` explicitly excluded from every delete-list; tags never touched |
| Recurrence | Drift returns next release cycle | Enable **Settings → General → "Automatically delete head branches"** (§9) |

Remote-branch deletion is a mutating, outward-facing action under AGENTS.md §5.1, so the run
paused for explicit human approval and presented the full list before executing.

---

## 7. Cost Considerations

Zero tooling cost — stock `git` and the `gh` CLI. The operation is **diagnosis-heavy and
deletion-light**: the read-only investigation is the bulk of the work, and the mutating step
is a single `git push --delete`. The ongoing cost after enabling auto-delete of head
branches is effectively nil, because merged branches are then reaped automatically.

This repository uses **squash-merge** for pull requests, which keeps `main` linear (one tidy
commit per PR, matching AGENTS.md §8's linear-history preference) — the same property that
makes the squash-merge detection trap above worth documenting.

---

## 8. Outcome

- ✅ **24 remote branches** deleted after verification; remote reduced to `origin/main`.
- ✅ **30 local branches** pruned (25 in a safe first pass + 5 squash-merged confirmed via
  PR state); local reduced to `main`.
- ✅ **All release tags intact**; nothing un-merged removed; **0 open PRs** disturbed.
- ✅ Repository restored to one long-lived branch + tagged releases.

> Branches and tags naturally diverge again as new work and releases land; this case study
> documents the *method*, not a target count. The healthy invariant is "no stale **merged**
> branches," not "branches == tags."

---

## 9. Future Enhancements

- **Prevent recurrence:** enable GitHub **"Automatically delete head branches"** so merged
  PR branches are reaped on merge (one-time, UI-only setting).
- **Scheduled hygiene check:** a read-only CI job (or `scripts/` CLI) that lists branches
  whose PR is `MERGED` but whose ref still exists, and reports them for review — never
  auto-deleting (fail-closed, human-in-the-loop per AGENTS.md §5.1).
- **Stale-branch report** in the status page: surface merged-but-undeleted branches and
  branch age alongside the existing drift gates.
- **Protect release branches** explicitly so any future automation can never target them.

---

## 10. Reproduce It Yourself

```bash
# 1. Diagnose (read-only) — how many branches, how many does Git call merged?
git fetch --prune origin
echo "remote branches: $(git branch -r | grep -vc HEAD)"
git branch -r --merged origin/main | grep -v HEAD

# 2. Classify anything Git didn't confirm, using the authoritative PR state:
for b in $(git branch -r | sed 's# *origin/##' | grep -Ev 'HEAD|^main$'); do
  st=$(gh pr list --state all --head "$b" --json state -q '.[0].state' 2>/dev/null)
  echo "  $b -> ${st:-NO PR}"
done

# 3. Guard + delete (only after confirming every branch is MERGED and no PR is open):
#    [ "$(gh pr list --state open --json number -q 'length')" = "0" ] || exit 1
#    git push origin --delete <verified-merged-branches>
```

---

*Part of the [IANUA](../../README.md). Destructive and outward-facing operations here follow
the human-approval gates in [AGENTS.md](../../AGENTS.md) §5.1 — verify first, fail closed,
never guess.*
