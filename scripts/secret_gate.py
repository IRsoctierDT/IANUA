#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Run ``AGENTS.md`` §7.1's secret gate end to end, including the re-scan after staging.

Purpose: one command that performs the §7.1 sequence and fails closed on every
branch of it, so the procedure is not a habit an operator remembers to finish.
Risk level: low — reads the tree; writes only ``.secrets.baseline``, and only
the hook's own refresh of it or the pre-run bytes back over that refresh;
stages that one file and nothing else; and puts the pre-run bytes and the
pre-run index entry back on every path that does not end in a staged refresh
whose re-scan passed. Skill level: none beyond reading the output. Deployment
complexity: none; stdlib and the declared dev dependency. The hook is invoked
with the same arguments CI gives it — in particular without ``--no-verify``,
because (measured) that flag makes the rewrite DROP the verification-policy
filter from the baseline, and a baseline's ``filters_used`` configures every
later scan that loads it.

``detect-secrets-hook`` has three exit codes, measured on 1.5.0 in throwaway
repositories (``AGENTS.md`` §7.1 records the measurements):

* **0** — clean.
* **1** — a finding not in the baseline. **Also** a baseline it cannot parse
  (``error: Unable to read baseline.``) and a tracked baseline with unstaged
  edits (``Your baseline file (.secrets.baseline) is unstaged``). One code,
  three meanings, so this script rules the second and third out before the
  hook runs and its 1 can only mean a finding. On a finding the baseline is
  **not** rewritten: a finding suppresses the refresh, so a tree that needs
  both a refresh and a fix exits 1 first and 3 only after the fix.
* **3** — no finding, but the hook rewrote the baseline and asks for it to be
  staged. Its message says "probably to keep line numbers of secrets
  up-to-date", and that is **one** of two things it does. An accepted entry's
  ``line_number`` moved, **or an accepted entry was retired** because its
  literal is no longer in the scanned file — measured: delete the literal and
  the hook exits 3 with the same message, and ``results`` shrinks by that
  entry. A literal that *moved* to another tracked file is a new finding
  there, exit 1, and the refresh is suppressed, so a retirement cannot hide a
  relocation. In both cases ``generated_at`` bumps and ``filters_used`` may
  gain ``is_baseline_file`` pinned to the baseline's own name; nothing else
  changes, and every surviving entry keeps its file, type, digest and audit
  flags (measured: ``is_secret`` and ``is_verified`` survive a rewrite).

A **refresh** is therefore exactly this: line numbers may move, entries may
disappear, ``generated_at`` may change, the baseline-file filter may appear.
Anything else — an entry appearing, any field of a surviving entry changing,
the ``version``, the plugin set, any other filter, any other key — is an
**acceptance**, which §7.1 makes a reviewed act (``detect-secrets scan
--baseline``, then read the whole diff), and this script refuses to stage it.

§7.1's procedure for 3 used to end at "verify, then stage". Verifying proves the
rewrite was a refresh. It does **not** prove the gate then passes — that is a
separate measurement, and this script makes it a requirement: after staging,
the hook is run again and must exit 0, or the sequence has failed and the
pre-run state is put back.

What is refused before the hook runs, each because the hook would otherwise
misreport it or run over it as if it were reviewed: a ``--root`` that is not a
directory, not a git work tree, or not its top level (``git ls-files`` in a
sub-directory lists that sub-tree only, so the gate would scan a fraction and
report on it); a baseline that is missing, is a symlink (git tracks and stages
the link while the hook reads and rewrites the target), is a hard link (the
hook's rewrite would go through the shared inode to a file outside this
script's stated scope), is untracked or ignored (never reviewed), does not
parse as a baseline, or carries *unstaged* edits; and **any tracked file with
unstaged changes** — the hook reads the work tree while a commit records the
index, so a credential staged and then removed by an unstaged edit scans clean
and is committed anyway (measured; found by review on #242). A *staged* edit
is what §7.1's acceptance procedure leaves behind before the commit, the hook
accepts it, and so does this script: it is gated, not refused.

Exit codes: 0 clean (including after a staged refresh whose re-scan passed);
1 findings, nothing changed; 2 the gate could not run or could not settle (any
refusal above, a hook exit code the hook does not have, a rewrite that is not
a refresh, or a re-scan after staging that did not exit 0) — and on every
exit-2 path the baseline holds its pre-run bytes and the index its pre-run
entry; 3 ``--no-stage`` found a stale baseline and restored the pre-run bytes.
Exit 1 is never a traceback: every refusal above is a message and exit 2.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess  # nosec B404 — fixed argv, shell=False, trusted local tooling (git, detect-secrets)
import sys
from pathlib import Path
from typing import Any

#: Relative to the repository root; the hook keys its self-exclusion filter to
#: this exact name, which is why a copy elsewhere is scanned as plain text.
BASELINE = Path(".secrets.baseline")
HOOK = "detect-secrets-hook"

#: The one filter a refresh may add, exactly as the hook writes it (measured).
BASELINE_FILTER = "detect_secrets.filters.common.is_baseline_file"
BASELINE_FILTER_ENTRY: dict[str, str] = {"path": BASELINE_FILTER, "filename": str(BASELINE)}

#: Top-level baseline keys a refresh may change; every other key must be identical.
_REFRESH_MAY_CHANGE = frozenset({"generated_at", "results", "filters_used"})

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_UNUSABLE = 2
EXIT_STALE = 3

#: git's own exit code outside a work tree ("fatal: not a git repository").
_GIT_NOT_A_REPOSITORY = 128


def _executable(name: str) -> str:
    """The absolute path of a tool on PATH, or the bare name if it is not there.

    Resolved once per call rather than hard-coded: a fixed absolute path would
    be wrong on the next machine, and a bare name is what bandit B607 flags.
    ``main`` refuses to run when the hook is absent, so the fallback is only
    ever reached by a caller that already checked.
    """
    return shutil.which(name) or name


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    """Run ``git`` with a fixed argv in ``root``; the caller reads the exit code."""
    return subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, shell=False
        [_executable("git"), *args], cwd=root, capture_output=True, check=False
    )


def _text(data: bytes) -> str:
    return data.decode("utf-8", "surrogateescape")


def repository_top_level(root: Path) -> Path | None:
    """``root``'s work tree as git sees it, or ``None`` when it is not inside one."""
    completed = _git(root, "rev-parse", "--show-toplevel")
    if completed.returncode != 0:
        return None
    return Path(_text(completed.stdout).strip()).resolve()


def tracked_files(root: Path) -> list[str]:
    """Every tracked path, NUL-delimited so a space or a leading dash survives."""
    completed = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, shell=False
        [_executable("git"), "ls-files", "-z"], cwd=root, capture_output=True, check=True
    )
    return [_text(entry) for entry in completed.stdout.split(b"\0") if entry]


def baseline_refusal(root: Path) -> str | None:
    """Why the baseline cannot be gated as it stands, or ``None`` when it can.

    Each refusal names what the hook would otherwise do with the state, all of
    it measured on 1.5.0:

    * **missing** — the hook exits 2; refused here so the message names the path.
    * **a symlink**, in the work tree or in the index (mode ``120000``) — git
      tracks and stages the *link* while the hook reads and rewrites the
      *target*, so the dirty check and the staging would act on one object and
      the scan on another.
    * **untracked or ignored** — the hook runs and reports (its own check is
      only ``git diff --name-only``), but the gate compares against a reviewed,
      committed baseline, and one git does not track was never reviewed.
    * **a hard link** — the symlink and git checks both pass for a link whose
      bytes match the tracked baseline, and the hook's rewrite then goes through
      the shared inode to the other name, outside this gate's stated scope.
    * **unstaged edits** — the hook refuses them at exit 1, a finding's code.
      Staged edits are not refused by the hook or here: §7.1's acceptance
      procedure stages the reviewed baseline before committing it, and this
      gate is what runs next.
    """
    baseline = root / BASELINE
    if baseline.is_symlink():
        return f"{BASELINE} is a symlink; the hook would read and rewrite its target"
    if not baseline.is_file():
        return f"no {BASELINE} at {root}"
    if baseline.stat().st_nlink > 1:
        return (
            f"{BASELINE} is a hard link ({baseline.stat().st_nlink} links); the hook's rewrite "
            "would go through the shared inode to a file outside this gate's scope"
        )
    staged = _git(root, "ls-files", "--stage", "--", str(BASELINE))
    if staged.returncode != 0 or not staged.stdout.strip():
        return (
            f"{BASELINE} is not tracked (untracked or ignored); the gate compares against a "
            "reviewed, committed baseline, and the hook would run over this one as if it were"
        )
    if _text(staged.stdout).split()[0] == "120000":
        return f"{BASELINE} is a symlink in the index; the hook would read and rewrite its target"
    unstaged = _git(root, "diff", "--name-only", "--", str(BASELINE))
    if unstaged.returncode != 0:
        return f"git diff failed for {BASELINE}: {_text(unstaged.stderr).strip()}"
    if unstaged.stdout.strip():
        return (
            f"{BASELINE} has unstaged edits. The hook reports that at exit 1 — the same code as "
            "a finding — so it is refused here first. Stage them (the ACCEPT procedure) or revert "
            "them, then re-run"
        )
    return None


def unstaged_changes(root: Path) -> list[str]:
    """Tracked paths whose work-tree content differs from the index.

    The hook scans the work tree; ``git commit`` records the index. A credential
    that is staged and then removed by an unstaged edit therefore scans clean
    and is committed anyway (measured), so the gate refuses to run over a tree
    where the two differ — stage or stash first, and the scan is of what will
    be committed. Untracked files are not listed: they are neither scanned nor
    committed.
    """
    completed = _git(root, "diff", "--name-only", "-z")
    if completed.returncode != 0:
        raise subprocess.SubprocessError(
            f"git diff failed: {_text(completed.stderr).strip() or completed.returncode}"
        )
    return sorted(_text(entry) for entry in completed.stdout.split(b"\0") if entry)


def parse_baseline(data: bytes) -> dict[str, Any]:
    """The baseline as a mapping, or ``ValueError`` naming why it is not one.

    The hook reports an unparseable baseline at exit 1 — a finding's code — so
    it is parsed here first and refused as unusable instead.
    """
    try:
        loaded = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"not JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError(f"not a JSON object but {type(loaded).__name__}")
    if not isinstance(loaded.get("results"), dict):
        raise ValueError("'results' is missing or is not a mapping")
    return loaded


EntryKey = tuple[str, str, str]


def _entries(baseline: dict[str, Any]) -> dict[EntryKey, dict[str, Any]]:
    """Accepted entries keyed by (file, type, digest), each without its line number."""
    entries: dict[EntryKey, dict[str, Any]] = {}
    for filename, found in baseline["results"].items():
        for entry in found:
            key = (str(filename), str(entry.get("type")), str(entry.get("hashed_secret")))
            entries[key] = {k: v for k, v in entry.items() if k != "line_number"}
    return entries


def retired_entries(before: dict[str, Any], after: dict[str, Any]) -> list[EntryKey]:
    """Accepted entries present before a rewrite and absent after it."""
    return sorted(set(_entries(before)) - set(_entries(after)))


def refresh_reasons(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Reasons a rewrite is NOT a refresh the hook may make on its own; empty means it is.

    A refresh may move ``line_number`` values, retire entries, change
    ``generated_at`` and add the baseline-file filter exactly as the hook
    writes it. It may not add an entry, change any field of a surviving entry,
    or touch ``version``, ``plugins_used``, any other filter or any other key.
    Each of those is an acceptance — a reviewed act under §7.1 — and the
    reasons returned name which one so the operator knows what they are
    looking at.
    """
    reasons: list[str] = []
    for key in sorted((set(before) | set(after)) - _REFRESH_MAY_CHANGE):
        if key not in before:
            reasons.append(f"top-level key {key!r} appeared")
        elif key not in after:
            reasons.append(f"top-level key {key!r} disappeared")
        elif before[key] != after[key]:
            what = "the plugin set" if key == "plugins_used" else f"top-level {key!r}"
            reasons.append(f"{what} changed")

    filters_before = before.get("filters_used", [])
    filters_after = after.get("filters_used", [])
    lost = [f for f in filters_before if f not in filters_after]
    gained = [f for f in filters_after if f not in filters_before]
    if lost:
        reasons.append(f"filters removed: {lost}")
    unexpected = [f for f in gained if f != BASELINE_FILTER_ENTRY]
    if unexpected:
        reasons.append(f"filters added beyond {BASELINE_FILTER_ENTRY}: {unexpected}")

    old, new = _entries(before), _entries(after)
    appeared = sorted(set(new) - set(old))
    if appeared:
        names = ", ".join(f"{path} ({kind})" for path, kind, _ in appeared)
        reasons.append(f"accepted entries appeared — that is an acceptance, not a refresh: {names}")
    changed = sorted(key for key in set(old) & set(new) if old[key] != new[key])
    if changed:
        names = ", ".join(f"{path} ({kind})" for path, kind, _ in changed)
        reasons.append(f"a surviving entry changed beyond its line number: {names}")
    return reasons


def run_hook(root: Path, files: list[str]) -> tuple[int, str]:
    """The hook over ``files``, directly — no ``xargs`` — so its exit code is its own.

    Through ``xargs`` every child exit in 1..125 is reported as 123, which is
    why the documented command cannot tell a finding from a refresh by code.
    """
    completed = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, shell=False
        [_executable(HOOK), "--baseline", str(BASELINE), "--", *files],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout + completed.stderr


def _restore(root: Path, before: bytes, *, staged: bool) -> None:
    """Put the baseline's pre-run bytes back, and its pre-run index entry if this run staged it.

    Unstaged edits were refused up front, so the pre-run index entry *is* the
    pre-run bytes; re-adding them restores the index exactly, including the
    case where the baseline was already staged before the run.
    """
    baseline = root / BASELINE
    try:
        current = baseline.read_bytes()
    except OSError:
        current = b""
    if current != before:
        baseline.write_bytes(before)
    if staged and _git(root, "add", "--", str(BASELINE)).returncode != 0:
        print(f"warning: could not restore the index entry; run `git add -- {BASELINE}`")


def main(argv: list[str] | None = None) -> int:
    """Entry point. See the module docstring for the sequence and the exit codes."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--root", default=".", help="repository top level (default: the working directory)"
    )
    parser.add_argument(
        "--no-stage",
        action="store_true",
        help="never stage; a stale baseline is reported (exit 3) and its pre-run bytes restored",
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()

    if shutil.which(HOOK) is None:
        print(
            f"error: {HOOK} is not installed; it is a declared dev dependency (pip install -e '.[dev]')"
        )
        return EXIT_UNUSABLE
    if not root.is_dir():
        print(f"error: {root} is not a directory")
        return EXIT_UNUSABLE
    top = repository_top_level(root)
    if top is None:
        print(f"error: {root} is not inside a git work tree (git exits {_GIT_NOT_A_REPOSITORY})")
        return EXIT_UNUSABLE
    if top != root:
        print(
            f"error: {root} is not the repository top level ({top}); a sub-directory root would "
            "scan that sub-tree only and report on the fraction"
        )
        return EXIT_UNUSABLE
    refusal = baseline_refusal(root)
    if refusal is not None:
        print(f"error: {refusal}")
        return EXIT_UNUSABLE
    try:
        dirty = unstaged_changes(root)
    except subprocess.SubprocessError as exc:
        print(f"error: {exc}")
        return EXIT_UNUSABLE
    if dirty:
        shown = ", ".join(dirty[:10]) + (f", … ({len(dirty)} in all)" if len(dirty) > 10 else "")
        print(
            f"error: {len(dirty)} tracked file(s) have unstaged changes: {shown}. The hook scans "
            "the work tree while a commit records the index, so the scan would not be of what is "
            "committed. Stage or stash them, then re-run"
        )
        return EXIT_UNUSABLE

    baseline = root / BASELINE
    before = baseline.read_bytes()
    try:
        parsed_before = parse_baseline(before)
    except ValueError as exc:
        print(
            f"error: {BASELINE} is not a baseline ({exc}); the hook would report that at exit 1 — "
            "a finding's code"
        )
        return EXIT_UNUSABLE
    files = tracked_files(root)  # the baseline is tracked, so this is never empty

    staged = False
    settled = False
    try:
        code, output = run_hook(root, files)
        if code == EXIT_CLEAN:
            print(f"secret gate: clean — {len(files)} tracked files, exit 0")
            settled = True
            return EXIT_CLEAN
        if code == EXIT_FINDINGS:
            print(output, end="")
            print(
                "secret gate: FINDINGS above; the baseline was not changed and nothing was staged"
            )
            return EXIT_FINDINGS
        if code != EXIT_STALE:
            print(output, end="")
            print(f"secret gate: the hook exited {code}, a code it does not have; nothing staged")
            return EXIT_UNUSABLE

        after = baseline.read_bytes()
        if after == before:
            print("secret gate: the hook exited 3 but did not rewrite the baseline; nothing staged")
            return EXIT_UNUSABLE
        try:
            parsed_after = parse_baseline(after)
        except ValueError as exc:
            print(f"secret gate: the hook's rewrite is not a baseline ({exc}); nothing staged")
            return EXIT_UNUSABLE
        reasons = refresh_reasons(parsed_before, parsed_after)
        if reasons:
            print("secret gate: the hook rewrote the baseline and the rewrite is NOT a refresh:")
            for reason in reasons:
                print(f"  - {reason}")
            print(
                "  pre-run bytes restored; nothing staged. Accepting a finding is a reviewed act "
                "(§7.1: `detect-secrets scan --baseline`, then read the whole diff)."
            )
            return EXIT_UNUSABLE
        retired = retired_entries(parsed_before, parsed_after)
        for path, kind, _ in retired:
            print(f"secret gate: retired accepted entry {path} ({kind}) — its literal is gone")
        if args.no_stage:
            print(
                "secret gate: STALE baseline — a refresh is needed. Restored the pre-run bytes; "
                "run without --no-stage to stage it and re-scan."
            )
            return EXIT_STALE

        add = _git(root, "add", "--", str(BASELINE))
        if add.returncode != 0:
            print(f"secret gate: git add failed ({_text(add.stderr).strip()}); nothing staged")
            return EXIT_UNUSABLE
        staged = True
        # The result the procedure used to stop short of. Verifying the rewrite
        # was a refresh says nothing about whether the gate now passes.
        code2, output2 = run_hook(root, files)
        if code2 == EXIT_CLEAN:
            print("secret gate: refresh staged; post-staging re-scan exit 0 — clean")
            settled = True
            return EXIT_CLEAN
        print(output2, end="")
        print(
            f"secret gate: post-staging re-scan exited {code2}; the refresh did not settle the "
            "gate. Pre-run bytes and index entry restored; nothing left staged"
        )
        return EXIT_FINDINGS if code2 == EXIT_FINDINGS else EXIT_UNUSABLE
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"secret gate: {exc}; nothing staged")
        return EXIT_UNUSABLE
    finally:
        if not settled:
            _restore(root, before, staged=staged)


if __name__ == "__main__":
    sys.exit(main())
