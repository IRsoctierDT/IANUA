#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Run ``AGENTS.md`` §7.1's secret gate end to end, including the re-scan after staging.

Purpose: one command that performs the §7.1 sequence and fails closed on every
branch of it, so the procedure is not a habit an operator remembers to finish.
Risk level: low — reads the tree, writes nothing but what ``detect-secrets-hook``
itself writes (a line-number refresh of ``.secrets.baseline``), and stages that
one file and nothing else. Skill level: none beyond reading the output.
Deployment complexity: none; stdlib and the declared dev dependency.

``detect-secrets-hook`` has three outcomes, measured on 1.5.0 in throwaway
repositories (``AGENTS.md`` §7.1 records the measurements):

* **0** — clean.
* **1** — a finding not in the baseline. The baseline is **not** rewritten:
  a finding suppresses the line-number refresh, so a tree that needs both a
  refresh and a fix exits 1 first and 3 only after the fix.
* **3** — no finding, but an accepted entry's line number moved, so the hook
  rewrote the baseline and asks for it to be staged. Entry count, digests and
  plugin set are unchanged; ``filters_used`` may gain ``is_baseline_file``;
  ``generated_at`` bumps.

§7.1's procedure for 3 used to end at "verify, then stage". Verifying proves the
rewrite was location-only. It does **not** prove the gate then passes — that
is a separate measurement, and this script makes it a requirement: after
staging, the hook is run again and must exit 0, or the sequence has failed.

Exit codes: 0 clean (including after a staged refresh whose re-scan passed);
1 findings; 2 the baseline is unusable (dirty before the run, a rewrite that
was not location-only, or an unexpected hook result) — nothing was staged;
3 ``--no-stage`` found a stale baseline and restored the pre-run bytes.
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


def _executable(name: str) -> str:
    """The absolute path of a tool on PATH, or the bare name if it is not there.

    Resolved once per call rather than hard-coded: a fixed absolute path would
    be wrong on the next machine, and a bare name is what bandit B607 flags.
    ``main`` refuses to run when the hook is absent, so the fallback is only
    ever reached by a caller that already checked.
    """
    return shutil.which(name) or name


BASELINE_FILTER = "detect_secrets.filters.common.is_baseline_file"

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_UNUSABLE = 2
EXIT_STALE = 3


def tracked_files(root: Path) -> list[str]:
    """Every tracked path, NUL-delimited so a space or a leading dash survives."""
    completed = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, shell=False
        [_executable("git"), "ls-files", "-z"], cwd=root, capture_output=True, check=True
    )
    return [
        entry.decode("utf-8", "surrogateescape") for entry in completed.stdout.split(b"\0") if entry
    ]


def baseline_is_dirty(root: Path) -> bool:
    """Whether the tracked baseline has uncommitted edits (staged or not).

    The hook refuses such a baseline with the message "is unstaged" and
    **exit 1** — the same code as a real finding — so it is checked here first
    rather than read back out of the hook's output.
    """
    completed = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, shell=False
        [_executable("git"), "status", "--porcelain", "--", str(BASELINE)],
        cwd=root,
        capture_output=True,
        check=True,
    )
    return bool(completed.stdout.strip())


def run_hook(root: Path, files: list[str]) -> tuple[int, str]:
    """One pass of the hook over ``files``; returns its exit code and combined output."""
    completed = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, shell=False
        [_executable(HOOK), "--baseline", str(BASELINE), "--", *files],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout + completed.stderr


def _entries(baseline: dict[str, Any]) -> list[tuple[str, str, str]]:
    return sorted(
        (filename, str(entry.get("type")), str(entry.get("hashed_secret")))
        for filename, found in baseline.get("results", {}).items()
        for entry in found
    )


def location_only(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Reasons a rewrite is NOT merely a line-number refresh; empty means it is.

    What may change: ``line_number`` values and ``generated_at``, and
    ``filters_used`` may *gain* the baseline-file filter (measured: the first
    such rewrite adds it). What may not: the number of entries, any entry's
    file, type or digest, the plugin set, or any other filter.
    """
    reasons: list[str] = []
    if _entries(before) != _entries(after):
        reasons.append(
            f"accepted entries changed: {len(_entries(before))} -> {len(_entries(after))} "
            "(or a file, type or digest differs) — that is an acceptance, not a refresh"
        )
    if before.get("plugins_used") != after.get("plugins_used"):
        reasons.append("the plugin set changed")
    gained = [f for f in after.get("filters_used", []) if f not in before.get("filters_used", [])]
    lost = [f for f in before.get("filters_used", []) if f not in after.get("filters_used", [])]
    if lost or any(f.get("path") != BASELINE_FILTER for f in gained):
        reasons.append(
            f"the filter set changed beyond gaining {BASELINE_FILTER}: +{gained} -{lost}"
        )
    return reasons


def main(argv: list[str] | None = None) -> int:
    """Entry point. See the module docstring for the sequence and the exit codes."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--root", default=".", help="repository root (default: the working directory)"
    )
    parser.add_argument(
        "--no-stage",
        action="store_true",
        help="never stage; a stale baseline is reported (exit 3) and its pre-run bytes restored",
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    baseline = root / BASELINE

    if shutil.which(HOOK) is None:
        print(
            f"error: {HOOK} is not installed; it is a declared dev dependency (pip install -e '.[dev]')"
        )
        return EXIT_UNUSABLE
    if not baseline.is_file():
        print(f"error: no {BASELINE} at {root}")
        return EXIT_UNUSABLE
    if baseline_is_dirty(root):
        print(
            f"error: {BASELINE} has uncommitted edits. The hook would refuse it with exit 1 — the same "
            "code as a finding — so this is refused here first. Commit or revert it, then re-run."
        )
        return EXIT_UNUSABLE

    before = baseline.read_bytes()
    files = tracked_files(root)
    code, output = run_hook(root, files)

    if code == EXIT_CLEAN:
        print(f"secret gate: clean — {len(files)} tracked files, exit 0")
        return EXIT_CLEAN
    if code == EXIT_FINDINGS:
        print(output, end="")
        print("secret gate: FINDINGS above; the baseline was not changed and nothing was staged")
        return EXIT_FINDINGS
    if code != EXIT_STALE:
        print(output, end="")
        print(f"secret gate: unexpected hook exit {code}; nothing staged")
        return EXIT_UNUSABLE

    after = baseline.read_bytes()
    if after == before:
        print("secret gate: the hook exited 3 but did not rewrite the baseline; nothing staged")
        return EXIT_UNUSABLE
    reasons = location_only(json.loads(before), json.loads(after))
    if reasons:
        baseline.write_bytes(before)
        print("secret gate: the hook rewrote the baseline and the rewrite is NOT location-only:")
        for reason in reasons:
            print(f"  - {reason}")
        print(
            "  restored the pre-run bytes; nothing staged. Accepting a finding is a reviewed act (§7.1)."
        )
        return EXIT_UNUSABLE
    if args.no_stage:
        baseline.write_bytes(before)
        print(
            "secret gate: STALE baseline — a location-only line-number refresh is needed. "
            "Restored the pre-run bytes; run without --no-stage to stage it and re-scan."
        )
        return EXIT_STALE

    subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, shell=False
        [_executable("git"), "add", "--", str(BASELINE)], cwd=root, check=True
    )
    # The result the procedure used to stop short of. Verifying the rewrite was
    # location-only says nothing about whether the gate now passes.
    code2, output2 = run_hook(root, files)
    if code2 == EXIT_CLEAN:
        print("secret gate: location-only refresh staged; post-staging re-scan exit 0 — clean")
        return EXIT_CLEAN
    print(output2, end="")
    print(f"secret gate: post-staging re-scan exited {code2}; the refresh did not settle the gate")
    return EXIT_FINDINGS if code2 == EXIT_FINDINGS else EXIT_UNUSABLE


if __name__ == "__main__":
    sys.exit(main())
