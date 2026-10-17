# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The §7.1 secret gate, end to end — including the result it used to stop short of.

Every scenario the real ``detect-secrets-hook`` can produce is built in a
throwaway repository with a real baseline and the real hook; nothing is mocked
there, because the thing under test is the hook's behaviour across its exit
codes and what the script does with each. The outcomes the real hook cannot
produce on demand — a code it does not have, an exit 3 without a rewrite, a
truncated rewrite, a re-scan that fails *after* staging — are driven by a
stand-in executable that is named as such, because the script's fail-closed
branches for them would otherwise be measured only in prose.

The planted literals are generated at run time and never written into this
file — the pattern alone (``AKIA`` + 16 characters) is what the detector
matches, and §5 forbids a key in a test as much as in source.

The last test is the one the owner asked for: the repository's **own**
committed baseline must pass the hook at exit 0. Verifying that a baseline
rewrite was a refresh proves the rewrite; only the scan after staging proves
the gate. The hook runs here exactly as CI runs it (no ``--no-verify``):
measured, the key-shaped fixtures these tests plant are reported identically
with the network namespace detached, so no scan here needs the network.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import string
import subprocess  # nosec B404 — fixed argv, shell=False, throwaway repositories
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.secret_gate import (
    BASELINE,
    BASELINE_FILTER_ENTRY,
    EXIT_CLEAN,
    EXIT_FINDINGS,
    EXIT_STALE,
    EXIT_UNUSABLE,
    HOOK,
    main,
    refresh_reasons,
    retired_entries,
    tracked_files,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _isolated_git_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Neither the throwaway repositories nor the script's own ``git`` calls read the
    invoking user's global or system git configuration (``core.hooksPath``,
    ``commit.gpgsign``, ``init.defaultBranch`` …), so a developer's dotfiles cannot
    change what these tests measure."""
    empty = tmp_path / "git-config-empty"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


@pytest.fixture(autouse=True)
def _hook_must_be_installed() -> None:
    """Fail, never skip: ``detect-secrets`` is a declared dev dependency.

    A security test that skips where the tool is absent proves nothing in
    exactly the environment that matters.
    """
    if shutil.which(HOOK) is None:
        pytest.fail(f"{HOOK} is not installed; `pip install -e '.[dev]'` provides it")


def _tool(name: str) -> str:
    """Absolute path of a tool, so the argv is never a partial path (ruff S607)."""
    found = shutil.which(name)
    assert found, f"{name} is not on PATH"
    return found


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, shell=False
        [_tool("git"), *args], cwd=repo, capture_output=True, text=True, check=True
    )
    return completed.stdout


def _key_shaped() -> str:
    """An AWS-access-key-shaped literal that is not a key. Generated, never stored."""
    # Composed from stdlib constants rather than written as one literal: a
    # 32-character alphabet spelled out is itself a high-entropy string, and
    # the gate this file tests flags it (measured: "Base64 High Entropy String").
    alphabet = string.ascii_uppercase + "234567"
    return "AKIA" + "".join(secrets.choice(alphabet) for _ in range(16))


def _repo(tmp_path: Path, *, accepted: bool = False) -> Path:
    """A committed repository with a reviewed baseline; optionally one accepted finding."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", ".")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "test")
    (repo / "clean.py").write_text("x = 1\n", encoding="utf-8")
    if accepted:
        (repo / "accepted.py").write_text(f'OLD = "{_key_shaped()}"\n', encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "files")
    scan = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, shell=False
        [_tool("detect-secrets"), "scan"], cwd=repo, capture_output=True, text=True, check=True
    )
    (repo / BASELINE).write_text(scan.stdout, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "baseline")
    return repo


def _staged(repo: Path) -> list[str]:
    return _git(repo, "diff", "--cached", "--name-only").split()


def _unstaged_edit_elsewhere(repo: Path) -> None:
    """An untracked file beside the tracked ones, so "stages nothing" and "stages that
    one file and nothing else" are measured against something a ``git add -A`` would
    have swept up, rather than against a tree with nothing to stage. Untracked rather
    than an unstaged edit to a tracked file, because the gate refuses the latter."""
    (repo / "extra.py").write_text("y = 2\n", encoding="utf-8")


def _assert_only_the_unstaged_edit_remains_unstaged(repo: Path) -> None:
    status = _git(repo, "status", "--porcelain")
    assert "?? extra.py" in status, status


def _baseline(repo: Path) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((repo / BASELINE).read_text(encoding="utf-8"))
    return loaded


def _write_baseline(repo: Path, baseline: dict[str, Any]) -> None:
    (repo / BASELINE).write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")


def _line_numbers(repo: Path) -> dict[str, list[int]]:
    return {
        name: [int(e["line_number"]) for e in found]
        for name, found in _baseline(repo)["results"].items()
    }


def _shift_accepted_literal(repo: Path) -> None:
    """Commit a line above the accepted literal, so its line number is stale."""
    body = (repo / "accepted.py").read_text(encoding="utf-8")
    (repo / "accepted.py").write_text(
        "# a line above shifts the accepted finding\n" + body, encoding="utf-8"
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "shift")


def _stand_in_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, plan: list[dict[str, Any]]
) -> Path:
    """Put an executable named like the hook first on PATH, driven by a step plan.

    Each invocation consumes one step: ``refresh`` rewrites the baseline exactly
    as the real hook's refresh does (measured shape), ``add_entry`` adds an
    accepted entry, ``write`` replaces the bytes, ``say`` is printed, ``exit`` is
    the code. Named a stand-in, not a mock: it exists only for the codes and
    sequences the real hook cannot be made to produce on demand.
    """
    bin_dir = tmp_path / "stand-in-bin"
    bin_dir.mkdir()
    plan_path = tmp_path / "stand-in-plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    script = bin_dir / HOOK
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, sys\n"
        f"plan_path = pathlib.Path({str(plan_path)!r})\n"
        "plan = json.loads(plan_path.read_text())\n"
        "step = plan.pop(0)\n"
        "plan_path.write_text(json.dumps(plan))\n"
        "baseline = pathlib.Path(sys.argv[sys.argv.index('--baseline') + 1])\n"
        "if step.get('refresh') or step.get('add_entry'):\n"
        "    d = json.loads(baseline.read_text())\n"
        "    d['generated_at'] = '2001-01-01T00:00:00Z'\n"
        f"    d['filters_used'].append({BASELINE_FILTER_ENTRY!r})\n"
        "    if step.get('add_entry'):\n"
        "        d['results']['ghost.py'] = [{'type': 'Secret Keyword', 'filename': 'ghost.py',"
        " 'hashed_secret': 'ab', 'is_verified': False, 'line_number': 1}]\n"
        "    baseline.write_text(json.dumps(d, indent=2) + '\\n')\n"
        "if 'write' in step:\n"
        "    baseline.write_text(step['write'])\n"
        "print(step.get('say', ''))\n"
        "sys.exit(step['exit'])\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    assert shutil.which(HOOK) == str(script)
    return plan_path


def _a_hook_that_would_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """For refusal tests: if the script ever reached the hook, this one would exit 0 and the
    test would see EXIT_CLEAN instead of the refusal — and its single step would be gone."""
    return _stand_in_hook(tmp_path, monkeypatch, [{"exit": 0}])


def _assert_the_hook_never_ran(plan_path: Path) -> None:
    assert json.loads(plan_path.read_text(encoding="utf-8")) == [{"exit": 0}], (
        "the refusal must come before the hook runs"
    )


# --------------------------------------------------------------------------- real hook


@pytest.mark.security
def test_a_clean_tree_passes_and_touches_nothing(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    before = (repo / BASELINE).read_bytes()
    assert main(["--root", str(repo)]) == EXIT_CLEAN
    assert (repo / BASELINE).read_bytes() == before
    assert _staged(repo) == []


@pytest.mark.security
def test_a_new_finding_fails_and_stages_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path)
    (repo / "planted.py").write_text(f'NEW = "{_key_shaped()}"\n', encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "planted")
    _unstaged_edit_elsewhere(repo)
    before = (repo / BASELINE).read_bytes()

    assert main(["--root", str(repo)]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "planted.py" in out and "FINDINGS" in out, out
    assert (repo / BASELINE).read_bytes() == before, "a finding must never rewrite the baseline"
    assert _staged(repo) == []
    _assert_only_the_unstaged_edit_remains_unstaged(repo)


@pytest.mark.security
def test_a_line_shift_refresh_is_staged_and_the_post_staging_scan_passes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The case the owner raised: staging is not the end of the procedure."""
    repo = _repo(tmp_path, accepted=True)
    assert _line_numbers(repo) == {"accepted.py": [1]}
    _shift_accepted_literal(repo)
    _unstaged_edit_elsewhere(repo)
    before = _baseline(repo)

    assert main(["--root", str(repo)]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "post-staging re-scan exit 0" in out, out
    assert _staged(repo) == [str(BASELINE)], "the refreshed baseline, and only it, is staged"
    _assert_only_the_unstaged_edit_remains_unstaged(repo)
    assert _line_numbers(repo) == {"accepted.py": [2]}
    assert refresh_reasons(before, _baseline(repo)) == []


@pytest.mark.security
def test_a_retired_entry_is_a_refresh_and_is_staged(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Measured: deleting an accepted literal exits 3 with the "line numbers" message and
    drops the entry. That is the hook retiring what no longer exists, not an acceptance —
    the first version of the script refused it as one, which left a stale entry only the
    opaque ``scan --baseline`` could clear."""
    repo = _repo(tmp_path, accepted=True)
    assert _line_numbers(repo) == {"accepted.py": [1]}
    (repo / "accepted.py").write_text("OLD = None\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "literal removed")
    _unstaged_edit_elsewhere(repo)
    before = _baseline(repo)

    assert main(["--root", str(repo)]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "retired accepted entry accepted.py" in out, out
    assert "post-staging re-scan exit 0" in out, out
    assert _line_numbers(repo) == {}, "the entry is gone from the staged baseline"
    assert _staged(repo) == [str(BASELINE)]
    _assert_only_the_unstaged_edit_remains_unstaged(repo)
    assert retired_entries(before, _baseline(repo)) == [
        ("accepted.py", "AWS Access Key", before["results"]["accepted.py"][0]["hashed_secret"])
    ]


@pytest.mark.security
def test_a_relocated_literal_is_a_finding_not_a_retirement(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """What makes allowing retirements safe: a literal that moved to another tracked file is
    a new finding there (exit 1) and the refresh is suppressed, so the baseline is untouched
    and the old entry is not quietly dropped."""
    repo = _repo(tmp_path, accepted=True)
    literal_line = (repo / "accepted.py").read_text(encoding="utf-8")
    (repo / "moved.py").write_text(literal_line, encoding="utf-8")
    (repo / "accepted.py").write_text("OLD = None\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "moved")
    _unstaged_edit_elsewhere(repo)
    before = (repo / BASELINE).read_bytes()

    assert main(["--root", str(repo)]) == EXIT_FINDINGS
    assert "moved.py" in capsys.readouterr().out
    assert (repo / BASELINE).read_bytes() == before
    assert _staged(repo) == []
    _assert_only_the_unstaged_edit_remains_unstaged(repo)


@pytest.mark.security
def test_a_shift_and_a_new_finding_together_fail_without_staging(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Measured: a finding suppresses the refresh, so exit 1 comes first and 3 only after the fix."""
    repo = _repo(tmp_path, accepted=True)
    body = (repo / "accepted.py").read_text(encoding="utf-8")
    (repo / "accepted.py").write_text("# shift\n" + body, encoding="utf-8")
    (repo / "planted.py").write_text(f'NEW = "{_key_shaped()}"\n', encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "shift and plant")
    _unstaged_edit_elsewhere(repo)
    before = (repo / BASELINE).read_bytes()

    assert main(["--root", str(repo)]) == EXIT_FINDINGS
    assert "planted.py" in capsys.readouterr().out
    assert (repo / BASELINE).read_bytes() == before
    assert _staged(repo) == []
    _assert_only_the_unstaged_edit_remains_unstaged(repo)


@pytest.mark.security
def test_no_stage_reports_a_stale_baseline_and_restores_the_bytes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path, accepted=True)
    _shift_accepted_literal(repo)
    _unstaged_edit_elsewhere(repo)
    before = (repo / BASELINE).read_bytes()

    assert main(["--root", str(repo), "--no-stage"]) == EXIT_STALE
    assert "STALE" in capsys.readouterr().out
    assert (repo / BASELINE).read_bytes() == before, "check mode must leave the tree as it found it"
    assert _staged(repo) == []
    _assert_only_the_unstaged_edit_remains_unstaged(repo)


@pytest.mark.security
def test_an_unstaged_baseline_edit_is_refused_before_the_hook_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The hook's refusal of an unstaged baseline exits 1 — a finding's code — so it is caught first."""
    repo = _repo(tmp_path, accepted=True)
    baseline = _baseline(repo)
    baseline["generated_at"] = "2000-01-01T00:00:00Z"
    _write_baseline(repo, baseline)
    before = (repo / BASELINE).read_bytes()
    plan = _a_hook_that_would_pass(tmp_path, monkeypatch)

    assert main(["--root", str(repo)]) == EXIT_UNUSABLE
    assert "unstaged edits" in capsys.readouterr().out
    assert (repo / BASELINE).read_bytes() == before
    assert _staged(repo) == []
    _assert_the_hook_never_ran(plan)


@pytest.mark.security
def test_a_staged_baseline_edit_is_gated_not_refused(tmp_path: Path) -> None:
    """§7.1's acceptance procedure stages the reviewed baseline and then runs the gate.
    Measured: the hook does not refuse a staged edit, so neither does the script — the
    first version refused the very state its own successful run leaves behind."""
    repo = _repo(tmp_path, accepted=True)
    baseline = _baseline(repo)
    baseline["generated_at"] = "2000-01-01T00:00:00Z"
    _write_baseline(repo, baseline)
    _git(repo, "add", "--", str(BASELINE))
    staged_bytes = (repo / BASELINE).read_bytes()

    assert main(["--root", str(repo)]) == EXIT_CLEAN
    assert (repo / BASELINE).read_bytes() == staged_bytes
    assert _staged(repo) == [str(BASELINE)], "the operator's staged edit is left exactly as it was"


@pytest.mark.security
@pytest.mark.parametrize("ignored", [False, True], ids=["untracked", "ignored"])
def test_an_untracked_baseline_is_refused(
    tmp_path: Path,
    ignored: bool,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The hook runs over an untracked or ignored baseline as if it were reviewed (its own
    check is only ``git diff --name-only``); the gate compares against a committed one."""
    repo = _repo(tmp_path)
    _git(repo, "rm", "-q", "--cached", "--", str(BASELINE))
    if ignored:
        (repo / ".gitignore").write_text(f"{BASELINE}\n", encoding="utf-8")
        _git(repo, "add", ".gitignore")
    _git(repo, "commit", "-qm", "baseline no longer tracked")
    assert (repo / BASELINE).is_file()
    plan = _a_hook_that_would_pass(tmp_path, monkeypatch)

    assert main(["--root", str(repo)]) == EXIT_UNUSABLE
    assert "not tracked" in capsys.readouterr().out
    assert _staged(repo) == []
    _assert_the_hook_never_ran(plan)


@pytest.mark.security
def test_a_symlinked_baseline_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """git tracks and stages the link; the hook reads and rewrites the target. A committed
    symlink whose target is untracked made a hand-edited acceptance pass as clean."""
    repo = _repo(tmp_path, accepted=True)
    target = repo / "baseline-target.json"
    target.write_bytes((repo / BASELINE).read_bytes())
    (repo / BASELINE).unlink()
    (repo / BASELINE).symlink_to(target.name)
    (repo / ".gitignore").write_text(f"{target.name}\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "symlinked baseline")
    assert _git(repo, "ls-files", "--stage", "--", str(BASELINE)).split()[0] == "120000"
    plan = _a_hook_that_would_pass(tmp_path, monkeypatch)

    assert main(["--root", str(repo)]) == EXIT_UNUSABLE
    assert "symlink" in capsys.readouterr().out
    assert _staged(repo) == []
    _assert_the_hook_never_ran(plan)


@pytest.mark.security
@pytest.mark.parametrize(
    "body",
    ["{not json\n", "[]\n", '{"version": "1.5.0"}\n'],
    ids=["not-json", "not-an-object", "no-results-mapping"],
)
def test_an_unparseable_baseline_is_unusable_not_a_finding(
    tmp_path: Path, body: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Measured: the hook exits 1 with ``error: Unable to read baseline.`` — a finding's code."""
    repo = _repo(tmp_path)
    (repo / BASELINE).write_text(body, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "damaged baseline")
    plan = _a_hook_that_would_pass(tmp_path, monkeypatch)

    code = main(["--root", str(repo)])
    assert code == EXIT_UNUSABLE and code != EXIT_FINDINGS
    assert "is not a baseline" in capsys.readouterr().out
    assert _staged(repo) == []
    _assert_the_hook_never_ran(plan)


@pytest.mark.security
def test_a_staged_credential_with_an_unstaged_removal_is_refused_not_passed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review on #242. The hook scans the work tree; ``git commit`` records the
    index. Measured before the fix: a key-shaped literal staged in ``staged.py`` and then
    removed by an unstaged edit scanned clean at exit 0 while ``git show :staged.py`` still
    held it. The gate now refuses any tracked file whose work tree differs from the index,
    before the hook runs."""
    repo = _repo(tmp_path)
    (repo / "staged.py").write_text(f'K = "{_key_shaped()}"\n', encoding="utf-8")
    _git(repo, "add", "--", "staged.py")
    (repo / "staged.py").write_text("K = None\n", encoding="utf-8")
    assert "AKIA" in _git(repo, "show", ":staged.py"), "the premise: the index holds the literal"
    plan = _a_hook_that_would_pass(tmp_path, monkeypatch)

    assert main(["--root", str(repo)]) == EXIT_UNUSABLE
    out = capsys.readouterr().out
    assert "unstaged changes" in out and "staged.py" in out, out
    _assert_the_hook_never_ran(plan)


@pytest.mark.security
def test_a_hard_linked_baseline_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review on #242. A hard link to a file outside the repository with the
    tracked baseline's bytes passes the symlink and git checks; measured, the hook's refresh
    then rewrote the external file through the shared inode. Refused before the hook runs,
    and the external file is untouched."""
    repo = _repo(tmp_path, accepted=True)
    external = tmp_path / "external.json"
    external.write_bytes((repo / BASELINE).read_bytes())
    (repo / BASELINE).unlink()
    (repo / BASELINE).hardlink_to(external)
    assert (repo / BASELINE).stat().st_nlink == 2
    assert _git(repo, "status", "--porcelain") == "", "the premise: git sees no change"
    _shift_accepted_literal(repo)
    before = external.read_bytes()
    plan = _a_hook_that_would_pass(tmp_path, monkeypatch)

    assert main(["--root", str(repo)]) == EXIT_UNUSABLE
    assert "hard link" in capsys.readouterr().out
    assert external.read_bytes() == before
    _assert_the_hook_never_ran(plan)


@pytest.mark.security
@pytest.mark.parametrize("kind", ["missing", "regular-file"])
def test_an_invalid_root_is_refused_without_a_traceback(
    tmp_path: Path, kind: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review on #242: a nonexistent root or a regular file raised from the first
    ``subprocess.run(cwd=root)`` before the guarded block, exiting 1 — a finding's code."""
    target = tmp_path / "nowhere"
    if kind == "regular-file":
        target.write_text("", encoding="utf-8")
    assert main(["--root", str(target)]) == EXIT_UNUSABLE
    assert "is not a directory" in capsys.readouterr().out


@pytest.mark.security
def test_a_missing_baseline_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path)
    _git(repo, "rm", "-q", "--", str(BASELINE))
    _git(repo, "commit", "-qm", "no baseline")
    plan = _a_hook_that_would_pass(tmp_path, monkeypatch)
    assert main(["--root", str(repo)]) == EXIT_UNUSABLE
    assert f"no {BASELINE}" in capsys.readouterr().out
    _assert_the_hook_never_ran(plan)


@pytest.mark.security
def test_a_missing_hook_is_refused_as_unusable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without the hook on PATH the gate cannot run, and says so at exit 2 before touching git."""
    repo = _repo(tmp_path)
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    assert shutil.which(HOOK) is None
    assert main(["--root", str(repo)]) == EXIT_UNUSABLE
    assert "is not installed" in capsys.readouterr().out


@pytest.mark.security
def test_a_root_outside_a_repository_is_refused_without_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    source = _repo(tmp_path)
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / BASELINE).write_bytes((source / BASELINE).read_bytes())
    plan = _a_hook_that_would_pass(tmp_path, monkeypatch)

    assert main(["--root", str(plain)]) == EXIT_UNUSABLE
    assert "not inside a git work tree" in capsys.readouterr().out
    _assert_the_hook_never_ran(plan)


@pytest.mark.security
def test_a_sub_directory_root_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``git ls-files`` in a sub-directory lists that sub-tree only, so a wrong root would scan
    a fraction of the repository and report clean while a literal sits above it."""
    repo = _repo(tmp_path)
    sub = repo / "sub"
    sub.mkdir()
    (sub / BASELINE).write_bytes((repo / BASELINE).read_bytes())
    (sub / "ok.py").write_text("y = 2\n", encoding="utf-8")
    (repo / "planted.py").write_text(f'NEW = "{_key_shaped()}"\n', encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "sub-tree with its own baseline")
    assert main(["--root", str(repo)]) == EXIT_FINDINGS, (
        "the control: the top level sees the literal"
    )
    assert "planted.py" in capsys.readouterr().out
    plan = _a_hook_that_would_pass(tmp_path, monkeypatch)

    assert main(["--root", str(sub)]) == EXIT_UNUSABLE
    assert "not the repository top level" in capsys.readouterr().out
    _assert_the_hook_never_ran(plan)


@pytest.mark.security
def test_tracked_paths_with_a_space_and_a_leading_dash_are_listed_and_scanned(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """§7.1's two measured ways of scanning nothing: an unquoted expansion word-splits a
    path with a space, and without ``--`` a dash-led name is read as a flag. The script
    lists NUL-delimited and terminates its argv, so both are scanned and both are named."""
    repo = _repo(tmp_path)
    spaced, dashed = "with space.py", "-- dash.py"
    (repo / spaced).write_text(f'A = "{_key_shaped()}"\n', encoding="utf-8")
    (repo / dashed).write_text(f'B = "{_key_shaped()}"\n', encoding="utf-8")
    _git(repo, "add", "--", spaced, dashed)
    _git(repo, "commit", "-qm", "awkward names")

    listed = tracked_files(repo)
    assert spaced in listed and dashed in listed, listed
    assert main(["--root", str(repo)]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert spaced in out and dashed in out, out


@pytest.mark.security
def test_a_failed_git_add_fails_closed_and_restores(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A held ``.git/index.lock`` makes ``git add`` fail after the hook has rewritten the
    baseline; the pre-run bytes come back and the exit is 2, not a traceback."""
    repo = _repo(tmp_path, accepted=True)
    _shift_accepted_literal(repo)
    before = (repo / BASELINE).read_bytes()
    lock = repo / ".git" / "index.lock"
    lock.write_bytes(b"")
    try:
        code = main(["--root", str(repo)])
        out = capsys.readouterr().out
    finally:
        lock.unlink()
    assert code == EXIT_UNUSABLE, out
    assert "git add failed" in out, out
    assert (repo / BASELINE).read_bytes() == before
    assert _staged(repo) == []


# ------------------------------------------------------------- refresh_reasons (unit)


@pytest.mark.security
@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        pytest.param(
            lambda b: b["results"].__setitem__(
                "new.py",
                [
                    {
                        "type": "Secret Keyword",
                        "filename": "new.py",
                        "hashed_secret": "ab",
                        "line_number": 1,
                    }
                ],
            ),
            "accepted entries appeared",
            id="an-entry-added",
        ),
        pytest.param(
            lambda b: b["results"]["accepted.py"][0].__setitem__("hashed_secret", "0" * 40),
            "accepted entries appeared",
            id="a-digest-changed",
        ),
        pytest.param(
            lambda b: b["results"]["accepted.py"][0].__setitem__("is_secret", True),
            "a surviving entry changed",
            id="an-audit-flag-flipped",
        ),
        pytest.param(
            lambda b: b["results"]["accepted.py"][0].__setitem__("filename", "elsewhere.py"),
            "a surviving entry changed",
            id="an-entry-filename-field-changed",
        ),
        pytest.param(
            lambda b: b["plugins_used"].pop(), "the plugin set changed", id="a-plugin-removed"
        ),
        pytest.param(lambda b: b["filters_used"].pop(0), "filters removed", id="a-filter-removed"),
        pytest.param(
            lambda b: b["filters_used"].append({**BASELINE_FILTER_ENTRY, "filename": "elsewhere"}),
            "filters added beyond",
            id="the-baseline-filter-with-another-filename",
        ),
        pytest.param(
            lambda b: b.__setitem__("version", "9.9.9"), "top-level 'version' changed", id="version"
        ),
        pytest.param(
            lambda b: b.__setitem__("exclude", {"files": ".*"}),
            "top-level key 'exclude' appeared",
            id="an-unknown-top-level-key",
        ),
        pytest.param(
            lambda b: b.__delitem__("version"),
            "top-level key 'version' disappeared",
            id="a-top-level-key-removed",
        ),
    ],
)
def test_a_rewrite_that_is_not_a_refresh_is_refused(
    tmp_path: Path, mutate: Callable[[dict[str, Any]], None], reason: str
) -> None:
    repo = _repo(tmp_path, accepted=True)
    before = _baseline(repo)
    after = json.loads(json.dumps(before))
    mutate(after)
    reasons = refresh_reasons(before, after)
    assert reasons and any(reason in r for r in reasons), reasons


@pytest.mark.security
def test_gaining_the_baseline_file_filter_is_a_refresh(tmp_path: Path) -> None:
    """Measured: a fresh ``detect-secrets scan`` carries no ``is_baseline_file`` filter and the
    first hook rewrite adds exactly ``BASELINE_FILTER_ENTRY``; that must not read as a change."""
    repo = _repo(tmp_path, accepted=True)
    before = _baseline(repo)
    assert BASELINE_FILTER_ENTRY not in before["filters_used"], "the premise: no filter yet"
    after = json.loads(json.dumps(before))
    after["filters_used"].append(BASELINE_FILTER_ENTRY)
    after["generated_at"] = "2001-01-01T00:00:00Z"
    assert refresh_reasons(before, after) == []
    after["results"]["accepted.py"][0]["line_number"] += 7
    assert refresh_reasons(before, after) == []


@pytest.mark.security
def test_retiring_an_entry_is_a_refresh_and_is_named(tmp_path: Path) -> None:
    repo = _repo(tmp_path, accepted=True)
    before = _baseline(repo)
    after = json.loads(json.dumps(before))
    del after["results"]["accepted.py"]
    assert refresh_reasons(before, after) == []
    assert [path for path, _, _ in retired_entries(before, after)] == ["accepted.py"]


# ---------------------------------------------- outcomes the real hook cannot produce


@pytest.mark.security
@pytest.mark.parametrize(
    ("plan", "expected", "fragment"),
    [
        pytest.param(
            [{"write": "{}\n", "exit": 7}],
            EXIT_UNUSABLE,
            "a code it does not have",
            id="a-code-the-hook-does-not-have",
        ),
        pytest.param(
            [{"exit": 3}],
            EXIT_UNUSABLE,
            "did not rewrite",
            id="exit-3-without-a-rewrite",
        ),
        pytest.param(
            [{"write": '{"results": {"a.py": [{"type": "x", "hashed', "exit": 3}],
            EXIT_UNUSABLE,
            "rewrite is not a baseline",
            id="a-truncated-rewrite",
        ),
        pytest.param(
            [{"add_entry": True, "exit": 3}],
            EXIT_UNUSABLE,
            "NOT a refresh",
            id="a-rewrite-that-accepts-an-entry",
        ),
        pytest.param(
            [{"refresh": True, "exit": 3}, {"say": "Location: planted.py:1", "exit": 1}],
            EXIT_FINDINGS,
            "post-staging re-scan exited 1",
            id="re-scan-after-staging-finds-something",
        ),
        pytest.param(
            [{"refresh": True, "exit": 3}, {"refresh": True, "exit": 3}],
            EXIT_UNUSABLE,
            "post-staging re-scan exited 3",
            id="re-scan-after-staging-is-stale-again",
        ),
    ],
)
def test_outcomes_the_real_hook_cannot_produce_fail_closed_and_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    plan: list[dict[str, Any]],
    expected: int,
    fragment: str,
) -> None:
    """Every path that does not end in a staged refresh with a passing re-scan leaves the
    baseline's pre-run bytes on disk and nothing staged — including the two that stage
    first and fail after, which the first version of the script left staged."""
    repo = _repo(tmp_path, accepted=True)
    before = (repo / BASELINE).read_bytes()
    _stand_in_hook(tmp_path, monkeypatch, plan)

    assert main(["--root", str(repo)]) == expected
    out = capsys.readouterr().out
    assert fragment in out, out
    assert (repo / BASELINE).read_bytes() == before, "pre-run bytes restored"
    assert _staged(repo) == [], "nothing left staged"
    assert json.loads((repo / BASELINE).read_text(encoding="utf-8")), "and it is a baseline again"


# ------------------------------------------------------------------ this repository


@pytest.mark.security
def test_the_repositorys_committed_baseline_passes_the_hook_at_exit_0(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The required post-staging result, for this repository, every run.

    Not a throwaway: this runs the hook over every tracked file of IANUA itself
    against the committed ``.secrets.baseline`` in check mode. Exit 3 means
    the baseline is stale — an edit above an accepted literal, or the removal
    of one, was committed without running the gate (measured: a refresh that
    *was* staged and committed re-scans at 0, so that is not what 3 reports);
    run ``python scripts/secret_gate.py`` and commit the result. Exit 1 means
    a finding, and §7.1 says what accepting one costs. Exit 2 means the gate
    could not run here (an unstaged baseline edit, most likely — stage or
    revert it). It takes the hook's full run over the tree; the cost is the
    point — a gate that is not run is a claim.

    The listing is also pinned: every path ``git ls-files -z`` reports is
    scanned, including the ones with spaces that an unquoted expansion would
    split (this repository has them under ``sample-logs/``, which the premise
    assertion documents rather than assumes).

    The script restores the pre-run bytes itself on every non-clean path; the
    snapshot here is the belt to that brace, so a crash between the hook's
    rewrite and the restore cannot leave this checkout modified by its own test.
    """
    listed = tracked_files(REPO_ROOT)
    raw = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, shell=False
        [_tool("git"), "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, check=True
    ).stdout
    assert len(listed) == len([p for p in raw.split(b"\0") if p]), "one argv entry per tracked path"
    assert any(" " in path for path in listed), "the premise: this tree has space-bearing paths"

    baseline = REPO_ROOT / BASELINE
    snapshot = baseline.read_bytes()
    index_before = _git(REPO_ROOT, "ls-files", "--stage", "--", str(BASELINE))
    try:
        code = main(["--root", str(REPO_ROOT), "--no-stage"])
        out = capsys.readouterr().out
    finally:
        if baseline.read_bytes() != snapshot:
            baseline.write_bytes(snapshot)
    assert code == EXIT_CLEAN, (
        f"the committed baseline does not pass the hook (exit {code}):\n{out}\n"
        "exit 3 = stale (run scripts/secret_gate.py and commit); exit 1 = a finding; "
        "exit 2 = the gate could not run here (see the message)"
    )
    assert _git(REPO_ROOT, "ls-files", "--stage", "--", str(BASELINE)) == index_before
