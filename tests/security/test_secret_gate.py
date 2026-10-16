# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The §7.1 secret gate, end to end — including the result it used to stop short of.

Every scenario here is built in a throwaway repository with a real baseline
and a real ``detect-secrets-hook``; nothing is mocked, because the thing under
test is the hook's behaviour across its three exit codes and what the script
does with each. The planted literals are generated at run time and never
written into this file — the pattern alone (``AKIA`` + 16 characters) is what
the detector matches, and §5 forbids a key in a test as much as in source.

The last test is the one the owner asked for: the repository's **own**
committed baseline must pass the hook at exit 0. Verifying that a baseline
refresh was location-only proves the rewrite; only the scan after staging
proves the gate.
"""

from __future__ import annotations

import json
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
    EXIT_CLEAN,
    EXIT_FINDINGS,
    EXIT_STALE,
    EXIT_UNUSABLE,
    HOOK,
    location_only,
    main,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


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


def _line_numbers(repo: Path) -> dict[str, list[int]]:
    baseline = json.loads((repo / BASELINE).read_text(encoding="utf-8"))
    return {
        name: [int(e["line_number"]) for e in found] for name, found in baseline["results"].items()
    }


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
    before = (repo / BASELINE).read_bytes()

    assert main(["--root", str(repo)]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "planted.py" in out and "FINDINGS" in out, out
    assert (repo / BASELINE).read_bytes() == before, "a finding must never rewrite the baseline"
    assert _staged(repo) == []


@pytest.mark.security
def test_a_location_only_refresh_is_staged_and_the_post_staging_scan_passes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The case the owner raised: staging is not the end of the procedure."""
    repo = _repo(tmp_path, accepted=True)
    assert _line_numbers(repo) == {"accepted.py": [1]}
    body = (repo / "accepted.py").read_text(encoding="utf-8")
    (repo / "accepted.py").write_text(
        "# a line above shifts the accepted finding\n" + body, encoding="utf-8"
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "shift")
    before = json.loads((repo / BASELINE).read_text(encoding="utf-8"))

    assert main(["--root", str(repo)]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "post-staging re-scan exit 0" in out, out
    assert _staged(repo) == [str(BASELINE)], "the refreshed baseline, and only it, is staged"
    after = json.loads((repo / BASELINE).read_text(encoding="utf-8"))
    assert _line_numbers(repo) == {"accepted.py": [2]}
    assert location_only(before, after) == []


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
    before = (repo / BASELINE).read_bytes()

    assert main(["--root", str(repo)]) == EXIT_FINDINGS
    assert "planted.py" in capsys.readouterr().out
    assert (repo / BASELINE).read_bytes() == before
    assert _staged(repo) == []


@pytest.mark.security
def test_no_stage_reports_a_stale_baseline_and_restores_the_bytes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path, accepted=True)
    body = (repo / "accepted.py").read_text(encoding="utf-8")
    (repo / "accepted.py").write_text("# shift\n" + body, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "shift")
    before = (repo / BASELINE).read_bytes()

    assert main(["--root", str(repo), "--no-stage"]) == EXIT_STALE
    assert "STALE" in capsys.readouterr().out
    assert (repo / BASELINE).read_bytes() == before, "check mode must leave the tree as it found it"
    assert _staged(repo) == []


@pytest.mark.security
def test_a_dirty_baseline_is_refused_before_the_hook_runs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The hook's refusal of a dirty baseline exits 1 — a finding's code — so it is caught first."""
    repo = _repo(tmp_path)
    baseline = json.loads((repo / BASELINE).read_text(encoding="utf-8"))
    baseline["generated_at"] = "2000-01-01T00:00:00Z"
    (repo / BASELINE).write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")

    assert main(["--root", str(repo)]) == EXIT_UNUSABLE
    assert "uncommitted edits" in capsys.readouterr().out


@pytest.mark.security
@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        pytest.param(
            lambda b: b["results"].__setitem__(
                "new.py", [{"type": "Secret Keyword", "hashed_secret": "ab", "line_number": 1}]
            ),
            "accepted entries changed",
            id="an-entry-added",
        ),
        pytest.param(
            lambda b: b["results"]["accepted.py"][0].__setitem__("hashed_secret", "0" * 40),
            "accepted entries changed",
            id="a-digest-changed",
        ),
        pytest.param(
            lambda b: b["plugins_used"].pop(), "plugin set changed", id="a-plugin-removed"
        ),
        pytest.param(
            lambda b: b["filters_used"].pop(0), "filter set changed", id="a-filter-removed"
        ),
    ],
)
def test_a_rewrite_that_is_not_location_only_is_refused(
    tmp_path: Path, mutate: Callable[[dict[str, Any]], None], reason: str
) -> None:
    repo = _repo(tmp_path, accepted=True)
    before = json.loads((repo / BASELINE).read_text(encoding="utf-8"))
    after = json.loads(json.dumps(before))
    mutate(after)
    reasons = location_only(before, after)
    assert reasons and any(reason in r for r in reasons), reasons


@pytest.mark.security
def test_gaining_the_baseline_file_filter_is_still_location_only(tmp_path: Path) -> None:
    """Measured: the first rewrite adds ``is_baseline_file``; that must not read as a change."""
    repo = _repo(tmp_path, accepted=True)
    before = json.loads((repo / BASELINE).read_text(encoding="utf-8"))
    after = json.loads(json.dumps(before))
    after["filters_used"] = [
        f for f in after["filters_used"] if "is_baseline_file" not in f.get("path", "")
    ]
    assert location_only(after, before) == [], (
        "gaining the baseline filter is the documented refresh shape"
    )
    after["results"]["accepted.py"][0]["line_number"] += 7
    assert location_only(before, after) == []


@pytest.mark.security
def test_the_repositorys_committed_baseline_passes_the_hook_at_exit_0(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The required post-staging result, for this repository, every run.

    Not a throwaway: this runs the hook over every tracked file of IANUA itself
    against the committed ``.secrets.baseline`` in check mode. Exit 3 means
    the baseline is stale — someone verified a refresh and stopped before the
    re-scan; run ``python scripts/secret_gate.py`` and commit the result. Exit 1
    means a finding, and §7.1 says what accepting one costs. Roughly 40 seconds
    on 566 files; the cost is the point — a gate that is not run is a claim.
    """
    code = main(["--root", str(REPO_ROOT), "--no-stage"])
    out = capsys.readouterr().out
    assert code == EXIT_CLEAN, (
        f"the committed baseline does not pass the hook (exit {code}):\n{out}\n"
        "exit 3 = stale line numbers (run scripts/secret_gate.py and commit); exit 1 = a finding"
    )
