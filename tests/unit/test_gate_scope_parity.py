# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Meta-test: every enforcement point names the same package set.

Gate-scope drift is how ~41 KB of compliance/ logic sat outside the coverage
gate while being type-checked, and how a blanket scripts.* mypy ignore hid
errors in new gate scripts. The canonical scope lives HERE, once; each config
surface is asserted against it, so adding a package to the repo without
adding it everywhere is a merge-blocking failure, not a convention.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest
import yaml

from tests.security import _sql_provenance as sqlprov

_REPO = Path(__file__).resolve().parents[2]

# The canonical scopes. A new package updates THIS list plus every config the
# assertions below point at — the point is that forgetting one fails loudly.
PACKAGES = {
    "agents",
    "attack",
    "intel",
    "ingest",
    "store",
    "correlation",
    "pipeline",
    "collect",
    "rag",
    "mcp",
    "dashboard",
    "scripts",
    "compliance",
    "sli",
}
MYPY_SCOPE = {
    "agents",
    "attack",
    "intel",
    "ingest",
    "store",
    "correlation",
    "pipeline",
    "collect",
    "scripts",
    "tests",
    "dashboard",
    "mcp",
    "rag",
    "compliance",
    "sli",
}
COVERAGE_SCOPE = {
    "agents",
    "attack",
    "intel",
    "ingest",
    "store",
    "correlation",
    "pipeline",
    "collect",
    "compliance",
    "rag",
    "mcp",
    "sli",
}
# Bandit covers the packages that parse untrusted or externally influenced
# input (agent pipeline, corpus loaders, operational scripts, MCP surface).
BANDIT_SCOPE = {
    "agents",
    "attack",
    "intel",
    "ingest",
    "store",
    "correlation",
    "pipeline",
    "collect",
    "scripts",
    "mcp",
    "sli",
}

#: Top-level directories holding Python that are deliberately outside
#: :data:`PACKAGES`, each with the reason. The point of naming them is that
#: ``test_every_python_directory_is_accounted_for`` then fails for a directory
#: nobody decided about — which is how ``cli/`` came to be in no gate at all.
UNGATED = {
    # Pre-charter entry points to the orchestrator: untyped (``def main():``),
    # and the path that reaches agents/tools/llm.py's urlopen with only three
    # enforce() sites behind it. Bringing it under the gates means annotating
    # it and gating that egress, which is its own stage in
    # docs/PRODUCTION_SOC_PLAN.md — not a silent omission.
    "cli",
    # The test suite is type-checked (it is in MYPY_SCOPE) but is not a
    # shipped package, so it is not in PACKAGES or the coverage source.
    "tests",
}


#: Flags the mypy invocation is expected to carry, and the reason. mypy
#: resolves imports against its OWN interpreter, so a standalone or pipx
#: install does not share one with the project: measured on a fresh container,
#: the bare command emits 134 errors in 132 files (132 of them a missing
#: ``pytest`` stub) while the flag gives "no issues in 287 source files". It is
#: a no-op where mypy is installed beside the dependencies, which is why every
#: invocation carries it rather than two commands diverging.
_REQUIRED_MYPY_FLAG = "--python-executable"


def _mypy_packages(command: str) -> set[str]:
    """The package list from a mypy command line, with its flags stripped.

    Asserts the interpreter flag is present rather than tolerating its absence:
    dropping it is a silent regression to 134 phantom errors in a required
    check, and the obvious next move for whoever sees them is to stop running
    the check.
    """
    assert _REQUIRED_MYPY_FLAG in command, (
        f"the mypy command dropped {_REQUIRED_MYPY_FLAG}: {command!r} — see the note above"
    )
    # Strip shell command substitutions before splitting. The documented
    # invocation passes `"$(command -v python)"`, which a naive split turns
    # into four tokens — two of them looking like a flag and a package. Parsed
    # here rather than contorting the command, because the command is what an
    # agent copies and it should read naturally.
    command = re.sub(r"\$\([^)]*\)", "", command)
    tokens = command.split()
    assert tokens and tokens[0] == "mypy", f"not a mypy command: {command!r}"
    packages: set[str] = set()
    skip_next = False
    for token in tokens[1:]:
        if skip_next:
            skip_next = False
            continue
        if token.startswith("-"):
            # A flag that takes a separate value consumes the next token.
            skip_next = "=" not in token and token in {_REQUIRED_MYPY_FLAG}
            continue
        packages.add(token)
    return packages


def _pyproject() -> dict:
    return tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8"))


@pytest.mark.unit
def test_setuptools_packages_match() -> None:
    include = _pyproject()["tool"]["setuptools"]["packages"]["find"]["include"]
    assert {entry.rstrip("*") for entry in include} == PACKAGES


@pytest.mark.unit
def test_mypy_files_match() -> None:
    files = _pyproject()["tool"]["mypy"]["files"]
    assert set(files) == MYPY_SCOPE


@pytest.mark.unit
def test_coverage_scopes_match() -> None:
    config = _pyproject()
    source = set(config["tool"]["coverage"]["run"]["source"])
    assert source == COVERAGE_SCOPE
    addopts = config["tool"]["pytest"]["ini_options"]["addopts"]
    cov_flags = {opt.removeprefix("--cov=") for opt in addopts if opt.startswith("--cov=")}
    assert cov_flags == COVERAGE_SCOPE, "pytest --cov flags disagree with coverage.run source"


@pytest.mark.unit
def test_ci_mypy_and_bandit_lines_match() -> None:
    ci = (_REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    mypy_line = next(line for line in ci.splitlines() if re.search(r"run: mypy ", line))
    assert _mypy_packages(mypy_line.split("run: ", 1)[1]) == MYPY_SCOPE
    bandit_line = next(line for line in ci.splitlines() if "run: bandit" in line)
    scope = set(bandit_line.split()[2:]) - {"-c", "pyproject.toml", "-r"}
    assert scope == BANDIT_SCOPE


@pytest.mark.unit
def test_release_workflow_mypy_scope_matches() -> None:
    """release.yml derives its scope from a list, and that list must not drift.

    This file asserted ci.yml's scope but never release.yml's, so the release
    job's copy was free to fall behind — the same by-omission gap that left
    ``cli/`` in no gate at all. The release job builds its scope by looping over
    directory names and skipping any absent at the tag (it runs against a
    detached tag, and a hard-coded list breaks release repair for every tag
    predating the newest package), so the literal list is what this checks.
    """
    release = (_REPO / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    loop = re.search(r"for dir in ([^\n]*(?:\\\n[^\n]*)*?); do", release)
    assert loop is not None, "release.yml must build its mypy scope from a directory list"
    listed = set(loop.group(1).replace("\\", " ").split())
    assert listed == MYPY_SCOPE, (
        f"release.yml mypy scope {sorted(listed)} drifted from the canonical scope"
    )


@pytest.mark.unit
def test_precommit_scopes_match() -> None:
    config = (_REPO / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    mypy_files = re.search(r"files: \^\(([a-z|]+)\)/", config)
    assert mypy_files is not None
    scoped = set(mypy_files.group(1).split("|"))
    assert scoped == MYPY_SCOPE, f"pre-commit mypy files regex covers {scoped}"
    bandit_args = re.search(r'"-r", ([^\]]+)\]', config)
    assert bandit_args is not None
    scope = {part.strip().strip('"') for part in bandit_args.group(1).split(",")}
    assert scope == BANDIT_SCOPE


#: The pre-commit hooks that run a tool the dev extras pin, and how each must
#: be invoked. As hosted hook repos they carried a second pin that drifted from
#: uv.lock (read on 2026-10-23: ruff v0.6.9 against 0.17.1, mypy v1.11.2 against
#: 2.4.0, bandit 1.7.10 against 1.9.4), and they ran in pre-commit's isolated
#: environments, which never saw the project's dependencies
#: (docs/PATH_RECONCILIATION_AUDIT.md G2). ``python -m`` binds each to the
#: interpreter the drift-gate hooks use, not whatever is first on ``PATH``.
#: Pairs, not a dict literal: detect-secrets' keyword rule reads
#: ``"detect-secrets": "<string>"`` as a secret assignment (measured).
_TOOLCHAIN_HOOKS: tuple[tuple[str, str], ...] = (
    ("ruff", "python -m ruff check "),
    ("ruff-format", "python -m ruff format "),
    ("mypy", "python -m mypy"),
    ("bandit", "python -m bandit"),
    ("detect-secrets", "python -m detect_secrets.pre_commit_hook"),
)


@pytest.mark.unit
def test_precommit_runs_the_locked_toolchain_not_a_second_pin() -> None:
    """Every toolchain hook is a ``local`` ``system`` hook on the project interpreter.

    A version-equality check would also close the drift, but it would leave a
    second pin to bump on every lock change and keep the isolated environment.
    So the shape is pinned, and there is nothing to keep in step.
    """
    entries = dict(_TOOLCHAIN_HOOKS)
    config = yaml.safe_load((_REPO / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    found = {
        hook["id"]: (repo["repo"], hook)
        for repo in config["repos"]
        for hook in repo["hooks"]
        if hook["id"] in entries
    }
    assert set(found) == set(entries), (
        f"pre-commit no longer runs {sorted(set(entries) - set(found))}"
    )
    for hook_id, (repo, hook) in found.items():
        assert repo == "local", f"the {hook_id} hook comes from {repo}, a second pin beside uv.lock"
        assert hook.get("language") == "system", (
            f"the {hook_id} hook runs in its own environment, not the project's"
        )
        assert str(hook.get("entry", "")).startswith(entries[hook_id]), (
            f"the {hook_id} hook runs {hook.get('entry')!r}, not through the project interpreter"
        )


@pytest.mark.unit
def test_every_local_hook_given_filenames_ends_its_options() -> None:
    """A local hook that receives filenames ends its ``args`` with ``--``.

    pre-commit appends the staged filenames after ``args``, so without the
    terminator a tracked file named like an option is read as one. Measured on
    the detect-secrets hook, a file named ``--help`` turned the secret scan into
    a pass at exit 0. ``tests/security/test_secret_gate.py`` proves that one
    behaviourally. This pins the rule for every local hook, so the next one
    added cannot leave it out. Hosted hooks (``pre-commit-hooks``) are not
    covered here: their argument parsing could not be measured offline.
    """
    config = yaml.safe_load((_REPO / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    given_files = [
        hook
        for repo in config["repos"]
        if repo["repo"] == "local"
        for hook in repo["hooks"]
        if hook.get("pass_filenames", True)
    ]
    assert given_files, "no local hook receives filenames, so this assertion would be vacuous"
    unterminated = [hook["id"] for hook in given_files if (hook.get("args") or [None])[-1] != "--"]
    assert not unterminated, f"these hooks take filenames without a trailing '--': {unterminated}"


@pytest.mark.unit
def test_agents_md_command_blocks_match() -> None:
    charter = (_REPO / "AGENTS.md").read_text(encoding="utf-8")
    mypy_match = re.search(r"^(mypy .+)$", charter, re.MULTILINE)
    assert mypy_match is not None, "AGENTS.md §7 must show the mypy command"
    assert _mypy_packages(mypy_match.group(1)) == MYPY_SCOPE, (
        "AGENTS.md §7 mypy scope drifted from the real gate"
    )
    bandit_match = re.search(r"^bandit -c pyproject\.toml -r (.+)$", charter, re.MULTILINE)
    assert bandit_match is not None, "AGENTS.md §7 must show the bandit command"
    assert set(bandit_match.group(1).split()) == BANDIT_SCOPE, (
        "AGENTS.md §7 bandit scope drifted from the real gate"
    )


@pytest.mark.unit
def test_the_charters_secret_scan_is_read_only_and_fails_closed() -> None:
    """§7.1's secret-scanning command must be the hook, not `scan`.

    Not a style preference, measured both ways:

    * ``detect-secrets scan --baseline .secrets.baseline`` rescans and
      **rewrites** the tracked baseline in place — bumping ``generated_at``,
      shifting line numbers, and silently absorbing a NEW finding as an
      accepted entry — and exits ``0`` either way. So the command §7.1 used to
      give could not do the one thing its own heading claims ("fail the build
      on any detected credential"), and it dirtied a tracked file as a side
      effect.
    * ``detect-secrets-hook --baseline .secrets.baseline <files>`` exits ``1``
      on a secret not in the baseline, exits ``0`` when clean, and leaves the
      baseline untouched in both cases.

    It is also what ``.pre-commit-config.yaml`` already runs, so the charter
    was the only place disagreeing with the repository.

    Pinned because planting the revert left every other test in this file
    green: nothing asserted this command, so the fix could have come straight
    back out. Comment lines are excluded from the ban, because the block
    deliberately documents ``scan`` as the *deliberate* way to accept a new
    finding into the baseline.
    """
    charter = (_REPO / "AGENTS.md").read_text(encoding="utf-8")
    section = re.search(r"### 7\.1 Extended gate.*?```bash\n(.*?)```", charter, re.DOTALL)
    assert section is not None, "AGENTS.md §7.1 must carry a bash block"
    block = section.group(1)
    runnable = [
        line for line in block.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]

    assert any("detect-secrets-hook --baseline" in line for line in runnable), (
        "§7.1 does not run detect-secrets-hook; a `scan --baseline` gate cannot fail "
        "and rewrites a tracked file"
    )
    offenders = [line for line in runnable if "detect-secrets scan" in line]
    assert not offenders, (
        f"§7.1 runs {offenders} as a gate — `scan` exits 0 and rewrites the baseline; "
        "it belongs in a comment as the deliberate way to accept a finding"
    )

    hook = (_REPO / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    assert "id: detect-secrets" in hook, (
        "pre-commit no longer runs detect-secrets, so the charter and the repo disagree again"
    )


def _secret_gate_lines() -> list[str]:
    """The runnable (non-comment) lines of §7.1's bash block."""
    charter = (_REPO / "AGENTS.md").read_text(encoding="utf-8")
    section = re.search(r"### 7\.1 Extended gate.*?```bash\n(.*?)```", charter, re.DOTALL)
    assert section is not None, "AGENTS.md §7.1 must carry a bash block"
    return [
        line
        for line in section.group(1).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


@pytest.mark.unit
def test_the_charters_secret_scan_can_actually_run() -> None:
    """Fails closed is worthless if the command dies in argparse.

    The test above pinned that §7.1 runs the *hook* rather than ``scan``. It
    did not pin that the invocation works, and it did not: the block passed an
    unquoted ``$(git ls-files)``, which word-splits the 58 tracked paths
    containing spaces under ``sample-logs/github log debugging/``. One of them
    is ``5_Run python -m build.txt``, so argparse received a bare ``-m`` and
    the command exited **2 with nothing scanned** — measured, verbatim:
    ``error: unrecognized arguments: -m build.txt ...``.

    A gate that cannot run cannot "fail the build on any detected credential",
    so this is the same defect class the docstring above records, reached by a
    different route. Pinned on the shape rather than by executing
    detect-secrets, because the suite should not depend on a dev tool being
    installed to tell whether the charter is self-consistent.

    A **third** route was found in review of the fix for the second, and it is
    the worst because it exits ``0`` rather than ``2``: ``xargs`` appends the
    paths as plain arguments, so one tracked file whose name begins with a
    dash is read as a flag. Measured in a throwaway repository holding one
    AWS-access-key-shaped literal and a file named ``--help``, the command
    without an option terminator printed usage and exited ``0`` with that key
    unscanned; with ``--`` the same repository exits ``1`` and names ``AWS
    Access Key`` at ``planted.py:1``. The literal is deliberately not
    reproduced here — this gate flags it, correctly, and §5 forbids a key in a
    docstring as much as in source. ``git add -- --help`` commits such a
    name, so any pull request can reach it. Hence the terminator assertion
    below — a leading-dash filename is covered by requiring the shape that
    neutralises it, not by committing one.
    """
    runnable = _secret_gate_lines()
    gate = [line for line in runnable if "detect-secrets-hook" in line]
    assert gate, "§7.1 no longer runs the detect-secrets hook at all"

    splitting = [line for line in gate if re.search(r"(?<!\")\$\(git ls-files\)", line)]
    assert not splitting, (
        f"§7.1 passes an unquoted command substitution: {splitting}. Tracked paths "
        "contain spaces, so this word-splits and argparse rejects the whole command "
        "at exit 2 having scanned nothing. Use `git ls-files -z | xargs -0 ...`."
    )
    assert any("-z" in line and "xargs -0" in line for line in gate), (
        "§7.1's secret gate must hand paths over NUL-delimited; any whitespace-"
        "delimited form breaks on the repo's own tracked filenames"
    )
    assert any(line.rstrip().endswith(" --") for line in gate), (
        "§7.1's secret gate must end option parsing with `--` before xargs appends "
        "the paths. Without it a tracked file named e.g. `--help` is read as a flag "
        "and the gate exits 0 having scanned nothing — measured, with a live AWS key "
        "in the repository and the gate reporting green."
    )


@pytest.mark.unit
def test_ci_runs_the_charters_secret_gate_too() -> None:
    """§8's "mirrored exactly in CI" was false for exactly one gate.

    §7.1's secret gate is detect-secrets; CI ran only gitleaks, and the two
    are **not** interchangeable however the charter once worded it ("or:").
    Measured on one tree: gitleaks green while detect-secrets was red on two
    findings unbaselined since ``2496c2e`` (#217) — three merges with a red
    §7.1 gate behind a green pipeline, because nothing in CI ran it.

    So CI must run both, with the same baseline and the same NUL-delimited
    shape. Asserted against the workflow text rather than by invoking the
    tool, for the reason the sibling test gives.
    """
    ci = (_REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "detect-secrets-hook --baseline .secrets.baseline" in ci, (
        "CI does not run §7.1's detect-secrets gate; gitleaks is a different scanner "
        "and was green on a tree this gate failed"
    )
    assert "gitleaks" in ci, "CI must keep gitleaks as well — the two catch different things"

    charter_gate = next(line for line in _secret_gate_lines() if "detect-secrets-hook" in line)
    assert charter_gate.strip() in ci, (
        f"CI's secret-scan command differs from §7.1's ({charter_gate.strip()!r}); "
        "§8 claims the two are mirrored exactly"
    )


@pytest.mark.unit
def test_the_secrets_baseline_names_only_files_that_exist() -> None:
    """A baseline entry for a deleted file silently accepts nothing.

    ``detect-secrets`` matches an accepted finding by its hashed digest, so a
    stale path is tolerated rather than reported — which means baseline rot is
    invisible from the gate's own exit code. It had already happened here in
    the other direction: four accepted entries carried line numbers that had
    drifted since the baseline was generated (2026-08-22), so the file read as
    a description of a tree that no longer existed.
    """
    baseline = json.loads((_REPO / ".secrets.baseline").read_text(encoding="utf-8"))
    results = baseline.get("results", {})
    assert results, "the baseline accepts nothing; a review would have had to remove every entry"
    missing = sorted(path for path in results if not (_REPO / path).is_file())
    assert not missing, (
        f"the secrets baseline accepts findings in files that no longer exist: {missing}. "
        "Re-run `detect-secrets scan --baseline .secrets.baseline` and read the diff."
    )


@pytest.mark.unit
def test_agents_md_ci_prose_names_the_same_mypy_scope() -> None:
    """§8 opens by claiming §7 is "mirrored exactly in CI" — so its own list counts.

    Only the §7 command *block* was pinned, so the §8 prose drifted to six of
    the fourteen packages while this stage added a fifteenth to §7, to
    ``ci.yml``, to ``release.yml``, to ``pyproject.toml`` and to pre-commit.
    A charter that states a scope and means a different one is worse than one
    that states none. Found by review.
    """
    charter = (_REPO / "AGENTS.md").read_text(encoding="utf-8")
    stage = re.search(r"2\. \*\*Static analysis\*\*(.+?)\n3\. ", charter, re.MULTILINE | re.DOTALL)
    assert stage is not None, "AGENTS.md §8 must describe the static-analysis stage"
    named = {word for word in re.findall(r"[a-z_]+", stage.group(1)) if word in MYPY_SCOPE}
    assert named == MYPY_SCOPE, (
        "AGENTS.md §8's static-analysis stage does not name the §7 mypy scope; missing "
        f"{sorted(MYPY_SCOPE - named)}"
    )


@pytest.mark.unit
def test_no_blanket_scripts_mypy_ignore() -> None:
    overrides = _pyproject()["tool"]["mypy"].get("overrides", [])
    for override in overrides:
        modules = override.get("module")
        names = [modules] if isinstance(modules, str) else list(modules)
        for name in names:
            assert name != "scripts.*" or not override.get("ignore_errors"), (
                "blanket scripts.* ignore_errors hides errors in new gate scripts"
            )


@pytest.mark.unit
def test_committed_package_data_is_not_gitignored() -> None:
    """An unanchored ignore pattern (e.g. bare ``data/``) must never shadow
    committed package data — that is exactly how the ATT&CK shards were once
    silently dropped from a push while every local gate stayed green."""
    import subprocess

    for probe in ("attack/data/catalog.json", "attack/pins/enterprise-attack.pin.json"):
        result = subprocess.run(  # noqa: S603 - fixed argv
            ["git", "check-ignore", "-q", probe],  # noqa: S607 - git from PATH, test env
            capture_output=True,
            cwd=_REPO,
            timeout=30,
            check=False,
        )
        assert result.returncode != 0, f"{probe} is gitignored — committed data would be dropped"


@pytest.mark.unit
def test_every_python_directory_is_accounted_for() -> None:
    """A new package must land in a scope or an explicit exclusion.

    Without this, the parity assertions above are all conditional on someone
    having remembered to add the directory to ``PACKAGES`` in the first place
    — and a directory nobody added is checked by nothing. That is not
    hypothetical: ``cli/`` sat in no gate scope at all, by omission, and every
    gate stayed green.
    """
    found = {
        entry.name
        for entry in _REPO.iterdir()
        if entry.is_dir() and not entry.name.startswith(".") and any(entry.glob("*.py"))
    }
    unaccounted = found - PACKAGES - UNGATED
    assert unaccounted == set(), (
        f"{sorted(unaccounted)} hold Python but are in no gate scope. Add each to "
        "PACKAGES (and every config the assertions above check), or to UNGATED "
        "with the reason."
    )


@pytest.mark.unit
def test_sql_provenance_sweep_covers_every_accounted_directory() -> None:
    """The SQL-provenance sweep has no config of its own, so pin its walk.

    ``tests/security/_sql_provenance.py`` derives its scope by walking the
    repository rather than reading a list, which is what makes a new package
    swept the day it lands. That removes one drift and introduces another: a
    walk answers only for the directories that happen to exist, so it cannot
    fail for a directory nobody decided about. The canonical set in this file
    can, which is why the two are tied together here.

    The sweep's scope is therefore asserted to be exactly
    ``PACKAGES | UNGATED`` minus its own stated exclusion, and that exclusion
    is asserted to be a directory this file has already accounted for — so
    "excluded from the sweep" can never become a way of being in no scope at
    all. ``tests/security/test_sql_provenance.py`` separately asserts that the
    one excluded directory still *earns* its exclusion by measurement.

    Unlike the gates above, this one needs no entry in ``pyproject.toml``,
    ``ci.yml``, ``release.yml``, ``.pre-commit-config.yaml`` or ``AGENTS.md``:
    it runs inside ``pytest``, which every one of those already invokes.
    """
    swept = {path.name for path in sqlprov.shipped_package_roots(_REPO)}
    assert swept == (PACKAGES | UNGATED) - set(sqlprov.UNSWEPT), (
        f"the SQL-provenance sweep covers {sorted(swept)}, which is not "
        f"{sorted((PACKAGES | UNGATED) - set(sqlprov.UNSWEPT))}"
    )
    unaccounted = set(sqlprov.UNSWEPT) - PACKAGES - UNGATED
    assert unaccounted == set(), (
        f"{sorted(unaccounted)} is excluded from the SQL sweep but is in no scope in this "
        "file either, so nothing accounts for it"
    )
