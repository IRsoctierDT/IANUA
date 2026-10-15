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

import re
import tomllib
from pathlib import Path

import pytest

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
    assert set(mypy_line.split()[2:]) == MYPY_SCOPE
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


@pytest.mark.unit
def test_agents_md_command_blocks_match() -> None:
    charter = (_REPO / "AGENTS.md").read_text(encoding="utf-8")
    mypy_match = re.search(r"^mypy (.+)$", charter, re.MULTILINE)
    assert mypy_match is not None, "AGENTS.md §7 must show the mypy command"
    assert set(mypy_match.group(1).split()) == MYPY_SCOPE, (
        "AGENTS.md §7 mypy scope drifted from the real gate"
    )
    bandit_match = re.search(r"^bandit -c pyproject\.toml -r (.+)$", charter, re.MULTILINE)
    assert bandit_match is not None, "AGENTS.md §7 must show the bandit command"
    assert set(bandit_match.group(1).split()) == BANDIT_SCOPE, (
        "AGENTS.md §7 bandit scope drifted from the real gate"
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
