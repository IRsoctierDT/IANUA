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
PACKAGES = {"agents", "attack", "rag", "mcp", "dashboard", "scripts", "compliance"}
MYPY_SCOPE = {"agents", "attack", "scripts", "tests", "dashboard", "mcp", "rag", "compliance"}
COVERAGE_SCOPE = {"agents", "attack", "compliance", "rag", "mcp"}
# Bandit covers the packages that parse untrusted or externally influenced
# input (agent pipeline, corpus loaders, operational scripts, MCP surface).
BANDIT_SCOPE = {"agents", "attack", "scripts", "mcp"}


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
def test_no_blanket_scripts_mypy_ignore() -> None:
    overrides = _pyproject()["tool"]["mypy"].get("overrides", [])
    for override in overrides:
        modules = override.get("module")
        names = [modules] if isinstance(modules, str) else list(modules)
        for name in names:
            assert name != "scripts.*" or not override.get("ignore_errors"), (
                "blanket scripts.* ignore_errors hides errors in new gate scripts"
            )
