"""Dependabot grouping must route tool bumps to the auto-merging group.

This exists because the obvious configuration was silently wrong. The `uv`
ecosystem's groups were keyed on ``dependency-type: "development"``, which
matches nothing in this project: Dependabot classifies everything in
``[project.optional-dependencies]`` as *production*, and the tools live in the
``dev`` extra so they install with ``pip install -e ".[dev]"``. Every ruff,
mypy and pytest bump therefore landed in the human-review-only ``runtime``
group — the slow path the ``dev-toolchain`` group was created to avoid
(dependabot-core#10606, #13202).

The replacement matches by explicit package name, which introduces a different
hazard: three places now have to agree — the group's ``patterns``, the
``runtime`` group's ``exclude-patterns``, and ``pyproject.toml``'s extras — and
nothing but these tests notices when they stop agreeing. That is precisely the
drift class ``docs/PATH_RECONCILIATION_AUDIT.md`` was written about, so it gets
a gate rather than a comment asking someone to remember.

Pattern matching here is modelled with ``fnmatch``. Dependabot's own matcher is
not specified in a form this repository can execute, so these tests pin the
*config's internal consistency*, which is what drifts, rather than claiming to
reproduce GitHub's engine.
"""

from __future__ import annotations

import fnmatch
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]

#: Packages that shipped code imports at runtime. They sit in the ``dev`` extra
#: for installation convenience, but a bump changes what the platform *does* —
#: `yaml` drives Sigma rule parsing, `reportlab` renders client PDFs,
#: `cryptography` signs the audit chain and the ATT&CK pin, `packaging` parses
#: versions in the lock gates. None may ever auto-merge; a human reads them.
NEVER_AUTO_MERGE = {"pyyaml", "reportlab", "cryptography", "packaging"}

#: The group name the auto-merge workflow matches on. Renaming the group
#: without renaming it there silently disables auto-merge.
AUTO_MERGE_GROUP = "dev-toolchain"


def _dependabot() -> dict[str, Any]:
    # Narrowed rather than cast: yaml.safe_load returns Any, and a malformed
    # config should fail here with a clear message instead of an AttributeError
    # several frames later.
    data = yaml.safe_load((_REPO / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    assert isinstance(data, dict), "dependabot.yml must parse to a mapping"
    return data


def _uv_groups() -> dict[str, Any]:
    uv = [u for u in _dependabot()["updates"] if u["package-ecosystem"] == "uv"]
    assert len(uv) == 1, "expected exactly one uv ecosystem block"
    groups = uv[0]["groups"]
    assert isinstance(groups, dict), "the uv block must declare a groups mapping"
    return groups


def _declared_packages() -> set[str]:
    """Every package name declared in pyproject's extras (and runtime deps)."""
    config = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8"))
    project = config["project"]
    specs = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        specs.extend(extra)
    names = set()
    for spec in specs:
        name = spec
        for sep in ("==", ">=", "<=", "~=", "!=", ">", "<", "["):
            if sep in name:
                name = name.split(sep)[0]
        names.add(name.strip())
    return names


@pytest.mark.unit
def test_groups_are_disjoint_by_construction() -> None:
    """The tool list and the runtime exclusions must be the same set.

    GitHub documents that group order matters, but relying on order would mean
    a reordering could silently route a tool bump into the human-review group,
    or a library bump into the auto-merging one. Making the groups disjoint
    removes the dependence on an ordering rule entirely — so the two lists have
    to stay identical.
    """
    groups = _uv_groups()
    tools = set(groups[AUTO_MERGE_GROUP].get("patterns", []))
    excluded = set(groups["runtime"].get("exclude-patterns", []))
    assert tools == excluded, (
        "dev-toolchain patterns and runtime exclude-patterns have diverged; "
        f"only in dev-toolchain: {sorted(tools - excluded)}; "
        f"only in runtime excludes: {sorted(excluded - tools)}"
    )


@pytest.mark.unit
def test_runtime_group_catches_everything_else() -> None:
    """Nothing may fall outside both groups and get an ungrouped PR."""
    groups = _uv_groups()
    assert groups["runtime"].get("patterns") == ["*"], (
        "runtime must match '*' so every non-tool bump is still grouped"
    )


@pytest.mark.unit
def test_every_tool_pattern_matches_a_declared_package() -> None:
    """A pattern naming nothing is dead config that reads as coverage."""
    tools = _uv_groups()[AUTO_MERGE_GROUP].get("patterns", [])
    declared = _declared_packages()
    stale = [p for p in tools if not any(fnmatch.fnmatch(n, p) for n in declared)]
    assert not stale, f"dev-toolchain patterns match no declared package: {stale}"


@pytest.mark.unit
def test_imported_libraries_never_auto_merge() -> None:
    """The security-relevant invariant, asserted directly.

    `dev-toolchain` auto-merges on patch/minor once CI is green. That is
    defensible for a linter or a test runner — a bad bump breaks the build
    loudly and reaches no user. It is not defensible for a library that shipped
    code imports, where a bump changes behaviour in production.
    """
    tools = _uv_groups()[AUTO_MERGE_GROUP].get("patterns", [])
    leaked = sorted(pkg for pkg in NEVER_AUTO_MERGE if any(fnmatch.fnmatch(pkg, p) for p in tools))
    assert not leaked, (
        f"{leaked} would auto-merge, but shipped code imports them — "
        "these belong in the human-reviewed runtime group"
    )


@pytest.mark.unit
def test_auto_merge_workflow_matches_the_group_name() -> None:
    """Renaming the group without updating the workflow disables auto-merge."""
    workflow = (_REPO / ".github" / "workflows" / "dependabot-automerge.yml").read_text(
        encoding="utf-8"
    )
    assert f"== '{AUTO_MERGE_GROUP}'" in workflow, (
        f"dependabot-automerge.yml no longer matches the group {AUTO_MERGE_GROUP!r}"
    )
    assert "'runtime'" not in workflow, (
        "the runtime group must never appear in the auto-merge condition"
    )
    assert "semver-major" in workflow, "majors must still be excluded from auto-merge"


@pytest.mark.unit
def test_dependency_type_is_not_used_for_the_uv_ecosystem() -> None:
    """Guard against a well-meaning revert.

    ``dependency-type`` reads as the natural key and is what the config used
    before; it matched nothing here. A future contributor restoring it would
    reintroduce the original defect with no visible symptom, so the absence is
    pinned.
    """
    for name, group in _uv_groups().items():
        assert "dependency-type" not in group, (
            f"group {name!r} uses dependency-type, which classifies this "
            "project's [project.optional-dependencies] tools as production — "
            "match them by name instead (see .github/dependabot.yml)"
        )
