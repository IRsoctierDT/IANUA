# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The Scorecard action belongs in a workflow, not in the pre-commit config.

#232 appended three lines to ``.pre-commit-config.yaml``::

      # --- OSSF Scorecard Scanning (scorecard) ---------------------------
       - name: OSSF Scorecard action
      uses: ossf/scorecard-action@v2.5.0

Two defects in three lines. The indentation made the file unparseable, so
``pre-commit run --all-files`` died with ``InvalidConfigError`` *before any
hook ran* — ruff, ruff-format, mypy, bandit, detect-secrets,
detect-private-key, check-yaml and the drift gates all silently skipped for
every developer, measured on the merge commit ``c043b1c``. And ``name``/
``uses`` is GitHub Actions syntax: a pre-commit ``repos`` entry needs ``repo``,
and a hosted one needs ``rev`` and ``hooks`` as well, so the stanza could never
have run a Scorecard scan even indented correctly.

``ci.yml`` now runs ``pre-commit validate-config``, which is the gate that
would have caught it. This file is the second layer, and the two are not
redundant: ``validate-config`` proves the file *loads*, while the assertions
below say the Scorecard action is in the one place that can execute it and that
nothing Actions-shaped has been pasted back.

**Boundary assertions are deliberately not here.** The workflow's egress
decision, its single write permission, its SHA pinning and its credential
handling live in ``tests/security/test_scorecard_boundary.py``, because §6.2
requires a ``tests/security`` case where a boundary is involved and §6 scopes
the independent Security pass to ``tests/security``. Review caught that: the
first version of this change put them here, where that pass would not see
them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]
_WORKFLOW = _REPO / ".github" / "workflows" / "scorecard.yml"
_PRE_COMMIT = _REPO / ".pre-commit-config.yaml"

#: Keys that only ever appear in a GitHub Actions workflow. None is a valid key
#: anywhere in a pre-commit configuration, so finding one there means workflow
#: YAML has been pasted into the wrong file — which is #232 exactly.
_WORKFLOW_ONLY_KEYS = ("uses", "runs-on", "steps", "jobs", "permissions")


def _load(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.mark.unit
def test_the_pre_commit_config_still_parses() -> None:
    """The first thing #232 broke, asserted directly.

    Deliberately the simplest assertion in this file: every other gate in the
    repository — ruff, mypy, bandit, the secret scanners, the drift gates — is
    invoked through this file locally, so when it does not load, nothing does.
    """
    config = _load(_PRE_COMMIT)
    assert isinstance(config, dict), "the pre-commit config is not a mapping"
    assert config.get("repos"), "the pre-commit config declares no repos"


@pytest.mark.unit
def test_every_pre_commit_entry_has_the_keys_the_schema_requires() -> None:
    """A correctly indented but wrong entry must fail too.

    Indentation was only half of #232. ``- name: ...`` / ``uses: ...`` is not a
    pre-commit repository mapping however it is laid out, so an assertion that
    only checked parseability would pass on a tidied-up version of the same
    mistake.

    ``rev`` is required for a hosted repository and must be *absent* for
    ``local`` and ``meta``, which is why this is keyed on the repo value rather
    than demanding all three keys everywhere.
    """
    offenders: list[str] = []
    for index, entry in enumerate(_load(_PRE_COMMIT)["repos"]):
        if not isinstance(entry, dict) or "repo" not in entry:
            offenders.append(f"repos[{index}]: no `repo` key — keys were {sorted(entry or [])}")
            continue
        if "hooks" not in entry:
            offenders.append(f"repos[{index}] ({entry['repo']}): no `hooks` key")
        if entry["repo"] not in {"local", "meta"} and "rev" not in entry:
            offenders.append(f"repos[{index}] ({entry['repo']}): hosted repo without `rev`")
    assert not offenders, f"pre-commit entries that the schema would refuse: {offenders}"


@pytest.mark.unit
@pytest.mark.parametrize("key", _WORKFLOW_ONLY_KEYS, ids=_WORKFLOW_ONLY_KEYS)
def test_no_workflow_syntax_leaked_into_the_pre_commit_config(key: str) -> None:
    """Keyed on the *text*, because a broken file has no structure to walk.

    The point of a textual check here is that it works on the file that caused
    this: once the YAML is invalid there is no mapping to inspect, so a
    structural assertion would error rather than report. This one reads the
    bytes and still names the problem.

    ``entry:`` is a legitimate pre-commit key and is not in the list; ``uses:``
    and ``runs-on:`` have no meaning in this file at all.
    """
    for number, line in enumerate(_PRE_COMMIT.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert not stripped.startswith(f"{key}:"), (
            f".pre-commit-config.yaml:{number} uses the GitHub Actions key {key!r} "
            f"({stripped!r}). Workflow steps belong in .github/workflows/, which is "
            "what #232 got wrong and what this file exists to stop recurring"
        )


@pytest.mark.unit
def test_the_scorecard_workflow_exists_and_runs_the_action() -> None:
    """The other half of the move: removed from one file, present in the other."""
    assert _WORKFLOW.is_file(), f"{_WORKFLOW.relative_to(_REPO)} is missing"
    steps = _load(_WORKFLOW)["jobs"]["analysis"]["steps"]
    actions = [step["uses"].split("@")[0] for step in steps if "uses" in step]
    assert "ossf/scorecard-action" in actions, (
        f"the workflow does not run the Scorecard action — it runs {actions}"
    )
