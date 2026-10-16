# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The Scorecard action belongs in a workflow, and its egress stays off.

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
below say the Scorecard action is in the one place that can actually execute it
and that the choices made about its egress still hold.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]
_WORKFLOW = _REPO / ".github" / "workflows" / "scorecard.yml"
_PRE_COMMIT = _REPO / ".pre-commit-config.yaml"

#: A full 40-character commit SHA. This repository pins every action to one
#: with a trailing ``# vN`` comment, and Scorecard's own Pinned-Dependencies
#: check grades exactly that — so a tag-pinned action here would be a finding
#: raised by the workflow against itself.
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")

#: Keys that only ever appear in a GitHub Actions workflow. None of them is a
#: valid key anywhere in a pre-commit configuration, so finding one there means
#: workflow YAML has been pasted into the wrong file — which is #232 exactly.
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


@pytest.mark.unit
def test_publishing_results_is_off_and_no_oidc_token_is_granted() -> None:
    """The egress decision, pinned so it cannot be flipped quietly.

    ``publish_results: true`` POSTs repository metadata to the OpenSSF REST API
    and is therefore an external-network action under AGENTS.md §5.1, which
    requires human approval with the URL shown in full. The owner chose to keep
    results inside the repository.

    ``id-token: write`` is asserted absent as the *corroborating* half, and it
    is not decoration: that permission exists only to sign published results,
    so a workflow holding it while claiming not to publish would be telling two
    different stories. Granting it is also the first thing anyone enabling
    publishing would have to do, which makes its absence the tripwire.
    """
    workflow = _load(_WORKFLOW)
    steps = workflow["jobs"]["analysis"]["steps"]
    scorecard = next(
        step for step in steps if step.get("uses", "").startswith("ossf/scorecard-action@")
    )
    assert scorecard["with"]["publish_results"] is False, (
        "publish_results is not False: this workflow would send repository metadata to "
        "https://api.securityscorecards.dev, which AGENTS.md §5.1 gates on human approval"
    )
    granted = {
        *(workflow.get("permissions") or {}),
        *(workflow["jobs"]["analysis"].get("permissions") or {}),
    }
    assert "id-token" not in granted, (
        "id-token is granted but nothing publishes: it signs published results only, so "
        "either publishing was turned on without revisiting the §5.1 decision or the "
        "permission is granted for nothing"
    )


@pytest.mark.unit
def test_the_workflow_holds_exactly_one_write_permission() -> None:
    """Least privilege (AGENTS.md §3), asserted rather than intended.

    The upstream starter workflow declares ``permissions: read-all`` at the top
    level; this repository's convention is an explicit ``contents: read``, and
    the job adds the single write it needs to put SARIF in the Code scanning
    tab. Anything further is a finding here.
    """
    workflow = _load(_WORKFLOW)
    assert workflow["permissions"] == {"contents": "read"}, (
        f"top-level permissions are {workflow['permissions']}, not a least-privilege "
        "`contents: read`"
    )
    job = workflow["jobs"]["analysis"]["permissions"]
    writes = {name for name, level in job.items() if level == "write"}
    assert writes == {"security-events"}, (
        f"the job holds writes {sorted(writes)}; only security-events is needed, to upload "
        "the SARIF to code scanning"
    )


@pytest.mark.unit
def test_every_action_is_pinned_to_a_full_commit_sha() -> None:
    """The convention, and a check Scorecard itself would otherwise flag.

    Pinned-Dependencies is one of the checks this very workflow runs, so a
    tag-pinned ``uses:`` here would have the workflow report a finding against
    itself. Every SHA below was taken from OpenSSF's own
    ``scorecard-analysis.yml`` rather than from memory, and two of the four
    resolve to pins this repository already uses elsewhere.
    """
    unpinned: list[str] = []
    for step in _load(_WORKFLOW)["jobs"]["analysis"]["steps"]:
        if "uses" not in step:
            continue
        action, _, reference = step["uses"].partition("@")
        if not _FULL_SHA.match(reference):
            unpinned.append(f"{action}@{reference}")
    assert not unpinned, f"these actions are not pinned to a full commit SHA: {unpinned}"


@pytest.mark.unit
def test_the_checkout_does_not_persist_credentials() -> None:
    """Scorecard grades this, and leaving a token on disk is the thing it means."""
    checkout = next(
        step
        for step in _load(_WORKFLOW)["jobs"]["analysis"]["steps"]
        if step.get("uses", "").startswith("actions/checkout@")
    )
    assert checkout["with"]["persist-credentials"] is False, (
        "the checkout persists credentials; nothing here needs the token on disk"
    )
