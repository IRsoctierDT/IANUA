# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The Scorecard workflow's boundary: no egress, one write, pinned, no token on disk.

``.github/workflows/scorecard.yml`` crosses two boundaries AGENTS.md §5 names, so
the assertions about them live here rather than beside the structural checks in
``tests/unit/test_scorecard_workflow.py``:

* **External network (§5, §5.1).** ``publish_results: true`` POSTs repository
  metadata to the OpenSSF REST API at ``https://api.securityscorecards.dev``
  and enables a public badge. §5.1 classes that as an external-network action
  requiring human approval with the URL shown in full. The owner was shown it
  and chose ``false``, so no egress is configured — and that is a decision, not
  a default, which is why it is asserted.
* **A repository write permission (§3).** The job holds ``security-events:
  write`` to upload SARIF to Code scanning. One write, for one step.

Review found the placement, not us: the first version put all of this in
``tests/unit/``, where ``pytest tests/security`` would never reach it. §6.2
requires "a ``tests/security`` case where a boundary is involved", and §6's
role table scopes the independent Security pass to "the security boundaries
(§5) and ``tests/security``" — so assertions about an egress decision that live
only under ``tests/unit`` are invisible to the one review pass meant to check
them. The full suite ran them either way; the reviewer would not have.
"""

from __future__ import annotations

import re
import typing
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]
_WORKFLOW = _REPO / ".github" / "workflows" / "scorecard.yml"
_PRE_COMMIT = _REPO / ".pre-commit-config.yaml"

#: A full 40-character commit SHA. Scorecard's own Pinned-Dependencies check
#: grades exactly this, so a tag-pinned action here would be a finding the
#: workflow raises against itself.
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")

#: The hooks that make ``.pre-commit-config.yaml`` a security control rather
#: than a convenience. Both are §5 controls — "never remove, weaken, comment
#: out, or bypass an existing control" — and both are unreachable when the
#: file does not load.
_SECRET_HOOKS = ("detect-secrets", "detect-private-key")


def _workflow() -> Any:
    return yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))


def _steps() -> list[dict[str, Any]]:
    # ``yaml.safe_load`` is untyped, so the subscript chain is ``Any``. Cast
    # rather than widening the signature: the shape is what every assertion
    # below reads, and stating it here is the point of the helper.
    return typing.cast("list[dict[str, Any]]", _workflow()["jobs"]["analysis"]["steps"])


@pytest.mark.security
def test_publishing_results_is_off() -> None:
    """The §5.1 egress decision, pinned so it cannot be flipped quietly.

    An approval gate answered once should not be re-openable by an edit nobody
    reads as a boundary change. Turning publishing on now fails here, which
    makes it a deliberate act with a test to delete.
    """
    scorecard = next(
        step for step in _steps() if step.get("uses", "").startswith("ossf/scorecard-action@")
    )
    assert scorecard["with"]["publish_results"] is False, (
        "publish_results is not False: this workflow would send repository metadata to "
        "https://api.securityscorecards.dev, which AGENTS.md §5.1 gates on human approval "
        "with the URL shown in full"
    )


@pytest.mark.security
def test_no_oidc_token_is_granted_anywhere() -> None:
    """The corroborating half, and not decoration.

    ``id-token: write`` exists solely to sign *published* results, so a
    workflow holding it while claiming not to publish would be telling two
    different stories. It is also the first thing anyone enabling publishing
    must add, which makes its absence the tripwire rather than a tidiness
    check.
    """
    workflow = _workflow()
    granted = {
        *(workflow.get("permissions") or {}),
        *(workflow["jobs"]["analysis"].get("permissions") or {}),
    }
    assert "id-token" not in granted, (
        "id-token is granted but nothing publishes: either publishing was turned on "
        "without revisiting the §5.1 decision, or the permission is granted for nothing"
    )


@pytest.mark.security
def test_the_workflow_holds_exactly_one_write_permission() -> None:
    """Least privilege (AGENTS.md §3), asserted rather than intended.

    The upstream starter workflow declares ``permissions: read-all`` at the top
    level. This repository's convention is an explicit ``contents: read``, with
    the job adding the single write it needs. Anything beyond that is a finding
    here, including a write added for a step someone appends later.
    """
    workflow = _workflow()
    assert workflow["permissions"] == {"contents": "read"}, (
        f"top-level permissions are {workflow['permissions']}, not a least-privilege "
        "`contents: read`"
    )
    job = workflow["jobs"]["analysis"]["permissions"]
    writes = {name for name, level in job.items() if level == "write"}
    assert writes == {"security-events"}, (
        f"the job holds writes {sorted(writes)}; only security-events is needed, to upload "
        "the SARIF to Code scanning"
    )


@pytest.mark.security
def test_every_action_is_pinned_to_a_full_commit_sha() -> None:
    """Supply chain: a tag is mutable, a commit is not.

    Every SHA in this workflow was taken from OpenSSF's own
    ``scorecard-analysis.yml`` rather than from memory, and two of the four
    resolve to pins this repository already uses elsewhere. One trap worth
    keeping: ``git ls-remote`` returns both ``refs/tags/vX`` (the annotated tag
    *object*) and ``refs/tags/vX^{}`` (the commit), and only the peeled commit
    belongs in ``uses:``.
    """
    unpinned: list[str] = []
    for step in _steps():
        if "uses" not in step:
            continue
        action, _, reference = step["uses"].partition("@")
        if not _FULL_SHA.match(reference):
            unpinned.append(f"{action}@{reference}")
    assert not unpinned, f"these actions are not pinned to a full commit SHA: {unpinned}"


@pytest.mark.security
def test_the_checkout_does_not_persist_credentials() -> None:
    """No token left on disk for the rest of the job to reach.

    Scorecard reads the tree and never needs it. This is also something
    Scorecard grades, so leaving it on would be a finding raised by the
    workflow against itself.
    """
    checkout = next(
        step for step in _steps() if step.get("uses", "").startswith("actions/checkout@")
    )
    assert checkout["with"]["persist-credentials"] is False, (
        "the checkout persists credentials; nothing in this job needs the token on disk"
    )


@pytest.mark.security
def test_the_secret_scanning_hooks_are_reachable() -> None:
    """The control #232 disabled, asserted as a control rather than as syntax.

    This is the security framing of what the unit suite checks structurally.
    ``.pre-commit-config.yaml`` carries ``detect-secrets`` and
    ``detect-private-key``; AGENTS.md §5 forbids removing, weakening or
    bypassing an existing control. #232 bypassed both without touching either
    hook — three misindented lines made the file unparseable, so
    ``pre-commit run --all-files`` died with ``InvalidConfigError`` before any
    hook ran. Measured on the merge commit ``c043b1c``.

    So "declared" is not enough and a substring check would not have caught it:
    the file has to **load**, and then the hooks have to be in it. A grep for
    ``detect-secrets`` passed throughout the outage.
    """
    config = yaml.safe_load(_PRE_COMMIT.read_text(encoding="utf-8"))
    assert isinstance(config, dict), (
        "the pre-commit config does not load, so every hook behind it is skipped — "
        "including the two secret scanners this asserts"
    )
    declared = {
        hook.get("id") for entry in config.get("repos", []) for hook in (entry.get("hooks") or [])
    }
    missing = [hook for hook in _SECRET_HOOKS if hook not in declared]
    assert not missing, f"the pre-commit config no longer declares {missing}"
