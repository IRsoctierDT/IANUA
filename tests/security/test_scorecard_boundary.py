# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The Scorecard workflow's boundary: no egress, one write, pinned, no token on disk.

``.github/workflows/scorecard.yml`` crosses two boundaries AGENTS.md §5 names, so
the assertions about them live here rather than beside the structural checks in
``tests/unit/test_scorecard_workflow.py``:

* **External network (§5, §5.1).** ``publish_results: true`` POSTs repository
  metadata to the OpenSSF REST API at ``https://api.scorecard.dev`` and enables
  a public badge. §5.1 classes that as an external-network action requiring
  human approval with the URL shown in full. The owner was shown it and chose
  ``false``, so no egress is configured — and that is a decision, not a
  default, which is why it is asserted.

  **The host was wrong here until review checked it**, and for a §5.1 record
  that is the whole point: this said ``api.securityscorecards.dev``, while the
  pinned action's ``internal_publish_base_url`` default is
  ``https://api.scorecard.dev`` (read from ``action.yaml`` at the SHA this
  workflow pins). An approval record naming the wrong endpoint documents
  approval for something that was never proposed.

  **And ``false`` buys less than this file used to claim.** IANUA is a *public*
  repository; the pinned README says the Scorecard team scans public
  repositories weekly and publishes those results regardless, with
  ``publish_results: true`` merely *replacing* them with our own run's. So this
  assertion pins "this run is not submitted", not "the results are private".
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


def _all_steps() -> list[tuple[str, dict[str, Any]]]:
    """Every step of every job, with its job name.

    The pin assertion below used ``_steps()`` — the ``analysis`` job alone —
    which was the whole workflow until the ``image-pin`` gate job was added.
    A guard scoped narrower than the file it guards is the pattern this
    repository keeps finding in its own controls, so it reads both jobs now.
    (``tests/security/test_workflow_permissions.py`` covers every job of every
    workflow independently; this is the second layer, not the only one.)
    """
    jobs = typing.cast("dict[str, dict[str, Any]]", _workflow()["jobs"])
    return [
        (name, step)
        for name, job in jobs.items()
        for step in typing.cast("list[dict[str, Any]]", job.get("steps") or [])
    ]


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
        "https://api.scorecard.dev (the pinned action's internal_publish_base_url "
        "default), which AGENTS.md §5.1 gates on human approval with the URL shown in "
        "full. Note this does not make the results private — IANUA is public and OpenSSF "
        "scans public repositories weekly either way; it decides whether OUR run is what "
        "the public dataset carries"
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
    exactly one job adding the single write it needs. Anything beyond that is a
    finding here, including a write added for a step someone appends later.
    """
    workflow = _workflow()
    assert workflow["permissions"] == {"contents": "read"}, (
        f"top-level permissions are {workflow['permissions']}, not a least-privilege "
        "`contents: read`"
    )
    writes = {
        name: sorted(
            scope for scope, level in (job.get("permissions") or {}).items() if level == "write"
        )
        for name, job in workflow["jobs"].items()
    }
    holders = {name: scopes for name, scopes in writes.items() if scopes}
    assert holders == {"code-scanning": ["security-events"]}, (
        f"writes are held by {holders}; exactly one job may hold exactly security-events,"
        " and it is the job that uploads the SARIF"
    )


@pytest.mark.security
def test_the_write_is_not_in_the_job_that_runs_the_third_party_action() -> None:
    """The reason the job boundary exists, asserted as a boundary.

    A workflow token is **job**-scoped, not step-scoped. While the SARIF upload
    lived in the ``analysis`` job, that job held ``security-events: write`` — so
    the scorecard container received a token carrying that write. Measured in
    ``action.yaml`` at the pinned SHA: ``repo_token`` and
    ``internal_default_token`` both default to ``${{ github.token }}``, so
    GitHub passes the job's token into the container, for an upload the
    container never performs. And because it is a **Docker** action whose image
    is named by a mutable tag, that token reached code this repository cannot
    read and does not pin.

    Least privilege is therefore not expressible inside one job, which is why
    this is a structural assertion and not a permissions nit: the only way to
    keep the write away from the container is for the write to live in a
    different job. Re-merging the two jobs fails here.

    This does **not** assert the SARIF is trustworthy. It is produced by the
    unreviewed image and uploaded verbatim either way; what changed is who
    holds the write.
    """
    workflow = _workflow()
    jobs = workflow["jobs"]

    vendor_jobs = {
        name
        for name, job in jobs.items()
        for step in (job.get("steps") or [])
        if str(step.get("uses", "")).startswith("ossf/scorecard-action@")
    }
    assert vendor_jobs, "no job runs the scorecard action; this assertion would be vacuous"

    for name in sorted(vendor_jobs):
        granted = (jobs[name].get("permissions") or {}).items()
        writes = sorted(scope for scope, level in granted if level == "write")
        assert not writes, (
            f"job {name!r} runs ossf/scorecard-action AND holds writes {writes}. A workflow"
            " token is job-scoped, so the container receives that write through its"
            " token-defaulted inputs. Move the write to a job that runs no third-party action"
        )

    uploader = {
        name
        for name, job in jobs.items()
        for step in (job.get("steps") or [])
        if "codeql-action/upload-sarif@" in str(step.get("uses", ""))
    }
    assert uploader, "no job uploads the SARIF"
    assert not (uploader & vendor_jobs), (
        f"the SARIF upload and the scorecard action share a job ({sorted(uploader & vendor_jobs)});"
        " the split is what keeps the write away from the vendor container"
    )


@pytest.mark.security
def test_no_third_party_action_runs_in_the_job_that_holds_the_write() -> None:
    """The converse, which is the direction a later edit would break.

    The test above stops the write moving to the vendor's job. This one stops a
    vendor action moving to the write's job — the same defect approached from
    the other side, and the easier mistake to make, because adding a step to an
    existing job looks smaller than adding a job.

    First-party owners are named here rather than imported from
    ``test_third_party_actions.py``: that module's list is the exemption list
    for the review-record gate, and coupling a boundary assertion to it would
    mean widening one silently widened the other.
    """
    first_party = ("actions/", "github/", "dependabot/")
    workflow = _workflow()
    for name, job in workflow["jobs"].items():
        granted = (job.get("permissions") or {}).items()
        if not any(level == "write" for _, level in granted):
            continue
        for step in job.get("steps") or []:
            uses = str(step.get("uses", ""))
            if not uses:
                continue
            assert uses.startswith(first_party), (
                f"job {name!r} holds a write and runs the third-party action {uses!r}."
                " A write-holding job may run only GitHub's own actions"
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
    for job_name, step in _all_steps():
        if "uses" not in step:
            continue
        action, _, reference = step["uses"].partition("@")
        if not _FULL_SHA.match(reference):
            unpinned.append(f"{job_name}: {action}@{reference}")
    assert not unpinned, f"these actions are not pinned to a full commit SHA: {unpinned}"
    # Named rather than counted: each of the three carries a boundary, so a
    # vanished job is a vanished control and the failure should say which.
    # `image-pin` gates on the mutable image tag; `analysis` runs the vendor
    # action under no write; `code-scanning` holds the only write and runs no
    # vendor action.
    assert set(_workflow()["jobs"]) == {"image-pin", "analysis", "code-scanning"}, (
        f"the jobs are {sorted(_workflow()['jobs'])}; expected image-pin, analysis and"
        " code-scanning. If a job was removed, check which boundary went with it"
    )


@pytest.mark.security
def test_no_checkout_in_any_job_persists_credentials() -> None:
    """No token left on disk for the rest of the job to reach.

    Scorecard reads the tree and never needs it. This is also something
    Scorecard grades, so leaving it on would be a finding raised by the
    workflow against itself.

    **Widened from the ``analysis`` job to every job**, and the new job is the
    one that makes it matter: ``code-scanning`` is where the
    ``security-events: write`` lives, so a credential persisted *there* would
    put a write-capable token on disk — strictly worse than in a read-only job,
    and precisely the place a narrow assertion would have missed.
    """
    checkouts = [
        (job, step)
        for job, step in _all_steps()
        if str(step.get("uses", "")).startswith("actions/checkout@")
    ]
    assert checkouts, "no checkout found; this assertion would be vacuous"
    for job, step in checkouts:
        assert (step.get("with") or {}).get("persist-credentials") is False, (
            f"the checkout in job {job!r} does not set persist-credentials: false;"
            " nothing in this workflow needs the token on disk"
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
