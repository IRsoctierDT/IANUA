# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The Penthera workflow's boundary: no scanning, no registry, pinned, two writes.

``.github/workflows/penthera.yml`` runs a third-party composite action over
this repository with a token, so it touches three things AGENTS.md §5 names.
The assertions about them live here rather than beside any structural check,
because §6.2 requires "a ``tests/security`` case where a boundary is involved"
and §6's role table scopes the independent Security pass to "the security
boundaries (§5) and ``tests/security``" — the same placement correction review
made on ``test_scorecard_boundary.py``.

* **Scanning a third-party system (§5).** The action has a third mode that
  takes a ``url`` and sends requests to it. §5 prohibits code that "scans,
  attacks, exploits, brute-forces, or accesses third-party systems without
  explicit, documented authorization", and the action's own input description
  says "Scan only systems you are authorized to test". IANUA declares no such
  target, so ``mode: scan`` and the ``url`` input must never appear here.
  Adding them is a §5.1 boundary-crossing gate, not a configuration change,
  and this is the assertion that makes that a failed build rather than a
  reviewer's catch.

* **External network (§5.1).** ``mode: agents`` runs ``npm ci`` against the
  action's committed lockfile, which fetches from ``https://registry.npmjs.org``.
  §5.1 classes that as an external-network action requiring human approval
  with the URL shown in full. The owner has not yet made that call, so the
  job is gated to a manual dispatch — asserted below, because the gate is a
  decision and not a default.

* **Repository write permissions (§3).** The ``deps`` job holds
  ``pull-requests: write`` for one comment and ``security-events: write`` for
  one SARIF upload. Two writes, for two steps, and nothing else — least
  privilege is only a claim until something counts the grants.

The pin itself is the fourth concern and the reason the rest can be trusted:
a floating ``@v1.9.0`` tag, which is what the vendor snippet offered, is
re-pointable by whoever holds the upstream repository. OpenSSF Scorecard's
Pinned-Dependencies check grades exactly this, so a tag-pinned action here
would also be a finding ``scorecard.yml`` raises against us.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]
_WORKFLOW = _REPO / ".github" / "workflows" / "penthera.yml"

#: A full 40-character commit SHA, per AGENTS.md §8's pinning convention.
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")

#: ``uses: owner/repo@<sha> # v<version>`` as this repository writes it.
_USES = re.compile(r"uses:\s*(?P<action>[^@\s]+)@(?P<ref>\S+)(?:\s*#\s*(?P<tag>\S+))?")

#: The upstream action under review. Its modes are the boundary.
_PENTHERA = "danoszz/penthera"

#: Write permissions this workflow is allowed to request, and the only ones.
#: ``contents`` is deliberately absent: a read is not a write, and nothing
#: here commits, tags or pushes.
_ALLOWED_WRITES = frozenset({"pull-requests", "security-events"})


def _load() -> Any:
    return yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))


def _jobs() -> dict[str, Any]:
    jobs = _load()["jobs"]
    assert isinstance(jobs, dict) and jobs, "the workflow declares no jobs"
    return jobs


def _penthera_steps() -> list[tuple[str, dict[str, Any]]]:
    """Every step in the workflow that runs the third-party action."""
    found: list[tuple[str, dict[str, Any]]] = []
    for name, job in _jobs().items():
        for step in job.get("steps") or []:
            uses = str(step.get("uses", ""))
            if uses.startswith(f"{_PENTHERA}@"):
                found.append((name, step))
    assert found, f"no step runs {_PENTHERA}; this test file is pinning nothing"
    return found


@pytest.mark.security
def test_the_live_url_scan_mode_is_never_configured() -> None:
    """§5: no job may scan a target, and none may name one.

    Both halves matter. ``mode`` is the switch, but a ``url`` left behind on a
    step that no longer sets ``mode: scan`` is a loaded gun for the next edit,
    so the input is refused outright rather than only in combination.
    """
    for job_name, step in _penthera_steps():
        inputs = step.get("with") or {}
        mode = str(inputs.get("mode", "")).strip()
        assert mode != "scan", (
            f"job {job_name!r} sets mode: scan. §5 prohibits accessing "
            "third-party systems without documented authorization; wiring "
            "this is a §5.1 boundary gate, not a config change."
        )
        assert "url" not in inputs, (
            f"job {job_name!r} passes a url to {_PENTHERA}. That input exists "
            "only for scan mode and must not appear in this repository."
        )


@pytest.mark.security
def test_the_agent_config_audit_cannot_reach_a_registry_unasked() -> None:
    """§5.1: the npm fetch runs only on an explicit manual dispatch.

    ``mode: agents`` needs the ``yaml`` package, which upstream does not
    vendor, so the step runs ``npm ci`` against ``registry.npmjs.org``. That
    is an external-network action awaiting the owner's approval, so the job
    must not be reachable from a pull request or a push.
    """
    agents_jobs = [
        (name, job)
        for name, job in _jobs().items()
        for step in job.get("steps") or []
        if str((step.get("with") or {}).get("mode", "")).strip() == "agents"
    ]
    for name, job in agents_jobs:
        condition = str(job.get("if", ""))
        assert "workflow_dispatch" in condition, (
            f"job {name!r} runs mode: agents without requiring a manual "
            "dispatch. That mode fetches from https://registry.npmjs.org, "
            "which §5.1 gates on human approval with the URL shown in full."
        )


@pytest.mark.security
def test_every_action_is_pinned_to_a_full_commit_sha() -> None:
    """§8: full SHA, never a floating tag — the vendor snippet offered a tag."""
    text = _WORKFLOW.read_text(encoding="utf-8")
    references = list(_USES.finditer(text))
    assert references, "no `uses:` reference found; the regex has gone stale"
    for match in references:
        action, ref = match.group("action"), match.group("ref")
        assert _FULL_SHA.match(ref), (
            f"{action} is pinned to {ref!r}, which is not a full 40-character "
            "commit SHA. A tag is re-pointable by whoever holds the upstream "
            "repository."
        )


@pytest.mark.security
def test_the_pinned_ref_and_the_asserted_version_stay_in_step() -> None:
    """The SHA and ``penthera-version`` must name the same release.

    The action reads its own bundled ``package.json`` and fails the job when
    ``penthera-version`` disagrees with it, which turns a re-pointed ref into
    a failed run instead of a silent swap. That only holds while the input
    tracks the pin, so a Dependabot bump that moves the SHA and its ``# v…``
    comment without touching the input fails here — deliberately, because a
    human then has to confirm which version is meant.
    """
    text = _WORKFLOW.read_text(encoding="utf-8")
    tags = {
        m.group("tag")
        for m in _USES.finditer(text)
        if m.group("action") == _PENTHERA and m.group("tag")
    }
    assert len(tags) == 1, f"{_PENTHERA} is pinned at inconsistent versions: {tags}"
    pinned = next(iter(tags)).lstrip("v")

    for job_name, step in _penthera_steps():
        declared = str((step.get("with") or {}).get("penthera-version", "")).strip()
        assert declared, (
            f"job {job_name!r} does not set penthera-version, so a re-pointed "
            "ref would run whatever version it now holds, silently."
        )
        assert declared == pinned, (
            f"job {job_name!r} asserts penthera-version {declared!r} while the "
            f"pin's comment says {pinned!r}. One of the two is stale."
        )


@pytest.mark.security
def test_the_workflow_requests_no_write_beyond_the_two_it_needs() -> None:
    """§3 least privilege, counted rather than claimed."""
    document = _load()
    top_level = document.get("permissions") or {}
    assert top_level == {"contents": "read"}, (
        f"the default permission block is {top_level!r}; it should be "
        "read-only so jobs opt into writes explicitly."
    )

    for name, job in _jobs().items():
        granted = job.get("permissions") or {}
        assert granted, f"job {name!r} declares no permissions block"
        writes = {key for key, value in granted.items() if value == "write"}
        unexpected = writes - _ALLOWED_WRITES
        assert not unexpected, (
            f"job {name!r} requests write on {sorted(unexpected)}, which is "
            "outside the one PR comment and one SARIF upload this workflow "
            "performs."
        )
        assert "id-token" not in granted, (
            f"job {name!r} requests an OIDC token. Nothing here signs or "
            "publishes anything, so it would be a permission granted for "
            "nothing."
        )


@pytest.mark.security
def test_no_checkout_persists_credentials_for_the_third_party_action() -> None:
    """The action runs after checkout; it must not inherit a git credential.

    ``persist-credentials: false`` keeps the token out of ``.git/config``,
    where any later step — including upstream's — could read it. The deps
    mode's own ``git fetch`` of the pull request base is anonymous against
    this public repository, so nothing needs it.
    """
    for name, job in _jobs().items():
        for step in job.get("steps") or []:
            if not str(step.get("uses", "")).startswith("actions/checkout@"):
                continue
            inputs = step.get("with") or {}
            assert inputs.get("persist-credentials") is False, (
                f"the checkout in job {name!r} does not set "
                "persist-credentials: false, so the token is written to "
                ".git/config before third-party code runs."
            )


@pytest.mark.security
def test_findings_are_report_only_by_an_explicit_choice() -> None:
    """``fail-on: none`` is written literally, so the choice shows in a diff.

    A new tool's first weeks on this repository should not be able to wedge
    the pipeline, and this workflow is deliberately not one of §8's required
    checks. Raising this to ``high`` is the documented escalation path and is
    meant to be a visible, reviewed edit rather than a default drifting.
    """
    for job_name, step in _penthera_steps():
        fail_on = str((step.get("with") or {}).get("fail-on", "")).strip()
        assert fail_on == "none", (
            f"job {job_name!r} sets fail-on: {fail_on!r}. If that is the "
            "intended escalation, update this assertion in the same commit "
            "so the change is deliberate."
        )
