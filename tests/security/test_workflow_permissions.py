# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Workflow tokens and pins: every write grant is named, every action is a commit.

Any ``write`` scope on ``GITHUB_TOKEN`` is the blast radius of the job that
holds it, so the grants are pinned here as an allow-list rather than audited by
hand on each change. Every file under ``.github/workflows/`` is read — ``*.yml``
**and** ``*.yaml``, since GitHub loads both and review measured that one
``.yaml`` file violating every property below left this suite green. The
extension compares case-insensitively, so ``.YML`` is read too (whether GitHub
loads one was not measured). Three assertions, each the mechanical form of an
AGENTS.md §3 or §8 claim:

* **Workflow-level permissions are a mapping and are read-only.** A write at
  the workflow level reaches every job, including one added later for an
  unrelated reason. Measured before this test existed:
  ``dependabot-automerge.yml`` granted ``contents: write`` + ``pull-requests:
  write`` and ``pages.yml`` granted ``pages: write`` + ``id-token: write`` to
  their whole workflow (zizmor ``excessive-permissions``, four hits). Both now
  grant them on the one job. A bare ``permissions:`` with no value counted as
  "declared" until review tried it; a mapping is required, at either level,
  and every level in it must be exactly ``read``, ``write`` or ``none`` — a
  ``Write`` is neither counted as a write nor accepted.
* **The set of (workflow, job, scope) write grants is exactly this list.** A new
  write is a deliberate edit that fails here first, with the reason beside it.
* **Every ``uses:`` is pinned to a full commit SHA with a version comment, and
  every checkout leaves the token off disk.** ``tests/security/
  test_scorecard_boundary.py`` asserts both for ``scorecard.yml``; this extends
  them to the other nine files. A tag is mutable, a commit is not, and a
  persisted credential is reachable by every later step in the job. The
  ``uses:`` values are taken from the *parsed* jobs and steps, not from a line
  regex alone: review measured that ``- {uses: actions/checkout@main, ...}``
  and ``"uses": actions/setup-python@main`` matched no line the regex looked
  for and passed. The line regex stays as a second layer, and the checkout
  check compares case-insensitively. The ref must begin with an owner-shaped
  segment (letters, digits, ``-``) and a slash, so a local ``./`` action or a
  ``docker://`` image fails here however it is suffixed: review measured
  ``docker://alpine@<40 hex>`` and ``./x@<40 hex>`` passing the earlier
  pattern; neither form is used. The whole value must match, so a trailing
  newline in the parsed value fails the pattern itself.

  What this does not hold, stated so it is not read in: a SHA is checked for
  shape, not provenance; "a checkout" means ``actions/checkout``, so a fork of
  it under another owner is not checked for ``persist-credentials``; a job's
  ``container:`` or ``services:`` image is not a ``uses:`` and is not read;
  and the version comment is looked for on any line carrying ``@<sha>``, so
  a flow-style step can take it from another such line, a comment included.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]
_WORKFLOWS = sorted(
    path
    for path in (_REPO / ".github" / "workflows").iterdir()
    if path.suffix.lower() in (".yml", ".yaml")
)

#: ``owner/repo[/path]@<40 hex>`` — the SHA is what runs. The owner segment
#: is letters, digits and ``-``, which ``.`` and ``docker:`` are not.
_PINNED_REF = re.compile(r"^[A-Za-z0-9-]+/[^@\s]+@[0-9a-f]{40}$")
#: ...and on the raw line the version comment Dependabot's ``actions-all``
#: group keeps in step with the SHA.
_PINNED_USES = re.compile(r"^\s*-?\s*uses:\s*\S+@[0-9a-f]{40}\s+#\s*v?\d")
_ANY_USES = re.compile(r"^\s*-?\s*uses:")
_LEVELS = frozenset({"read", "write", "none"})

#: Every write scope a job may hold, and why. Anything else fails the test.
WRITE_GRANTS: dict[tuple[str, str], dict[str, str]] = {
    ("ci.yml", "build"): {
        "id-token": "OIDC for Sigstore keyless signing of the SBOM/provenance",
        "attestations": "store the signed attestations (push to main only)",
    },
    ("release.yml", "publish-assets"): {
        "contents": "upload assets to this repository's releases",
        "id-token": "OIDC for Sigstore keyless signing",
        "attestations": "store the signed attestations",
    },
    ("release-on-merge.yml", "publish"): {
        "contents": "create the tag ref (create-only; never moved)",
        "actions": "dispatch release.yml; read the release environment's rules",
    },
    ("pages.yml", "deploy"): {
        "pages": "actions/deploy-pages creates the Pages deployment",
        "id-token": "OIDC token presented to the Pages service",
    },
    ("dependabot-automerge.yml", "automerge"): {
        "contents": "enable auto-merge; GitHub performs the squash merge",
        "pull-requests": "gh pr merge --auto sets the PR's auto-merge flag",
    },
    ("scorecard.yml", "analysis"): {
        "security-events": "upload the Scorecard SARIF to Code scanning",
    },
}


def _load(path: Path) -> dict[Any, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path.name} must parse to a mapping"
    return data


def _writes(permissions: Any, where: str) -> set[str]:
    # ``write-all`` / ``read-all`` shorthands and a bare ``permissions:`` with
    # no value say nothing a reviewer can read; only a mapping is accepted.
    assert isinstance(permissions, dict), f"{where}: permissions must be a mapping"
    bad = {
        scope: level
        for scope, level in permissions.items()
        if not (isinstance(level, str) and level in _LEVELS)
    }
    assert not bad, f"{where}: a permission level is read, write or none — {bad}"
    return {scope for scope, level in permissions.items() if level == "write"}


def _uses(workflow: dict[Any, Any]) -> list[tuple[str, str]]:
    """Every ``uses:`` value: job-level reusable workflows and steps alike."""
    found = [
        (job_name, str(job["uses"])) for job_name, job in workflow["jobs"].items() if "uses" in job
    ]
    found += [
        (f"{job_name}/{index}", str(step["uses"]))
        for job_name, job in workflow["jobs"].items()
        for index, step in enumerate(job.get("steps") or [])
        if "uses" in step
    ]
    return found


@pytest.mark.security
@pytest.mark.parametrize("path", _WORKFLOWS, ids=lambda p: p.name)
def test_workflow_level_permissions_are_declared_and_read_only(path: Path) -> None:
    workflow = _load(path)
    assert "permissions" in workflow, f"{path.name} does not declare top-level permissions"
    assert not _writes(workflow["permissions"], path.name), (
        f"{path.name} grants a write scope to the whole workflow; grant it on the one job"
    )


@pytest.mark.security
def test_every_job_write_grant_is_on_the_allow_list() -> None:
    found: dict[tuple[str, str], set[str]] = {}
    for path in _WORKFLOWS:
        for job_name, job in _load(path)["jobs"].items():
            if "permissions" not in job:
                continue
            writes = _writes(job["permissions"], f"{path.name}/{job_name}")
            if writes:
                found[(path.name, job_name)] = writes
    expected = {key: set(scopes) for key, scopes in WRITE_GRANTS.items()}
    assert found == expected, (
        "job-level write grants drifted from the allow-list — "
        f"unexpected: { {k: v for k, v in found.items() if expected.get(k) != v} }; "
        f"missing: { {k: v for k, v in expected.items() if found.get(k) != v} }"
    )


@pytest.mark.security
@pytest.mark.parametrize("path", _WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_full_commit_sha_with_a_version_comment(
    path: Path,
) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    unpinned = [
        f"{path.name}:{number}: {line.strip()}"
        for number, line in enumerate(lines, 1)
        if _ANY_USES.match(line) and not _PINNED_USES.match(line)
    ]
    for where, ref in _uses(_load(path)):
        if not _PINNED_REF.fullmatch(ref):
            unpinned.append(f"{path.name} {where}: {ref}")
            continue
        sha = ref.rsplit("@", 1)[1]
        if not any(re.search(rf"@{sha}\b.*#\s*v?\d", line) for line in lines):
            unpinned.append(f"{path.name} {where}: {ref} carries no version comment")
    assert not unpinned, f"actions not pinned to a 40-hex commit with a version comment: {unpinned}"


@pytest.mark.security
@pytest.mark.parametrize("path", _WORKFLOWS, ids=lambda p: p.name)
def test_every_checkout_leaves_the_token_off_disk(path: Path) -> None:
    persisting = [
        f"{job_name}/{index}"
        for job_name, job in _load(path)["jobs"].items()
        for index, step in enumerate(job.get("steps") or [])
        if str(step.get("uses", "")).lower().startswith("actions/checkout@")
        and (step.get("with") or {}).get("persist-credentials") is not False
    ]
    assert not persisting, f"{path.name}: checkouts persisting credentials: {persisting}"
