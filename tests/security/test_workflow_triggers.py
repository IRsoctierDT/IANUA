# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Workflow triggers: no untrusted-code trigger, no shell interpolation, gated ``workflow_run``.

A workflow is privileged code that runs on every push or pull request, so the
OpenSSF Scorecard *Dangerous-Workflow* criteria are asserted here against every
file under ``.github/workflows/`` — ``*.yml`` **and** ``*.yaml``, since GitHub
loads both and a pin that reads one extension is evaded by the other (review
measured exactly that: one ``.yaml`` file violating every property below left
this suite green).

* **No ``pull_request_target``.** It runs with the base repository's secrets
  against a pull request from anywhere; nothing in this repository needs it.
* **No ``${{ }}`` expression inside a ``run:`` block.** An event field
  (``github.event.*``, ``inputs.*``, ``head_ref``) interpolated into a shell
  script is script injection. Every event-derived value this repository hands
  to a shell goes through ``env:`` instead, so the shell sees a variable and
  never the expression. The match spans lines, because an expression split
  across a newline is still one expression. A ``with:`` input that executes
  its value (``actions/github-script``'s ``script``) is not read here — a
  stated limit of this pin, not a claim about it.
* **``workflow_run`` is gated on the triggering run, not on its colour.** The
  trigger's ``branches: [main]`` filter applies to the triggering run's *head*
  branch, so a ``pull_request`` CI run from a fork whose head branch is named
  ``main`` (the default name for a fork) satisfies it as well. Every entry job
  of a ``workflow_run`` workflow must carry, as its **whole** ``if:``, the
  condition :data:`WORKFLOW_RUN_GATES` records for it — an equality, not a
  substring search. Review measured that the four conditions joined with
  ``||`` plus ``|| true``, and the four negated as one block, each contained
  every required substring and each passed the earlier check. A dependant job
  (``needs``) inherits the gate only while its ``if:`` calls no status
  function: ``always()``, ``!cancelled()`` and ``!failure()`` run it when the
  gated job was *skipped*, so a dependant that names one must carry the gate
  itself.
* **A ``workflow_run`` workflow never cancels at the workflow level.** A
  workflow-level ``concurrency`` group is claimed when the *run* is created,
  before any job ``if:`` is evaluated, so a run whose only job is then skipped
  still cancels the in-progress one. Measured by review from this repository's
  Actions history: four Pages deploys waiting for approval were cancelled by
  runs whose only job was ``skipped``, the cancellation landing one second
  before the canceller's job was evaluated. The gate above closes the enqueue
  half of that hole; this closes the cancel half by requiring any
  ``cancel-in-progress`` group to sit on the gated job, which a skipped job
  never claims. ``cancel-in-progress: false`` at the workflow level is
  tolerated (``release-on-merge.yml``): it cannot cancel a running job, though
  GitHub keeps one *pending* run per group, so an unprivileged wake can still
  displace a legitimate run that has not started — a narrower residual,
  recorded here rather than closed.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]
_WORKFLOWS = sorted(
    path for ext in ("*.yml", "*.yaml") for path in (_REPO / ".github" / "workflows").glob(ext)
)

#: A GitHub Actions expression, possibly spanning lines. Inside ``run:`` it is
#: expanded *before* the shell starts, so a value containing ``"; curl ...``
#: becomes code.
_EXPRESSION = re.compile(r"\$\{\{.*?\}\}", re.DOTALL)

#: A status function in a dependant's ``if:`` replaces the implicit
#: ``success()`` that otherwise skips it when a needed job was skipped.
_STATUS_FUNCTION = re.compile(r"\b(?:always|cancelled|failure|success)\s*\(")

_PUSH_TO_MAIN = (
    "github.event.workflow_run.conclusion == 'success' && "
    "github.event.workflow_run.event == 'push' && "
    "github.event.workflow_run.head_branch == 'main' && "
    "github.event.workflow_run.head_repository.full_name == github.repository"
)

#: The whole ``if:`` of every entry job of every ``workflow_run`` workflow,
#: whitespace-normalised and compared for equality. A new ``workflow_run``
#: workflow, or a changed gate, is a deliberate edit that fails here first.
WORKFLOW_RUN_GATES: dict[tuple[str, str], str] = {
    ("release-on-merge.yml", "detect"): _PUSH_TO_MAIN,
    ("pages.yml", "deploy"): (
        "(github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main') || "
        f"(github.event_name == 'workflow_run' && {_PUSH_TO_MAIN})"
    ),
}


def _load(path: Path) -> dict[Any, Any]:
    # ``dict[Any, Any]``: PyYAML's YAML 1.1 loader reads the key ``on`` as the
    # boolean True, so the top-level mapping is not keyed by str alone.
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path.name} must parse to a mapping"
    return data


def _triggers(workflow: dict[Any, Any]) -> dict[str, Any]:
    on = workflow.get(True, workflow.get("on"))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return dict.fromkeys(on)
    assert isinstance(on, dict), "a workflow must declare its triggers"
    return on


def _canonical(condition: object) -> str:
    return " ".join(str(condition).split())


@pytest.mark.security
@pytest.mark.parametrize("path", _WORKFLOWS, ids=lambda p: p.name)
def test_no_workflow_uses_pull_request_target(path: Path) -> None:
    assert "pull_request_target" not in _triggers(_load(path)), (
        f"{path.name} uses pull_request_target, which runs with this repository's "
        "secrets against code from any fork"
    )


@pytest.mark.security
@pytest.mark.parametrize("path", _WORKFLOWS, ids=lambda p: p.name)
def test_no_expression_is_interpolated_into_a_run_block(path: Path) -> None:
    offenders = [
        f"{job_name}/{step.get('name') or step.get('id') or index}: {match}"
        for job_name, job in _load(path)["jobs"].items()
        for index, step in enumerate(job.get("steps") or [])
        if isinstance(step.get("run"), str)
        for match in _EXPRESSION.findall(step["run"])
    ]
    assert not offenders, (
        f"{path.name} expands an expression inside a shell script (script injection); "
        f"route the value through env: instead — {offenders}"
    )


@pytest.mark.security
@pytest.mark.parametrize("path", _WORKFLOWS, ids=lambda p: p.name)
def test_workflow_run_jobs_gate_on_a_push_to_main_from_this_repository(path: Path) -> None:
    workflow = _load(path)
    triggers = _triggers(workflow)
    if "workflow_run" not in triggers:
        pytest.skip("not a workflow_run workflow")
    assert triggers["workflow_run"].get("branches") == ["main"], (
        f"{path.name}: workflow_run must filter on the triggering run's head branch"
    )
    for job_name, job in workflow["jobs"].items():
        condition = _canonical(job.get("if", ""))
        gate = WORKFLOW_RUN_GATES.get((path.name, job_name))
        if gate is not None:
            assert condition == gate, (
                f"{path.name}: job {job_name!r} must carry exactly the recorded gate as its "
                f"whole if: — got {condition!r}"
            )
        elif not job.get("needs"):
            pytest.fail(
                f"{path.name}: entry job {job_name!r} runs with this repository's token "
                "without a gate recorded in WORKFLOW_RUN_GATES"
            )
        else:
            assert not _STATUS_FUNCTION.search(condition), (
                f"{path.name}: dependant job {job_name!r} calls a status function in its if:, "
                "so it runs when its gated predecessor was skipped; gate it directly"
            )


@pytest.mark.security
@pytest.mark.parametrize("path", _WORKFLOWS, ids=lambda p: p.name)
def test_workflow_run_workflows_never_cancel_at_the_workflow_level(path: Path) -> None:
    workflow = _load(path)
    if "workflow_run" not in _triggers(workflow):
        pytest.skip("not a workflow_run workflow")
    concurrency = workflow.get("concurrency")
    if concurrency is None:
        return
    assert isinstance(concurrency, dict) and concurrency.get("cancel-in-progress") is False, (
        f"{path.name}: a workflow-level concurrency group is claimed when the run is created, "
        "before any job gate is evaluated, so a run whose job is then skipped still cancels a "
        "deploy waiting for approval; put the cancel-in-progress group on the gated job"
    )
