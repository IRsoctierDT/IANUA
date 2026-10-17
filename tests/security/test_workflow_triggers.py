# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Workflow triggers: no untrusted-code trigger, no shell interpolation, gated ``workflow_run``.

A workflow is privileged code that runs on every push or pull request, so the
three OpenSSF Scorecard *Dangerous-Workflow* criteria are asserted here against
every file under ``.github/workflows/``:

* **No ``pull_request_target``.** It runs with the base repository's secrets
  against a pull request from anywhere; nothing in this repository needs it.
* **No ``${{ }}`` expression inside a ``run:`` block.** An event field
  (``github.event.*``, ``inputs.*``, ``head_ref``) interpolated into a shell
  script is script injection. Every event-derived value this repository hands
  to a shell goes through ``env:`` instead, so the shell sees a variable and
  never the expression.
* **``workflow_run`` is gated on the triggering run, not on its colour.** The
  trigger's ``branches: [main]`` filter applies to the triggering run's *head*
  branch, so a ``pull_request`` CI run from a fork whose head branch is named
  ``main`` (the default name for a fork) satisfies it as well. Measured on the
  tree before this test existed: ``release-on-merge.yml`` required a successful
  ``push`` to ``main`` from this repository, and ``pages.yml`` required only
  ``conclusion == 'success'`` — so an unprivileged pull request could enqueue a
  Pages deploy under the approval gate and, through ``cancel-in-progress``,
  cancel one already waiting. Every entry job of a ``workflow_run`` workflow
  must now carry all four conditions.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]
_WORKFLOWS = sorted((_REPO / ".github" / "workflows").glob("*.yml"))

#: A GitHub Actions expression. Inside ``run:`` it is expanded *before* the
#: shell starts, so a value containing ``"; curl ...`` becomes code.
_EXPRESSION = re.compile(r"\$\{\{.*?\}\}")

#: What a ``workflow_run`` job must establish about the run that woke it before
#: doing anything with the base repository's token.
_WORKFLOW_RUN_GATE = (
    "github.event.workflow_run.conclusion == 'success'",
    "github.event.workflow_run.event == 'push'",
    "github.event.workflow_run.head_branch == 'main'",
    "github.event.workflow_run.head_repository.full_name == github.repository",
)


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
def test_workflow_run_entry_jobs_gate_on_a_push_to_main_from_this_repository(
    path: Path,
) -> None:
    workflow = _load(path)
    triggers = _triggers(workflow)
    if "workflow_run" not in triggers:
        pytest.skip("not a workflow_run workflow")
    assert triggers["workflow_run"].get("branches") == ["main"], (
        f"{path.name}: workflow_run must filter on the triggering run's head branch"
    )
    # Entry jobs are those nothing else gates; a job with `needs` inherits its
    # predecessors' conditions because a skipped job skips its dependants.
    for job_name, job in workflow["jobs"].items():
        if job.get("needs"):
            continue
        condition = " ".join(str(job.get("if", "")).split())
        missing = [gate for gate in _WORKFLOW_RUN_GATE if gate not in condition]
        assert not missing, (
            f"{path.name}: entry job {job_name!r} runs with this repository's token "
            f"without establishing {missing} about the run that woke it"
        )
