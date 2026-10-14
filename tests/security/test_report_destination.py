# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Security tests: an incident report may not be written into the repository.

A report carries event content — the hostname, the account, the source address
and the raw log message. The default destination used to be
``reports/markdown/orchestrated_incident.md``, a **tracked file**, and both
shipped entry points call ``process_log`` without a path, so running either
over a real log line wrote telemetry into the working tree one ``git add -A``
away from being published. AGENTS.md §5 forbids committing logs and client
information; nothing enforced it. Found by review.

The default now points under the gitignored lab root, and ``generate_report``
refuses any destination inside the repository but outside ``data/``.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest
from agents.incident_report_agent import _LAB_ROOT, _REPO_ROOT, _refuse_tracked_destination
from agents.tools.validation import ValidationError

_LOG = "Oct 14 10:02:01 web-01 sshd[1]: Failed password for svc-deploy from 203.0.113.9 port 22"


@pytest.mark.security
@pytest.mark.parametrize(
    "relative",
    [
        "reports/markdown/orchestrated_incident.md",
        "reports/markdown/orchestrated_sequence_incident.md",
        "docs/leak.md",
        "leak.md",
        "knowledge-base/leak.md",
        "data/../docs/leak.md",
    ],
)
def test_a_destination_inside_the_repository_is_refused(relative: str) -> None:
    """Including the two paths that used to be the defaults, and a traversal.

    The check is on the *resolved* path, so ``data/../docs`` is refused even
    though its first component is the one allowed directory.
    """
    with pytest.raises(ValidationError, match="inside the repository"):
        _refuse_tracked_destination(_REPO_ROOT / relative)


@pytest.mark.security
@pytest.mark.parametrize("relative", ["reports/orchestrated_incident.md", "reports/nested/r.md"])
def test_a_destination_under_the_lab_root_is_allowed(relative: str) -> None:
    """``data/`` is gitignored, which is what makes it the one safe place."""
    _refuse_tracked_destination(_LAB_ROOT / relative)


@pytest.mark.security
def test_a_destination_outside_the_repository_is_allowed(tmp_path: Path) -> None:
    """Tests and operators legitimately write elsewhere; only the repo is fenced."""
    _refuse_tracked_destination(tmp_path / "report.md")


@pytest.mark.security
def test_the_shipped_defaults_point_under_the_lab_root() -> None:
    """The guard is the backstop; the default is what actually protects a user.

    Both shipped CLIs call ``process_log``/``process_sequence`` with no
    ``report_path``, so the signature default is the destination in practice.
    """
    from agents.orchestrator_agent import OrchestratorAgent

    for name in ("process_log", "process_sequence"):
        default = (
            inspect.signature(getattr(OrchestratorAgent, name)).parameters["report_path"].default
        )
        assert default.startswith("data/"), (
            f"{name}'s default report destination is {default!r}, which is not under the "
            "gitignored lab root"
        )


@pytest.mark.security
def test_writing_a_report_to_a_tracked_path_raises_before_the_file_is_created() -> None:
    """Refused *before* the write, so a refusal leaves nothing behind to clean up."""
    from agents.incident_report_agent import IncidentReportAgent

    target = _REPO_ROOT / "docs" / "should-not-exist.md"
    try:
        with pytest.raises(ValidationError):
            IncidentReportAgent().generate_report(_LOG, str(target))
        assert not target.exists(), "a refused report still created its file"
    finally:
        # Cleaned up unconditionally: when this test was first run against the
        # guard removed, it left a real 1996-byte incident report in docs/ and
        # poisoned every later run of itself. A test that fails must not also
        # leave the artifact whose absence it asserts.
        target.unlink(missing_ok=True)
