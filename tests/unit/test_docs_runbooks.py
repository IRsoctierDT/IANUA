# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Meta-test: a runbook a document points at has to exist.

The retention runbook was cited by three tracked files — ``DESIGN.md``'s
decision log (twice), ``docs/RESTORE.md``'s cost section and
``scripts/run_retention.py``'s own module constants — plus a
``see "Running retention" below`` pointer in ``docs/PRODUCTION_SOC_PLAN.md``
aimed at a section that did not exist either. None of them resolved. Two of
the citations were circular: ``RESTORE.md`` credited its measured per-event
figures to "its own runbook" while that runbook was the thing citing
``RESTORE.md`` back.

Nothing caught it. ``AGENTS.md`` §7 lists ten ``--check`` drift gates and not
one of them reads a runbook or the production plan, which is also how
``#208`` re-inserted a stage row ``#207`` had already corrected and passed CI
with the table carrying four rows for two stages.

So this file pins the two properties that would have failed then and should
fail again: a named runbook resolves to a file, and the plan's stage table
names each stage once. It deliberately asserts *structure and resolvability*,
never prose — a runbook whose content is wrong is a review problem, but one
that is absent is a merge-blocking one.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]

#: Every runbook the repository promises, and the sections AGENTS.md §9
#: requires of a deliverable. Adding a runbook adds a row here.
RUNBOOKS = {
    "docs/RESTORE.md": "Backup and restore runbook",
    "docs/RETENTION.md": "Event retention runbook",
    "docs/RELEASING.md": "Releasing IANUA",
}

#: AGENTS.md §9's documentation structure. "Implementation Steps" is optional
#: by that section's own wording ("also state" for tool docs), and neither
#: existing runbook carries it, so it is not required here.
REQUIRED_SECTIONS = (
    "Executive Summary",
    "Objectives",
    "Risks",
    "Cost Considerations",
    "Future Enhancements",
)

#: AGENTS.md §9's component fields, which both runbooks carry as bold leaders.
COMPONENT_FIELDS = (
    "Purpose",
    "Risk level",
    "Skill level required",
    "Deployment complexity",
)

#: Files whose citations of a runbook used to dangle. Each must still name a
#: path that exists — the point is that renaming or deleting a runbook breaks
#: the build rather than the reader.
CITING_FILES = (
    "DESIGN.md",
    "docs/RESTORE.md",
    "docs/PRODUCTION_SOC_PLAN.md",
    "scripts/run_retention.py",
    "AGENTS.md",
)

_DOC_REF = re.compile(r"docs/[A-Za-z0-9_.-]*\.md")


def _read(relative: str) -> str:
    return (_REPO / relative).read_text(encoding="utf-8")


@pytest.mark.parametrize("relative", sorted(RUNBOOKS))
def test_a_promised_runbook_exists_and_is_titled(relative: str) -> None:
    """The failure this file exists for: a cited runbook that is not there."""
    path = _REPO / relative
    assert path.is_file(), f"{relative} is cited in this repository but does not exist"
    first = _read(relative).split("\n", 1)[0]
    assert first == f"# {RUNBOOKS[relative]}", (
        f"{relative} should open with '# {RUNBOOKS[relative]}', found {first!r}"
    )


@pytest.mark.parametrize("relative", sorted(RUNBOOKS))
def test_a_runbook_carries_the_section_9_structure(relative: str) -> None:
    """A runbook that skips Risks or Cost is not review-ready (AGENTS.md §9)."""
    headings = {
        line.lstrip("#").strip() for line in _read(relative).split("\n") if line.startswith("## ")
    }
    missing = [s for s in REQUIRED_SECTIONS if s not in headings]
    assert not missing, f"{relative} is missing §9 section(s): {missing}"


@pytest.mark.parametrize("relative", ["docs/RESTORE.md", "docs/RETENTION.md"])
def test_an_operational_runbook_states_its_risk_and_skill_level(relative: str) -> None:
    """§9's component fields: an operator needs them before step one."""
    head = "\n".join(_read(relative).split("\n")[:20])
    missing = [f for f in COMPONENT_FIELDS if f"**{f}**" not in head]
    assert not missing, f"{relative} does not declare: {missing}"


@pytest.mark.parametrize("relative", CITING_FILES)
def test_every_docs_reference_resolves(relative: str) -> None:
    """A citation of a ``docs/*.md`` path names a file that exists.

    Written as a sweep rather than a list of known sites, so a *new* dangling
    reference in one of these files fails too. Scoped to the files that
    carried the original defect; widening it to the whole tree would drag in
    illustrative paths from fixtures and templates.
    """
    text = _read(relative)
    broken = sorted({ref for ref in _DOC_REF.findall(text) if not (_REPO / ref).is_file()})
    assert not broken, f"{relative} points at non-existent doc(s): {broken}"


def test_the_retention_runbook_is_reachable_from_the_cli_and_the_plan() -> None:
    """The two places an operator actually starts from.

    ``scripts/run_retention.py`` told the reader to "see the runbook" without
    naming one, and the plan pointed at a section heading that was never
    written. Both now have to name the file.
    """
    assert "docs/RETENTION.md" in _read("scripts/run_retention.py"), (
        "run_retention.py cites a runbook for its storage cost; it must name the file"
    )
    plan = _read("docs/PRODUCTION_SOC_PLAN.md")
    assert "docs/RETENTION.md" in plan, "the production plan must name the retention runbook"
    assert 'see "Running retention" below' not in plan, (
        'the plan pointed at a "Running retention" section that never existed'
    )


def test_the_restore_and_retention_runbooks_are_not_circular() -> None:
    """The cost figures have one home, and the other side cites it.

    ``RESTORE.md`` used to credit its measured per-event figures to the
    retention runbook, which did not exist; writing that runbook made the
    pair circular unless one side owns the measurement. ``RESTORE.md`` owns
    it, so its text must not attribute the figures elsewhere.
    """
    restore = _read("docs/RESTORE.md")
    assert "whose own runbook figures these came from" not in restore, (
        "RESTORE.md must not credit its own measured figures to another document"
    )
    assert "1761-1885 bytes" in restore, "RESTORE.md is the home of the measured band"
    assert "docs/RESTORE.md" in _read("docs/RETENTION.md"), (
        "the retention runbook must cite RESTORE.md for the per-event band"
    )


def test_the_stage_table_names_each_stage_once() -> None:
    """What let a corrected stage row be silently re-inserted.

    ``#207`` removed a stale stage 7 row; ``#208`` re-added byte-identical
    text two lines above the correction, leaving the table with two rows for
    stage 6 and two for stage 7 whose statuses contradicted each other
    ("Retention done; posture open" against "Planned"). No gate reads this
    file, so CI was green.
    """
    rows = [
        line
        for line in _read("docs/PRODUCTION_SOC_PLAN.md").split("\n")
        if re.match(r"^\| (?:\d+b?) \|", line)
    ]
    ids = [line.split("|")[1].strip() for line in rows]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    assert not duplicates, f"stage table has duplicate row(s) for stage(s): {duplicates}"
    assert len(ids) >= 9, f"expected the full stage table, found {len(ids)} row(s)"
