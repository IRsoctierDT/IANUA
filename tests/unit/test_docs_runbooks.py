# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Meta-test: a reference a document makes has to resolve.

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

So this file pins the properties that would have failed then and should fail
again: a named runbook resolves to a file, the plan's stage table names each
stage once, and — the third, added after a rename left three docstrings
pointing at ``:func:`_single_instance``` while the symbol had always been
``single_instance`` — a cross-reference a docstring makes resolves to a symbol
that exists. It deliberately asserts *structure and resolvability*, never
prose: a runbook whose content is wrong is a review problem, but one that is
absent is a merge-blocking one, and the same holds for a citation that points
nowhere.
"""

from __future__ import annotations

import ast
import builtins
import re
import subprocess
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


#: Cross-reference roles this repository's docstrings actually use, measured over
#: every tracked non-test module. ``~`` prefixes are stripped before resolution,
#: since Sphinx reads them as display sugar and not as part of the target.
_SYMBOL_REF = re.compile(r":(?:data|func|class|meth|attr|mod):`~?([A-Za-z_][A-Za-z0-9_.]*)`")


def _tracked_python() -> list[str]:
    """Tracked ``*.py`` paths, so an untracked scratch file cannot fail the gate.

    Uses ``git ls-files`` rather than a tree walk: a walk would pick up
    ``.venv/`` and build output, which are not this repository's to document.
    NUL-delimited, for the reason ``AGENTS.md`` §7.1 records at length — this
    tree carries 58 tracked paths containing spaces, and splitting on
    whitespace is how a gate silently scans the wrong set.
    """
    out = subprocess.run(
        ["git", "ls-files", "-z", "*.py"],  # noqa: S607 - git from PATH, test env
        cwd=_REPO,
        capture_output=True,
        text=True,
        check=True,
    )
    return [path for path in out.stdout.split("\0") if path]


def _module_bindings(tree: ast.Module) -> set[str]:
    """Every name the module binds, at any nesting depth.

    Deliberately depth-insensitive: a docstring on a class legitimately cites a
    helper defined in a sibling method, and scoping that properly would mean
    re-implementing name resolution to reject references a reader can follow.
    Parameters and attribute stores are **not** counted — measured on this tree,
    excluding them costs zero false positives and removes two ways for a typo to
    resolve against something that is not the symbol being cited.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
        elif isinstance(node, ast.alias):
            names.add((node.asname or node.name).split(".")[0])
    return names


def test_every_docstring_symbol_reference_resolves() -> None:
    """A ``:func:``/``:data:``/``:class:`` reference names a symbol that exists.

    The companion to :func:`test_every_docs_reference_resolves`, for the other
    half of what a docstring cites. The defect it exists for is a rename that
    updates the code and leaves the prose pointing at the old name: measured on
    this tree, three sites said ``:func:`_single_instance``` while the symbol
    had always been ``single_instance``, and nothing read them.

    Resolution is deliberately generous, because a false positive here would get
    the gate switched off rather than obeyed — the failure mode this
    repository's charter names in those terms. A reference resolves against
    builtins, any name the citing module binds, any top-level name bound in any
    tracked non-test module, a tracked module stem, or a tracked top-level
    package. A dotted reference is resolved on its **head** only: following
    ``a.b.c`` through would mean importing ``a``, and importing modules to check
    prose is a worse trade than not checking the tail.

    What that generosity costs is stated rather than implied: a typo that
    happens to match a symbol defined anywhere in the repository resolves, and
    so does a reference whose head is right and whose tail is wrong. What it
    buys is that the gate has no false positives on the shipped tree, so a
    failure here is a defect every time.
    """
    tracked = _tracked_python()
    assert len(tracked) > 100, f"expected the tracked Python tree, found {len(tracked)} file(s)"
    non_test = [rel for rel in tracked if not rel.startswith("tests/")]

    sources = {rel: (_REPO / rel).read_text(encoding="utf-8") for rel in tracked}
    bindings = {rel: _module_bindings(ast.parse(text)) for rel, text in sources.items()}
    repo_wide: set[str] = set()
    for rel in non_test:
        repo_wide |= bindings[rel]
    resolvable = (
        set(dir(builtins))
        | repo_wide
        | {Path(rel).stem for rel in tracked}
        | {Path(rel).parts[0] for rel in tracked}
    )

    broken: list[str] = []
    seen = 0
    for rel in non_test:
        for number, line in enumerate(sources[rel].split("\n"), start=1):
            for symbol in _SYMBOL_REF.findall(line):
                seen += 1
                head = symbol.split(".")[0]
                if head in resolvable or head in bindings[rel]:
                    continue
                broken.append(f"{rel}:{number} cites {symbol!r} ({head!r} resolves to nothing)")

    assert seen > 400, f"expected the docstring cross-reference corpus, found {seen} reference(s)"
    assert not broken, (
        "docstring reference(s) name a symbol that does not exist:\n  " + "\n  ".join(broken)
    )
