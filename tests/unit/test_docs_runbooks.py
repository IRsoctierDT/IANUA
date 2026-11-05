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
    """Names the module binds that a docstring could legitimately cite.

    **Module scope and class bodies, never function bodies — plus imports at any
    depth.** That asymmetry is the whole of this function and it is deliberate:

    - A function-local ``import`` names a real, importable module, so
      ``:func:`importlib.util.find_spec``` in ``compliance/controls.py`` is a
      reference a reader can follow even though ``import importlib.util`` sits
      inside the function seven lines below it.
    - A function-local *variable* names nothing outside that call. ``:data:``
      means module-level data, so a reference resolving against a local is a
      dangling reference this gate reported as fine.

    An earlier version walked the whole tree with ``ast.walk`` and counted every
    ``Name`` store at any depth, which admitted exactly that. Measured on the
    probe: a bare ``_LOCAL_ONLY = 7`` inside a function, and a comprehension
    target ``[x for _COMP_ONLY in ...]``, both entered the binding set and both
    satisfied a ``:data:`` reference to them. Found by review on ``#329``, which
    is the fifth bypass of this kind in this repository's AST-reading guards and
    the one ``AGENTS.md`` told the next reviewer to expect.

    Scoping it costs **nothing**: measured over all 578 references in the tree,
    the narrow rule leaves zero unresolved, exactly as the wide one did. The
    prior docstring justified the wide rule by saying a class docstring
    "legitimately cites a helper defined in a sibling method" — no such citation
    exists here, so that was a hypothetical paying a real price.

    Parameters and attribute stores are likewise not counted, for the same
    reason and at the same measured cost of zero.
    """
    names: set[str] = set()
    # Imports bind an importable name wherever they appear, function bodies
    # included, so they are collected before scope is considered at all.
    for node in ast.walk(tree):
        if isinstance(node, ast.alias):
            names.add((node.asname or node.name).split(".")[0])

    def add_targets(node: ast.AST) -> None:
        """Record every name an assignment, loop or ``with`` target binds.

        Walks the target expression, so tuple and nested unpacking
        (``for a, (b, c) in ...``) contribute every name rather than the first.
        """
        for inner in ast.walk(node):
            if isinstance(inner, ast.Name):
                names.add(inner.id)

    def add_pattern(pattern: ast.pattern) -> None:
        """Record names a ``match`` case binds.

        Separate from :func:`add_targets` because a pattern does **not** hold
        ``ast.Name`` nodes for its captures: ``MatchAs`` and ``MatchStar`` carry
        a bare ``name`` string and ``MatchMapping`` a ``rest``. A target walk
        therefore sees nothing, which is why the previous ``ast.walk`` rule
        missed these too — this is a gap being closed, not merely restored.
        """
        for inner in ast.walk(pattern):
            if isinstance(inner, ast.MatchAs | ast.MatchStar) and inner.name:
                names.add(inner.name)
            elif isinstance(inner, ast.MatchMapping) and inner.rest:
                names.add(inner.rest)

    def collect(body: list[ast.stmt]) -> None:
        """Walk statements in module or class scope, never into a function."""
        for statement in body:
            if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
                names.add(statement.name)  # the name, not what its body binds
            elif isinstance(statement, ast.ClassDef):
                names.add(statement.name)
                collect(statement.body)  # methods and class attributes
            elif isinstance(statement, ast.Assign | ast.AnnAssign | ast.AugAssign):
                targets = (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                for target in targets:
                    add_targets(target)
            elif isinstance(statement, ast.For | ast.AsyncFor):
                # `for ITEM in ...` at module or class scope binds ITEM there.
                add_targets(statement.target)
                collect(statement.body)
                collect(statement.orelse)
            elif isinstance(statement, ast.With | ast.AsyncWith):
                # `with ... as HANDLE` likewise.
                for item in statement.items:
                    if item.optional_vars is not None:
                        add_targets(item.optional_vars)
                collect(statement.body)
            elif isinstance(statement, ast.Match):
                for case in statement.cases:
                    add_pattern(case.pattern)
                    collect(case.body)
            elif isinstance(statement, ast.If | ast.Try | ast.While):
                # A module-level constant can sit under `if TYPE_CHECKING:` or
                # in a try/except import guard; both are still module scope.
                for attribute in ("body", "orelse", "finalbody"):
                    collect(getattr(statement, attribute, None) or [])
                for handler in getattr(statement, "handlers", None) or []:
                    collect(handler.body)

    collect(tree.body)
    return names


def test_a_function_local_name_does_not_satisfy_a_reference() -> None:
    """The regression fixture for the bypass review found on ``#329``.

    Driven against planted source rather than the shipped tree, because the
    shipped tree has no such reference — and a guard proven only by the absence
    of a counterexample is not proven. The three cases are the ones measured as
    having been *accepted* by the previous rule, plus the local import that must
    keep working.
    """
    planted = ast.parse(
        "import os\n"
        "MODULE_LEVEL = 1\n"
        "class C:\n"
        "    ATTR = 2\n"
        "    def meth(self) -> None: ...\n"
        "def f():\n"
        "    local_only = 3\n"
        "    return [comp_only for comp_only in range(local_only)]\n"
        "def g():\n"
        "    import importlib.util\n"
        "    return importlib.util\n"
    )
    bound = _module_bindings(planted)

    for name in ("local_only", "comp_only"):
        assert name not in bound, (
            f"{name!r} is only bound inside a function body, so a reference to it "
            "dangles; counting it is the bypass #329's review found"
        )
    for name in ("os", "MODULE_LEVEL", "C", "ATTR", "meth", "f", "g", "importlib"):
        assert name in bound, (
            f"{name!r} is legitimately citable ({'a function-local import' if name == 'importlib' else 'module or class scope'}), "
            "so the narrowing must not have dropped it"
        )


def test_a_compound_statement_at_module_scope_still_binds_its_targets() -> None:
    """The regression for what the narrowing itself broke, found by review on ``#330``.

    Scoping to module and class bodies is not enough on its own: Python binds a
    ``for`` target, a ``with ... as`` name and a ``match`` capture **in the
    enclosing namespace**, so a rule that only recurses into ``body``/``orelse``
    /``finalbody`` drops them and newly *rejects* a reference the previous rule
    accepted. Measured before the fix — all six of the first cases below were
    rejected, which is a false positive, and a false positive is what gets a
    gate switched off rather than obeyed.

    ``match`` is the exception that proves the mechanism rather than a seventh
    instance of it: a pattern carries its captures as bare ``name``/``rest``
    strings and not as ``ast.Name`` nodes, so the old ``ast.walk`` rule missed
    those too. That one is a gap being closed, not restored.
    """
    planted = ast.parse(
        "for LOOP_TARGET in range(3):\n    pass\n"
        "with open('x') as HANDLE:\n    pass\n"
        "for A, (B, C) in []:\n    pass\n"
        "class K:\n    for CLS_LOOP in range(2):\n        pass\n"
        "match 1:\n    case MATCH_BOUND:\n        pass\n"
        "match {}:\n    case {'k': MAP_VALUE, **MAP_REST}:\n        pass\n"
        "match []:\n    case [SEQ_ITEM, *SEQ_STARRED]:\n        pass\n"
    )
    bound = _module_bindings(planted)

    restored = ("LOOP_TARGET", "HANDLE", "A", "B", "C", "CLS_LOOP")
    for name in restored:
        assert name in bound, (
            f"{name!r} is bound at module or class scope by a compound statement; "
            "dropping it makes the gate reject a reference a reader can follow"
        )
    # Not merely restored: a pattern's captures are strings, so the former
    # `ast.walk` rule never saw these either.
    for name in ("MATCH_BOUND", "MAP_VALUE", "MAP_REST", "SEQ_ITEM", "SEQ_STARRED"):
        assert name in bound, f"{name!r} is bound by a match pattern and must resolve"


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
