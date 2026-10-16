# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Every statement handed to sqlite3, in every shipped package, from literals.

The analysis lives in ``tests/security/_sql_provenance.py``; this file is what
asserts it, and what widens it from one package to all of them.

**Why it was one package.** It was written for ``store/``, where nineteen
statements sit in one module behind one connection. Measured while writing it,
the same analysis over every package in the repository was already green —
``rag/vector_store.py`` holds six statements and nothing covered them, and
``scripts/run_*.py`` import :mod:`sqlite3` while executing nothing through it.
Extending coverage was therefore free, and was deliberately left out of that
change because it is a different claim: new coverage, not a fixed control.

**What the extension actually cost**, because "free" was measured for the
*lattice* and not for the three shape rules the lattice depends on:

* The lattice found **one** finding repository-wide, and it was not SQL:
  ``agents/tools/containment.py`` called ``self.executor.execute(capability,
  target)`` on a :class:`~agents.tools.containment.ContainmentExecutor`. A
  pure name collision with sqlite3's method, and the method is now
  ``perform``. The alternative was an exemption table, which would have put a
  maintained allow-list under a control whose design rejects one; the
  reasoning is recorded on the Protocol itself, and ``def perform`` joined
  ``tests/security/test_response_no_executor.py``'s marker list in the same
  change so the rename could not weaken that boundary.
* The namespace shape rule, applied unchanged, produced **seventeen** findings
  that have nothing to do with SQL — fifteen ``sys.path.insert`` calls in
  ``scripts/``, one in ``compliance/``, and one ``st.session_state[...] = ...``
  in ``dashboard/``. It also **missed a real route**, measured on merged code:
  it collected module bases from ``ast.Import`` aliases only, and ``store/``
  binds every sibling with ``from store.schema import <names>``, so three of
  the six routes it claimed to forbid needed a binding the package never
  writes. :func:`_sql_provenance._module_bases` carries both corrections and
  the measurements; the four spellings are pinned below.
* Review then found a **third** problem with the same rule, and that one was a
  regression the narrowing had caused: a swept module re-bound to a name no
  ``import`` statement bound. Codex reported one spelling; measuring the class
  found nine more that the baseline rule had accepted as well, so the hole was
  mostly open before and the narrowing widened it by one spelling. Module
  identity does not travel with a name, so three shape rules close it — see
  :func:`_sql_provenance.namespace_findings` and the pinned table below.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.security import _sql_provenance as sqlprov

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _shipped_sources() -> dict[str, str]:
    return sqlprov.sources_for(sqlprov.shipped_package_roots(_REPO_ROOT), _REPO_ROOT)


# --------------------------------------------------------------------------
# The invariant, over every shipped package
# --------------------------------------------------------------------------


@pytest.mark.security
def test_every_statement_reaching_sqlite_is_built_only_from_literals() -> None:
    """No caller value becomes SQL text, anywhere in the shipped packages.

    Stated as a provenance requirement rather than a list of forbidden
    constructs: the statement handed to sqlite3 must be traceable to string
    literals written in the swept source set. A parameter, a call's return
    value, or a name whose bindings do not all resolve to literals fails.
    """
    findings = sqlprov.non_literal_statements(_shipped_sources())
    assert not findings, "statement text not traceable to a literal:\n  " + "\n  ".join(findings)


@pytest.mark.security
def test_the_sweep_reaches_every_executed_statement() -> None:
    """Non-vacuity: a sweep that found no call sites would pass silently.

    The floor is the count at the time of writing — 25, being nineteen in
    ``store/events.py`` and six in ``rag/vector_store.py``. A floor rather
    than an equality so that adding a statement does not fail here, but a
    refactor that moves statements out of the swept set should fail and be
    looked at rather than quietly reduce what the assertion above covers.
    """
    sites = sqlprov.statement_sites(_shipped_sources())
    assert len(sites) >= 25, f"expected at least 25 statements reached, found {len(sites)}"
    assert all(kind == sqlprov.LITERAL for _where, _line, kind, _source in sites)


@pytest.mark.security
def test_only_the_two_known_packages_execute_sql() -> None:
    """A third package gaining a statement is worth a human's attention.

    The shape rules below already run over every shipped package, so a new
    sqlite writer is *analysed* the moment it lands; this assertion is about
    review rather than analysis. AGENTS.md §6.1 ranks injection first, and a
    package taking a connection for the first time is the change that deserves
    an eye on it. Equality, not a subset, because a subset assertion is how a
    discovery predicate goes vacuous without saying so.
    """
    packages = {
        where.split(":", 1)[0].split(".", 1)[0]
        for where, _line, _kind, _source in sqlprov.statement_sites(_shipped_sources())
    }
    assert packages == {"rag", "store"}, (
        f"packages executing SQL changed to {sorted(packages)} — confirm the three shape "
        "rules below hold for the newcomer (they are asserted repository-wide, so a "
        "violation fails on its own), then update this list"
    )


@pytest.mark.security
def test_no_shipped_package_defines_its_own_execute() -> None:
    """``execute`` means sqlite3 here, which is what makes the sweep sound.

    :func:`_sql_provenance.executed_statements` finds a sink by method name
    with no knowledge of the receiver's type — over one sqlite-only package
    that was harmless, and repository-wide it is not: the one finding of the
    first full sweep was ``ContainmentExecutor.execute(capability, target)``,
    which touches no database at all.

    So the decision recorded here is that a shipped package does not define a
    method named ``execute``, ``executemany`` or ``executescript`` unless its
    first argument is literal SQL. Measured at zero definitions. If a non-SQL
    one is ever genuinely wanted, this is the assertion to change, and the
    change wants an exemption table in :mod:`_sql_provenance` with a reason
    per entry and a non-vacuity assertion of its own — not a wider sink name.
    """
    offenders = [
        f"{module}:{node.lineno}: def {node.name}"
        for module, text in sorted(_shipped_sources().items())
        for node in ast.walk(ast.parse(text))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in sqlprov.EXECUTORS
    ]
    assert not offenders, (
        "a shipped package defines its own executor method, so the sweep above now "
        f"judges a non-SQL call site: {offenders} — see this test's docstring"
    )


# --------------------------------------------------------------------------
# Scope: derived, not hand-listed
# --------------------------------------------------------------------------


@pytest.mark.security
def test_the_sweep_covers_every_top_level_python_directory_but_tests() -> None:
    """The scope is walked, so a new package is swept the day it lands.

    ``tests/unit/test_gate_scope_parity.py`` holds this against that file's
    canonical package set, which is what makes a directory in neither
    ``PACKAGES`` nor ``UNGATED`` fail rather than be swept in silence. The
    assertion here is the weaker, local one: nothing is missing from the walk.
    """
    swept = {path.name for path in sqlprov.shipped_package_roots(_REPO_ROOT)}
    present = {
        path.name
        for path in _REPO_ROOT.iterdir()
        if path.is_dir() and not path.name.startswith(".") and any(path.rglob("*.py"))
    }
    assert swept == present - sqlprov.UNSWEPT
    assert swept, "the walk found no packages at all"


@pytest.mark.security
def test_the_one_unswept_directory_is_excluded_for_a_reason_that_still_holds() -> None:
    """``tests/`` is left out because it *plants* what the rules refuse.

    An exclusion nobody re-measures becomes a hole, so this asserts the
    reason rather than the name: sweeping ``tests/`` would fail, because the
    evidence for every refusal below is a planted route. Measured: 12
    namespace findings (``sys.modules`` substitution, ``setattr`` on an
    imported module) and 72 calls of a call.

    If this test ever fails because ``tests/`` came back clean, the exclusion
    has stopped being load-bearing and the directory can simply be swept.
    """
    assert set(sqlprov.UNSWEPT) == {"tests"}
    planted = sqlprov.sources_for([_REPO_ROOT / "tests"], _REPO_ROOT)
    namespace = sqlprov.namespace_findings(planted)
    call_of_call = sqlprov.call_of_call_findings(planted)
    assert namespace, "tests/ no longer plants a namespace route — stop excluding it"
    assert call_of_call, "tests/ no longer plants a call of a call — stop excluding it"


# --------------------------------------------------------------------------
# The three shape rules, over every shipped package
# --------------------------------------------------------------------------


@pytest.mark.security
def test_no_swept_module_namespace_is_written() -> None:
    """See :func:`_sql_provenance.namespace_findings` for the six routes."""
    findings = sqlprov.namespace_findings(_shipped_sources())
    assert not findings, "a swept module's namespace is reachable:\n  " + "\n  ".join(findings)


@pytest.mark.security
def test_an_executor_is_never_taken_as_a_value() -> None:
    """See :func:`_sql_provenance.executor_as_value_findings` for the seven."""
    findings = sqlprov.executor_as_value_findings(_shipped_sources())
    assert not findings, "an executor is reached as a value:\n  " + "\n  ".join(findings)


@pytest.mark.security
def test_no_statement_is_dispatched_through_a_dynamic_attribute() -> None:
    """See :func:`_sql_provenance.call_of_call_findings` for the route."""
    findings = sqlprov.call_of_call_findings(_shipped_sources())
    assert not findings, "a call's result is called:\n  " + "\n  ".join(findings)


# --------------------------------------------------------------------------
# Pinned: the namespace routes the ast.Import-only base set let through
# --------------------------------------------------------------------------
#
# Two modules of one package, mirroring store/'s shape: `events` declares the
# SQL constant and reads it by bare name, `schema` rebinds it from outside.
# Every spelling below was measured ACCEPTED on merged code by both the
# lattice and the shape rule, except the `import a.b as b` control.

_DECLARING = """\
_COUNT_BEFORE = "SELECT COUNT(*) AS n FROM events e WHERE e.ingested_at < ?"


def run(conn, before):
    return conn.execute(_COUNT_BEFORE, (before,)).fetchone()
"""

_REJECTED_NAMESPACE = (
    (
        "from-import module, aliased",
        "from sample import events as _ev\n\n\n"
        "def plant(clause):\n"
        '    _ev._COUNT_BEFORE = "SELECT COUNT(*) AS n FROM events e WHERE " + clause\n',
    ),
    (
        "from-import module, unaliased",
        "from sample import events\n\n\n"
        "def plant(clause):\n"
        '    events._COUNT_BEFORE = "SELECT COUNT(*) AS n FROM events e WHERE " + clause\n',
    ),
    (
        "relative from-import module",
        "from . import events\n\n\n"
        "def plant(clause):\n"
        '    events._COUNT_BEFORE = "SELECT COUNT(*) AS n FROM events e WHERE " + clause\n',
    ),
    (
        "from-import module, mutating a declared container",
        "from sample import events as _ev\n\n\ndef plant(extra):\n    _ev._EQUALITY.update(extra)\n",
    ),
    (
        "dotted import, unaliased — binds the PACKAGE, not the module",
        "import sample.events\n\n\n"
        "def plant(clause):\n"
        '    sample.events._COUNT_BEFORE = "SELECT COUNT(*) AS n FROM events e WHERE " + clause\n',
    ),
    (
        "bare package import, reaching a submodule through it",
        "import sample\n\n\n"
        "def plant(clause):\n"
        '    sample.events._COUNT_BEFORE = "SELECT COUNT(*) AS n FROM events e WHERE " + clause\n',
    ),
    (
        "from-import of a SUBPACKAGE, reaching its module",
        "from sample import inner\n\n\n"
        "def plant(clause):\n"
        '    inner.leaf._COUNT_BEFORE = "SELECT COUNT(*) AS n FROM events e WHERE " + clause\n',
    ),
    (
        "plain import alias (the control: refused before this change too)",
        "import sample.events as events\n\n\n"
        "def plant(clause):\n"
        '    events._COUNT_BEFORE = "SELECT COUNT(*) AS n FROM events e WHERE " + clause\n',
    ),
)


@pytest.mark.security
@pytest.mark.parametrize(("label", "source"), _REJECTED_NAMESPACE)
def test_a_cross_module_namespace_write_is_refused_however_the_module_is_bound(
    label: str, source: str
) -> None:
    """A binding reaches a namespace; the spelling it was made with does not.

    Four of these needed a ``from`` import, which the old ``ast.Import``-only
    base set never collected — and ``store/`` binds every sibling that way, so
    the rule's "measured at zero occurrences" was true of them for the wrong
    reason. Three more are dotted: the swept set is keyed by *file*, so
    ``store`` and ``sample.inner`` are never keys while everything under them
    is, and a membership test on the bound name would have let the narrowing
    trade one evasion for another. Those three were found by re-reading the
    function, not by a planted route, and two of them were refused by the
    baseline rule — which is exactly why they are here.

    Non-vacuity is measured against the baseline rule re-implemented over
    these exact sources, with the lattice consulted too so a pin counts only
    where *nothing* refused it: **5 of 8 newly closed** — the four ``from``
    spellings and the subpackage one. The other three were refused before as
    well, and are not padding: two are **regression guards on the narrowing**
    (the dotted and bare-package imports, which the ``ast.Import`` rule caught
    and a naive membership test on the bound name would have dropped), and the
    last is labelled a control. Every case is refused now.
    """
    sources = {
        "sample.events": _DECLARING,
        "sample.inner.leaf": _DECLARING,
        "sample.schema": '_EQUALITY = {"vendor": "e.vendor = ?"}\n\n\n' + source,
    }
    assert sqlprov.namespace_findings(sources), f"{label} was accepted"


_SANCTIONED_NAMESPACE = (
    (
        "sys.path.insert — scripts/ does this fifteen times",
        "import sys\nfrom pathlib import Path\n\n\n"
        "def bootstrap(root):\n    sys.path.insert(0, str(Path(root)))\n",
    ),
    (
        "a third-party module's own state container",
        "import streamlit as st\n\n\ndef remember(report):\n    st.session_state['r'] = report\n",
    ),
    (
        "a from-import of a VALUE, which binds no namespace",
        "from sample.events import run\n\n\ndef call(conn, before):\n    return run(conn, before)\n",
    ),
)


@pytest.mark.security
@pytest.mark.parametrize(("label", "source"), _SANCTIONED_NAMESPACE)
def test_a_write_outside_the_swept_set_is_not_a_finding(label: str, source: str) -> None:
    """The narrowing, pinned, because it is the half that could be wrong.

    Widening the base set to ``from`` imports is unambiguously a tightening.
    Restricting the assignment and mutator clauses to *swept* module bases is
    the judgement call, and the argument is that the lattice trusts exactly
    one thing — a bare name bound in a swept module — while a cross-module
    attribute read is :data:`~_sql_provenance.OTHER` by default. Mutating
    ``sys.path`` or Streamlit's session state cannot reach what it trusts.

    Measured: under the old form these were seventeen real findings in
    ``scripts/``, ``compliance/`` and ``dashboard/``, so the first
    ``conn.execute`` added to ``scripts/`` would have put a gate between an
    engineer and fifteen ``sys.path.insert`` calls that carry no SQL. A gate
    that demands that is a gate people route around.

    Of the three cases here, the baseline rule flagged the first two and not
    the third: a ``from`` import of a *value* binds no namespace, so it was
    never a finding and is the negative control for the widening — the
    widening must not make an ordinary function import look like a module
    binding.

    The registry clause is deliberately *not* narrowed — ``sys.modules``
    reaches every module, swept or not — and
    ``test_a_cross_module_namespace_write_is_refused_however_the_module_is_bound``
    is the other side of this pin.
    """
    sources = {"sample.events": _DECLARING, "sample.helper": source}
    assert not sqlprov.namespace_findings(sources), f"{label} was refused"


# --------------------------------------------------------------------------
# Pinned: a swept module reached under a name no import bound
# --------------------------------------------------------------------------
#
# Codex filed a P1 against the narrowing above and it was right: narrowing the
# assignment clause to *swept* module bases dropped a route the old
# ast.Import-only rule happened to catch. Its example was
#
#     import math as sink        # `sink` is an imported base, and NOT swept
#     from sample import events  # `events` IS a swept base
#     sink = events              # `sink` now aliases a swept module
#     sink._SQL = clause         # ... and rebinds its SQL constant
#
# which the old rule refused only because `sink` happened to have been bound by
# an `import` statement. Measuring the class rather than the example showed the
# report understated it: NINE sibling spellings were accepted by the baseline
# rule too, so this was mostly open before and the narrowing widened it by one
# spelling. Restoring "any imported base" would have re-closed one of the ten.
#
# So the closure is by shape, which is this analysis's answer wherever identity
# is not decidable (compare the use-whitelist in `escaping_names` and "an
# executor may appear only as a call's function"): a swept module's binding may
# appear ONLY as the base of an attribute access, nothing may hand back a module
# named by a string, and the attributes that ARE a namespace are refused
# whatever they hang off. All three cost zero on shipped code, measured.

_DECLARING_SELF = """\
_SQL = "SELECT COUNT(*) AS n FROM events"


def run(conn):
    return conn.execute(_SQL).fetchone()


"""

_REJECTED_MODULE_IDENTITY = (
    (
        "the P1 verbatim: an unswept imported name re-bound to a swept module",
        "import math as sink\nfrom sample import events\n\n\n"
        "def plant(clause):\n"
        "    global sink\n"
        "    sink = events\n"
        '    sink._SQL = "SELECT x WHERE " + clause\n',
        True,  # the baseline refused this one — accepting it was MY regression
    ),
    (
        "a plain alias, with no imported name to borrow",
        "from sample import events\n\n\n"
        "def plant(clause):\n"
        "    sink = events\n"
        '    sink._SQL = "SELECT x WHERE " + clause\n',
        False,
    ),
    (
        "a chained assignment, which aliases by construction",
        "from sample import events\n\n\n"
        "def plant(clause):\n"
        "    a = b = events\n"
        '    b._SQL = "SELECT x WHERE " + clause\n',
        False,
    ),
    (
        "tuple unpacking",
        "from sample import events\n\n\n"
        "def plant(clause):\n"
        "    (x,) = (events,)\n"
        '    x._SQL = "SELECT x WHERE " + clause\n',
        False,
    ),
    (
        "the module passed to a helper that writes it",
        "from sample import events\n\n\n"
        "def _write(mod, clause):\n"
        '    mod._SQL = "SELECT x WHERE " + clause\n\n\n'
        "def plant(clause):\n"
        "    _write(events, clause)\n",
        False,
    ),
    (
        "the module held in a container",
        "from sample import events\n\n\n"
        "def plant(clause):\n"
        '    registry = {"e": events}\n'
        '    registry["e"]._SQL = "SELECT x WHERE " + clause\n',
        False,
    ),
    (
        "importlib.import_module, so no import statement binds it at all",
        "import importlib\n\n\n"
        "def plant(clause):\n"
        '    mod = importlib.import_module("sample.events")\n'
        '    mod._SQL = "SELECT x WHERE " + clause\n',
        False,
    ),
    (
        "__globals__ of an imported module's function",
        "from sample import events\n\n\n"
        "def plant(clause):\n"
        '    events.run.__globals__["_SQL"] = "SELECT x WHERE " + clause\n',
        False,
    ),
    (
        "__globals__ of a function in the SAME module, so no import to restrict",
        _DECLARING_SELF + "def plant(clause):\n"
        '    run.__globals__["_SQL"] = "SELECT x WHERE " + clause\n',
        False,
    ),
    (
        "f_globals of a frame, which is not a call-of-a-call either",
        "import inspect\n\n\n" + _DECLARING_SELF + "def plant(clause):\n"
        '    inspect.currentframe().f_globals["_SQL"] = "SELECT x WHERE " + clause\n',
        False,
    ),
    (
        "setattr on the alias (the control: refused before this change too)",
        "from sample import events\n\n\n"
        "def plant(clause):\n"
        '    setattr(events, "_SQL", "SELECT x WHERE " + clause)\n',
        True,
    ),
)


@pytest.mark.security
@pytest.mark.parametrize(
    ("label", "source", "refused_by_baseline"),
    [(label, source, baseline) for label, source, baseline in _REJECTED_MODULE_IDENTITY],
    ids=[label.split(",")[0][:48] for label, _s, _b in _REJECTED_MODULE_IDENTITY],
)
def test_a_swept_module_cannot_be_reached_under_another_name(
    label: str, source: str, refused_by_baseline: bool
) -> None:
    """A module's identity does not travel with the name it was imported under.

    Measured against the baseline rule re-implemented over these exact sources:
    **9 newly closed, 1 regression closed, 1 control**. The regression is the
    first entry — the one Codex reported — and it is the only case the
    ast.Import-only rule refused. The other nine were open before this PR and
    before the narrowing, so the honest statement is that the narrowing widened
    an existing hole by one spelling and the fix closes the hole.

    Each case rebinds, at runtime, the module constant whose literal provenance
    the lattice relies on. No name-keyed lattice can follow module identity
    through an assignment, a container or a call, which is why the closure is
    three shape rules rather than a dataflow.
    """
    sources = {"sample.events": _DECLARING, "sample.helper": source}
    assert sqlprov.namespace_findings(sources), f"{label} was accepted" + (
        " — and this one was refused BEFORE the narrowing, so accepting it is a regression,"
        " not a pre-existing gap"
        if refused_by_baseline
        else ""
    )


@pytest.mark.security
def test_the_module_identity_tally_is_the_one_stated() -> None:
    """Pin the tally, so an unclassified case cannot quietly inflate it.

    Two entries above were refused by the baseline rule: the P1 itself and the
    ``setattr`` control. The other nine were accepted, which is the measurement
    that makes "the narrowing widened an existing hole by one spelling" a
    statement about this repository rather than a reading of the report.
    """
    baseline_refused = [label for label, _s, refused in _REJECTED_MODULE_IDENTITY if refused]
    baseline_accepted = [label for label, _s, refused in _REJECTED_MODULE_IDENTITY if not refused]
    assert len(baseline_refused) == 2, baseline_refused
    assert len(baseline_accepted) == 9, baseline_accepted


@pytest.mark.security
def test_an_ordinary_objects_dict_is_not_a_module_namespace() -> None:
    """``__dict__`` stays restricted to an imported module base, and must.

    ``__globals__``, ``f_globals``, ``f_locals`` and ``f_builtins`` are refused
    on **any** base, because none of them means anything but "the globals of
    something". ``__dict__`` is different: on an ordinary object it is ordinary
    introspection, and ``compliance/evidence.py`` does exactly that on a
    dataclass record. Banning it outright was measured at one real occurrence,
    so it keeps the imported-base restriction and this pins the difference.
    """
    holder = """\
class Holder:
    tag = "x"


def relabel(h, v):
    h.__dict__["tag"] = v
"""
    sources = {"sample.events": _DECLARING, "sample.holder": holder}
    assert not sqlprov.namespace_findings(sources)


@pytest.mark.security
def test_the_three_module_identity_rules_are_not_vacuous() -> None:
    """Four shipped modules really do bind a swept module, so the rules watch something.

    A shape rule measured at zero findings is only worth having if the thing it
    forbids is reachable. Measured: ``ingest/normalize.py`` binds six parser
    modules, ``scripts/prepare_release.py`` three, ``scripts/release_notes.py``
    one and ``dashboard/app.py`` one — eleven live module bindings across the
    shipped packages, every one of which the escape rule now constrains.
    """
    sources = _shipped_sources()
    swept = frozenset(sources)
    bound = {
        module: sorted(sqlprov._module_bases(ast.parse(text), module, swept)[1])
        for module, text in sources.items()
    }
    live = {module: names for module, names in bound.items() if names}
    total = sum(len(names) for names in live.values())
    assert total >= 11, f"only {total} swept-module bindings found, in {sorted(live)}"


# --------------------------------------------------------------------------
# The pair: neither SQL assertion may disappear without the other noticing
# --------------------------------------------------------------------------


@pytest.mark.security
def test_both_sql_assertions_still_exist() -> None:
    """Two checks carry this invariant, and nothing used to assert the pair.

    ``test_store_hardening.py::test_no_sql_statement_is_built_by_interpolation``
    names three interpolation constructs at the site where the SQL is written;
    the sweep in this file carries the invariant. If a future edit deleted
    either, the other would still pass and both files would still *read* as
    though the invariant were covered. So the pair is asserted by name.
    """
    required = {
        "tests/security/test_store_hardening.py": (
            "test_no_sql_statement_is_built_by_interpolation",
            "test_every_statement_reaching_sqlite_is_built_only_from_literals",
        ),
        "tests/security/test_sql_provenance.py": (
            "test_every_statement_reaching_sqlite_is_built_only_from_literals",
            "test_the_sweep_reaches_every_executed_statement",
            "test_no_swept_module_namespace_is_written",
            "test_an_executor_is_never_taken_as_a_value",
            "test_no_statement_is_dispatched_through_a_dynamic_attribute",
        ),
    }
    for relative, names in required.items():
        tree = ast.parse((_REPO_ROOT / relative).read_text(encoding="utf-8"))
        defined = {
            node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))
        }
        missing = sorted(set(names) - defined)
        assert not missing, (
            f"{relative} no longer defines {missing} — the SQL-injection invariant is "
            "carried by both the narrow construct check and the provenance sweep, and "
            "deleting one leaves the other passing while the files read as if it were covered"
        )
