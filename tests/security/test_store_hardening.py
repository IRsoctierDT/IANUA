# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The event store holds evidence — hold its properties closed.

``store/`` is the first package in this platform that writes a database, and
it writes one whose rows are security evidence. Three classes of failure
matter, and each gets assertions rather than a comment:

* **Integrity** — history cannot be rewritten (the engine refuses ``UPDATE``),
  and a row edited outside this platform is detected on read rather than
  returned as a plausible event.
* **Containment** — the database cannot escape the gitignored lab-data root,
  the package reaches no network or subprocess, and it reads no clock.
* **Injection** — no caller value becomes SQL text. Asserted over the AST,
  because "we used parameters" is a property of today's code and this test is
  what keeps it a property of tomorrow's. Asserted at the ``execute`` call as
  a *provenance* requirement, not as a list of forbidden constructs: the
  earlier form matched three syntactic shapes and five routes were measured
  past it, three of them the same three shapes with the literal bound to a
  name first.

The store also inherits ``ingest/``'s no-message-body invariant, and that is
checked here on the *read* path: an email body smuggled into a stored row
must not survive reconstruction.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import math
import sqlite3
import typing
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ingest import normalize
from ingest.errors import MalformedProjectionError
from ingest.schema import (
    MAX_FIELD_LEN,
    MAX_NOTES,
    MAX_OBSERVABLES,
    MAX_RAW_EXCERPT,
    NormalizedEvent,
)
from store import (
    MAX_PROJECTION_BYTES,
    MAX_QUERY_LIMIT,
    EventStore,
    Query,
    SchemaVersionError,
    StoreCorruptionError,
    StoreError,
    StoreIntegrityError,
    StorePathError,
    canonical_json,
    event_id,
)
from store.schema import HIGH_WATER_KEY, SCHEMA_VERSION, VERSION_KEY
from tests.security import _sql_provenance as sqlprov

_REPO_ROOT = Path(__file__).resolve().parents[2]
_STORE_ROOT = _REPO_ROOT / "store"

#: The store needs sqlite3, hashlib, json, re and pathlib. It must not be able
#: to reach the network, spawn anything, or import code dynamically.
_BANNED_IMPORTS = {
    "socket",
    "subprocess",
    "requests",
    "urllib",
    "http",
    "ftplib",
    "telnetlib",
    "smtplib",
    "importlib",
    "pickle",
    "shelve",
    "ctypes",
}
_BANNED_CALLS = {"eval", "exec", "compile", "__import__", "input"}

#: Two distinct records, so a refused second write is distinguishable from a
#: content-addressed no-op.
_RECORD = "Failed password for root from 10.0.0.5 port 22 ssh2"
_OTHER_RECORD = "Accepted password for alice from 10.0.0.9 port 22 ssh2"

#: A literal is "SQL-ish" if it carries a statement keyword. Used to decide
#: which strings must never be built by interpolation.
_SQL_KEYWORDS = (
    "SELECT ",
    "INSERT ",
    "UPDATE ",
    "DELETE ",
    "WHERE ",
    "ORDER BY",
    "FROM ",
    "CREATE ",
    "DROP ",
    "PRAGMA ",
)


def _store_modules() -> list[Path]:
    return sorted(_STORE_ROOT.rglob("*.py"))


def _is_sql(text: str) -> bool:
    upper = text.upper()
    return any(keyword in upper for keyword in _SQL_KEYWORDS)


# --------------------------------------------------------------------------
# Injection
# --------------------------------------------------------------------------


@pytest.mark.security
def test_no_sql_statement_is_built_by_interpolation() -> None:
    """No f-string, ``%``, or ``.format()`` may produce SQL text *in place*.

    Three syntactic shapes, each checked separately so a failure names which
    one appeared, and each matched only where the SQL is the literal operand
    written at the site. That is narrower than the invariant and was once
    mistaken for it: binding the literal to a module name first walks past
    all three, measured. This is kept because an in-place interpolation is
    worth naming precisely when it appears, and because it also catches one
    that is built but never executed. What carries the invariant is
    :func:`test_every_statement_reaching_sqlite_is_built_only_from_literals`,
    which starts at the ``execute`` call instead.
    """
    for path in _store_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            # f"... {value} ..." containing SQL
            if isinstance(node, ast.JoinedStr):
                literal = "".join(
                    part.value
                    for part in node.values
                    if isinstance(part, ast.Constant) and isinstance(part.value, str)
                )
                assert not _is_sql(literal), f"{path}: SQL built by f-string: {literal!r}"
            # "SELECT ..." % value
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                left = node.left
                if isinstance(left, ast.Constant) and isinstance(left.value, str):
                    assert not _is_sql(left.value), f"{path}: SQL built by %: {left.value!r}"
            # "SELECT ...".format(value)
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
                and isinstance(node.func.value, ast.Constant)
                and isinstance(node.func.value.value, str)
            ):
                assert not _is_sql(node.func.value.value), (
                    f"{path}: SQL built by .format(): {node.func.value.value!r}"
                )


@pytest.mark.security
def test_a_quote_in_a_filter_value_cannot_alter_the_query(tmp_path: Path) -> None:
    """The positive half: a classic payload matches nothing, and does not error."""
    with EventStore.open(tmp_path) as store:
        store.append(
            normalize("Failed password for root from 10.0.0.5 port 22 ssh2"), ingested_at=1.0
        )
        store.append(
            normalize("Accepted password for alice from 10.0.0.9 port 22 ssh2"), ingested_at=2.0
        )
        assert store.count() == 2
        for payload in ("' OR '1'='1", "'; DROP TABLE events; --", '" OR 1=1 --'):
            assert store.query(Query(user_name=payload)) == ()
            assert store.query(Query(hostname=payload)) == ()
            assert store.query(Query(observable=payload)) == ()
        # The table is still there, which a successful DROP would have ended.
        assert store.count() == 2


def _store_sources() -> dict[str, str]:
    """``store/`` alone, which is the scope of the assertions in this file.

    ``tests/security/test_sql_provenance.py`` sweeps every shipped package
    with the same analysis. This narrower call is kept because
    ``store/events.py`` docstrings cite the assertion below by name, and a
    reader following that pointer should find it in the file named for the
    package it is about.
    """
    return sqlprov.sources_for([_STORE_ROOT], _REPO_ROOT)


@pytest.mark.security
def test_every_statement_reaching_sqlite_is_built_only_from_literals() -> None:
    """No caller value becomes SQL text — asserted at the ``execute`` call.

    This is the assertion that carries the invariant, and it is stated as a
    provenance requirement rather than a list of forbidden constructs: the
    statement handed to sqlite3 must be traceable to string literals written
    in this package. A parameter, a call's return value, or a name whose
    bindings do not all resolve to literals fails.
    """
    findings = sqlprov.non_literal_statements(_store_sources())
    assert not findings, "statement text not traceable to a literal:\n  " + "\n  ".join(findings)


@pytest.mark.security
def test_the_provenance_check_reaches_every_executed_statement() -> None:
    """Non-vacuity: a checker that found no call sites would pass silently.

    The floor is the count at the time of writing (19, every one of them in
    ``store/events.py``). It is a floor and not an equality so that adding a
    statement does not fail here, but a refactor that moves statements out of
    this package should fail and be looked at rather than quietly reduce what
    the assertion above covers.
    """
    sites = sqlprov.statement_sites(_store_sources())
    assert len(sites) >= 19, f"expected at least 19 statements reached, found {len(sites)}"
    assert all(kind == sqlprov.LITERAL for _where, _line, kind, _source in sites)


#: Routes into an ``execute`` call that must be refused. The first five are
#: measured: each one passed ``test_no_sql_statement_is_built_by_interpolation``
#: when planted into :meth:`store.events.EventStore.count_before`.
_REJECTED = (
    ("+ concatenation", 'statement + " -- " + str(before)'),
    ("% behind a name", "_TEMPLATE % repr(before)"),
    (".format behind a name", "_TEMPLATE.format(repr(before))"),
    ("str.join with a value", '" ".join([_TEMPLATE, repr(before)])'),
    ("f-string as a join element", '"".join([_TEMPLATE, f"{before!r}"])'),
    ("the parameter itself", "before"),
    ("f-string, the classic", 'f"SELECT * FROM events WHERE vendor = {before}"'),
    ("a helper that returns SQL", "_build(before)"),
    ("a literal with a value substituted in", '_TEMPLATE.replace("?", before)'),
    ("a mapping something updates", "_MUTATED[column]"),
    ("one branch of a choice", "_TEMPLATE if column else before"),
)

#: What ``store/events.py`` actually does. Pinned so that a future tightening
#: which breaks the real package fails *here*, naming the pattern and why it
#: is sanctioned, rather than in the whole-package assertion with a line
#: number and no explanation.
_SANCTIONED = (
    ("a bare literal", '"SELECT COUNT(*) AS n FROM events"'),
    ("module constants concatenated", "_TEMPLATE + _AND + _TEMPLATE"),
    ("a literal-valued mapping, keyed at runtime", "_EQUALITY[column]"),
    ("a runtime choice between two constants", "_TEMPLATE if column else _AND"),
    ("a joined list of constants", '" AND ".join([_TEMPLATE, _AND])'),
    ("an f-string with nothing substituted", 'f"SELECT 1"'),
)

#: One module, with the shapes the store declares, so each case above differs
#: from the next by exactly the expression under test.
_HARNESS = """
_TEMPLATE = "SELECT COUNT(*) AS n FROM events WHERE vendor = ?"
_AND = " AND "
_EQUALITY = {{"vendor": "e.vendor = ?", "hostname": "e.hostname = ?"}}
_MUTATED = {{"vendor": "e.vendor = ?"}}
_MUTATED.update({{"hostname": "e.hostname = ?"}})


def _build(value):
    return _TEMPLATE + value


def run(conn, before, column):
    {body}
    conn.execute(statement)
"""


def _harness(expression: str) -> str:
    return _HARNESS.format(body="statement = " + expression)


@pytest.mark.security
@pytest.mark.parametrize(("label", "expression"), _REJECTED)
def test_the_provenance_check_rejects_each_measured_evasion(label: str, expression: str) -> None:
    """Every known route by which a value becomes SQL text must be refused."""
    assert sqlprov.non_literal_statements({"sample": _harness(expression)}), (
        f"{label} was accepted: {expression}"
    )


#: Routes that need more than one statement, so they cannot go in
#: :data:`_REJECTED`. The last three were holes in this checker's own first
#: version, found by attacking it rather than by review, and each was measured
#: accepted before the fix named in the function it broke.
_REJECTED_MODULES = (
    (
        "+= of a value",
        _HARNESS.format(body="statement = _TEMPLATE\n    statement += str(before)"),
    ),
    (
        "nonlocal rebinding in a nested function",
        """
_TEMPLATE = "SELECT COUNT(*) AS n FROM events WHERE vendor = ?"


def outer(conn, before):
    statement = _TEMPLATE

    def inner():
        nonlocal statement
        statement = statement + before

    inner()
    conn.execute(statement)
""",
    ),
    (
        "a module constant reassigned inside a module-level if",
        """
import os

_TEMPLATE = "SELECT COUNT(*) AS n FROM events"
if os.environ.get("X"):
    _TEMPLATE = "SELECT COUNT(*) FROM events WHERE vendor = " + os.environ["X"]


def run(conn):
    conn.execute(_TEMPLATE)
""",
    ),
    (
        "the statement passed as a keyword argument",
        """
_TEMPLATE = "SELECT COUNT(*) AS n FROM events"


def run(conn, before):
    conn.execute(sql=_TEMPLATE + before)
""",
    ),
)


#: A module head for the cases below, so each differs from the next by only
#: the function body under test.
_MODULE_HEAD = '_TEMPLATE = "SELECT COUNT(*) AS n FROM events WHERE vendor = "\n\n\n'

#: The two P1 findings a reviewer raised on #224, and the four further variants
#: the same two fixes closed. Measured against the pre-fix commit (``4fdf714``)
#: and the fix: every one of the six was ACCEPTED before and is rejected now.
#: Both reported routes produce a working injection — ``list.insert`` executed
#: ``SELECT COUNT(*) AS n FROM events WHERE vendor = 'x' OR 1=1 --`` — and the
#: ``match`` capture was confirmed by *running* it, which printed the caller's
#: value where the literal had been.
_REJECTED_PATTERN_AND_MUTATION = (
    (
        "match: a bare capture pattern rebinds the statement",
        "def run(conn, before):\n"
        "    statement = _TEMPLATE\n"
        "    match before:\n"
        "        case statement:\n"
        "            pass\n"
        "    conn.execute(statement)\n",
    ),
    (
        "match: a star pattern (MatchStar) rebinds it",
        "def run(conn, before):\n"
        "    statement = _TEMPLATE\n"
        "    match before:\n"
        "        case [_, *statement]:\n"
        "            pass\n"
        "    conn.execute(statement)\n",
    ),
    (
        "match: a mapping rest pattern (MatchMapping) rebinds it",
        "def run(conn, before):\n"
        "    statement = _TEMPLATE\n"
        "    match before:\n"
        '        case {"a": 1, **statement}:\n'
        "            pass\n"
        "    conn.execute(statement)\n",
    ),
    (
        "match: an 'as' capture rebinds it",
        "def run(conn, before):\n"
        "    statement = _TEMPLATE\n"
        "    match before:\n"
        "        case str() as statement:\n"
        "            pass\n"
        "    conn.execute(statement)\n",
    ),
    (
        "list.insert, the method the ACCUMULATORS comment already named",
        "def run(conn, before):\n"
        "    clauses = [_TEMPLATE]\n"
        "    clauses.insert(1, before)\n"
        '    conn.execute("".join(clauses))\n',
    ),
    (
        "dict.update on a literal-valued mapping read by subscript",
        "def run(conn, before, column):\n"
        '    equality = {"vendor": "e.vendor = ?"}\n'
        '    equality.update({"vendor": before})\n'
        "    conn.execute(_TEMPLATE + equality[column])\n",
    ),
    (
        "an empty list plus insert, so the WHOLE statement is the caller's",
        "def run(conn, before):\n"
        "    parts = []\n"
        "    parts.insert(0, before)\n"
        '    conn.execute(" ".join(parts))\n',
    ),
)

#: Routes that were ALREADY refused before those fixes. Kept separate so the
#: table above cannot quietly take credit for them, and kept at all because
#: they are the neighbours of what broke.
_REJECTED_ALREADY = (
    (
        "list slice assignment",
        "def run(conn, before):\n"
        "    clauses = [_TEMPLATE]\n"
        "    clauses[1:1] = [before]\n"
        '    conn.execute("".join(clauses))\n',
    ),
    (
        "list index assignment",
        "def run(conn, before):\n"
        "    clauses = [_TEMPLATE]\n"
        "    clauses[0] = before\n"
        '    conn.execute("".join(clauses))\n',
    ),
    (
        "list.extend with a non-literal element",
        "def run(conn, before):\n"
        "    clauses = [_TEMPLATE]\n"
        "    clauses.extend([before])\n"
        '    conn.execute("".join(clauses))\n',
    ),
)


@pytest.mark.security
@pytest.mark.parametrize(("label", "source"), _REJECTED_MODULES)
def test_the_provenance_check_rejects_each_multi_statement_route(label: str, source: str) -> None:
    """Routes that take more than one statement to express."""
    assert sqlprov.non_literal_statements({"sample": source}), f"{label} was accepted"


#: An adversarial review pass against the version that closed the two P1
#: findings above measured **eleven further routes**, each with a runtime
#: proof of real injection, and named the root cause: a name-keyed lattice
#: over mutable objects. Ten are closed by the two structural changes those
#: findings forced — :func:`sqlprov.escaping_names`' use-whitelist, and module scope
#: reusing :func:`sqlprov.rebinding_names` instead of modelling three node types —
#: and are pinned as whole modules because each needs several statements. The
#: eleventh, ``globals()[name] = ...``, is closed by shape in
#: :func:`test_no_module_constant_is_rebound_through_the_module_dict`.
_REJECTED_ESCAPES = (
    (
        "an alias name appends to the same list object",
        "def run(conn, before):\n"
        "    parts = [_TEMPLATE]\n"
        "    sink = parts\n"
        "    sink.append(before)\n"
        '    conn.execute(" ".join(parts))\n',
    ),
    (
        "mutation through a subscript receiver, not a bare name",
        "def run(conn, before):\n"
        "    parts = [_TEMPLATE]\n"
        "    holder = (parts,)\n"
        "    holder[0].append(before)\n"
        '    conn.execute(" ".join(parts))\n',
    ),
    (
        "the clause list handed to a helper that appends to it",
        "def _add_clause(bucket, clause):\n"
        "    bucket.append(clause)\n"
        "\n"
        "\n"
        "def run(conn, tag):\n"
        "    clauses = []\n"
        "    _add_clause(clauses, f\"e.tag = '{tag}'\")\n"
        "    parts = [_TEMPLATE]\n"
        "    if clauses:\n"
        '        parts.append(" WHERE ")\n'
        '        parts.append(" AND ".join(clauses))\n'
        '    conn.execute("".join(parts))\n',
    ),
    (
        "a nested closure appends, needing no nonlocal",
        "def run(conn, before):\n"
        "    parts = [_TEMPLATE]\n"
        "\n"
        "    def add_vendor():\n"
        "        parts.append(before)\n"
        "\n"
        "    add_vendor()\n"
        '    conn.execute(" ".join(parts))\n',
    ),
)

#: Scope-boundary routes: a value computed where the analysis was not looking,
#: then executed where it was. **Three of the four were measured accepted at**
#: ``6b86450``; the module-join form was already refused there, and is kept
#: beside its sibling rather than counted as a fix, because the two were
#: reported together and the pair is what makes the module-scope defect legible.
_REJECTED_SCOPE_BOUNDARY = (
    (
        "a nested function's default argument runs in the ENCLOSING frame",
        "def query(conn, vendor):\n"
        "    statement = _TEMPLATE + vendor\n"
        "\n"
        "    def _run(_rows=conn.execute(statement)):\n"
        "        statement = _TEMPLATE\n"
        "        return (_rows, statement)\n"
        "\n"
        "    return _run()\n",
    ),
    (
        "a nested function's decorator expression runs in the ENCLOSING frame",
        "def _tap(_cursor):\n"
        "    def deco(fn):\n"
        "        return fn\n"
        "\n"
        "    return deco\n"
        "\n"
        "\n"
        "def query(conn, vendor):\n"
        "    statement = _TEMPLATE + vendor\n"
        "\n"
        "    @_tap(conn.execute(statement))\n"
        "    def _marker():\n"
        "        statement = _TEMPLATE\n"
        "        return statement\n"
        "\n"
        "    return _marker\n",
    ),
    (
        "a module copy taken from a constant the checker demotes",
        "import os\n"
        "\n"
        'for _TEMPLATE in [_TEMPLATE + os.environ.get("IANUA_VENDOR", "?")]:\n'
        "    break\n"
        "\n"
        "_STATEMENT = _TEMPLATE\n"
        "\n"
        "\n"
        "def query(conn):\n"
        "    conn.execute(_STATEMENT)\n",
    ),
    (
        "a module join taken from a list the checker demotes",
        "import os\n"
        "\n"
        "_PARTS = [_TEMPLATE]\n"
        '_PARTS.append(os.environ.get("IANUA_VENDOR", "?"))\n'
        '_STATEMENT = "".join(_PARTS)\n'
        "\n"
        "\n"
        "def query(conn):\n"
        "    conn.execute(_STATEMENT)\n",
    ),
)

#: The descent family. Each shadows a name the enclosing scope bound to a
#: literal, then walks the statement through enough assignment hops that the
#: old descending fixed point ran out of passes. Measured accepted at
#: ``6b86450`` and refused once the loop seeded bound names at the bottom of
#: the lattice. The first is the one that matters: **every line but one is the
#: shape ``store/events.py`` already writes.**
_REJECTED_DESCENT = (
    (
        "a 5-hop staged SQL build, with one module constant shadowed",
        '_WHERE = " WHERE 1=1"\n'
        "\n"
        "\n"
        "class Store:\n"
        "    def query(self, conn, raw):\n"
        "        _TEMPLATE = raw\n"
        "        head = _TEMPLATE + _WHERE\n"
        "        body = head + _WHERE\n"
        "        tail = body + _WHERE\n"
        "        statement = tail + _WHERE\n"
        "        conn.execute(statement)\n",
    ),
    (
        "a list/join oscillator over a shadowed constant",
        "class Store:\n"
        "    def count_before(self, conn, before):\n"
        "        _TEMPLATE = before\n"
        "        head = [_TEMPLATE]\n"
        '        clause = "".join(head)\n'
        "        parts = [clause]\n"
        '        statement = "".join(parts)\n'
        "        conn.execute(statement)\n",
    ),
    (
        "a six-link shadowing chain",
        '_B = "SELECT 1"\n'
        '_C = "SELECT 2"\n'
        '_D = "SELECT 3"\n'
        '_E = "SELECT 4"\n'
        "\n"
        "\n"
        "class Store:\n"
        "    def count_before(self, conn, before):\n"
        "        _TEMPLATE = before\n"
        "        _B = _TEMPLATE\n"
        "        _C = _B\n"
        "        _D = _C\n"
        "        _E = _D\n"
        "        conn.execute(_E)\n",
    ),
    (
        "the same pulse inside a nested class body, seeded from a parameter",
        '_PAD = " -- pad"\n'
        "\n"
        "\n"
        "def build(conn, raw):\n"
        "    class _Plan:\n"
        "        _TEMPLATE = raw\n"
        "        h1 = _TEMPLATE + _PAD\n"
        "        h2 = h1 + _PAD\n"
        "        h3 = h2 + _PAD\n"
        "        script = h3 + _PAD\n"
        "        conn.execute(script)\n"
        "\n"
        "    del _Plan\n",
    ),
)

#: A third round from the same pass, against the version that closed the
#: previous two. All four share a theme: a container reached under a name the
#: analysis was not watching, or sanctioned on the strength of a method's
#: *name* without checking what it is a method of.
_REJECTED_ALIASING = (
    (
        "a chained assignment binds one list to two names",
        "def run(conn, before):\n"
        "    parts = sink = [_TEMPLATE]\n"
        "    sink.append(before)\n"
        '    conn.execute("".join(parts))\n',
    ),
    (
        "a chained assignment on a literal-valued mapping",
        "def run(conn, before, column):\n"
        '    equality = overlay = {"vendor": "e.vendor = ?"}\n'
        "    overlay.update({column: before})\n"
        "    conn.execute(_TEMPLATE + equality[column])\n",
    ),
    (
        "a nested class BODY mutates an enclosing container",
        "def run(conn, before):\n"
        "    parts = [_TEMPLATE]\n"
        "\n"
        "    class _Collected:\n"
        "        parts.append(before)\n"
        "\n"
        '    conn.execute("".join(parts))\n',
    ),
    (
        "a method merely NAMED join, whose receiver is not a literal",
        "class _Renderer:\n"
        "    def __init__(self, extra):\n"
        "        self._extra = extra\n"
        "\n"
        "    def join(self, parts):\n"
        "        parts.append(self._extra)\n"
        '        return "".join(parts)\n'
        "\n"
        "\n"
        "def run(conn, before):\n"
        "    parts = [_TEMPLATE]\n"
        "    renderer = _Renderer(before)\n"
        "    renderer.join(parts)\n"
        '    conn.execute("".join(parts))\n',
    ),
)

#: Two further routes the same adversarial pass found against the restructure
#: above, each with a runtime proof that executed ``DROP TABLE events``. Both
#: have a structural cause rather than a missing construct: a ``def``/``class``
#: name was not treated as a binding at all, and a class body was analysed by
#: one half of the checker and not the other.
_REJECTED_SCOPE_SHAPES = (
    (
        "a class body inside a function, checked against the enclosing env",
        '_SELECT = "SELECT * FROM events WHERE "\n'
        "\n"
        "\n"
        "def query(conn, columns):\n"
        '    clause = "e.vendor = ?"\n'
        "\n"
        "    class _Plan:\n"
        "        for clause in columns:\n"
        "            conn.execute(_SELECT + clause)\n"
        "\n"
        "    return _Plan\n",
    ),
    (
        "a decorated def rebinding a name bound to a literal",
        '_COUNT = "SELECT COUNT(*) AS n FROM events"\n'
        '_WHERE = " WHERE ingested_at < "\n'
        "\n"
        "\n"
        "def _rendered(before):\n"
        "    def decorate(_func):\n"
        "        return _COUNT + _WHERE + str(before)\n"
        "\n"
        "    return decorate\n"
        "\n"
        "\n"
        "def count_before(conn, before):\n"
        "    statement = _COUNT\n"
        "\n"
        "    @_rendered(before)\n"
        "    def statement():\n"
        '        """The statement for this call."""\n'
        "\n"
        "    conn.execute(statement)\n",
    ),
    (
        "a decorated def rebinding a module constant",
        "import os\n"
        "\n"
        "\n"
        "def _rendered(_func):\n"
        '    return "SELECT COUNT(*) AS n FROM events" + os.environ.get("IANUA_SUFFIX", "")\n'
        "\n"
        "\n"
        '_COUNT = "SELECT COUNT(*) AS n FROM events"\n'
        "\n"
        "\n"
        "@_rendered\n"
        "def _COUNT():\n"
        '    """The statement for this deployment."""\n'
        "\n"
        "\n"
        "def count(conn):\n"
        "    conn.execute(_COUNT)\n",
    ),
    (
        "an undecorated def rebinding a name bound to a literal",
        '_COUNT = "SELECT COUNT(*) AS n FROM events"\n'
        "\n"
        "\n"
        "def run(conn):\n"
        "    statement = _COUNT\n"
        "\n"
        "    def statement():\n"
        '        """Shadows the literal above."""\n'
        "\n"
        "    conn.execute(statement)\n",
    ),
)

#: The same family on the mapping lattice and at module scope. ``_EQUALITY``
#: is not hypothetical — a literal-valued mapping keyed at runtime is one of
#: the sanctioned patterns, and it is what ``store/events.py:1008`` actually
#: does, which is what made these worth closing rather than dismissing as
#: contrived.
_REJECTED_MODULE_SCOPE = (
    (
        "a module mapping aliased to a second module name, then written",
        '_EQUALITY = {"vendor": "e.vendor = ?"}\n'
        "_REGISTRY = _EQUALITY\n"
        "\n"
        "\n"
        "def register(column, clause):\n"
        "    _REGISTRY[column] = clause\n"
        "\n"
        "\n"
        "def run(conn, column, clause):\n"
        "    register(column, clause)\n"
        "    conn.execute(_TEMPLATE + _EQUALITY[column])\n",
    ),
    (
        "a module mapping passed to a helper as a parameter",
        '_EQUALITY = {"vendor": "e.vendor = ?"}\n'
        "\n"
        "\n"
        "def _remember(table, column, clause):\n"
        "    table[column] = clause\n"
        "\n"
        "\n"
        "def run(conn, column, clause):\n"
        "    _remember(_EQUALITY, column, clause)\n"
        "    conn.execute(_TEMPLATE + _EQUALITY[column])\n",
    ),
    (
        "module-level += onto a string constant",
        "import os\n"
        "\n"
        '_STATEMENT = "SELECT COUNT(*) AS n FROM events WHERE vendor = "\n'
        '_STATEMENT += os.environ.get("IANUA_VENDOR", "?")\n'
        "\n"
        "\n"
        "def run(conn):\n"
        "    conn.execute(_STATEMENT)\n",
    ),
    (
        "module-level |= widens a literal-valued mapping in place",
        "import os\n"
        "\n"
        '_EQUALITY = {"vendor": "e.vendor = ?"}\n'
        '_EQUALITY |= {"hostname": "hostname = " + os.environ.get("IANUA_HOST", "?")}\n'
        "\n"
        "\n"
        "def run(conn, column):\n"
        "    conn.execute(_TEMPLATE + _EQUALITY[column])\n",
    ),
    (
        "a module-level for target rebinds a string constant",
        "import os\n"
        "\n"
        '_STATEMENT = "SELECT COUNT(*) AS n FROM events"\n'
        'for _STATEMENT in [_STATEMENT + os.environ.get("IANUA_VENDOR", "?")]:\n'
        "    pass\n"
        "\n"
        "\n"
        "def run(conn):\n"
        "    conn.execute(_STATEMENT)\n",
    ),
)


@pytest.mark.security
@pytest.mark.parametrize(
    ("label", "body"),
    (
        *_REJECTED_PATTERN_AND_MUTATION,
        *_REJECTED_ALREADY,
        *_REJECTED_ESCAPES,
        *_REJECTED_MODULE_SCOPE,
        *_REJECTED_SCOPE_SHAPES,
        *_REJECTED_ALIASING,
        *_REJECTED_DESCENT,
        *_REJECTED_SCOPE_BOUNDARY,
    ),
)
def test_a_pattern_capture_or_unmodelled_mutation_demotes_the_name(label: str, body: str) -> None:
    """Structural-pattern captures and container mutations this checker cannot model.

    Two of these were reported as P1 findings on #224 and were genuine: the
    ``match`` capture and ``list.insert``. The fix for each is general rather
    than shaped to the report — pattern bindings are read off
    :class:`ast.pattern`'s ``name``/``rest`` slots, and an unmodelled method on
    a tracked container demotes it — which is why four further variants in this
    table closed with them.
    """
    assert sqlprov.non_literal_statements({"sample": _MODULE_HEAD + body}), f"{label} was accepted"


@pytest.mark.security
def test_a_wildcard_pattern_binds_nothing_and_must_stay_accepted() -> None:
    """The permissive half of the pattern fix: ``case _:`` is not a binding.

    ``MatchAs`` with ``name=None`` is the wildcard, and demoting on it would
    make any ``match`` in this package poison every name in its scope. Measured
    both before and after the fix: accepted, correctly, because ``statement``
    really does still hold the literal.
    """
    body = (
        "def run(conn, before):\n"
        "    statement = _TEMPLATE\n"
        "    match before:\n"
        "        case _:\n"
        "            pass\n"
        "    conn.execute(statement)\n"
    )
    findings = sqlprov.non_literal_statements({"sample": _MODULE_HEAD + body})
    assert not findings, "a wildcard pattern must not demote:\n  " + "\n  ".join(findings)


@pytest.mark.security
@pytest.mark.parametrize(("label", "expression"), _SANCTIONED)
def test_the_provenance_check_accepts_what_the_store_actually_does(
    label: str, expression: str
) -> None:
    """The permissive half, so a tightening that breaks the store says why."""
    findings = sqlprov.non_literal_statements({"sample": _harness(expression)})
    assert not findings, f"{label} was refused: {expression}\n  " + "\n  ".join(findings)


@pytest.mark.security
def test_a_chained_module_binding_does_not_survive_the_import_boundary() -> None:
    """The alias rule has to hold across files, not just inside one scope.

    Measured accepted before the chained-assignment rule reached
    :func:`sqlprov.module_env`: one module binds a fragment list to two names, a
    helper there mutates it through the second, and a sibling imports it under
    the first. The import resolution that makes ``executescript(DDL)`` work is
    the same machinery that carried the stale provenance across.
    """
    schema = (
        'DDL_PARTS = _SINK = ["SELECT COUNT(*) AS n FROM events WHERE vendor = "]\n'
        "\n"
        "\n"
        "def add_clause(clause):\n"
        "    _SINK.append(clause)\n"
    )
    events = (
        "from sample.schema import DDL_PARTS, add_clause\n"
        "\n"
        "\n"
        "def run(conn, before):\n"
        "    add_clause(before)\n"
        '    conn.execute("".join(DDL_PARTS))\n'
    )
    findings = sqlprov.non_literal_statements({"sample.schema": schema, "sample.events": events})
    assert findings, "a chained module binding survived the import boundary"


@pytest.mark.security
def test_a_shadowed_imported_constant_cannot_outrun_the_fixed_point() -> None:
    """The descent family's cross-module form, mirroring ``executescript(DDL)``.

    ``EventStore.migrate`` runs ``executescript(DDL)`` on a literal imported
    from :mod:`store.schema`. This is that method's shape with one line added,
    ``DDL = extra_ddl``, and then four concatenation hops. Measured accepted
    while :func:`sqlprov.scope_env` descended from the inherited env: the import
    resolution that makes the real call work is what carried the stale literal
    provenance into a scope that had rebound the name.
    """
    schema = (
        'DDL = "CREATE TABLE events (event_id TEXT PRIMARY KEY)"\n'
        '_PRAGMAS = " PRAGMA foreign_keys=ON;"\n'
        '_ANALYZE = " ANALYZE;"\n'
    )
    events = (
        "from sample.schema import DDL, _ANALYZE, _PRAGMAS\n"
        "\n"
        "\n"
        "class EventStore:\n"
        "    def migrate(self, conn, extra_ddl):\n"
        "        DDL = extra_ddl\n"
        "        step1 = DDL + _PRAGMAS\n"
        "        step2 = step1 + _ANALYZE\n"
        "        step3 = step2 + _ANALYZE\n"
        "        script = step3 + _ANALYZE\n"
        "        conn.executescript(script)\n"
    )
    findings = sqlprov.non_literal_statements({"sample.schema": schema, "sample.events": events})
    assert findings, "a shadowed imported constant outran the fixed point"


@pytest.mark.security
def test_a_cross_module_mutation_demotes_the_declaring_module_too() -> None:
    """Demotion is a property of the package, not of each module separately.

    Measured accepted before :func:`sqlprov.package_envs` applied the suspect set
    package-wide: module A declares ``_EQUALITY``, executes
    ``_PREFIX + _EQUALITY[column]`` with it, and module B does
    ``_EQUALITY[column] = clause`` on the name it imported from A. B's env was
    demoted and A's was not, so the statement A executes stayed classified as
    a literal. The registry in this fixture is deliberately the real shape —
    ``store/events.py``'s ``_EQUALITY``, whose own comment says the column
    name in every statement is "a literal from this module rather than a value
    threaded in from a caller".
    """
    schema = (
        '_PREFIX = "SELECT COUNT(*) AS n FROM events WHERE "\n'
        "_EQUALITY = {\n"
        '    "source_type": "e.source_type = ?",\n'
        '    "vendor": "e.vendor = ?",\n'
        "}\n"
        "\n"
        "\n"
        "def count_where(conn, column):\n"
        "    return conn.execute(_PREFIX + _EQUALITY[column]).fetchone()\n"
    )
    events = (
        "from sample.schema import _EQUALITY, count_where\n"
        "\n"
        "\n"
        "def register_column(column, clause):\n"
        "    _EQUALITY[column] = clause\n"
        "\n"
        "\n"
        "def count(conn, column):\n"
        "    return count_where(conn, column)\n"
    )
    findings = sqlprov.non_literal_statements({"sample.schema": schema, "sample.events": events})
    assert findings, "a cross-module mutation left the declaring module's env literal"


@pytest.mark.security
def test_the_provenance_check_resolves_a_literal_imported_from_a_sibling() -> None:
    """``executescript(DDL)`` crosses files, in both import spellings.

    If this broke, the real package would fail its own check rather than pass
    — the fail-closed direction — but it would fail for the wrong reason, so
    the resolution is pinned here where the failure names itself.
    """
    schema = 'DDL = "CREATE TABLE events (event_id TEXT PRIMARY KEY)"\n'
    for spelling in ("from sample.schema import DDL", "from .schema import DDL"):
        events = f"{spelling}\n\n\ndef init(conn):\n    conn.executescript(DDL)\n"
        sources = {"sample.schema": schema, "sample.events": events}
        assert not sqlprov.non_literal_statements(sources), f"{spelling} did not resolve"


# --------------------------------------------------------------------------
# Integrity
# --------------------------------------------------------------------------


@pytest.mark.security
def test_stored_events_cannot_be_rewritten(tmp_path: Path) -> None:
    """Append-only is enforced by the engine, not by API discipline."""
    event = normalize("Failed password for root from 10.0.0.5 port 22 ssh2")
    assert event.observables, (
        "this test needs an event with an observable: a BEFORE UPDATE trigger "
        "fires per matched row, so an empty observables table would make the "
        "second assertion below pass vacuously"
    )
    with EventStore.open(tmp_path) as store:
        identifier = store.append(event, ingested_at=1.0)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._conn.execute(
                "UPDATE events SET projection = ? WHERE event_id = ?", ("{}", identifier)
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._conn.execute(
                "UPDATE observables SET value = ? WHERE event_id = ?", ("x", identifier)
            )
        # Unchanged, and still readable.
        assert len(store.query()) == 1


@pytest.mark.security
def test_a_row_edited_outside_the_platform_is_detected_on_read(tmp_path: Path) -> None:
    """Content addressing makes tampering loud instead of plausible."""
    with EventStore.open(tmp_path) as store:
        store.append(normalize("sshd: session opened for user root"), ingested_at=1.0)
        # UPDATE is refused, so forge by inserting a row whose projection does
        # not hash to its id — the shape a direct sqlite3 edit would leave.
        with store._conn:
            store._conn.execute(
                "INSERT INTO events (event_id, ingested_at, occurred_at, source_type, "
                "vendor, parse_status, user_name, hostname, src_ip, dst_ip, projection) "
                "VALUES (?, ?, NULL, 'unknown', 'forged', 'text', NULL, NULL, NULL, NULL, ?)",
                ("0" * 64, 2.0, "{}"),
            )
        with pytest.raises(StoreIntegrityError, match="modified outside this platform"):
            store.query()


@pytest.mark.security
def test_a_schema_written_by_another_version_is_refused(tmp_path: Path) -> None:
    """No implicit migration: old rows must not be read into a new shape."""
    with EventStore.open(tmp_path) as store, store._conn:
        store._conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
    with pytest.raises(SchemaVersionError, match="version '99'"):
        EventStore.open(tmp_path).close()


#: Schema versions no build writes, planted with raw SQL as anything holding the
#: file can. Every build writes ``str(SCHEMA_VERSION)``, a short integer.
_FORGED_VERSIONS: dict[str, str | bytes] = {
    # Measured before the bound: a 50,154-character SchemaVersionError.
    "long_text": "PLANTED-" + "q" * 50_000,
    # TEXT affinity keeps a BLOB a BLOB, and it was echoed as str(bytes).
    "blob": b"PLANTED-" + b"q" * 50_000,
    # Short enough never to be cut, so only repr keeps it off a terminal. C0, C1,
    # a bidi override and a line separator, since an escaper that knows only C0
    # passes on the first two.
    "control_characters": "9\x1b[2J\x1b[H\nok: all met\r\n\x9b2J\u202e\u2028",
}


@pytest.mark.security
@pytest.mark.parametrize("case", sorted(_FORGED_VERSIONS), ids=lambda value: value)
def test_a_forged_schema_version_cannot_write_its_content_into_the_refusal(
    tmp_path: Path, case: str
) -> None:
    """The stored version is quoted, but through ``repr`` and bounded, because a row chooses it.

    Measured before the bound: a 50,000-character version made a 50,154-character
    ``SchemaVersionError``, which ``sli``'s ``_open_store`` carries into both store
    objectives' details, the detail ``AUD-03`` tells an operator to record; and a
    version holding ``ESC[2J`` reached ``scripts/report_sli.py``'s stdout raw.
    Pinned against literals rather than the module's constant, because an
    assertion scaled from the constant under test cannot fail.
    """
    planted = _FORGED_VERSIONS[case]
    with EventStore.open(tmp_path) as store, store._conn:
        store._conn.execute("UPDATE meta SET value = ? WHERE key = ?", (planted, VERSION_KEY))
        stored = store._conn.execute(
            "SELECT typeof(value) FROM meta WHERE key = ?", (VERSION_KEY,)
        ).fetchone()[0]
    assert stored == ("blob" if isinstance(planted, bytes) else "text"), "this tests nothing"
    with pytest.raises(SchemaVersionError) as raised:
        EventStore.open(tmp_path).close()
    message = str(raised.value)
    assert message.startswith("event store was written by schema version "), message
    assert message.isprintable(), repr(message)
    assert len(message) < 500, f"{len(message)} chars of a forged version's refusal"
    if case == "control_characters":
        assert "cut)" not in message, "the plant was cut, so repr alone is not what is tested"
        assert "\\x1b[2J" in message and "\\u202e" in message, message
    else:
        assert "q" * 100 not in message
        unit = "bytes" if isinstance(planted, bytes) else "chars"
        assert f"({len(planted)} {unit}, cut)" in message, "a cut must say that it is one"


@pytest.mark.security
@pytest.mark.parametrize(
    "version",
    [
        pytest.param(str(SCHEMA_VERSION + 1), id="next-build"),
        # The largest integer SQLite holds, as TEXT affinity renders it.
        pytest.param(str(2**63 - 1), id="largest-integer"),
    ],
)
def test_a_real_version_from_another_build_is_still_named(tmp_path: Path, version: str) -> None:
    """The control for the test above: the bound must not cost an operator the version.

    A version written by another build is what tells an operator which build to
    run against the store, so it is named whole. Pinned as the full clause, so
    neither a cut nor naming only the value's type and length passes.
    """
    with EventStore.open(tmp_path) as store, store._conn:
        store._conn.execute("UPDATE meta SET value = ? WHERE key = ?", (version, VERSION_KEY))
    with pytest.raises(SchemaVersionError) as raised:
        EventStore.open(tmp_path).close()
    message = str(raised.value)
    expected = f"written by schema version '{version}', this build speaks version {SCHEMA_VERSION};"
    assert expected in message, message
    assert "cut)" not in message, message


# --------------------------------------------------------------------------
# Containment
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize(
    "filename",
    [
        "../escape.sqlite3",
        "../../escape.sqlite3",
        "/etc/passwd",
        "sub/dir.sqlite3",
        "..",
        ".",
        ".hidden",
        "",
        "a\x00b",
    ],
)
def test_the_database_cannot_escape_the_events_directory(tmp_path: Path, filename: str) -> None:
    with pytest.raises(StorePathError):
        EventStore.open(tmp_path, filename=filename).close()


@pytest.mark.security
def test_the_database_lands_under_the_gitignored_lab_root(tmp_path: Path) -> None:
    with EventStore.open(tmp_path) as store:
        assert store.path.parent == (tmp_path / "data" / "events").resolve()


@pytest.mark.security
def test_store_imports_nothing_that_could_reach_out_or_execute() -> None:
    for path in _store_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in _BANNED_IMPORTS, f"{path}: {alias.name}"
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in _BANNED_IMPORTS, f"{path}: {node.module}"


@pytest.mark.security
def test_store_calls_no_executor() -> None:
    for path in _store_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in _BANNED_CALLS, f"{path}: calls {node.func.id}()"


@pytest.mark.security
def test_store_reads_no_clock() -> None:
    """``ingested_at`` is injected, so the storage timeline is reproducible.

    Asserted over the AST rather than the raw source, because the package
    docstring deliberately shows a *caller* passing ``time.time()`` in. A
    text search cannot tell the documented caller apart from the module doing
    it itself, and the property under test is only the latter.
    """
    forbidden = {"now", "utcnow", "today", "time", "monotonic", "time_ns"}
    for path in _store_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in forbidden, (
                    f"{path}: reads the clock via .{node.func.attr}()"
                )


@pytest.mark.security
def test_store_adds_no_runtime_dependency() -> None:
    """``dependencies = []`` is a load-bearing repository property.

    Read from ``pyproject.toml``, not installed metadata, so this runs
    everywhere rather than skipping wherever the package is not pip-installed.
    Installed metadata is checked too when available, since that would also
    catch a dependency the build backend injected rather than one declared
    here.
    """
    import tomllib

    config = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = config["project"]["dependencies"]
    assert declared == [], f"store must not introduce runtime dependencies: {declared}"

    import importlib.metadata as metadata

    try:
        installed = metadata.requires("ianua") or []
    except metadata.PackageNotFoundError:
        return  # not installed here; the committed declaration is the contract
    runtime = [req for req in installed if "extra ==" not in req]
    assert runtime == [], f"installed metadata declares runtime dependencies: {runtime}"


# --------------------------------------------------------------------------
# Bounds
# --------------------------------------------------------------------------


@pytest.mark.security
def test_an_oversized_projection_is_refused(tmp_path: Path) -> None:
    """A hand-built event that skipped ingest/'s bounds does not get stored."""
    huge = NormalizedEvent(
        source_type="unknown",
        vendor="hand-built",
        vendor_event_id=None,
        timestamp=None,
        message="m",
        activity=None,
        parse_status="text",
        raw_excerpt="x" * (MAX_PROJECTION_BYTES + 1),
    )
    with EventStore.open(tmp_path) as store:
        with pytest.raises(StoreIntegrityError, match="ceiling"):
            store.append(huge, ingested_at=1.0)
        assert store.count() == 0, "a refused event must leave nothing behind"


# --------------------------------------------------------------------------
# What is writable must be readable back
#
# `query` rebuilds every row it returns through `NormalizedEvent.from_dict`
# and raises on the first bad one, so a single unreadable row denied the whole
# window and the cursor could never advance past it. `UPDATE` is
# trigger-refused and `prune` takes only a time cutoff, so the sanctioned
# recovery was destroying the store. These assert that the store refuses on
# write exactly what it would refuse on read.
# --------------------------------------------------------------------------


def _hand_built(**overrides: Any) -> NormalizedEvent:
    """An event that skipped ingest/'s bounds, as a direct caller would build."""
    base: dict[str, Any] = {
        "source_type": "unknown",
        "vendor": "hand-built",
        "vendor_event_id": None,
        "timestamp": None,
        "message": "m",
        "activity": None,
        "parse_status": "text",
    }
    return NormalizedEvent(**{**base, **overrides})


#: One case per bound `from_dict` enforces that the size ceiling does not
#: catch. Each is far under MAX_PROJECTION_BYTES, which is the whole point.
_UNREADABLE: dict[str, dict[str, Any]] = {
    "message": {"message": "x" * (MAX_FIELD_LEN + 1)},
    "raw_excerpt": {"raw_excerpt": "y" * (MAX_RAW_EXCERPT + 1)},
    "one_long_note": {"notes": ("z" * (MAX_FIELD_LEN + 1),)},
    "too_many_notes": {"notes": tuple(f"n{index}" for index in range(MAX_NOTES + 1))},
    "too_many_observables": {
        "observables": tuple(f"10.0.0.{index}" for index in range(MAX_OBSERVABLES + 1))
    },
    # Not lengths, but bounds `from_dict` enforces all the same, and both
    # sides accepted all three before the reader refused them.
    "nan_timestamp": {"timestamp": math.nan},
    "positive_infinite_timestamp": {"timestamp": math.inf},
    "negative_infinite_timestamp": {"timestamp": -math.inf},
}


@pytest.mark.security
@pytest.mark.parametrize("case", sorted(_UNREADABLE), ids=lambda value: value)
def test_append_refuses_exactly_what_query_would_refuse(tmp_path: Path, case: str) -> None:
    """The symmetry, asserted as one property rather than two bound lists.

    Both sides must reject the same event, and with the same error — which is
    what makes "append refuses iff query refuses" checkable instead of a
    comment. The projection is well inside the byte ceiling in every case, so
    the pre-existing size check cannot be what catches it.
    """
    event = _hand_built(**_UNREADABLE[case])
    projection = canonical_json(event.to_dict())
    assert len(projection.encode("utf-8")) < MAX_PROJECTION_BYTES, "size check would mask this"

    # The read path refuses it...
    with pytest.raises(MalformedProjectionError):
        NormalizedEvent.from_dict(json.loads(projection))

    # ...so the write path must too, and must leave nothing behind.
    with EventStore.open(tmp_path) as store:
        store.append(normalize("sshd: session opened for user root"), ingested_at=1.0)
        with pytest.raises(MalformedProjectionError):
            store.append(event, ingested_at=2.0)
        assert store.count() == 1
        assert len(store.query()) == 1, "the store must still read after a refusal"


@pytest.mark.security
def test_one_unreadable_row_can_no_longer_wedge_every_later_query(tmp_path: Path) -> None:
    """The consequence, asserted through the store rather than argued.

    Before this, the refused event was *stored*: `append` returned an id and
    every subsequent `query` raised for the entire result set, so detection
    stopped permanently while the collector kept exiting 0.
    """
    with EventStore.open(tmp_path) as store:
        store.append(
            normalize("Failed password for a from 203.0.113.1 port 22 ssh2"), ingested_at=1.0
        )
        with pytest.raises(MalformedProjectionError):
            store.append(_hand_built(message="x" * (MAX_FIELD_LEN + 1)), ingested_at=2.0)
        # The store keeps working: reads succeed and later writes still land,
        # which is what the cursor needs in order to advance.
        store.append(
            normalize("Failed password for b from 203.0.113.2 port 22 ssh2"), ingested_at=3.0
        )
        assert store.count() == 2
        assert len(store.query()) == 2
    # And again after a reopen, since the row is simply not there.
    with EventStore.open(tmp_path) as store:
        assert len(store.query()) == 2


@pytest.mark.security
def test_a_batch_holding_one_unreadable_event_is_refused_whole(tmp_path: Path) -> None:
    """All-or-nothing: the projection pass completes before the transaction opens."""
    good = normalize("Accepted password for v from 10.0.0.1 port 22 ssh2")
    with EventStore.open(tmp_path) as store:
        with pytest.raises(MalformedProjectionError):
            store.append_many(
                (good, _hand_built(message="x" * (MAX_FIELD_LEN + 1))), ingested_at=1.0
            )
        assert store.count() == 0, "a refused batch must not store its good events"
        assert store.append_many((good,), ingested_at=1.0) == 1


#: Fields no value can overfill: two closed vocabularies. Named so the
#: reflection below cannot quietly cover nothing and pass. ``timestamp`` was a
#: third, "an epoch float", until the reader refused NaN and the infinities:
#: now a value can put it outside its bound, so it is exercised below.
_UNOVERFILLABLE = frozenset({"source_type", "parse_status"})


def _one_overfilled_field(name: str) -> NormalizedEvent:
    """An event valid everywhere except ``name``, which is one past its bound.

    One field at a time, deliberately. An event overfilled in *every* field
    exceeds MAX_PROJECTION_BYTES and is caught by the size ceiling, so it
    never reaches the read-back — it is the few-fields case that falls in the
    gap between the two checks, and that is the case this covers.
    """
    if name in _UNOVERFILLABLE:
        raise AssertionError(f"{name} has no overfillable value")
    hints = typing.get_type_hints(NormalizedEvent)
    annotation = hints[name]
    long_text = "A" * (MAX_FIELD_LEN + 1)
    if name == "timestamp":
        return _hand_built(timestamp=math.nan)
    if name == "raw_excerpt":
        return _hand_built(raw_excerpt="A" * (MAX_RAW_EXCERPT + 1))
    if dataclasses.is_dataclass(annotation) and isinstance(annotation, type):
        group = typing.cast("type[Any]", annotation)
        group_hints = typing.get_type_hints(group)
        scalar = next(f.name for f in dataclasses.fields(group) if group_hints[f.name] is not tuple)
        return _hand_built(**{name: group(**{scalar: long_text})})
    if typing.get_origin(annotation) is tuple:
        return _hand_built(**{name: (long_text,)})
    return _hand_built(**{name: long_text})


#: Parametrized over the overfillable fields only, so the test body carries no
#: skip branch. The coverage check below is what stops this list from quietly
#: shrinking to nothing.
_OVERFILLABLE = sorted(
    f.name for f in dataclasses.fields(NormalizedEvent) if f.name not in _UNOVERFILLABLE
)


@pytest.mark.security
@pytest.mark.parametrize("name", _OVERFILLABLE)
def test_every_field_past_its_bound_is_refused_on_write(tmp_path: Path, name: str) -> None:
    """By reflection over the dataclass, so a new field is covered unasked.

    For each field: one past its bound is refused with the error the *read*
    path raises, and the same event through ``bounded()`` is accepted. That
    ties the three pieces together — ``bounded()`` is what makes an event
    storable, and the store refuses anything it did not fix.
    """
    event = _one_overfilled_field(name)
    projection = canonical_json(event.to_dict())
    assert len(projection.encode("utf-8")) < MAX_PROJECTION_BYTES, "size check would mask this"
    with EventStore.open(tmp_path) as store:
        with pytest.raises(MalformedProjectionError):
            store.append(event, ingested_at=1.0)
        assert store.count() == 0
        store.append(event.bounded(), ingested_at=1.0)
        assert store.count() == 1
        assert len(store.query()) == 1


@pytest.mark.security
def test_the_reflection_above_covers_every_field_it_can() -> None:
    """A parametrized test covering nothing would pass in silence."""
    names = {f.name for f in dataclasses.fields(NormalizedEvent)}
    assert names > _UNOVERFILLABLE, "a field named in _UNOVERFILLABLE no longer exists"
    assert set(_OVERFILLABLE) == names - _UNOVERFILLABLE
    assert len(_OVERFILLABLE) >= 12, f"only {len(_OVERFILLABLE)} fields exercised"
    for name in sorted(_UNOVERFILLABLE):
        with pytest.raises(AssertionError):
            _one_overfilled_field(name)


def _plant(store: EventStore, projection: str, *, ingested_at: float | str | bytes) -> str:
    """Write a row the API would refuse, under an ``event_id`` that matches it.

    The hash is recomputed on purpose. ``event_id`` is an unkeyed sha256, so a
    matching hash is what a row from an earlier build and a forged row both
    carry, and the hash check is not what stops either of them. ``ingested_at``
    takes text and bytes too, because the column is outside the hash and SQLite
    stores whatever storage class it is given.
    """
    identifier = event_id(projection)
    with store._conn:
        store._conn.execute(
            "INSERT INTO events (event_id, ingested_at, occurred_at, source_type, "
            "vendor, parse_status, user_name, hostname, src_ip, dst_ip, projection) "
            "VALUES (?, ?, NULL, 'unknown', 'planted', 'text', NULL, NULL, NULL, NULL, ?)",
            (identifier, ingested_at, projection),
        )
    return identifier


@pytest.mark.security
@pytest.mark.parametrize("case", sorted(_UNREADABLE), ids=lambda value: value)
def test_query_refuses_what_append_refuses_and_as_a_store_error(tmp_path: Path, case: str) -> None:
    """The symmetry, checked through ``query`` itself and with the class it raises.

    ``test_append_refuses_exactly_what_query_would_refuse`` asserts the read
    side through ``from_dict`` directly. That is why it stayed green while the
    read path's refusal escaped every ``except StoreError``: ``query`` raised
    the reader's ``MalformedProjectionError``, an ``IngestError``, and
    ``sli`` graded ``store-readable``'s own headline failure "the probe
    raised". This test plants the projection ``append`` refuses, under a
    matching hash, and reads it back through the store.
    """
    event = _hand_built(**_UNREADABLE[case])
    projection = canonical_json(event.to_dict())
    with EventStore.open(tmp_path) as store:
        with pytest.raises(MalformedProjectionError) as refused:
            store.append(event, ingested_at=1.0)
        identifier = _plant(store, projection, ingested_at=2.0)
        with pytest.raises(StoreIntegrityError) as raised:
            store.query()
    assert not isinstance(raised.value, StoreCorruptionError), "a row, not a damaged file"
    assert isinstance(raised.value.__cause__, MalformedProjectionError)
    assert str(raised.value.__cause__) == str(refused.value), "one refusal, read on both sides"
    assert identifier in str(raised.value)
    assert str(refused.value) in str(raised.value), "the cause must be named, not only typed"


#: Hash-valid projections that fail to rebuild by a route other than a field
#: bound, with what the decoder or reader raises on each. Each one was measured
#: escaping ``query`` as something other than a ``StoreError``.
_UNREBUILDABLE: dict[str, tuple[Callable[[dict[str, Any]], str], type[BaseException]]] = {
    "integer_timestamp_past_float": (
        lambda base: canonical_json({**base, "timestamp": 10**400}),
        MalformedProjectionError,
    ),
    "not_a_mapping": (lambda base: json.dumps(sorted(base)), MalformedProjectionError),
    "nesting_past_the_decoder": (lambda base: "[" * 100_000 + "]" * 100_000, RecursionError),
}


@pytest.mark.security
@pytest.mark.parametrize("case", sorted(_UNREBUILDABLE), ids=lambda value: value)
def test_every_route_to_an_unrebuildable_row_is_a_store_error(tmp_path: Path, case: str) -> None:
    """The routes other than a bound, which a fix catching only the bound would miss.

    Before this change, ``10**400`` raised ``OverflowError`` from the reader's
    ``float()``, which a mapping of ``MalformedProjectionError`` alone would not
    catch. And 100,000 nested brackets raised json's own ``RecursionError``,
    which is not the ``ValueError`` the decode branch caught. The precondition
    is asserted first. Otherwise a future decoder that accepted the nesting, or
    a reader that went back to raising ``OverflowError``, would leave this test
    checking nothing.
    """
    build, cause = _UNREBUILDABLE[case]
    projection = build(normalize(_RECORD).to_dict())
    with pytest.raises(cause):
        NormalizedEvent.from_dict(json.loads(projection))
    with EventStore.open(tmp_path) as store:
        identifier = _plant(store, projection, ingested_at=1.0)
        with pytest.raises(StoreIntegrityError) as raised:
            store.query()
    assert isinstance(raised.value.__cause__, cause)
    assert identifier in str(raised.value)


#: A forged row chooses what two of the reader's sentences quote: the stored
#: value of a closed-vocabulary field, and the names of undeclared keys.
_QUOTING: dict[str, Callable[[dict[str, Any], str], dict[str, Any]]] = {
    "literal_value": lambda base, planted: {**base, "source_type": planted},
    "undeclared_key": lambda base, planted: {**base, planted: 1},
}


@pytest.mark.security
@pytest.mark.parametrize("case", sorted(_QUOTING), ids=lambda value: value)
def test_a_forged_row_cannot_write_its_content_into_the_refusal(tmp_path: Path, case: str) -> None:
    """The reader's sentence is carried, but bounded, because it quotes the row.

    Measured: a 50,000-character ``source_type`` made a 50,107-character
    ``MalformedProjectionError``. ``sli.measure_store_readable`` puts the
    store's message into its detail, so an unbounded copy would let a forged
    row write 50 KB into the SLI report an operator records for ``AUD-03``.
    Pinned against literals rather than the module's constant, because an
    assertion scaled from the constant under test cannot fail.
    """
    planted = "PLANTED-" + "q" * 50_000
    projection = canonical_json(_QUOTING[case](normalize(_RECORD).to_dict(), planted))
    with EventStore.open(tmp_path) as store:
        _plant(store, projection, ingested_at=1.0)
        with pytest.raises(StoreIntegrityError) as raised:
            store.query()
    reader = str(raised.value.__cause__)
    assert len(reader) > 50_000, "the reader no longer quotes the row; this tests nothing"
    message = str(raised.value)
    assert len(message) < 500, f"{len(message)} chars of a forged row's refusal"
    assert "q" * 300 not in message
    assert f"({len(reader)} chars, cut)" in message, "a cut must say that it is one"


#: ``ingested_at`` values no write path stores, as SQLite keeps them in a REAL
#: column, with the reader's exception for each. The column is outside the
#: hash, so each needs nothing but write access to the file.
_CORRUPT_STAMPS: dict[str, tuple[str | bytes | float, type[Exception]]] = {
    # Raised a bare ValueError from float(), so `sli` read "the probe raised".
    "text": ("PLANTED-STAMP", TypeError),
    "blob": (b"PLANTED-STAMP", TypeError),
    # Read back *silently* before: float() parses bytes, and +/-inf converts.
    "numeric_blob": (b"1.5", TypeError),
    "positive_infinity": (math.inf, ValueError),
    "negative_infinity": (-math.inf, ValueError),
}


@pytest.mark.security
@pytest.mark.parametrize("case", sorted(_CORRUPT_STAMPS), ids=lambda value: value)
def test_a_corrupt_ingestion_stamp_is_a_store_integrity_error(tmp_path: Path, case: str) -> None:
    """The one column the read path converts and the hash does not cover.

    A refusal that names the corruption, rather than a runtime ``ValueError``
    that ``sli`` cannot tell from a bug in the probe. And it covers the two
    shapes ``float()`` accepted without complaint, a numeric BLOB and an
    infinity, which a fix catching only ``ValueError`` would still have let
    through. The planted text must not reach the message: a forged row
    chooses it.
    """
    value, cause = _CORRUPT_STAMPS[case]
    projection = canonical_json(normalize(_RECORD).to_dict())
    with EventStore.open(tmp_path) as store:
        identifier = _plant(store, projection, ingested_at=value)
        with pytest.raises(StoreIntegrityError) as raised:
            store.query()
    assert not isinstance(raised.value, StoreCorruptionError), "a row, not a damaged file"
    assert isinstance(raised.value.__cause__, cause)
    message = str(raised.value)
    assert identifier in message
    assert "ingested_at" in message
    assert "PLANTED" not in message


@pytest.mark.security
def test_a_finite_ingestion_stamp_in_any_numeric_spelling_still_reads(tmp_path: Path) -> None:
    """The control, or every refusal above is satisfied by refusing all rows.

    An integer is a legitimate stamp: the column's REAL affinity stores it as
    a float, which is what a reader must accept. And NaN is not a read case at
    all, because SQLite stores NaN as NULL and the column is NOT NULL. That is
    asserted rather than assumed, so a SQLite that changed it would fail here
    instead of leaving a gap the cases above do not cover.
    """
    projection = canonical_json(normalize(_RECORD).to_dict())
    with EventStore.open(tmp_path) as store:
        _plant(store, projection, ingested_at=5)
        (stored,) = store.query()
        assert stored.ingested_at == 5.0
        with pytest.raises(sqlite3.IntegrityError, match="NOT NULL"):
            _plant(store, canonical_json(normalize(_OTHER_RECORD).to_dict()), ingested_at=math.nan)


@pytest.mark.security
def test_a_query_limit_cannot_exceed_the_ceiling(tmp_path: Path) -> None:
    with EventStore.open(tmp_path) as store:
        store.append(normalize("sshd: session opened for user root"), ingested_at=1.0)
        # Asking for more than the ceiling is clamped, not honored.
        assert len(store.query(Query(limit=MAX_QUERY_LIMIT * 100))) == 1
        # A non-positive limit yields nothing rather than everything.
        for limit in (0, -1, -10_000):
            assert store.query(Query(limit=limit)) == ()


@pytest.mark.security
@pytest.mark.parametrize(
    "limit",
    [math.nan, 2.5, 5.0, math.inf, "5", b"5", None],
    ids=["nan", "fraction", "integral_float", "inf", "text", "bytes", "none"],
)
def test_a_non_integer_query_limit_is_a_type_error(tmp_path: Path, limit: object) -> None:
    """A count that is not an integer is a caller's bad argument, said as one.

    Measured before: NaN and ``2.5`` raised a raw ``sqlite3.IntegrityError``
    ("datatype mismatch"), the class ``_refuse_corruption`` keeps for the
    append-only trigger; ``inf`` was taken silently as the ceiling; text, bytes
    and ``None`` failed inside ``min()``; and ``5.0`` worked by accident. A
    float is refused whatever its value, so the rule is about the type.
    """
    with EventStore.open(tmp_path) as store:
        store.append(normalize(_RECORD), ingested_at=1.0)
        with pytest.raises(TypeError, match="limit must be an integer"):
            store.query(Query(limit=limit))  # type: ignore[arg-type]


@pytest.mark.security
def test_an_integer_query_limit_still_reads(tmp_path: Path) -> None:
    """The control: the index protocol takes every integer the old code took."""
    with EventStore.open(tmp_path) as store:
        store.append(normalize(_RECORD), ingested_at=1.0)
        store.append(normalize(_OTHER_RECORD), ingested_at=2.0)
        assert len(store.query(Query(limit=1))) == 1
        assert len(store.query(Query(limit=10**30))) == 2, "a huge limit is clamped, not refused"
        assert store.query(Query(limit=0)) == ()


#: Bytes that are not UTF-8. Bound as a BLOB and cast in SQL, because a
#: ``CAST`` to TEXT keeps the bytes and Python cannot bind such a ``str``.
#: The ``PLANTED`` prefix is what a refusal must not repeat.
_NOT_UTF8 = b"PLANTED\xff"


def _plant_not_utf8(store: EventStore, where: str) -> None:
    """Put non-UTF-8 TEXT where ``where`` names, as anything holding the file can.

    Rows go in through ``INSERT``, which the append-only triggers allow, so the
    schema is not touched. ``meta`` has no trigger: its mark moves on every write.
    """
    projection = canonical_json(normalize(_OTHER_RECORD).to_dict())
    tail = ", NULL, 'unknown', 'planted', 'text', NULL, NULL, NULL, NULL)"
    insert = (
        "INSERT INTO events (event_id, ingested_at, projection, occurred_at, source_type, "
        "vendor, parse_status, user_name, hostname, src_ip, dst_ip) VALUES "
    )
    with store._conn:
        if where == "high_water_mark":
            store._conn.execute(
                "UPDATE meta SET value = CAST(? AS TEXT) WHERE key = ?", (_NOT_UTF8, HIGH_WATER_KEY)
            )
        elif where == "schema_version":
            store._conn.execute(
                "UPDATE meta SET value = CAST(? AS TEXT) WHERE key = ?", (_NOT_UTF8, VERSION_KEY)
            )
        elif where == "projection":
            store._conn.execute(
                insert + "(?, 2.0, CAST(? AS TEXT)" + tail, (event_id(projection), _NOT_UTF8)
            )
        else:
            store._conn.execute(insert + "(CAST(? AS TEXT), 2.0, ?" + tail, (_NOT_UTF8, projection))


#: Where the bytes are planted, and every public read that decodes that column.
_NOT_UTF8_ROUTES: dict[str, tuple[str, ...]] = {
    "high_water_mark": ("high_water_mark", "next_stamp", "append", "attest"),
    "schema_version": ("open",),
    "projection": ("query",),
    "event_id": ("query", "attest"),
}


def _read_route(store: EventStore, root: Path, route: str) -> object:
    calls: dict[str, Callable[[], object]] = {
        "high_water_mark": store.high_water_mark,
        "next_stamp": lambda: store.next_stamp(9.0),
        "append": lambda: store.append(
            normalize("sshd: session opened for user root"), ingested_at=9.0
        ),
        "attest": store.attest,
        "query": store.query,
        "open": lambda: EventStore.open(root).close(),
    }
    return calls[route]()


@pytest.mark.security
@pytest.mark.parametrize(
    ("where", "route"),
    [(where, route) for where, routes in _NOT_UTF8_ROUTES.items() for route in routes],
)
def test_non_utf8_text_is_a_store_integrity_error_that_does_not_quote_it(
    tmp_path: Path, where: str, route: str
) -> None:
    """Every TEXT column the store decodes, through every public read of it.

    ``sqlite3``'s own decoder raised a raw ``OperationalError``, which no
    first-party ``except StoreError`` catches, and its message quoted the bytes
    (``… with text 'PLANTED�'``). No write path stores non-UTF-8, because every
    write binds ``str``, so this is a row written outside the platform.
    """
    with EventStore.open(tmp_path) as store:
        store.append(normalize(_RECORD), ingested_at=1.0)
        _plant_not_utf8(store, where)
        held = store._conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
        with pytest.raises(StoreIntegrityError) as raised:
            _read_route(store, tmp_path, route)
        assert not isinstance(raised.value, StoreCorruptionError), "a row, not a damaged file"
        assert "not valid UTF-8" in str(raised.value)
        assert "PLANTED" not in str(raised.value), "the refusal quoted the stored bytes"
        assert raised.value.__cause__ is None and raised.value.__suppress_context__
        if route == "append":
            assert store._conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"] == held


@pytest.mark.security
def test_non_ascii_utf8_text_still_round_trips(tmp_path: Path) -> None:
    """The control, or the refusal above is satisfied by refusing all text."""
    event = _hand_built(message="café ✓ 日本")
    with EventStore.open(tmp_path) as store:
        store.append(event, ingested_at=1.0)
        (stored,) = store.query()
    assert stored.event.message == "café ✓ 日本"


# --------------------------------------------------------------------------
# Inherited invariant: no message body, including on the read path
# --------------------------------------------------------------------------


@pytest.mark.security
def test_a_smuggled_email_body_cannot_survive_reconstruction(tmp_path: Path) -> None:
    """``from_dict`` rejects undeclared keys, so the no-body rule holds on read.

    ``ingest/`` proves no parser *reads* a body. This is the other direction:
    if a row somehow carries one, rebuilding the event refuses rather than
    quietly dropping it — a silent drop would let the field round-trip through
    storage for anything reading the raw projection.
    """
    event = normalize("sshd: session opened for user root")
    payload = event.to_dict()
    payload["email"]["body"] = "secret contents"
    forged = canonical_json(payload)
    with EventStore.open(tmp_path) as store:
        with store._conn:
            store._conn.execute(
                "INSERT INTO events (event_id, ingested_at, occurred_at, source_type, "
                "vendor, parse_status, user_name, hostname, src_ip, dst_ip, projection) "
                "VALUES (?, ?, NULL, 'unknown', 'forged', 'text', NULL, NULL, NULL, NULL, ?)",
                (event_id(forged), 1.0, forged),
            )
        with pytest.raises(Exception, match="undeclared key"):
            store.query()


@pytest.mark.security
def test_a_bound_is_reasserted_on_read_not_trusted(tmp_path: Path) -> None:
    """The writer bounded the field, but the bytes have been on disk since."""
    event = normalize("sshd: session opened for user root")
    payload = event.to_dict()
    payload["raw_excerpt"] = "x" * (MAX_RAW_EXCERPT + 1)
    forged = canonical_json(payload)
    with EventStore.open(tmp_path) as store:
        with store._conn:
            store._conn.execute(
                "INSERT INTO events (event_id, ingested_at, occurred_at, source_type, "
                "vendor, parse_status, user_name, hostname, src_ip, dst_ip, projection) "
                "VALUES (?, ?, NULL, 'unknown', 'forged', 'text', NULL, NULL, NULL, NULL, ?)",
                (event_id(forged), 1.0, forged),
            )
        with pytest.raises(Exception, match="exceeds"):
            store.query()


@pytest.mark.security
def test_a_symlinked_events_directory_cannot_relocate_the_database(tmp_path: Path) -> None:
    """The one escape a filename cannot express, so the path check must catch it.

    The filename regex forbids separators and traversal, which makes the
    containment check look redundant. It is not: if ``data/events`` is itself a
    symlink pointing elsewhere, every valid filename resolves outside the root.
    Relocating an evidence database by planting a symlink is precisely the move
    the check exists for.
    """
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    events = tmp_path / "data" / "events"
    events.parent.mkdir(parents=True)
    events.symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(StorePathError, match="is a symlink"):
        EventStore.open(tmp_path).close()


@pytest.mark.security
def test_a_store_with_tables_but_no_version_row_is_refused(tmp_path: Path) -> None:
    """Re-stamping the current version would assert what cannot be known.

    Creation writes the tables and the version row in one transaction, so this
    state only arises if the row was removed. Treating it as a fresh database
    would re-stamp the running version onto rows of unknown provenance — a
    fail-open, and the reason this refuses instead.
    """
    with EventStore.open(tmp_path) as store, store._conn:
        store._conn.execute("DELETE FROM meta WHERE key = 'schema_version'")
    with pytest.raises(SchemaVersionError, match="no recorded schema version"):
        EventStore.open(tmp_path).close()


@pytest.mark.security
def test_a_failure_before_the_version_row_leaves_no_half_created_store(tmp_path: Path) -> None:
    """The "one transaction" the test above relies on, made true and pinned.

    ``executescript`` commits any pending transaction and then runs its script
    in autocommit mode. Measured on the parent commit: ``in_transaction`` was
    False after it and a second connection saw all three tables before the
    version row existed, so a failure between the two statements left a store
    the next open refused as "the version row was removed" — fail-closed, but
    a misdiagnosis, and one an operator can clear only by deleting the file.
    With the DDL opened by an explicit ``BEGIN`` inside the script, a failure
    rolls the tables back with the row that never landed.
    """
    from store import SCHEMA_VERSION

    real = sqlite3.connect(tmp_path / "fresh.sqlite3")
    try:
        with pytest.raises(RuntimeError, match="simulated"):
            EventStore._apply_schema(_FailBeforeVersionRow(real))  # type: ignore[arg-type]
        assert real.in_transaction is False
        tables = real.execute("SELECT count(*) FROM sqlite_master WHERE type = 'table'").fetchone()
        assert tables[0] == 0, f"{tables[0]} table(s) survived a failed creation"
        # And the same connection creates the store cleanly afterwards.
        EventStore._apply_schema(real)
        row = real.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        assert row is not None and row[0] == str(SCHEMA_VERSION)
    finally:
        real.close()


class _FailBeforeVersionRow:
    """A connection proxy that fails the version-row INSERT and nothing else.

    Dunders are delegated by name because ``with conn:`` and attribute lookup
    through ``__getattr__`` are different protocols.
    """

    def __init__(self, real: sqlite3.Connection) -> None:
        self._real = real

    def execute(self, sql: str, *args: Any) -> Any:
        if sql.lstrip().upper().startswith("INSERT INTO META"):
            raise RuntimeError("simulated crash before the version row")
        return self._real.execute(sql, *args)

    def __enter__(self) -> Any:
        return self._real.__enter__()

    def __exit__(self, *exc: Any) -> Any:
        return self._real.__exit__(*exc)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


@pytest.mark.security
def test_a_projection_that_is_not_json_is_refused(tmp_path: Path) -> None:
    """Hash-consistent but undecodable: a row only a direct edit could produce."""
    forged = "this is not json"
    with EventStore.open(tmp_path) as store:
        with store._conn:
            store._conn.execute(
                "INSERT INTO events (event_id, ingested_at, occurred_at, source_type, "
                "vendor, parse_status, user_name, hostname, src_ip, dst_ip, projection) "
                "VALUES (?, ?, NULL, 'unknown', 'forged', 'text', NULL, NULL, NULL, NULL, ?)",
                (event_id(forged), 1.0, forged),
            )
        with pytest.raises(StoreIntegrityError, match="does not decode as JSON"):
            store.query()


@pytest.mark.security
def test_a_symlinked_database_file_cannot_relocate_the_store(tmp_path: Path) -> None:
    """The file-level twin of the directory case, checked for the same reason."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    decoy = elsewhere / "real.sqlite3"
    decoy.touch()
    events = tmp_path / "data" / "events"
    events.mkdir(parents=True)
    (events / "events.sqlite3").symlink_to(decoy)
    with pytest.raises(StorePathError, match="is a symlink"):
        EventStore.open(tmp_path).close()


# --------------------------------------------------------------------------
# Ingestion order is a control, not a contract on callers
# --------------------------------------------------------------------------


@pytest.mark.security
def test_a_write_behind_the_high_water_mark_is_refused(tmp_path: Path) -> None:
    """Stage 4 documented this as a collector's responsibility; that was not enough.

    The pipeline pages by a ``(ingested_at, event_id)`` keyset, so an event
    stamped earlier than one already stored sits behind a cursor that has
    already passed it — never read, by any cycle, ever. Silent data loss in the
    layer whose purpose is not having blind spots, which is why it is refused at
    write time rather than left to whoever writes next.
    """
    from store import IngestionOrderError

    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD),), ingested_at=200.0)
        before = store.count()
        with pytest.raises(IngestionOrderError, match="behind the high-water mark"):
            store.append_many((normalize(_OTHER_RECORD),), ingested_at=150.0)
        assert store.count() == before, "a refused batch still wrote rows"


@pytest.mark.security
def test_the_high_water_mark_survives_retention(tmp_path: Path) -> None:
    """Which is the whole reason it is stored rather than derived from MAX().

    A derived watermark resets the moment a window ages out, and a collector
    could then stamp an event behind a cursor that had already passed it. The
    mark lives in the existing ``meta`` table — a new *row*, so the DDL is
    unchanged and no ``SCHEMA_VERSION`` bump is provoked.
    """
    from store import IngestionOrderError

    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD),), ingested_at=200.0)
        assert store.prune(before=1_000.0) == 1
        assert store.count() == 0
        assert store.high_water_mark() == 200.0
        with pytest.raises(IngestionOrderError):
            store.append_many((normalize(_OTHER_RECORD),), ingested_at=100.0)


@pytest.mark.security
def test_an_existing_store_written_before_this_control_is_not_defenceless(
    tmp_path: Path,
) -> None:
    """The population that matters most: a database already in service.

    ``SCHEMA_VERSION`` is deliberately unchanged, so every store written by
    stages 1-4 opens with rows and no ``meta`` entry. Returning ``None`` there
    left the control inert exactly where there was already history to get
    behind — the first write after the upgrade could land under its own rows
    and sit behind a cursor that had passed it. Found by review and reproduced
    before the fix.

    Simulated by deleting the meta row from a store that has rows, which is
    byte-for-byte the state an upgraded database is in.
    """
    import sqlite3

    from store import IngestionOrderError

    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD),), ingested_at=1_000.0)
        database = store.path

    connection = sqlite3.connect(database)
    with connection:
        connection.execute("DELETE FROM meta WHERE key = ?", (HIGH_WATER_KEY,))
    connection.close()

    with EventStore.open(tmp_path) as store:
        assert store.high_water_mark() == 1_000.0, "the mark was not derived from the rows"
        assert store.next_stamp(500.0) > 1_000.0
        with pytest.raises(IngestionOrderError):
            store.append_many((normalize(_OTHER_RECORD),), ingested_at=500.0)


@pytest.mark.security
def test_the_stored_mark_wins_over_the_derived_one(tmp_path: Path) -> None:
    """The fallback is for a missing row, never a preference.

    Checking the rows first would let the mark move *backwards* whenever the
    newest rows go away while the stored row remains — and a mark that moves
    backwards re-opens exactly the window it exists to close, because the
    pipeline's cursor has already passed the value it used to hold.

    Reached here by deleting the newest row directly, because
    :meth:`EventStore.prune` is keyed on ``ingested_at`` and so only ever
    removes a *prefix*: under pruning alone ``MAX(ingested_at)`` either equals
    the mark or the table is empty, and both orderings agree. A test built on
    ``prune`` therefore cannot fail, which is how the first version of this one
    was written. The deletion below is not hypothetical — the store is a plain
    SQLite file, and an operator clearing a bad batch or a restore from an
    older snapshot produces precisely this state.
    """
    import sqlite3

    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD),), ingested_at=2_000.0)
        store.append_many((normalize(_OTHER_RECORD),), ingested_at=3_000.0)
        database = store.path

    connection = sqlite3.connect(database)
    with connection:
        connection.execute("DELETE FROM events WHERE ingested_at >= ?", (3_000.0,))
        rows = connection.execute("SELECT MAX(ingested_at) AS mark FROM events").fetchone()
    connection.close()
    assert rows[0] == 2_000.0, "the fixture no longer leaves the rows behind the stored mark"

    with EventStore.open(tmp_path) as store:
        assert store.high_water_mark() == 3_000.0, (
            "the mark regressed to the rows' maximum; an event re-stamped at 2000 would "
            "sit behind a cursor that has already passed 3000"
        )


def _plant_mark(store: EventStore, value: object) -> None:
    """Overwrite the stored high-water mark, as anything holding the file can.

    ``meta`` carries no append-only trigger: the mark has to move on every
    write, so the store's own control over it is what it accepts on read.
    """
    with store._conn:
        store._conn.execute("UPDATE meta SET value = ? WHERE key = ?", (value, HIGH_WATER_KEY))


#: Stored marks no write path produces, as SQLite keeps them in a TEXT column,
#: with the reader's exception for each. ``_advance_high_water`` writes
#: ``repr(float)`` of a stamp ``_require_monotonic`` has already checked.
_CORRUPT_MARKS: dict[str, tuple[str | bytes, type[Exception]]] = {
    # Raised a bare ValueError from float(), so `sli` read "the probe raised".
    "text": ("PLANTED-MARK", ValueError),
    # Each read back silently. NaN compares false against every stamp, so an
    # append behind every stored row went through and rewrote the mark lower;
    # an infinity refused every later append as out of order.
    "nan": ("nan", ValueError),
    "positive_infinity": ("inf", ValueError),
    "negative_infinity": ("-inf", ValueError),
    "overflowing_text": ("1e400", ValueError),
    # TEXT affinity leaves a BLOB a BLOB, and float() parses bytes.
    "blob": (b"PLANTED-MARK", TypeError),
    "numeric_blob": (b"1.5", TypeError),
}


@pytest.mark.security
@pytest.mark.parametrize("case", sorted(_CORRUPT_MARKS), ids=lambda value: value)
def test_a_corrupt_stored_high_water_mark_is_a_store_integrity_error(
    tmp_path: Path, case: str
) -> None:
    """A mark that is not a finite number is refused by every route that reads it.

    The ``nan`` case is the one that matters most and the one the original
    report did not name: before this, ``append(ingested_at=500.0)`` under a
    stored ``nan`` succeeded behind a row stamped 1000, which is the silent
    blind spot the ordering control exists to refuse, and then rewrote the mark
    to 500. So the refused append is asserted to write nothing, mark included.
    The planted text must not reach the message: a forged row chooses it.
    """
    value, cause = _CORRUPT_MARKS[case]
    with EventStore.open(tmp_path) as store:
        store.append(normalize(_RECORD), ingested_at=1_000.0)
        _plant_mark(store, value)
        held = store.count()
        routes: dict[str, Callable[[], object]] = {
            "high_water_mark": store.high_water_mark,
            "next_stamp": lambda: store.next_stamp(2_000.0),
            "append": lambda: store.append(normalize(_OTHER_RECORD), ingested_at=500.0),
            "attest": store.attest,
        }
        for route, call in routes.items():
            with pytest.raises(StoreIntegrityError) as raised:
                call()
            assert not isinstance(raised.value, StoreCorruptionError), (
                f"{route}: a row, not a damaged file"
            )
            assert isinstance(raised.value.__cause__, cause), route
            message = str(raised.value)
            assert "high-water mark" in message, route
            assert "PLANTED" not in message, f"{route} echoed the stored text"
            assert "PLANTED" not in str(raised.value.__cause__), f"{route}'s cause echoed it"
        assert store.count() == held, "a refused append still wrote a row"
        stored = store._conn.execute(
            "SELECT value FROM meta WHERE key = ?", (HIGH_WATER_KEY,)
        ).fetchone()
        assert stored["value"] == value, "a refused append rewrote the mark"


@pytest.mark.security
@pytest.mark.parametrize("spelling", ["1000.0", "1000", "1e3", 1000])
def test_a_stored_mark_in_any_finite_numeric_spelling_still_reads(
    tmp_path: Path, spelling: object
) -> None:
    """The control, or every refusal above is satisfied by refusing every mark.

    ``1000.0`` is what the writer produces. An integer is what TEXT affinity
    makes of ``UPDATE meta SET value = 1000``, and is planted as one so that
    conversion is exercised rather than assumed. The ordering control must
    still hold against the parsed value, or "it reads" is true of a mark that
    no longer guards anything.
    """
    from store import IngestionOrderError

    with EventStore.open(tmp_path) as store:
        store.append(normalize(_RECORD), ingested_at=1_000.0)
        _plant_mark(store, spelling)
        assert store.high_water_mark() == 1_000.0
        with pytest.raises(IngestionOrderError):
            store.append(normalize(_OTHER_RECORD), ingested_at=500.0)


#: ``ingested_at`` values a store with no stored mark derives one from. The
#: same shapes #268 refuses in ``_rebuild``, reached here through ``MAX()``.
_CORRUPT_NEWEST_STAMPS: dict[str, tuple[str | bytes | float, type[Exception]]] = {
    "text": ("PLANTED-STAMP", TypeError),
    "blob": (b"PLANTED-STAMP", TypeError),
    "numeric_blob": (b"1.5", TypeError),
    "positive_infinity": (math.inf, ValueError),
}


@pytest.mark.security
@pytest.mark.parametrize("case", sorted(_CORRUPT_NEWEST_STAMPS), ids=lambda value: value)
def test_a_corrupt_derived_high_water_mark_is_a_store_integrity_error(
    tmp_path: Path, case: str
) -> None:
    """The fallback for a store with rows and no stored mark — an upgraded one.

    SQLite sorts TEXT and BLOB above every REAL, so one corrupt ``ingested_at``
    is the ``MAX`` however many good rows sit beside it; the good row below is
    there to show that. Before this, text raised a bare ``ValueError``, while a
    numeric BLOB read back silently as ``1.5`` (an append behind the good row
    then succeeded) and ``+inf`` refused every later append as out of order.
    """
    value, cause = _CORRUPT_NEWEST_STAMPS[case]
    with EventStore.open(tmp_path) as store:
        _plant(store, canonical_json(normalize(_RECORD).to_dict()), ingested_at=1_000.0)
        _plant(store, canonical_json(normalize(_OTHER_RECORD).to_dict()), ingested_at=value)
        assert (
            store._conn.execute(
                "SELECT value FROM meta WHERE key = ?", (HIGH_WATER_KEY,)
            ).fetchone()
            is None
        ), "the fixture stored a mark, so the fallback is not what is under test"
        held = store.count()
        third = normalize("sshd: session opened for user root")
        for route, call in (
            ("high_water_mark", store.high_water_mark),
            ("append", lambda: store.append(third, ingested_at=500.0)),
        ):
            with pytest.raises(StoreIntegrityError) as raised:
                call()
            assert isinstance(raised.value.__cause__, cause), route
            message = str(raised.value)
            assert "no high-water mark is stored" in message, route
            assert "PLANTED" not in message, f"{route} echoed the stored text"
        assert store.count() == held, "a refused append still wrote a row"


@pytest.mark.security
def test_a_stored_mark_below_the_rows_is_a_store_integrity_error(tmp_path: Path) -> None:
    """A finite mark can be forged too, and below the rows it re-opens the window.

    Measured before: ``meta`` set to ``'1.0'`` over rows at 1000 to 1002 let
    ``append(ingested_at=5.0)`` succeed behind all three and moved the mark to
    5.0. The refusals above all concern a mark that is not a number; this one
    is a number no write path leaves, because every write raises the mark with
    its rows under one write lock. Above the rows stays legitimate, which
    ``test_the_stored_mark_wins_over_the_derived_one`` pins.
    """
    with EventStore.open(tmp_path) as store:
        for index, record in enumerate((_RECORD, _OTHER_RECORD)):
            store.append(normalize(record), ingested_at=1_000.0 + index)
        _plant_mark(store, "1.0")
        held = store.count()
        routes: dict[str, Callable[[], object]] = {
            "high_water_mark": store.high_water_mark,
            "next_stamp": lambda: store.next_stamp(2_000.0),
            "append": lambda: store.append(
                normalize("sshd: session opened for user root"), ingested_at=5.0
            ),
            "attest": store.attest,
        }
        for route, call in routes.items():
            with pytest.raises(StoreIntegrityError, match="below the newest stored") as raised:
                call()
            assert not isinstance(raised.value, StoreCorruptionError), route
        assert store.count() == held, "a refused append still wrote a row"
        stored = store._conn.execute(
            "SELECT value FROM meta WHERE key = ?", (HIGH_WATER_KEY,)
        ).fetchone()
        assert stored["value"] == "1.0", "a refused append rewrote the mark"
        # Equal to the newest row is the ordinary state after any write.
        _plant_mark(store, "1001.0")
        assert store.high_water_mark() == 1_001.0


@pytest.mark.security
def test_a_corrupt_newest_stamp_is_refused_under_a_valid_stored_mark(tmp_path: Path) -> None:
    """The ``MAX`` the invariant reads is converted the way the fallback's is.

    TEXT sorts above every REAL, so one planted row is the ``MAX`` whatever
    the stored mark says, and comparing a float with it would raise a bare
    ``TypeError``.
    """
    with EventStore.open(tmp_path) as store:
        store.append(normalize(_RECORD), ingested_at=1_000.0)
        _plant(store, canonical_json(normalize(_OTHER_RECORD).to_dict()), ingested_at="PLANTED")
        with pytest.raises(StoreIntegrityError) as raised:
            store.high_water_mark()
    assert isinstance(raised.value.__cause__, TypeError)
    assert "no high-water mark is stored" not in str(raised.value), "a mark is stored"
    assert "PLANTED" not in str(raised.value)


@pytest.mark.security
@pytest.mark.parametrize("method", ["append", "append_many"])
def test_a_second_writer_cannot_interleave_between_the_mark_check_and_the_insert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    """The ordering check and the insert are one decision, so they share one lock.

    Measured before: the connection's default transaction handling opens a
    transaction before an ``INSERT`` and never before a ``SELECT``, so the
    mark was read outside the transaction its insert then opened. A second
    writer committing at 200 between the first writer's check at 150 and its
    insert left a row at 150 behind a stored row at 200, regressed the mark to
    150, and ``append_many`` reported the other writer's row as its own. Driven
    deterministically from inside the first writer's check. The second writer's
    busy timeout is zero so contention is immediate rather than five seconds.
    """
    with EventStore.open(tmp_path) as seed:
        seed.append(normalize(_RECORD), ingested_at=100.0)
    first, second = EventStore.open(tmp_path), EventStore.open(tmp_path)
    second._conn.execute("PRAGMA busy_timeout = 0")
    original = EventStore._require_monotonic
    interleaved: list[BaseException | None] = []

    def check_then_interleave(self: EventStore, stamp: float) -> None:
        original(self, stamp)
        if self is first and not interleaved:
            try:
                second.append(normalize(_OTHER_RECORD), ingested_at=200.0)
                interleaved.append(None)
            except sqlite3.OperationalError as exc:
                interleaved.append(exc)

    monkeypatch.setattr(EventStore, "_require_monotonic", check_then_interleave)
    third = normalize("sshd: session opened for user root")
    try:
        if method == "append":
            first.append(third, ingested_at=150.0)
        else:
            assert first.append_many((third,), ingested_at=150.0) == 1, (
                "append_many counted another writer's row as its own"
            )
        (outcome,) = interleaved
        assert isinstance(outcome, sqlite3.OperationalError), (
            "the second writer committed between the first writer's check and its insert"
        )
        assert outcome.sqlite_errorname == "SQLITE_BUSY"
        mark = first.high_water_mark()
        newest = first._conn.execute("SELECT MAX(ingested_at) AS m FROM events").fetchone()["m"]
        assert mark == newest == 150.0
    finally:
        first.close()
        second.close()


@pytest.mark.security
def test_append_many_counts_only_the_rows_it_wrote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The new-row count is taken inside the write lock, not before it.

    The interleaving above is now refused, but a second writer may still
    commit just before the first takes its lock, which is ordinary contention.
    ``append_many`` counted the store before its transaction, so that commit
    landed between its two counts: measured, a batch of one new event reported
    2 when the count sat outside the lock.
    """
    with EventStore.open(tmp_path) as seed:
        seed.append(normalize(_RECORD), ingested_at=100.0)
    first, second = EventStore.open(tmp_path), EventStore.open(tmp_path)
    original = EventStore._begin_write

    def let_the_other_writer_in_first(self: EventStore) -> None:
        if self is first:
            second.append(normalize(_OTHER_RECORD), ingested_at=200.0)
        original(self)

    monkeypatch.setattr(EventStore, "_begin_write", let_the_other_writer_in_first)
    try:
        added = first.append_many(
            (normalize("sshd: session opened for user root"),), ingested_at=300.0
        )
        assert first.count() == 3, "the fixture did not put both writers' rows in"
        assert added == 1, f"append_many reported {added} new rows for a batch of one"
    finally:
        first.close()
        second.close()


@pytest.mark.security
def test_a_commit_between_the_mark_and_the_rows_is_not_read_as_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mark and ``MAX(ingested_at)`` come from one snapshot.

    The invariant above compares two values, and the first version read them
    with two autocommit ``SELECT``s, each with its own snapshot. A collector
    committing between them gave a reader the old mark beside the new ``MAX``,
    and a healthy store raised "modified outside this platform". Found by
    review, reproduced by committing at 200 from inside the parse of a mark
    of 100. That is an ordinary path: ``sli``, retention and the backup
    verifier all read while the collector writes. The reader must return its
    snapshot's mark, and the next read the new one.
    """
    import store.events as events_module

    with EventStore.open(tmp_path) as seed:
        seed.append(normalize(_RECORD), ingested_at=100.0)
    reader, writer = EventStore.open(tmp_path), EventStore.open(tmp_path)
    original = events_module._stored_mark
    committed: list[bool] = []

    def commit_while_parsing(value: object) -> float:
        # Flagged before the append, whose own mark read comes back through here.
        if not committed:
            committed.append(True)
            writer.append(normalize(_OTHER_RECORD), ingested_at=200.0)
        return original(value)

    monkeypatch.setattr(events_module, "_stored_mark", commit_while_parsing)
    try:
        assert reader.high_water_mark() == 100.0
        assert committed, "the fixture never committed in between"
        assert reader.high_water_mark() == 200.0
    finally:
        reader.close()
        writer.close()


@pytest.mark.security
def test_an_equal_timestamp_is_accepted(tmp_path: Path) -> None:
    """Batches share one ``ingested_at`` by design, so equality must pass.

    Refusing it would break ``append_many``'s own batching, and the composite
    cursor exists precisely because ties are the normal case.
    """
    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD),), ingested_at=200.0)
        store.append_many((normalize(_OTHER_RECORD),), ingested_at=200.0)
        assert store.count() == 2


@pytest.mark.security
def test_an_empty_batch_is_not_order_checked(tmp_path: Path) -> None:
    """It writes nothing, so there is nothing to place out of order."""
    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD),), ingested_at=200.0)
        assert store.append_many((), ingested_at=1.0) == 0


@pytest.mark.security
def test_the_mark_does_not_break_the_stores_idempotence(tmp_path: Path) -> None:
    """Content idempotence and ingestion order are different promises.

    Re-appending identical content at the *current* time is a no-op that stores
    nothing new — the honest form of a replay, since it is being ingested now
    rather than then.
    """
    with EventStore.open(tmp_path) as store:
        assert store.append_many((normalize(_RECORD),), ingested_at=200.0) == 1
        assert store.append_many((normalize(_RECORD),), ingested_at=300.0) == 0
        assert store.count() == 1


@pytest.mark.security
def test_the_schema_version_is_unchanged_by_the_watermark(tmp_path: Path) -> None:
    """A new ``meta`` row must not look like a new schema to an older build.

    ``SchemaVersionError`` refuses a differing version, so storing the mark as a
    column would have forced a migration on every existing store.
    """
    from store.schema import SCHEMA_VERSION

    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD),), ingested_at=200.0)
    # Re-opening is what would raise if the version had moved.
    with EventStore.open(tmp_path) as reopened:
        assert reopened.high_water_mark() == 200.0
    assert SCHEMA_VERSION == 1


@pytest.mark.security
def test_append_is_order_checked_too_not_only_append_many(tmp_path: Path) -> None:
    """The monotonicity tests covered only the batch path.

    Both of ``append``'s high-water-mark calls could be deleted with the suite
    green — found by review. ``append`` is public API, so a caller using it
    must hit the same control.
    """
    from store import IngestionOrderError

    with EventStore.open(tmp_path) as store:
        store.append(normalize(_RECORD), ingested_at=200.0)
        assert store.high_water_mark() == 200.0, "append did not advance the mark"
        before = store.count()
        with pytest.raises(IngestionOrderError):
            store.append(normalize(_OTHER_RECORD), ingested_at=100.0)
        assert store.count() == before


@pytest.mark.security
@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_a_non_finite_ingestion_time_is_refused(tmp_path: Path, bad: float) -> None:
    """NaN would disable the control rather than violate it.

    It compares false against every bound, so it slips past the ordering check
    and then poisons the mark for every later write; an infinity raises the
    mark beyond anything a clock can reach, wedging the store permanently.
    Found by review.
    """
    from store import IngestionOrderError

    with EventStore.open(tmp_path) as store:
        with pytest.raises(IngestionOrderError, match="finite"):
            store.append_many((normalize(_RECORD),), ingested_at=bad)
        assert store.count() == 0
        assert store.high_water_mark() is None, "a refused write moved the mark"


@pytest.mark.security
@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_a_non_finite_retention_threshold_is_refused_by_the_delete_too(
    tmp_path: Path, bad: float
) -> None:
    """``count_before`` refused a non-finite threshold; ``prune`` did not.

    Measured on the parent commit with three stored events:
    ``prune(before=inf)`` deleted all three and ``prune(before=nan)`` deleted
    none, both silently, after ``count_before`` had raised for the same value.
    Retention is report-then-apply, so a threshold the report refuses must be
    refused by the delete it would have authorised — the write-side twin of a
    read-side bound, which is the defect class ``_project`` already records.
    """
    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD), normalize(_OTHER_RECORD)), ingested_at=1_000.0)
        held = store.count()
        assert held > 0, "the fixture stored nothing"
        with pytest.raises(ValueError, match="finite"):
            store.count_before(before=bad)
        with pytest.raises(ValueError, match="finite"):
            store.prune(before=bad)
        assert store.count() == held, "a refused prune removed rows"


class _StatefulFloat:
    """``__float__`` answers ``first`` once, then ``then`` on every later call.

    The shape that defeats a check-then-convert pair: ``math.isfinite(x)`` and
    ``float(x)`` each convert ``x`` afresh, so one object can be finite for the
    check and infinite for the statement.
    """

    def __init__(self, first: float, then: float) -> None:
        self.first = first
        self.then = then
        self.calls = 0

    def __float__(self) -> float:
        self.calls += 1
        return self.first if self.calls == 1 else self.then


@pytest.mark.security
@pytest.mark.parametrize("then", [float("inf"), float("-inf"), float("nan")])
def test_a_retention_threshold_is_converted_once_and_the_checked_value_is_bound(
    tmp_path: Path, then: float
) -> None:
    """The value that passed the finiteness check must be the value the SQL binds.

    Measured on the parent commit with three stored events: ``prune`` ran
    ``math.isfinite(before)`` and then ``float(before)`` as two separate
    conversions, so an object answering ``1.0`` first and ``inf`` second passed
    the check and the DELETE removed all three rows; ``count_before`` had the
    same shape, and its keyset bound converted three times. Not reachable from
    ``scripts/run_retention.py``, which passes argparse floats — but the store
    is the boundary that outlives any one caller, and the test above pins that
    report and apply refuse the same inputs, which held only for stateless
    values. Found by review.

    The oracle is the plain float the object first answers: every result must
    equal that float's, and the object must have been converted exactly once.
    Two events at 100 and 300 with a first answer of 200 make each
    parametrization discriminate in both directions — ``inf`` would count or
    delete both, ``-inf`` and ``nan`` neither.
    """
    first = 200.0
    with EventStore.open(tmp_path) as store:
        store.append(normalize(_RECORD), ingested_at=100.0)
        store.append(normalize(_OTHER_RECORD), ingested_at=300.0)
        assert store.count() == 2, "the fixture stored fewer than two events"
        assert store.count_before(before=first) == 1
        assert store.count_before(before=2e9, after=(first, "")) == 1

        value = _StatefulFloat(first, then)
        assert store.count_before(before=value) == 1, (  # type: ignore[arg-type]
            "count_before bound a later answer"
        )
        assert value.calls == 1, f"count_before converted the threshold {value.calls} times"

        value = _StatefulFloat(first, then)
        assert store.count_before(before=2e9, after=(value, "")) == 1, (  # type: ignore[arg-type]
            "the keyset bound bound a later answer"
        )
        assert value.calls == 1, f"count_before converted the keyset bound {value.calls} times"

        value = _StatefulFloat(first, then)
        assert store.prune(before=value) == 1, "prune bound a later answer"  # type: ignore[arg-type]
        assert value.calls == 1, f"prune converted the threshold {value.calls} times"
        assert store.count() == 1, "prune deleted other than what the checked value selects"


@pytest.mark.security
@pytest.mark.parametrize("text", ["2000000000", b"2000000000"])
def test_a_textual_retention_threshold_is_still_refused(tmp_path: Path, text: object) -> None:
    """Folding the conversion into one must not start parsing text as a number.

    ``float()`` parses ``str`` and ``bytes``; ``math.isfinite()`` refuses them,
    and so did both methods before the fold — measured on the parent commit,
    ``TypeError`` from each with the rows untouched. Pinned so the fix cannot
    quietly widen the accepted domain while closing the double conversion.
    """
    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD), normalize(_OTHER_RECORD)), ingested_at=1_000.0)
        held = store.count()
        with pytest.raises(TypeError, match="real number"):
            store.count_before(before=text)  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="real number"):
            store.prune(before=text)  # type: ignore[arg-type]
        assert store.count() == held, "a refused prune removed rows"


#: Each time bound ``Query`` carries, built around one value. The keyset pairs
#: take an empty ``event_id`` because only the timestamp is under test.
_QUERY_BOUNDS: dict[str, Callable[[Any], Query]] = {
    "since": lambda at: Query(since=at),
    "until": lambda at: Query(until=at),
    "ingested_from": lambda at: Query(ingested_from=at),
    "ingested_after": lambda at: Query(ingested_after=(at, "")),
    "ingested_before": lambda at: Query(ingested_before=(at, "")),
}

#: A finite value per bound that every event in ``_bounded_store`` satisfies,
#: so the control below proves the refusals are not "refuse every bound".
_INCLUSIVE: dict[str, float] = {
    "since": 0.0,
    "until": 4e9,
    "ingested_from": 0.0,
    "ingested_after": 0.0,
    "ingested_before": 4e9,
}


def _bounded_store(store: EventStore) -> int:
    """Two events with source timestamps, since ``since``/``until`` skip undated ones."""
    store.append(_hand_built(message="a", timestamp=1_760_000_000.0), ingested_at=100.0)
    store.append(_hand_built(message="b", timestamp=1_760_000_100.0), ingested_at=300.0)
    return store.count()


@pytest.mark.security
@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf], ids=["nan", "inf", "-inf"])
@pytest.mark.parametrize("bound", sorted(_QUERY_BOUNDS))
def test_a_non_finite_query_bound_is_refused(tmp_path: Path, bound: str, bad: float) -> None:
    """A bad window is a caller error, not a quiet period.

    Measured on five stored events before this: NaN in any of the five bounds
    returned **0** rows with no error, because SQLite binds NaN as NULL and a
    comparison with NULL matches nothing; so did an infinity on the closed side
    (``since=inf``, ``until=-inf``, ``ingested_from=inf``, ``ingested_after``
    at ``inf``, ``ingested_before`` at ``-inf``). An infinity on the open side
    returned all five, which an unset field already says, so all three are
    refused alike — the rule ``prune`` and ``count_before`` already follow.
    """
    with EventStore.open(tmp_path) as store:
        assert _bounded_store(store) == 2
        with pytest.raises(ValueError, match=f"{bound} must be finite"):
            store.query(_QUERY_BOUNDS[bound](bad))
        # An empty limit returns `()` without a query, and used to do so before
        # any bound was checked, so a bad window under it read as a quiet period.
        empty = dataclasses.replace(_QUERY_BOUNDS[bound](bad), limit=0)
        with pytest.raises(ValueError, match=f"{bound} must be finite"):
            store.query(empty)


@pytest.mark.security
@pytest.mark.parametrize("text", ["5", b"5"])
@pytest.mark.parametrize("bound", sorted(_QUERY_BOUNDS))
def test_a_textual_query_bound_is_refused(tmp_path: Path, bound: str, text: object) -> None:
    """``float()`` parsed text, so ``since="5"`` was read as ``5.0`` and matched.

    The fields are annotated ``float``, which a type checker enforces on
    first-party code and nothing enforces at runtime, where a value built from
    configuration or JSON arrives.
    """
    with EventStore.open(tmp_path) as store:
        assert _bounded_store(store) == 2
        with pytest.raises(TypeError, match=f"{bound} must be a real number"):
            store.query(_QUERY_BOUNDS[bound](text))
        empty = dataclasses.replace(_QUERY_BOUNDS[bound](text), limit=0)
        with pytest.raises(TypeError, match=f"{bound} must be a real number"):
            store.query(empty)


@pytest.mark.security
@pytest.mark.parametrize("bound", sorted(_QUERY_BOUNDS))
def test_a_finite_query_bound_still_selects(tmp_path: Path, bound: str) -> None:
    """The control: every bound still accepts a finite value, an integer included."""
    with EventStore.open(tmp_path) as store:
        held = _bounded_store(store)
        assert len(store.query(_QUERY_BOUNDS[bound](_INCLUSIVE[bound]))) == held
        assert len(store.query(_QUERY_BOUNDS[bound](int(_INCLUSIVE[bound])))) == held


@pytest.mark.security
@pytest.mark.parametrize(
    ("bound", "first", "then"),
    [("ingested_after", 200.0, 100.0), ("ingested_before", 200.0, 300.0)],
)
def test_a_keyset_bound_is_converted_once_for_both_placeholders(
    tmp_path: Path, bound: str, first: float, then: float
) -> None:
    """A keyset pair binds its timestamp twice, and both must be the checked value.

    ``query`` used to bind ``float(at), float(at)``, two conversions, so one
    object could put different values in the strict comparison and in the
    equality tie-break. ``then`` is a stamp a stored row holds, which is what
    makes a wrong second answer select an extra row: the tie-break's
    ``event_id`` bound (``""`` after, ``"g"`` before) admits any hex id. The
    oracle is the plain float the object first answers.
    """
    edge = "" if bound == "ingested_after" else "g"
    with EventStore.open(tmp_path) as store:
        store.append(normalize(_RECORD), ingested_at=100.0)
        store.append(normalize(_OTHER_RECORD), ingested_at=300.0)
        build = {
            "ingested_after": lambda at: Query(ingested_after=(at, edge)),
            "ingested_before": lambda at: Query(ingested_before=(at, edge)),
        }[bound]
        expected = len(store.query(build(first)))
        assert expected == 1, "the fixture does not split at the first answer"
        value = _StatefulFloat(first, then)
        assert len(store.query(build(value))) == expected, "a later answer was bound"
        assert value.calls == 1, f"{bound} was converted {value.calls} times"


@pytest.mark.security
def test_next_stamp_is_strictly_after_the_mark(tmp_path: Path) -> None:
    """Equality is permitted for batching, and that is what the hazard needs.

    The pipeline's keyset is strictly after ``(ingested_at, event_id)``, so an
    event written at exactly the mark with a lower event_id sits behind a
    cursor that has already passed it. A caller clamping with
    ``max(now, mark)`` walks into that on any backwards clock step — four
    events stored, three ever read. The store hands out the safe stamp because
    the mark and the cursor contract are both its own.
    """
    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD),), ingested_at=1_000.0)
        mark = store.high_water_mark()
        assert mark is not None
        assert store.next_stamp(mark - 60.0) > mark, "a behind clock stamped at or below"
        assert store.next_stamp(mark) > mark, "an equal clock stamped at the mark"
        assert store.next_stamp(mark + 60.0) == mark + 60.0, "an ahead clock was altered"
    with pytest.raises(ValueError, match="finite"), EventStore.open(tmp_path) as store:
        store.next_stamp(float("nan"))


@pytest.mark.security
def test_events_written_at_the_safe_stamp_are_all_reachable(tmp_path: Path) -> None:
    """End to end, because the defect lived in the interaction and not in a layer.

    Reproduced before the fix: four events accepted by the store, three ever
    read by the pipeline.
    """
    from pipeline import run_cycle

    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_RECORD), normalize(_OTHER_RECORD)), ingested_at=1_000.0)
        first = run_cycle(store, lookback=0)
        stamp = store.next_stamp(first.cursor.ingested_at - 60.0)  # type: ignore[union-attr]
        store.append_many(
            (normalize("sshd: third record"), normalize("sshd: fourth record")),
            ingested_at=stamp,
        )
        second = run_cycle(store, cursor=first.cursor, lookback=0)
        assert first.events_read + second.events_read == store.count(), (
            "the store accepted events the cursor can never reach"
        )


# ------------------------------------------- the attestation reads a table page


def _s3_record(index: int) -> str:
    """One realistic cloud record, distinct from every other, as JSON text.

    Distinct because ``event_id`` is content-addressed: 200 copies of one line
    store as **one** event, which is a fixture bug this repository has already
    paid for once.
    """
    return json.dumps(
        {
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "eventTime": f"2026-10-15T09:00:{index % 60:02d}Z",
            "sourceIPAddress": f"10.0.{index // 256 % 256}.{index % 256}",
            "userIdentity": {"userName": f"svc-{index:05d}"},
        }
    )


@pytest.mark.security
def test_an_attestation_cannot_be_produced_over_rows_that_cannot_be_read(
    tmp_path: Path,
) -> None:
    """The completeness control used to sign off on a store that had lost every row.

    Every one of ``attest()``'s statements is a covering-index scan — the id
    stream, the counts, and the observables stream added for
    ``observables_digest`` — measured with ``EXPLAIN QUERY PLAN`` and pinned by
    ``test_every_attest_statement_is_a_covering_index_scan`` in
    ``tests/unit/test_event_store.py`` rather than only stated here (this
    sentence used to say "both", and nothing would have gone red when a third
    was added). So the digests and the counts prove the
    *indexes* agree and say nothing about whether a row body is readable.
    Zeroing a 400-event store's 134 table leaf pages while leaving every index
    page intact produced a bit-identical digest and count while ``query()``
    raised ``database disk image is malformed``.

    The damaged page is **found by measurement, not by asking SQLite which
    pages are table pages**. ``dbstat`` is a compile-time option, and a
    security test that skips where the option is absent proves nothing in the
    environment that matters. So every page is zeroed in turn and the ones
    whose loss breaks a row read are discovered — which is also the property
    itself, stated directly: there must exist no page whose loss the
    attestation cannot see.

    The refusal must be a :class:`StoreIntegrityError` specifically, and that
    is not pedantry — it is the second half of the fix. ``PRAGMA quick_check``
    *raises* ``database disk image is malformed`` for some losses and
    *reports* a verdict string for others, measured both ways on this same
    construction, so the first version of the gate let a raw ``sqlite3``
    error out of ``attest()``. Every caller in this repository catches
    ``StoreError``; a ``sqlite3.DatabaseError`` sails past all of them and
    reaches the operator as a traceback. Asserting the exception *type* is
    what made the "run the pragma, ignore its verdict" plant fail — it had
    survived a version of this test that accepted any exception.

    Non-vacuity is asserted twice, because each has been how a test like this
    measured nothing: the sweep must find at least one page whose loss breaks
    a row read (or the loop below is empty and passes), and the pristine store
    must attest cleanly (or "refuses" is indistinguishable from "always
    refuses").
    """
    root = tmp_path / "lab"
    root.mkdir(parents=True)
    with EventStore.open(root) as store:
        store.append_many(
            tuple(normalize(_s3_record(index)) for index in range(200)),
            ingested_at=1_760_000_000.0,
        )
        intact = store.attest()
    assert intact.events == 200, f"the fixture stored {intact.events} of 200 events"

    database = root / "data" / "events" / "events.sqlite3"
    # Fold the WAL into the main file so a page index means something, and read
    # the page size from the database rather than assuming SQLite's default.
    folding = sqlite3.connect(database)
    try:
        folding.execute("PRAGMA journal_mode=DELETE")
        page_size = int(folding.execute("PRAGMA page_size").fetchone()[0])
    finally:
        folding.close()
    pristine = database.read_bytes()
    pages = len(pristine) // page_size
    assert pages > 1, "a single-page store cannot distinguish table from index"

    unreadable: list[int] = []
    wrong: dict[int, str] = {}
    # Page 1 holds the file header; zeroing it is a different failure (the file
    # stops being a database at all) and is covered by the aborted-copy test.
    for pageno in range(2, pages + 1):
        offset = (pageno - 1) * page_size
        database.write_bytes(pristine[:offset] + bytes(page_size) + pristine[offset + page_size :])
        try:
            with EventStore.open(root) as store:
                try:
                    store.query(Query(limit=5))
                except StoreIntegrityError:
                    # Tightened from `(StoreIntegrityError, sqlite3.Error)`.
                    # Accepting the raw driver error here is what let this test
                    # stay green while `query` leaked one, and would let a
                    # future contributor remove the mapping unnoticed.
                    unreadable.append(pageno)
                else:
                    continue
                try:
                    recovered = store.attest()
                except StoreIntegrityError:
                    continue
                except sqlite3.Error as exc:
                    wrong[pageno] = f"raw {type(exc).__name__}"
                    continue
                if (recovered.digest, recovered.events) == (intact.digest, intact.events):
                    wrong[pageno] = "the intact store's digest and count"
                else:
                    wrong[pageno] = f"a digest of its own ({recovered.events} event(s))"
        except (StoreIntegrityError, SchemaVersionError):
            # The store would not open at all, which is a loud failure and not
            # the silent one under test. `sqlite3.Error` was removed from this
            # tuple with the one above: `EventStore.open` used to leak a raw
            # driver error for the `meta` pages, and it must not again.
            continue
    database.write_bytes(pristine)

    assert unreadable, "the sweep found no page whose loss breaks a row read"
    assert not wrong, (
        f"{len(wrong)} of {len(unreadable)} page(s) whose loss makes the rows unreadable "
        "did not refuse with StoreIntegrityError: "
        + ", ".join(f"page {page} gave {why}" for page, why in sorted(wrong.items())[:6])
    )


#: Every public entry point that executes SQL, with a call that reaches it. The
#: fix is scoped to the surface rather than to one method, so the test is too:
#: measured before it, a raw ``sqlite3`` error escaped at least one of these
#: for **95 of 95** single-page losses, and a ``query``-only fix left six of
#: them leaking while the whole suite stayed green.
_SQL_ENTRY_POINTS: dict[str, Any] = {
    "query": lambda store: store.query(Query(limit=5)),
    "query(observable=)": lambda store: store.query(Query(limit=5, observable="10.0.0.1")),
    "count": lambda store: store.count(),
    "count_before": lambda store: store.count_before(before=2e9),
    "high_water_mark": lambda store: store.high_water_mark(),
    "next_stamp": lambda store: store.next_stamp(1.0),
    "attest": lambda store: store.attest(),
    "verify_integrity": lambda store: store.verify_integrity(),
    "append": lambda store: store.append(normalize(_s3_record(90_001)), ingested_at=1.8e9),
    "prune": lambda store: store.prune(before=2e9),
}


@pytest.mark.security
def test_no_public_entry_point_hands_a_caller_a_raw_sqlite_error(tmp_path: Path) -> None:
    """A driver exception is not a ``StoreError`` and sails past every handler.

    Measured at the commit before the mapping: zeroing each of a 200-event
    store's 95 non-header pages in turn, a raw ``sqlite3.DatabaseError``
    escaped at least one public entry point for **95 of 95** pages — ``prune``
    on 93 of the 93 that open, ``query(observable=)`` on 75, ``query`` on 69,
    ``append`` on 16, ``open`` on 2, ``count`` and ``count_before`` on 1.
    ``attest`` was the only one already covered.

    The sweep is over the **whole surface** for a measured reason: a fix that
    wrapped ``query`` alone produced *2187 passed, 7 skipped* — the suite could
    not distinguish a partial fix from a complete one, because the existing
    page sweep only ever calls ``query`` and ``attest``. This is the assertion
    that can.
    """
    root = tmp_path / "lab"
    root.mkdir(parents=True)
    with EventStore.open(root) as store:
        store.append_many(
            tuple(normalize(_s3_record(index)) for index in range(200)),
            ingested_at=1_760_000_000.0,
        )
    database = root / "data" / "events" / "events.sqlite3"
    folding = sqlite3.connect(database)
    try:
        folding.execute("PRAGMA journal_mode=DELETE")
        page_size = int(folding.execute("PRAGMA page_size").fetchone()[0])
    finally:
        folding.close()
    pristine = database.read_bytes()
    pages = len(pristine) // page_size
    assert pages > 50, f"the fixture is {pages} pages; too small to sweep meaningfully"

    def sweep(baseline: bytes) -> tuple[dict[str, list[int]], int, dict[str, int]]:
        leaked: dict[str, list[int]] = {}
        other: dict[str, int] = {}
        reached = 0
        for pageno in range(2, pages + 1):
            offset = (pageno - 1) * page_size
            database.write_bytes(
                baseline[:offset] + bytes(page_size) + baseline[offset + page_size :]
            )
            try:
                EventStore.open(root).close()
            except StoreError:
                continue
            except sqlite3.Error:
                leaked.setdefault("open", []).append(pageno)
                continue
            for name, call in _SQL_ENTRY_POINTS.items():
                try:
                    with EventStore.open(root) as store:
                        call(store)
                except StoreError:
                    reached += 1
                except sqlite3.Error:
                    leaked.setdefault(name, []).append(pageno)
                except (ValueError, OSError) as exc:
                    # Neither is the leak under test: `next_stamp` rejects a
                    # non-finite clock with ValueError, and an OSError is the
                    # filesystem. Counted rather than swallowed so a fixture
                    # that starts failing for one of these cannot look like
                    # coverage.
                    key = f"{name}:{type(exc).__name__}"
                    other[key] = other.get(key, 0) + 1
        database.write_bytes(baseline)
        return leaked, reached, other

    # Regime 1: the stored high-water row present, which is every store this
    # platform writes today.
    leaked, reached, other = sweep(pristine)
    assert reached, "no entry point refused on any damaged page, so nothing was exercised"
    assert not leaked, (
        "with the high-water row present, a raw sqlite3 error reached a caller from: "
        + ", ".join(f"{name} on {len(hits)} page(s)" for name, hits in sorted(leaked.items()))
        + f" (non-leak failures seen: {other})"
    )

    # Regime 2: the row ABSENT — the pre-control database state, reachable on an
    # upgraded store. A different code path, not a different fixture:
    # `high_water_mark` falls back to `SELECT MAX(ingested_at)`, which plans as
    # `SEARCH events USING COVERING INDEX events_ingested_at` and so leaks on
    # that index's page, where the stored-row path leaks on none. The first
    # version of this test swept only regime 1 and so proved one of two.
    stripping = sqlite3.connect(database)
    try:
        stripping.execute("DELETE FROM meta WHERE key = ?", (HIGH_WATER_KEY,))
        assert stripping.total_changes == 1, "the high-water row was not there to remove"
        stripping.commit()
        stripping.execute("PRAGMA journal_mode=DELETE")
    finally:
        stripping.close()
    without_mark = database.read_bytes()
    with EventStore.open(root) as store:
        assert store.high_water_mark() is not None, (
            "the fallback returned nothing, so regime 2 does not exercise the path "
            "it is written for"
        )

    leaked, reached, other = sweep(without_mark)
    database.write_bytes(pristine)
    assert reached, "regime 2 exercised nothing"
    assert not leaked, (
        "with the high-water row absent, a raw sqlite3 error reached a caller from: "
        + ", ".join(f"{name} on {len(hits)} page(s)" for name, hits in sorted(leaked.items()))
        + f" (non-leak failures seen: {other})"
    )


@pytest.mark.security
def test_the_corruption_mapping_lets_three_other_sqlite_errors_keep_their_meaning() -> None:
    """Each exclusion is a measured false positive, not caution.

    All three are ``sqlite3.DatabaseError`` subclasses, so a mapping written on
    the class alone relabels every one of them as evidence damage — and
    ``sli.measure_store_readable`` grades evidence damage as ``0.0``, a
    breach. This asserts the predicate discriminates, which the class hierarchy
    cannot do for it.
    """
    from store.events import _is_corruption

    assert issubclass(sqlite3.IntegrityError, sqlite3.DatabaseError)
    assert issubclass(sqlite3.OperationalError, sqlite3.DatabaseError)
    assert issubclass(sqlite3.ProgrammingError, sqlite3.DatabaseError)

    def _named(cls: type[sqlite3.Error], name: str, code: int) -> sqlite3.Error:
        exc = cls("measured message")
        exc.sqlite_errorname = name
        exc.sqlite_errorcode = code
        return exc

    # The append-only trigger firing: a security control working.
    assert not _is_corruption(_named(sqlite3.IntegrityError, "SQLITE_CONSTRAINT_TRIGGER", 1811))
    # Lock contention, with quick_check returning "ok" at that same moment.
    assert not _is_corruption(_named(sqlite3.OperationalError, "SQLITE_BUSY", 5))
    # A caller bug: a closed store, a bad bind type.
    assert not _is_corruption(_named(sqlite3.ProgrammingError, "SQLITE_MISUSE", 21))
    # And the two that are corruption, by name rather than by class.
    assert _is_corruption(_named(sqlite3.DatabaseError, "SQLITE_CORRUPT", 11))
    assert _is_corruption(_named(sqlite3.DatabaseError, "SQLITE_NOTADB", 26))
    # An unnamed DatabaseError is not assumed to be corruption.
    assert not _is_corruption(sqlite3.DatabaseError("no errorname at all"))

    # The class exclusions, pinned separately — and this case is CONSTRUCTED,
    # not engine-produced, which is the honest thing to say about it. CPython
    # derives the sqlite3 exception class from the error code, so every
    # exception I could reach through the engine carried a code in its own
    # family: IntegrityError 1811, OperationalError 5 and 1, DatabaseError 11
    # and 26. I could not make SQLite raise an IntegrityError bearing
    # SQLITE_CORRUPT. The exclusion is therefore a second layer against that
    # mapping ever changing, and without this assertion it is inert: removing
    # the isinstance line left all 175 tests in this area green, because the
    # name gate alone caught every case the other assertions use. A guard no
    # test can make fire is the shape this suite has spent the session
    # removing, so it is pinned here or it should not exist.
    assert not _is_corruption(_named(sqlite3.IntegrityError, "SQLITE_CORRUPT", 11))
    assert not _is_corruption(_named(sqlite3.ProgrammingError, "SQLITE_NOTADB", 26))


@pytest.mark.security
def test_the_append_only_trigger_still_raises_sqlite_integrity_error(tmp_path: Path) -> None:
    """End to end, not just through the predicate.

    The trigger refusal travels through ``store._conn`` rather than a public
    method, which is exactly why the mapping is at the method boundary: a
    connection-level wrap was measured to be the *only* shape that breaks this
    suite, and this is the property it breaks.
    """
    root = tmp_path / "lab"
    root.mkdir(parents=True)
    with EventStore.open(root) as store:
        store.append(normalize(_s3_record(1)), ingested_at=1_760_000_000.0)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._conn.execute("UPDATE events SET vendor = 'rewritten'")


@pytest.mark.security
def test_a_reported_quick_check_verdict_refuses_and_names_more_than_the_banner(
    tmp_path: Path,
) -> None:
    """SQLite gives two answers, and only one of them was being tested.

    ``PRAGMA quick_check`` *raises* for some page losses and *reports* a
    verdict string for others. Nothing in the suite reached the reported
    branch, so planting "run the pragma, look at the verdict, ignore it" left
    every test green — the same shape as the plant that survived the first
    version of the attestation fix.

    Measured reachability, which is why this is a sweep and not a hard-coded
    page: at 200 / 400 / 1200 events the reported branch is **20 of 95**,
    **41 of 186** and **98 of 525** single-page losses. Not exotic.

    The second assertion pins :func:`store.events._verdict_reason`. Every
    reported verdict's first line is the bare banner ``*** in database main
    ***``, which tells an operator nothing; the reason is on the next line
    (``Tree 4 page 185: btreeInitPage() returns error``). A refusal message of
    just the banner is a refusal with no diagnosis.
    """
    root = tmp_path / "lab"
    root.mkdir(parents=True)
    with EventStore.open(root) as store:
        store.append_many(
            tuple(normalize(_s3_record(index)) for index in range(200)),
            ingested_at=1_760_000_000.0,
        )
    database = root / "data" / "events" / "events.sqlite3"
    folding = sqlite3.connect(database)
    try:
        folding.execute("PRAGMA journal_mode=DELETE")
        page_size = int(folding.execute("PRAGMA page_size").fetchone()[0])
    finally:
        folding.close()
    pristine = database.read_bytes()

    banner_only: list[int] = []
    refusals: list[str] = []
    for pageno in range(2, len(pristine) // page_size + 1):
        offset = (pageno - 1) * page_size
        database.write_bytes(pristine[:offset] + bytes(page_size) + pristine[offset + page_size :])
        probe = sqlite3.connect(database)
        try:
            verdict = str(probe.execute("PRAGMA quick_check").fetchone()[0])
        except sqlite3.DatabaseError:
            continue  # the raising branch; covered by the sweep above
        finally:
            probe.close()
        if verdict == "ok":
            continue
        assert verdict.splitlines()[0].strip() == "*** in database main ***", (
            f"page {pageno}: a reported verdict no longer leads with the banner, "
            "so the second assertion below would pass for the wrong reason"
        )
        banner_only.append(pageno)
        try:
            with EventStore.open(root) as store:
                store.verify_integrity()
        except StoreIntegrityError as exc:
            refusals.append(str(exc))
        except (StoreError, sqlite3.Error):
            continue
        else:
            database.write_bytes(pristine)
            raise AssertionError(
                f"page {pageno}: quick_check reported {verdict.splitlines()[0]!r} "
                "and verify_integrity() accepted the store anyway"
            )
    database.write_bytes(pristine)

    assert banner_only, (
        "no page's loss made quick_check REPORT rather than raise, so this test "
        "did not reach the branch it exists for"
    )
    assert refusals, "the reported branch was reached but produced no refusal"
    uninformative = [
        message for message in refusals if message.rstrip().endswith("in database main ***")
    ]
    assert not uninformative, (
        f"{len(uninformative)} of {len(refusals)} refusal(s) carry only quick_check's "
        f"banner and no reason: {uninformative[:1]}"
    )
