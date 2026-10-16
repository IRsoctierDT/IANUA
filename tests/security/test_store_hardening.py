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
import sqlite3
import typing
from collections.abc import Iterator
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
    StoreError,
    StoreIntegrityError,
    StorePathError,
    canonical_json,
    event_id,
)
from store.schema import HIGH_WATER_KEY

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


# --------------------------------------------------------------------------
# Injection, at the boundary: literal provenance of every executed statement
# --------------------------------------------------------------------------
#
# The check above pattern-matches three constructs, and that is not the
# invariant. The invariant is that no caller value becomes SQL text, and
# measured on this package five routes reached an ``execute`` call while
# that check reported green:
#
#   1. ``statement + " -- " + str(before)``         (``+`` concatenation)
#   2. ``_TEMPLATE % repr(before)``                 (``%`` behind a name)
#   3. ``_TEMPLATE.format(repr(before))``           (``.format`` behind a name)
#   4. ``" ".join([_TEMPLATE, repr(before)])``      (``str.join``)
#   5. ``"".join([_TEMPLATE, f"{before!r}"])``      (f-string as an element)
#
# Three of those are the very constructs that check names: binding the
# literal to a module name first walks past all three, because the check
# only looks at a ``Constant`` in the operator position. Route 5 is worse
# than that — the f-string *is* inspected, but ``f"{before!r}"`` has no
# literal part of its own, so the SQL sitting in the sibling list element
# is never compared against it.
#
# So the assertion below works the other way round. It starts at the
# ``execute`` call and demands that the statement be traceable to string
# literals written in this package, refusing whatever it cannot account
# for. The default for an unrecognized expression is "not a literal",
# which is what makes a sixth route nobody has thought of fail too.

#: The provenance lattice. ``_OTHER`` is the default, and the only safe
#: default: an expression this checker cannot account for may be a caller's.
_LITERAL = "a string literal of this package"
_LITERAL_SEQ = "a sequence whose every element is a literal"
_LITERAL_MAP = "a mapping whose every value is a literal"
_OTHER = "NOT traceable to a literal"

#: The sqlite3 methods that take SQL text as their first argument.
_EXECUTORS = {"execute", "executemany", "executescript"}

#: ``name.append(x)`` keeps ``name`` literal-only when ``x`` is a literal, and
#: ``name.extend(xs)`` when ``xs`` is a literal-only sequence. Any *other*
#: method call on a bare name demotes it, which covers ``insert``, ``update``,
#: slice assignment and whatever arrives later without an allow-list that has
#: to be maintained against the standard library.
_ACCUMULATORS = {"append": _LITERAL, "extend": _LITERAL_SEQ}

#: Methods that change a container in place. A module-level constant one of
#: these is called on is not a constant, so it is demoted wherever it is read:
#: ``_EQUALITY`` earns its literal provenance from its declared values, and an
#: ``_EQUALITY.update(...)`` anywhere in the module would end that.
_MUTATORS = frozenset(
    {
        "append",
        "clear",
        "extend",
        "insert",
        "pop",
        "popitem",
        "remove",
        "reverse",
        "setdefault",
        "sort",
        "update",
        "__setitem__",
        "__delitem__",
    }
)


def _meet(left: str, right: str) -> str:
    """The conservative join: two different provenances are no provenance."""
    return left if left == right else _OTHER


def _note(accumulated: dict[str, str], name: str, kind: str) -> None:
    """Record ``name``'s provenance as the meet over every binding seen."""
    accumulated[name] = _meet(accumulated[name], kind) if name in accumulated else kind


def _target_names(target: ast.expr) -> set[str]:
    return {node.id for node in ast.walk(target) if isinstance(node, ast.Name)}


def _scope_nodes(scope: ast.AST) -> Iterator[ast.AST]:
    """Every node of one scope, without entering a nested scope."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        stack.extend(ast.iter_child_nodes(node))


def _provenance(node: ast.expr, env: dict[str, str]) -> str:
    """Classify one expression. Every unrecognized shape is :data:`_OTHER`."""
    if isinstance(node, ast.Constant):
        return _LITERAL if isinstance(node.value, str) else _OTHER
    if isinstance(node, ast.Name):
        return env.get(node.id, _OTHER)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        if all(_provenance(element, env) == _LITERAL for element in node.elts):
            return _LITERAL_SEQ
        return _OTHER
    if isinstance(node, ast.Dict):
        # The keys may be anything; it is the values that become SQL text.
        if node.values and all(_provenance(value, env) == _LITERAL for value in node.values):
            return _LITERAL_MAP
        return _OTHER
    if isinstance(node, ast.Subscript):
        # ``_EQUALITY[column]`` — whatever the key is, the value is a literal.
        return _LITERAL if _provenance(node.value, env) == _LITERAL_MAP else _OTHER
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            pair = (_provenance(node.left, env), _provenance(node.right, env))
            if pair == (_LITERAL, _LITERAL):
                return _LITERAL
            if pair == (_LITERAL_SEQ, _LITERAL_SEQ):
                return _LITERAL_SEQ
        return _OTHER  # ``%`` is interpolation; the rest is not string building
    if isinstance(node, ast.JoinedStr):
        # An f-string with nothing substituted is a literal; one with any
        # substitution is the textbook vector, whatever its literal parts say.
        if any(isinstance(part, ast.FormattedValue) for part in node.values):
            return _OTHER
        return _LITERAL
    if isinstance(node, ast.IfExp):
        return _meet(_provenance(node.body, env), _provenance(node.orelse, env))
    if isinstance(node, ast.BoolOp):
        kinds = {_provenance(value, env) for value in node.values}
        return kinds.pop() if len(kinds) == 1 else _OTHER
    if isinstance(node, ast.Call):
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "join"
            and len(node.args) == 1
            and _provenance(func.value, env) == _LITERAL
        ):
            return _LITERAL if _provenance(node.args[0], env) == _LITERAL_SEQ else _OTHER
        # Every other call returns a value this checker cannot see into,
        # ``.format()`` and a helper that returns a statement included.
        return _OTHER
    return _OTHER


def _pattern_bound_names(node: ast.AST) -> set[str]:
    """Names a structural-pattern node binds.

    ``case statement:`` is a *capture* pattern: it binds the subject to
    ``statement``, exactly as an assignment would. Measured before this
    existed, and reported as a P1 on #224: ``statement = _TEMPLATE`` followed
    by ``match before: case statement: pass`` left ``statement`` classified as
    a literal while at runtime it held the caller's value — confirmed by
    running the match, which printed ``'INJECTED'``.

    Read off :class:`ast.pattern` rather than enumerating ``MatchAs``,
    ``MatchStar`` and ``MatchMapping``: the binding slots are the ``name`` and
    ``rest`` attributes, so a pattern node added by a later Python is covered
    without this growing a version-keyed list. ``case _:`` carries
    ``name=None`` and binds nothing.
    """
    if not isinstance(node, ast.pattern):
        return set()
    return {
        bound
        for attribute in ("name", "rest")
        if isinstance(bound := getattr(node, attribute, None), str)
    }


def _rebinding_names(scope: ast.AST) -> set[str]:
    """Names a scope binds by a construct that carries no provenance.

    A ``for``, ``with``, ``except``, walrus or ``match`` target is whatever
    the subject happened to be, a plain ``import`` binds a module object, and
    ``global``/``nonlocal`` hands the binding to someone else.

    Shared by :func:`_opaque_names` (function scope) and :func:`_module_env`
    (module scope) **because the two had drifted**. Measured: module scope
    modelled only ``ImportFrom``, ``Assign`` and ``AnnAssign``, so
    ``for _TEMPLATE in [_TEMPLATE + os.environ["X"]]: pass`` at module level
    kept its literal provenance and was accepted, while the identical
    construct inside a function was refused. One loop, two callers.
    """
    names: set[str] = set()
    for node in _scope_nodes(scope):
        if isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            names |= _target_names(node.target)
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            names |= _target_names(node.optional_vars)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, ast.NamedExpr):
            names |= _target_names(node.target)
        elif isinstance(node, ast.Import):
            names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # ``def NAME`` and ``class NAME`` bind NAME, and a decorator makes
            # that binding any value at all. Measured accepted before this
            # arm existed: ``statement = _COUNT`` followed by
            # ``@_rendered(before)`` / ``def statement(): ...`` executed
            # ``SELECT COUNT(*) AS n FROM events WHERE ingested_at <
            # 1760000000``, and the module-level spelling of the same thing
            # ran ``... FROM events; DROP TABLE events``. Neither env builder
            # had a ``FunctionDef`` arm, so these were not bindings at all as
            # far as the checker was concerned. Covering the *name* rather
            # than the decorator expression also catches the undecorated
            # rebinding, which is the same defect with no decorator.
            names.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            names.update(node.names)
        else:
            names |= _pattern_bound_names(node)
    return names


def _opaque_names(scope: ast.AST) -> set[str]:
    """Names a scope binds by anything other than plain assignment.

    A parameter is a caller's value by definition. ``from x import y`` is
    opaque *here* but resolved at module scope, which is the one difference
    between this and :func:`_rebinding_names`.
    """
    names = _rebinding_names(scope)
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        spec = scope.args
        names.update(arg.arg for arg in (*spec.posonlyargs, *spec.args, *spec.kwonlyargs))
        names.update(arg.arg for arg in (spec.vararg, spec.kwarg) if arg is not None)
    for node in _scope_nodes(scope):
        if isinstance(node, ast.ImportFrom):
            names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
    return names


def _escaping_names(nodes: typing.Iterable[ast.AST]) -> set[str]:
    """Names whose use hides a possible later mutation from this checker.

    **This is the second inversion, and it is the load-bearing one.** The
    first version of this checker chased *mutations*: it demoted a container
    when it saw ``name.insert(...)`` or ``name[i] = ...``. That is a
    deny-list over a mutable object reached through one name, and a review
    pass measured eleven ways past it on merged code, every one with a
    runtime proof of real injection. The root cause was named exactly:
    a name-keyed lattice over mutable objects. A few of the eleven:

    * ``sink = parts; sink.append(before); " ".join(parts)`` — the demotion
      landed on ``sink``, and ``parts`` is the same list object.
    * ``_add_clause(clauses, f"e.tag = '{tag}'")`` where the helper appends.
      ``store/events.py::query`` writes ``clauses.append(...)`` fourteen
      times; factoring that into a helper is the refactor a reviewer would
      *ask for*, and it removes the list from this checker's view entirely.
    * ``def add_vendor(): parts.append(before)`` — mutating a list needs no
      ``nonlocal``, so :func:`_nonlocal_names` covered the rare half of that
      gap and missed the common one.
    * ``holder = (parts,); holder[0].append(before)`` — the method branch
      requires a bare ``Name`` receiver, so any other receiver passed through.

    So this does not look for mutations. It whitelists the **uses that keep a
    container provable** and treats every other appearance of the name as an
    escape. The four sanctioned uses are exactly what ``store/events.py``
    does: ``name.append(x)``/``name.extend(xs)``, ``<literal>.join(name)``,
    ``name[key]`` read, and a bare truthiness test (``if clauses:``). Being a
    whitelist, a route nobody has imagined escapes by default — which is the
    same reason the statement-level check is a provenance requirement rather
    than a list of forbidden constructs.
    """
    population = list(nodes)
    sanctioned: set[int] = set()
    for node in population:
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                if func.attr in _ACCUMULATORS and isinstance(func.value, ast.Name):
                    sanctioned.add(id(func.value))  # clauses.append(<literal>)
                elif (
                    func.attr == "join"
                    and len(node.args) == 1
                    and isinstance(node.args[0], ast.Name)
                    # The RECEIVER has to be a string literal written here.
                    # It used to be unchecked, so ANY one-argument method
                    # named ``join`` sanctioned its argument — measured, a
                    # ``class _Renderer`` with ``def join(self, parts):
                    # parts.append(self._extra)`` passed ``renderer.join(parts)``
                    # and kept ``parts`` literal-only. Requiring a constant is
                    # exactly what ``store/events.py`` writes (``" AND ".join``
                    # and ``"".join``); a module constant as receiver
                    # (``_AND.join(x)``) would be refused, which is a false
                    # positive in the fail-closed direction and the price of
                    # not threading an env into a function computed before one
                    # exists.
                    and isinstance(func.value, ast.Constant)
                    and isinstance(func.value.value, str)
                ):
                    sanctioned.add(id(node.args[0]))  # " AND ".join(clauses)
        elif isinstance(node, (ast.If, ast.While, ast.IfExp)) and isinstance(node.test, ast.Name):
            sanctioned.add(id(node.test))  # if clauses:
        elif (
            isinstance(node, ast.UnaryOp)
            and isinstance(node.op, ast.Not)
            and isinstance(node.operand, ast.Name)
        ):
            sanctioned.add(id(node.operand))  # if not clauses:
        elif (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and isinstance(node.ctx, ast.Load)
        ):
            sanctioned.add(id(node.value))  # _EQUALITY[column], a READ
    return {
        node.id
        for node in population
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and id(node) not in sanctioned
    }


def _nested_scope_names(scope: ast.AST) -> set[str]:
    """Every name a nested scope mentions, read or written.

    :func:`_scope_nodes` stops at a nested function by design, so anything it
    does to an enclosing container is invisible. :func:`_nonlocal_names`
    closed the *rebinding* half of that; this closes the mutation half, which
    is the common one — ``parts.append(before)`` inside a closure needs no
    ``nonlocal`` declaration at all, and was measured accepted.

    ``ClassDef`` belongs in this walk, and the reason is worth stating because
    the caller *exempts* a class body from this penalty. The two are different
    things. A class **body** is executed immediately, in the enclosing frame,
    and can read and mutate that frame's locals — measured accepted before
    this: ``class _Collected: parts.append(before)`` inside the function that
    then joins ``parts``. A **method** is a separate scope that cannot read a
    class-body local as a closure variable at all, which is why
    :func:`_scope_env` skips the penalty when the scope under analysis *is* a
    class. Nested class body: penalised here. Methods of a class being
    analysed: exempt there.
    """
    names: set[str] = set()
    for node in ast.walk(scope):
        if node is scope:
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            names |= {inner.id for inner in ast.walk(node) if isinstance(inner, ast.Name)}
    return names


def _demote_escaped(env: dict[str, str], escaped: set[str]) -> None:
    """Demote every tracked container in ``escaped``, in place.

    Only containers: a string is immutable, so handing it to a function
    cannot change what it holds.
    """
    for name, kind in list(env.items()):
        if kind in (_LITERAL_SEQ, _LITERAL_MAP) and name in escaped:
            env[name] = _OTHER


def _nonlocal_names(scope: ast.AST) -> set[str]:
    """Names a *nested* scope rebinds through ``nonlocal``.

    :func:`_scope_nodes` deliberately stops at a nested function, so a
    rebinding inside one is invisible to the fixed point below. Measured
    before this was added: a nested ``inner()`` doing
    ``nonlocal statement; statement = statement + before`` was **accepted**.
    Walking the whole subtree for the declaration and demoting the name is
    enough — it does not matter what the nested scope assigns, only that it
    can.
    """
    return {
        name for node in ast.walk(scope) if isinstance(node, ast.Nonlocal) for name in node.names
    }


def _scope_env(scope: ast.AST, inherited: dict[str, str]) -> dict[str, str]:
    """Provenance of every name visible in one scope.

    A name's provenance is the *meet* over every binding of it in the scope,
    so a variable that is a literal on one branch and a parameter on another
    is not a literal. Iterated to a fixed point, because ``store.events``
    appends to its clause list after binding it.
    """
    env = dict(inherited)
    opaque = _opaque_names(scope) | _nonlocal_names(scope)
    for name in opaque:
        env[name] = _OTHER
    # Computed once — it is a property of the source, not of the iteration —
    # and applied INSIDE the loop below rather than after it. Applying it
    # after would leave ``statement = "".join(parts)`` classified as a
    # literal from an earlier pass, which is the only value that reaches an
    # ``execute`` call.
    escaped = _escaping_names(_scope_nodes(scope))
    if not isinstance(scope, ast.ClassDef):
        # The nested-scope penalty is about FUNCTION locals: a closure can
        # mutate the local of the function enclosing it. A class body is
        # different, and the difference is a language rule rather than a
        # judgement call — **class scope is not a closure scope**, so a
        # method cannot read a class-body local as a closure variable at all
        # (``class C: x = 1`` then ``def f(self): return x`` is a NameError).
        # A method mentioning a name therefore says nothing about the class
        # body's binding of it. Applying the penalty here anyway demoted
        # every container any method mentions — measured: it put
        # ``EventStore.query``'s own ``statement`` out of reach of the real
        # package's check. A method that mutates a MODULE container is
        # covered, by :func:`_module_env`'s whole-tree sweep.
        escaped |= _nested_scope_names(scope)
    _demote_escaped(env, escaped)
    for _ in range(4):
        inferred: dict[str, str] = {}
        for node in _scope_nodes(scope):
            if isinstance(node, ast.Assign):
                # ``parts = sink = [_SELECT]`` binds ONE list to two names, and
                # neither of them escapes under the use-whitelist: both targets
                # are in Store context, so there is no Load appearance to
                # catch. Measured accepted — ``sink.append(before)`` then
                # ``"".join(parts)``. A chained assignment is an alias by
                # construction, so every target is demoted.
                chained = len([t for t in node.targets if isinstance(t, ast.Name)]) > 1
                for target in node.targets:
                    if isinstance(target, ast.Name) and not chained:
                        _note(inferred, target.id, _provenance(node.value, env))
                    else:
                        # ``x[i] = v`` and ``x.a = v`` say nothing about ``x``.
                        for name in _target_names(target):
                            _note(inferred, name, _OTHER)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                # ``clauses: list[str] = []`` and its annotated-only form.
                kind = _LITERAL_SEQ if node.value is None else _provenance(node.value, env)
                _note(inferred, node.target.id, kind)
            elif isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add):
                    _note(inferred, node.target.id, _provenance(node.value, env))
                else:
                    for name in _target_names(node.target):
                        _note(inferred, name, _OTHER)
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                    # A method this checker does not model DEMOTES the name.
                    # It used to ``continue`` here, which preserved whatever
                    # the name's assignment said — so ``clauses.insert(1,
                    # before)`` left the list literal-only and
                    # ``"".join(clauses)`` executed
                    # ``... WHERE vendor = 'x' OR 1=1 --``. Measured, and
                    # reported as a P1 on #224. The comment on
                    # :data:`_ACCUMULATORS` had promised this behaviour from
                    # the start, naming ``insert``; the code did the opposite.
                    want = _ACCUMULATORS.get(func.attr)
                    kept = (
                        want is not None
                        and len(node.args) == 1
                        and _provenance(node.args[0], env) == want
                    )
                    _note(inferred, func.value.id, _LITERAL_SEQ if kept else _OTHER)
        for name, kind in inferred.items():
            if name not in opaque:
                env[name] = kind
        _demote_escaped(env, escaped)
    return env


def _mutated_names(tree: ast.Module) -> set[str]:
    """Module-level names something in the module changes in place or rebinds.

    A module-level ``match`` is exotic, but its capture binds a module name as
    surely as an assignment does, and :func:`_module_env` reads only
    assignments and imports. Leaving the asymmetry would be the
    fixed-one-copy-not-the-other shape this repository warns about in
    ``pipeline/cursor.py``, so pattern-bound names are demoted here too.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, (ast.Subscript, ast.Attribute)):
                    names |= _target_names(target)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                names |= _target_names(target)
        elif isinstance(node, ast.Global):
            names.update(node.names)
        elif isinstance(node, ast.pattern):
            names |= _pattern_bound_names(node)
        elif isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in _MUTATORS
                and isinstance(func.value, ast.Name)
            ):
                names.add(func.value.id)
    return names


def _import_source(module: str, level: int, within: str) -> str:
    """Resolve an ``ImportFrom`` to a dotted module name, relative form included."""
    if not level:
        return module
    base = within.rsplit(".", level)[0]
    return f"{base}.{module}" if module else base


def _module_env(name: str, tree: ast.Module, package: dict[str, dict[str, str]]) -> dict[str, str]:
    """Module-level provenance, resolving ``from <module> import NAME``.

    This has to cross files or the real package fails its own check:
    ``store.events`` runs ``executescript(DDL)`` on a literal declared in
    ``store.schema``. An import that cannot be resolved stays
    :data:`_OTHER`, so an unmodelled import shape fails loudly at the
    ``execute`` call rather than passing quietly.
    """
    env: dict[str, str] = {}
    for _ in range(2):  # a constant may be declared below its first use
        inferred: dict[str, str] = {}
        # Not ``tree.body``: an assignment nested in a module-level ``if``,
        # ``try`` or ``for`` is still a module binding. Measured before this
        # walked the scope — a top-level ``_TEMPLATE = "SELECT ..."`` followed
        # by a conditional ``_TEMPLATE = "SELECT ... " + os.environ["X"]`` kept
        # its literal provenance and was **accepted**.
        for node in _scope_nodes(tree):
            if isinstance(node, ast.ImportFrom):
                source = package.get(_import_source(node.module or "", node.level, name), {})
                for alias in node.names:
                    _note(inferred, alias.asname or alias.name, source.get(alias.name, _OTHER))
            elif isinstance(node, ast.Assign):
                # Same alias-by-construction rule as the scope env: measured,
                # ``DDL_PARTS = _SINK = [...]`` in one module, mutated through
                # ``_SINK`` and read through ``from schema import DDL_PARTS``,
                # survived the import boundary.
                chained = len([t for t in node.targets if isinstance(t, ast.Name)]) > 1
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        _note(
                            inferred,
                            target.id,
                            _OTHER if chained else _provenance(node.value, env),
                        )
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if node.value is not None:
                    _note(inferred, node.target.id, _provenance(node.value, env))
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                # Measured accepted before this branch existed: a module-level
                # ``_TEMPLATE += os.environ.get("IANUA_VENDOR", "'?'")``. The
                # same construct inside a function was already refused, so one
                # scope agreed with the other only by accident of which node
                # types each modelled.
                augmented = _provenance(node.value, env) if isinstance(node.op, ast.Add) else _OTHER
                _note(inferred, node.target.id, augmented)
        env = inferred
    for rebound in _rebinding_names(tree) | _mutated_names(tree):
        if rebound in env:
            env[rebound] = _OTHER
    # Whole tree, not the module scope: a module container handed to a helper
    # escapes wherever that helper is, and a mutation inside one function is
    # invisible to another function's scope env. Measured accepted before
    # this: ``_remember(_EQUALITY, column, clause)`` with a helper doing
    # ``table[column] = clause``, then ``_EQUALITY[column]`` read back into
    # the statement — and ``_EQUALITY[column]`` is a SANCTIONED pattern at
    # store/events.py:1008, which is what made it worth closing.
    _demote_escaped(env, _escaping_names(ast.walk(tree)))
    return env


def _executed_statements(
    node: ast.AST, env: dict[str, str], scope: str
) -> Iterator[tuple[int, str, str, str]]:
    """Yield ``(line, provenance, scope, source)`` per executed statement."""
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _EXECUTORS:
            # Positional is the sqlite3 spelling, and the second positional is
            # the parameter sequence, which is legitimately not a literal — so
            # only the first is taken. With no positional argument at all,
            # every keyword is taken instead, ``**kwargs`` included: measured
            # before this, ``conn.execute(sql=_TEMPLATE + before)`` was
            # **accepted** because the check looked only at ``node.args``.
            carried = list(node.args[:1]) or [keyword.value for keyword in node.keywords]
            for argument in carried:
                yield node.lineno, _provenance(argument, env), scope, ast.unparse(argument)
    for child in ast.iter_child_nodes(node):
        # ``ClassDef`` belongs here, with the functions. It used to fall into
        # the generic branch below, so a class body was walked with the
        # ENCLOSING scope's env — while :func:`_scope_nodes` stops at a
        # ``ClassDef`` and never collected its bindings. The two halves
        # disagreed, and the gap was exactly the construct whose bindings one
        # half refused to look at. Measured accepted: a ``for clause in
        # columns:`` loop inside a ``class _Plan:`` nested in a function ran
        # ``SELECT * FROM events WHERE 1=1; DROP TABLE events; --``.
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            inner = "<lambda>" if isinstance(child, ast.Lambda) else child.name
            yield from _executed_statements(child, _scope_env(child, env), f"{scope}.{inner}")
        else:
            yield from _executed_statements(child, env, scope)


def _package_envs(sources: dict[str, str]) -> dict[str, dict[str, str]]:
    """Per-module provenance, with demotion applied across the whole package.

    Both demotion passes used to run per module, and a package is not a
    module. Measured accepted: module A declares ``_EQUALITY``, executes
    ``_PREFIX + _EQUALITY[column]`` with it, and module B does
    ``_EQUALITY[column] = clause`` on the name it imported from A. B's env was
    demoted and A's was not, so the statement A executes was still classified
    as a literal. A name that anything in the package mutates, or uses in a
    way that hides a mutation, is suspect in **every** module of it — which is
    the whole point of a package sharing one namespace of constants.
    """
    trees = {name: ast.parse(text) for name, text in sources.items()}
    suspect: set[str] = set()
    for tree in trees.values():
        suspect |= _mutated_names(tree)
        suspect |= _escaping_names(ast.walk(tree))
    package: dict[str, dict[str, str]] = {}
    for _ in range(3):  # resolve imports between the package's own modules
        package = {name: _module_env(name, tree, package) for name, tree in trees.items()}
    for env in package.values():
        _demote_escaped(env, suspect)
    return package


def _statement_sites(sources: dict[str, str]) -> list[tuple[str, int, str, str]]:
    """Every statement handed to sqlite3 in ``sources``, with its provenance."""
    package = _package_envs(sources)
    sites: list[tuple[str, int, str, str]] = []
    for name, text in sorted(sources.items()):
        for line, kind, scope, source in _executed_statements(ast.parse(text), package[name], name):
            sites.append((f"{name}:{line} in {scope}", line, kind, source[:160]))
    return sites


def _non_literal_statements(sources: dict[str, str]) -> list[str]:
    return [
        f"{where}: {kind}: {source}"
        for where, _line, kind, source in _statement_sites(sources)
        if kind != _LITERAL
    ]


def _store_sources() -> dict[str, str]:
    return {
        ".".join(path.relative_to(_REPO_ROOT).with_suffix("").parts): path.read_text(
            encoding="utf-8"
        )
        for path in _store_modules()
    }


@pytest.mark.security
def test_every_statement_reaching_sqlite_is_built_only_from_literals() -> None:
    """No caller value becomes SQL text — asserted at the ``execute`` call.

    This is the assertion that carries the invariant, and it is stated as a
    provenance requirement rather than a list of forbidden constructs: the
    statement handed to sqlite3 must be traceable to string literals written
    in this package. A parameter, a call's return value, or a name whose
    bindings do not all resolve to literals fails.
    """
    findings = _non_literal_statements(_store_sources())
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
    sites = _statement_sites(_store_sources())
    assert len(sites) >= 19, f"expected at least 19 statements reached, found {len(sites)}"
    assert all(kind == _LITERAL for _where, _line, kind, _source in sites)


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
    assert _non_literal_statements({"sample": _harness(expression)}), (
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
        "list.insert, the method the _ACCUMULATORS comment already named",
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
    assert _non_literal_statements({"sample": source}), f"{label} was accepted"


#: An adversarial review pass against the version that closed the two P1
#: findings above measured **eleven further routes**, each with a runtime
#: proof of real injection, and named the root cause: a name-keyed lattice
#: over mutable objects. Ten are closed by the two structural changes those
#: findings forced — :func:`_escaping_names`' use-whitelist, and module scope
#: reusing :func:`_rebinding_names` instead of modelling three node types —
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
    assert _non_literal_statements({"sample": _MODULE_HEAD + body}), f"{label} was accepted"


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
    findings = _non_literal_statements({"sample": _MODULE_HEAD + body})
    assert not findings, "a wildcard pattern must not demote:\n  " + "\n  ".join(findings)


@pytest.mark.security
@pytest.mark.parametrize(("label", "expression"), _SANCTIONED)
def test_the_provenance_check_accepts_what_the_store_actually_does(
    label: str, expression: str
) -> None:
    """The permissive half, so a tightening that breaks the store says why."""
    findings = _non_literal_statements({"sample": _harness(expression)})
    assert not findings, f"{label} was refused: {expression}\n  " + "\n  ".join(findings)


#: Builtins that hand out, or write into, a namespace. Rebinding a module
#: constant through one is invisible to any name-keyed analysis.
_NAMESPACE_BUILTINS = frozenset({"globals", "vars", "locals", "setattr", "delattr"})

#: Methods that change a container in place, as :data:`_MUTATORS`, but checked
#: here against an *attribute* receiver rather than a bare name.
_ATTRIBUTE_MUTATORS = _MUTATORS


@pytest.mark.security
def test_no_module_namespace_is_written_in_this_package() -> None:
    """A Python module's namespace is writable from outside. Close that by shape.

    This is the one class of route that **analysis cannot close**, and the
    reason is a language property rather than a gap in the lattice: a module's
    globals are an ordinary mutable mapping that any other module can reach.
    An adversarial pass measured six spellings of it against merged code, each
    leaving a constant classified as a literal while the executed statement
    carried a caller's value:

    * ``globals()["_TEMPLATE"] = "SELECT ... WHERE " + clause`` —
      :func:`_target_names` walks the target, finds the ``Name`` ``globals``,
      and dutifully demotes *that*.
    * ``sys.modules[__name__].__dict__.update(OVERRIDES)`` — the same thing
      respelled, and it walked past the narrower version of this very test.
    * ``events.WHERE_VENDOR = clause`` from a sibling module. Note what this
      defeats: :func:`_demote_escaped` exempts strings because a string is
      immutable, which is true of the *object* and false of the *binding*.
    * ``setattr(events, name, clause)`` — the same route with a computed name,
      so no analysis could know which constant it hits.
    * ``schema._EQUALITY[column] = clause`` and
      ``schema._EQUALITY.update(extra)`` — ``update`` is in
      :data:`_MUTATORS`, but both demotion passes require a bare ``Name``
      receiver, so an attribute receiver skipped the check entirely.
    * ``from schema import *`` layered over a locally declared literal, which
      binds the name ``"*"`` and meets with nothing.

    Each is forbidden outright instead. Measured at **zero** occurrences
    across ``store/`` for every one of the six, so the rule costs nothing
    today, and unlike the lattice it is *sound*: there is no provenance
    argument to get wrong. The attribute rules are deliberately scoped to the
    base names bound by a plain ``import``, so ordinary instance state
    (``self._conn``, ``self._cache.append(...)``) is untouched — it is a
    *module* namespace that cannot be proven sealed, not every attribute.
    """
    for path in _store_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        modules = {
            alias.asname or alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }

        def _base(expression: ast.expr) -> str | None:
            while isinstance(expression, (ast.Attribute, ast.Subscript)):
                expression = expression.value
            return expression.id if isinstance(expression, ast.Name) else None

        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in _NAMESPACE_BUILTINS, (
                    f"{path}:{node.lineno}: {node.func.id}() reads or writes a namespace as "
                    f"a mutable mapping, through which a module constant can be rebound past "
                    f"the provenance check: {ast.unparse(node)[:120]}"
                )
            if isinstance(node, ast.ImportFrom):
                assert all(alias.name != "*" for alias in node.names), (
                    f"{path}:{node.lineno}: a star import can replace a locally declared "
                    f"literal with a name this package cannot see: {ast.unparse(node)[:120]}"
                )
            if isinstance(node, ast.Attribute) and node.attr in {"modules", "__dict__"}:
                assert _base(node) not in modules, (
                    f"{path}:{node.lineno}: reaching a module's namespace directly bypasses "
                    f"every provenance rule here: {ast.unparse(node)[:120]}"
                )
            if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete)):
                targets = (
                    node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
                )
                for target in targets:
                    if isinstance(target, (ast.Attribute, ast.Subscript)):
                        assert _base(target) not in modules, (
                            f"{path}:{node.lineno}: writing into an imported module's namespace "
                            f"rebinds a constant that module believes is sealed: "
                            f"{ast.unparse(target)[:120]}"
                        )
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in _ATTRIBUTE_MUTATORS
                and isinstance(node.func.value, (ast.Attribute, ast.Subscript))
            ):
                assert _base(node.func.value) not in modules, (
                    f"{path}:{node.lineno}: mutating a container held in an imported module "
                    f"skips every demotion pass, which needs a bare name receiver: "
                    f"{ast.unparse(node)[:120]}"
                )


@pytest.mark.security
def test_an_executor_is_never_taken_as_a_value() -> None:
    """A sink reached as a *value* is the whole remaining class. Close it by shape.

    :func:`_executed_statements` recognises a sink only where ``node.func`` is
    an ``Attribute`` named in :data:`_EXECUTORS`. An adversarial pass measured
    seven ``func`` shapes that are neither that nor the call-of-a-call the
    rule below forbids — every one accepted with **zero statement sites**, and
    every one injecting at runtime:

    * ``ex = conn.execute`` then ``ex(built)`` — one line inside an existing
      method, with ``conn.execute`` still verbatim in the diff
    * ``sinks = {"count": conn.execute}`` then ``sinks["count"](built)``
    * ``functools.partial(conn.execute, built)`` then ``runner()``
    * ``(trace or conn.execute)(built)``
    * ``(conn.executescript if script else conn.execute)(built)``
    * ``for ex in (conn.execute,): ex(built)``
    * ``tuple(map(conn.execute, [built]))``

    Enumerating those seven would be the deny-list mistake a third time. What
    they share is that each must mention the executor **as a value** before
    calling it through something else, so the rule is that an executor
    attribute may appear *only* as the function of a call. Together with the
    no-call-of-a-call rule below, reaching a connection's ``execute`` without
    naming it as a call's function requires ``getattr``, ``methodcaller`` or
    ``__getattribute__`` — each of which is a call whose result is called, and
    so already refused. Measured at zero occurrences across ``store/``: all
    nineteen sites are already ``X.execute(...)``.

    What held is worth recording too, because it says where the fail-closed
    default earned its keep. Every attempt to reshape the *arguments* was
    refused: ``conn.execute(*[built])``, ``conn.execute(**{"sql": built})``,
    ``conn.execute(statement := built)``, ``executemany``/``executescript``
    with a built statement, ``await conn.execute(built)``,
    ``conn.cursor().execute(built)``, a subclass overriding ``execute``, and
    even ``self.execute = conn.execute`` followed by ``self.execute(built)``
    — which is still an attribute call named ``execute``.

    And one hypothesis is **refuted**: ``sqlite3.Connection.execute(conn,
    statement)`` does make this checker read the wrong argument — the finding
    it emits names ``conn``, and the statement at argument 1 is never
    classified — but it is refused anyway, because no expression evaluating to
    a connection can carry literal provenance. Reading the wrong argument is
    real and is not an evasion.
    """
    for path in _store_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        called = {id(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in _EXECUTORS:
                assert id(node) in called, (
                    f"{path}:{node.lineno}: {ast.unparse(node)[:60]} is taken as a value "
                    f"rather than called. A sink reached through a later expression is "
                    f"invisible to the provenance check, which finds sinks in the "
                    f"function position of a call."
                )


@pytest.mark.security
def test_no_statement_is_dispatched_through_a_dynamic_attribute() -> None:
    """The provenance check finds its sinks by name, so close the indirection.

    ``_executed_statements`` looks for an ``Attribute`` call named ``execute``,
    ``executemany`` or ``executescript``. Measured: ``getattr(conn, "execute")
    (_TEMPLATE + before)`` is **not detected**, because the sink is a call's
    result rather than a named attribute. Rather than chase attribute names
    through a dataflow, forbid the shape: nothing in this package calls the
    result of a call. Measured at **zero** such nodes across ``store/``, so
    this costs nothing today and makes the one route that hides a sink from
    the check above fail here instead.

    This does **not** close the other residual, which is stated and not fixed:
    a statement handed to a differently *named* method —
    ``conn.run_sql(_TEMPLATE + before)`` — is not detected either, and closing
    that means deciding statically whether an arbitrary expression is SQL.
    What stands against it is that such a wrapper would have to be added to
    this package, where it is a reviewable change to the only module holding a
    connection, not a configuration.
    """
    for path in _store_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                assert not isinstance(node.func, ast.Call), (
                    f"{path}:{node.lineno}: a call's result is called, which can "
                    f"dispatch a statement past the provenance check: "
                    f"{ast.unparse(node)[:120]}"
                )


@pytest.mark.security
def test_a_chained_module_binding_does_not_survive_the_import_boundary() -> None:
    """The alias rule has to hold across files, not just inside one scope.

    Measured accepted before the chained-assignment rule reached
    :func:`_module_env`: one module binds a fragment list to two names, a
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
    findings = _non_literal_statements({"sample.schema": schema, "sample.events": events})
    assert findings, "a chained module binding survived the import boundary"


@pytest.mark.security
def test_a_cross_module_mutation_demotes_the_declaring_module_too() -> None:
    """Demotion is a property of the package, not of each module separately.

    Measured accepted before :func:`_package_envs` applied the suspect set
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
    findings = _non_literal_statements({"sample.schema": schema, "sample.events": events})
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
        assert not _non_literal_statements(sources), f"{spelling} did not resolve"


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
    with pytest.raises(SchemaVersionError, match="version 99"):
        EventStore.open(tmp_path).close()


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


#: Fields no value can overfill: two closed vocabularies and an epoch float.
#: Named so the reflection below cannot quietly cover nothing and pass.
_UNOVERFILLABLE = frozenset({"source_type", "parse_status", "timestamp"})


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


@pytest.mark.security
def test_a_query_limit_cannot_exceed_the_ceiling(tmp_path: Path) -> None:
    with EventStore.open(tmp_path) as store:
        store.append(normalize("sshd: session opened for user root"), ingested_at=1.0)
        # Asking for more than the ceiling is clamped, not honored.
        assert len(store.query(Query(limit=MAX_QUERY_LIMIT * 100))) == 1
        # A non-positive limit yields nothing rather than everything.
        for limit in (0, -1, -10_000):
            assert store.query(Query(limit=limit)) == ()


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
        with pytest.raises(StoreIntegrityError, match="not JSON"):
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

    Both of ``attest()``'s statements are covering-index scans — measured with
    ``EXPLAIN QUERY PLAN``: ``SCAN events USING COVERING INDEX
    sqlite_autoindex_events_1`` for the id stream, ``... COVERING INDEX
    events_ingested_at`` for the count. So the digest and the count prove the
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
    ``sli.measure_store_readable`` grades any ``StoreError`` as ``0.0``, a
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
