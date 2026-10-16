# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Literal-provenance analysis for every statement handed to sqlite3.

**The first non-test module under ``tests/``, and the reason is scope.** This
analysis was written inline in ``tests/security/test_store_hardening.py``,
where it matched that file's existing AST machinery and the absence of any
helper-module convention here. It judged one package. It now judges every
shipped package, which is no longer a fact about the store, so it lives in a
module both callers import rather than one test file reaching into another.

Two test modules import it:

* ``tests/security/test_sql_provenance.py`` — the repository-wide sweep, the
  three shape rules the analysis depends on, and the pinned evasion tables.
* ``tests/security/test_store_hardening.py`` — the store-scoped assertion
  that ``store/events.py`` docstrings cite by name, kept because that is the
  package the invariant was written for and a reader of those docstrings
  should find it where they are pointed.

The names here deliberately lost their leading underscore in the move: they
are this module's API now, and importing ``_private`` names across modules is
the smell that would have followed a verbatim copy. Everything the analysis
keeps to itself stayed private.

Security consideration: this module only *reads* source text and parses it
with :mod:`ast`. It imports nothing from the packages it judges, executes
none of their code, and has no filesystem reach beyond the repository paths
its callers hand it. A checker that imported what it checked would run the
code an attacker had just edited.
"""

from __future__ import annotations

import ast
import typing
from collections.abc import Iterable, Iterator
from pathlib import Path

# --------------------------------------------------------------------------
# The analysis: literal provenance of every executed statement
# --------------------------------------------------------------------------
#
# ``test_store_hardening.py::test_no_sql_statement_is_built_by_interpolation``
# pattern-matches three constructs, and that is not the invariant. The
# invariant is that no caller value becomes SQL text, and measured on
# ``store/`` five routes reached an ``execute`` call while that check
# reported green:
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
# So this works the other way round. It starts at the ``execute`` call and
# demands that the statement be traceable to string literals written in the
# swept source set, refusing whatever it cannot account for. The default for
# an unrecognized expression is "not a literal", which is what makes a sixth
# route nobody has thought of fail too.
#
# Both checks are required, and neither replaces the other: the narrow one
# names the three constructs a reader recognises at the site where the SQL is
# written, and this one carries the invariant. Nothing used to assert that
# both still exist, so deleting this one would have left the file reading as
# though the invariant were covered — ``test_sql_provenance.py`` asserts the
# pair now.

#: The provenance lattice. ``OTHER`` is the default, and the only safe
#: default: an expression this checker cannot account for may be a caller's.
LITERAL = "a string literal of this package"
LITERAL_SEQ = "a sequence whose every element is a literal"
LITERAL_MAP = "a mapping whose every value is a literal"
OTHER = "NOT traceable to a literal"

#: The sqlite3 methods that take SQL text as their first argument.
EXECUTORS = {"execute", "executemany", "executescript"}

#: ``name.append(x)`` keeps ``name`` literal-only when ``x`` is a literal, and
#: ``name.extend(xs)`` when ``xs`` is a literal-only sequence. Any *other*
#: method call on a bare name demotes it, which covers ``insert``, ``update``,
#: slice assignment and whatever arrives later without an allow-list that has
#: to be maintained against the standard library.
ACCUMULATORS = {"append": LITERAL, "extend": LITERAL_SEQ}

#: Passes :func:`module_env` allows itself. It ascends from ``{}`` — the
#: bottom of the lattice — with every demotion applied inside the loop, so a
#: truncated run leaves names at :data:`OTHER`, which is refused rather than
#: accepted. Two was enough only for "a constant declared below its first
#: use"; a chain of module-level copies needs one pass per link.
_MODULE_PASSES = 12

#: Passes :func:`scope_env` allows itself before giving up. The loop ascends
#: from the bottom of the lattice and breaks as soon as it is stable, so a
#: truncated run leaves names at :data:`OTHER` — refused, not accepted. The
#: bound therefore buys false-positive headroom on a long legitimate chain and
#: nothing else; the real package's longest is two hops.
_SCOPE_PASSES = 12

#: Methods that change a container in place. A module-level constant one of
#: these is called on is not a constant, so it is demoted wherever it is read:
#: ``_EQUALITY`` earns its literal provenance from its declared values, and an
#: ``_EQUALITY.update(...)`` anywhere in the module would end that.
MUTATORS = frozenset(
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
    return left if left == right else OTHER


def _note(accumulated: dict[str, str], name: str, kind: str) -> None:
    """Record ``name``'s provenance as the meet over every binding seen."""
    accumulated[name] = _meet(accumulated[name], kind) if name in accumulated else kind


def target_names(target: ast.expr) -> set[str]:
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
    """Classify one expression. Every unrecognized shape is :data:`OTHER`."""
    if isinstance(node, ast.Constant):
        return LITERAL if isinstance(node.value, str) else OTHER
    if isinstance(node, ast.Name):
        return env.get(node.id, OTHER)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        if all(_provenance(element, env) == LITERAL for element in node.elts):
            return LITERAL_SEQ
        return OTHER
    if isinstance(node, ast.Dict):
        # The keys may be anything; it is the values that become SQL text.
        if node.values and all(_provenance(value, env) == LITERAL for value in node.values):
            return LITERAL_MAP
        return OTHER
    if isinstance(node, ast.Subscript):
        # ``_EQUALITY[column]`` — whatever the key is, the value is a literal.
        return LITERAL if _provenance(node.value, env) == LITERAL_MAP else OTHER
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            pair = (_provenance(node.left, env), _provenance(node.right, env))
            if pair == (LITERAL, LITERAL):
                return LITERAL
            if pair == (LITERAL_SEQ, LITERAL_SEQ):
                return LITERAL_SEQ
        return OTHER  # ``%`` is interpolation; the rest is not string building
    if isinstance(node, ast.JoinedStr):
        # An f-string with nothing substituted is a literal; one with any
        # substitution is the textbook vector, whatever its literal parts say.
        if any(isinstance(part, ast.FormattedValue) for part in node.values):
            return OTHER
        return LITERAL
    if isinstance(node, ast.IfExp):
        return _meet(_provenance(node.body, env), _provenance(node.orelse, env))
    if isinstance(node, ast.BoolOp):
        kinds = {_provenance(value, env) for value in node.values}
        return kinds.pop() if len(kinds) == 1 else OTHER
    if isinstance(node, ast.Call):
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "join"
            and len(node.args) == 1
            and _provenance(func.value, env) == LITERAL
        ):
            return LITERAL if _provenance(node.args[0], env) == LITERAL_SEQ else OTHER
        # Every other call returns a value this checker cannot see into,
        # ``.format()`` and a helper that returns a statement included.
        return OTHER
    return OTHER


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


def rebinding_names(scope: ast.AST) -> set[str]:
    """Names a scope binds by a construct that carries no provenance.

    A ``for``, ``with``, ``except``, walrus or ``match`` target is whatever
    the subject happened to be, a plain ``import`` binds a module object, and
    ``global``/``nonlocal`` hands the binding to someone else.

    Shared by :func:`_opaque_names` (function scope) and :func:`module_env`
    (module scope) **because the two had drifted**. Measured: module scope
    modelled only ``ImportFrom``, ``Assign`` and ``AnnAssign``, so
    ``for _TEMPLATE in [_TEMPLATE + os.environ["X"]]: pass`` at module level
    kept its literal provenance and was accepted, while the identical
    construct inside a function was refused. One loop, two callers.
    """
    names: set[str] = set()
    for node in _scope_nodes(scope):
        if isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            names |= target_names(node.target)
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            names |= target_names(node.optional_vars)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, ast.NamedExpr):
            names |= target_names(node.target)
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
    between this and :func:`rebinding_names`.
    """
    names = rebinding_names(scope)
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        spec = scope.args
        names.update(arg.arg for arg in (*spec.posonlyargs, *spec.args, *spec.kwonlyargs))
        names.update(arg.arg for arg in (spec.vararg, spec.kwarg) if arg is not None)
    for node in _scope_nodes(scope):
        if isinstance(node, ast.ImportFrom):
            names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
    return names


def escaping_names(nodes: typing.Iterable[ast.AST]) -> set[str]:
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
                if func.attr in ACCUMULATORS and isinstance(func.value, ast.Name):
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
    :func:`scope_env` skips the penalty when the scope under analysis *is* a
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


def demote_escaped(env: dict[str, str], escaped: set[str]) -> None:
    """Demote every tracked container in ``escaped``, in place.

    Only containers: a string is immutable, so handing it to a function
    cannot change what it holds.
    """
    for name, kind in list(env.items()):
        if kind in (LITERAL_SEQ, LITERAL_MAP) and name in escaped:
            env[name] = OTHER


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


def _assigned_names(scope: ast.AST) -> set[str]:
    """Names this scope binds by plain assignment."""
    names: set[str] = set()
    for node in _scope_nodes(scope):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                names |= target_names(target)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            names |= target_names(node.target)
    return names


def scope_env(scope: ast.AST, inherited: dict[str, str]) -> dict[str, str]:
    """Provenance of every name visible in one scope.

    A name's provenance is the *meet* over every binding of it in the scope,
    so a variable that is a literal on one branch and a parameter on another
    is not a literal. Iterated to a fixed point, because ``store.events``
    appends to its clause list after binding it.
    """
    env = dict(inherited)
    opaque = _opaque_names(scope) | _nonlocal_names(scope)
    # EVERY name this scope binds starts at the bottom of the lattice, not at
    # the value it happens to have in the enclosing scope. That is a soundness
    # requirement and it is also what Python means: a function that assigns a
    # name makes it local for the whole body, so the enclosing binding is not
    # visible there at all — inheriting a module constant's literal provenance
    # for a name the function rebinds was wrong on the language as well as on
    # the lattice.
    #
    # The consequence is the point. Seeded from ``inherited``, this loop
    # *descended*: it started ABOVE the fixed point for any shadowed name and
    # walked down one assignment link per pass, while ``env[name] = kind``
    # overwrites rather than meets, so nothing stopped it finishing above the
    # fixed point. ``range(4)`` was measured **exactly one pass short**, and
    # five routes exploited it — a 5-hop staged SQL build whose every line but
    # one is the shape ``store/events.py`` already writes, a list/join
    # oscillator, a 6-link chain, the same pulse inside a nested class body,
    # and a cross-module form mirroring ``executescript(DDL)``. Raising the
    # count would have been the wrong fix: a longer chain needs a higher count,
    # with no bound.
    #
    # Seeded at the bottom the loop *ascends* instead, like
    # :func:`module_env` and :func:`package_envs`, which both start from
    # ``{}`` and were sound for exactly that reason. Truncating an ascent
    # leaves names LOW, which is the fail-closed direction, so the bound below
    # is only about avoiding false positives on a long legitimate chain.
    for name in opaque | _assigned_names(scope):
        env[name] = OTHER
    # Computed once — it is a property of the source, not of the iteration —
    # and applied INSIDE the loop below rather than after it. Applying it
    # after would leave ``statement = "".join(parts)`` classified as a
    # literal from an earlier pass, which is the only value that reaches an
    # ``execute`` call.
    escaped = escaping_names(_scope_nodes(scope))
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
        # covered, by :func:`module_env`'s whole-tree sweep.
        escaped |= _nested_scope_names(scope)
    demote_escaped(env, escaped)
    for _ in range(_SCOPE_PASSES):
        previous = dict(env)
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
                        for name in target_names(target):
                            _note(inferred, name, OTHER)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                # ``clauses: list[str] = []`` and its annotated-only form.
                kind = LITERAL_SEQ if node.value is None else _provenance(node.value, env)
                _note(inferred, node.target.id, kind)
            elif isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add):
                    _note(inferred, node.target.id, _provenance(node.value, env))
                else:
                    for name in target_names(node.target):
                        _note(inferred, name, OTHER)
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
                    # :data:`ACCUMULATORS` had promised this behaviour from
                    # the start, naming ``insert``; the code did the opposite.
                    want = ACCUMULATORS.get(func.attr)
                    kept = (
                        want is not None
                        and len(node.args) == 1
                        and _provenance(node.args[0], env) == want
                    )
                    _note(inferred, func.value.id, LITERAL_SEQ if kept else OTHER)
        for name, kind in inferred.items():
            if name not in opaque:
                env[name] = kind
        demote_escaped(env, escaped)
        if env == previous:
            break  # a fixed point; further passes cannot change anything
    return env


def _mutated_names(tree: ast.Module) -> set[str]:
    """Module-level names something in the module changes in place or rebinds.

    A module-level ``match`` is exotic, but its capture binds a module name as
    surely as an assignment does, and :func:`module_env` reads only
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
                    names |= target_names(target)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                names |= target_names(target)
        elif isinstance(node, ast.Global):
            names.update(node.names)
        elif isinstance(node, ast.pattern):
            names |= _pattern_bound_names(node)
        elif isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in MUTATORS
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


def module_env(name: str, tree: ast.Module, package: dict[str, dict[str, str]]) -> dict[str, str]:
    """Module-level provenance, resolving ``from <module> import NAME``.

    This has to cross files or the real package fails its own check:
    ``store.events`` runs ``executescript(DDL)`` on a literal declared in
    ``store.schema``. An import that cannot be resolved stays
    :data:`OTHER`, so an unmodelled import shape fails loudly at the
    ``execute`` call rather than passing quietly.
    """
    env: dict[str, str] = {}
    # Computed once, and applied INSIDE the loop below. They used to be applied
    # after it, which is the same defect :func:`scope_env` carried one scope
    # down: a copy taken from a demoted name was computed during the loop,
    # while that name was still a literal, and the demotion then landed only on
    # the original. Measured accepted — a module doing
    # ``for _TEMPLATE in [_TEMPLATE + os.environ[...]]: break`` and then
    # ``_STATEMENT = _TEMPLATE`` executed ``_STATEMENT``, and the list form
    # (``_PARTS.append(os.environ[...])`` then ``"".join(_PARTS)``) did the
    # same. The taint source at module scope is the environment rather than a
    # caller, which is what this package's own ``rebinding_names`` docstring
    # already uses as the canonical module-scope taint.
    suspect = rebinding_names(tree) | _mutated_names(tree)
    escaped = escaping_names(ast.walk(tree))
    for _ in range(_MODULE_PASSES):
        previous = dict(env)
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
                    _note(inferred, alias.asname or alias.name, source.get(alias.name, OTHER))
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
                            OTHER if chained else _provenance(node.value, env),
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
                augmented = _provenance(node.value, env) if isinstance(node.op, ast.Add) else OTHER
                _note(inferred, node.target.id, augmented)
        env = inferred
        for rebound in suspect:
            if rebound in env:
                env[rebound] = OTHER
        demote_escaped(env, escaped)
        if env == previous:
            break  # a fixed point; further passes cannot change anything
    return env


def _evaluated_in_enclosing_scope(child: ast.AST) -> list[ast.expr]:
    """Parts of a nested scope that Python evaluates in the *enclosing* frame.

    A decorator expression, an argument default and a class's bases all run
    where the ``def``/``class`` statement is written, not inside the scope it
    creates. Descending into the whole node with the inner env therefore
    classified them against the wrong bindings. Measured accepted:

        def query(conn, vendor):
            statement = _SELECT + vendor          # not a literal

            def _run(_rows=conn.execute(statement)):
                statement = _SELECT               # a literal, INNER scope
                return (_rows, statement)

            return _run()

    The default argument executes the *outer* ``statement``, which carries
    ``vendor``; the checker read the inner rebinding and called it a literal.

    Annotations are deliberately **not** included. Under
    ``from __future__ import annotations`` — which every module in this
    package uses — they are never evaluated at all, so classifying them would
    refuse code that cannot run.
    """
    parts: list[ast.expr] = list(getattr(child, "decorator_list", []))
    spec = getattr(child, "args", None)
    if isinstance(spec, ast.arguments):
        parts += [default for default in spec.defaults if default is not None]
        parts += [default for default in spec.kw_defaults if default is not None]
    if isinstance(child, ast.ClassDef):
        parts += list(child.bases) + [keyword.value for keyword in child.keywords]
    return parts


def _scope_body(child: ast.AST) -> list[ast.AST]:
    """A nested scope's own statements. ``Lambda.body`` is a bare expression."""
    body = getattr(child, "body", [])
    return list(body) if isinstance(body, list) else [body]


def executed_statements(
    node: ast.AST, env: dict[str, str], scope: str
) -> Iterator[tuple[int, str, str, str]]:
    """Yield ``(line, provenance, scope, source)`` per executed statement."""
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in EXECUTORS:
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
        yield from _walk_one(child, env, scope)


def _walk_one(
    node: ast.AST, env: dict[str, str], scope: str
) -> Iterator[tuple[int, str, str, str]]:
    """Dispatch one node: a nested scope is split, anything else inherits ``env``.

    Mutually recursive with :func:`executed_statements`, and separate from it
    for a reason that cost a regression. The split used to live inline in that
    function's child loop, so handing it a nested ``FunctionDef`` *as the node*
    rather than as a child skipped the split entirely — a class's methods were
    then walked with the class body's env and labelled with the class's scope
    (``s.Store`` instead of ``s.Store.count_before``), which quietly re-opened
    two pinned routes. The decision belongs to the node, not to the position it
    was found in.
    """
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
        # What runs HERE keeps this env; only the body gets the nested one.
        for outer in _evaluated_in_enclosing_scope(node):
            yield from executed_statements(outer, env, scope)
        inner_env = scope_env(node, env)
        inner = "<lambda>" if isinstance(node, ast.Lambda) else node.name
        for statement in _scope_body(node):
            yield from _walk_one(statement, inner_env, f"{scope}.{inner}")
    else:
        yield from executed_statements(node, env, scope)


def package_envs(sources: dict[str, str]) -> dict[str, dict[str, str]]:
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
        suspect |= escaping_names(ast.walk(tree))
    package: dict[str, dict[str, str]] = {}
    for _ in range(3):  # resolve imports between the package's own modules
        package = {name: module_env(name, tree, package) for name, tree in trees.items()}
    for env in package.values():
        demote_escaped(env, suspect)
    return package


def statement_sites(sources: dict[str, str]) -> list[tuple[str, int, str, str]]:
    """Every statement handed to sqlite3 in ``sources``, with its provenance."""
    package = package_envs(sources)
    sites: list[tuple[str, int, str, str]] = []
    for name, text in sorted(sources.items()):
        for line, kind, scope, source in executed_statements(ast.parse(text), package[name], name):
            sites.append((f"{name}:{line} in {scope}", line, kind, source[:160]))
    return sites


def non_literal_statements(sources: dict[str, str]) -> list[str]:
    return [
        f"{where}: {kind}: {source}"
        for where, _line, kind, source in statement_sites(sources)
        if kind != LITERAL
    ]


# --------------------------------------------------------------------------
# Source discovery
# --------------------------------------------------------------------------


def sources_for(roots: Iterable[Path], repo: Path) -> dict[str, str]:
    """Every ``*.py`` under ``roots``, keyed by dotted module name.

    The key is what every finding is reported against, so it is derived from
    the path relative to ``repo`` rather than from an import: nothing here
    imports the code it judges.
    """
    return {
        ".".join(path.relative_to(repo).with_suffix("").parts): path.read_text(encoding="utf-8")
        for root in roots
        for path in sorted(root.rglob("*.py"))
    }


#: The one top-level Python directory the sweep leaves out, and why. The test
#: suite plants the very routes this analysis refuses — ``sys.modules``
#: substitution, ``setattr`` on an imported module, a call of a call — because
#: that is how the refusals are proved. Sweeping it would assert that the
#: evidence does not exist.
UNSWEPT = frozenset({"tests"})


def shipped_package_roots(repo: Path) -> list[Path]:
    """Every top-level directory holding Python, minus :data:`UNSWEPT`.

    Derived by walking rather than hand-listed, so a package added to the
    repository is swept the day it lands and nobody has to remember a list.
    ``tests/unit/test_gate_scope_parity.py`` pins the result against that
    file's canonical package set, so a directory that is in neither
    ``PACKAGES`` nor ``UNGATED`` fails there rather than being swept silently.
    """
    return sorted(
        path
        for path in repo.iterdir()
        if path.is_dir()
        and not path.name.startswith(".")
        and path.name not in UNSWEPT
        and any(path.rglob("*.py"))
    )


# --------------------------------------------------------------------------
# Shape rules: the three preconditions the analysis above depends on
# --------------------------------------------------------------------------
#
# Each returns findings instead of asserting, so one swept source set can be
# judged by all three and the test module decides what to say about them.

#: Builtins that read or write a namespace as a mutable mapping. Through any
#: of them a module constant can be rebound past every rule below.
NAMESPACE_BUILTINS = frozenset({"globals", "vars", "locals", "setattr", "delattr"})

#: Attributes that ARE a namespace, whatever they hang off. Unlike ``modules``
#: and ``__dict__`` — which are checked only against an imported module base,
#: because ``.modules`` is a plausible ordinary attribute and ``record.__dict__``
#: on a dataclass is ordinary introspection (``compliance/evidence.py`` does it)
#: — none of these has any meaning except "the globals of something".
#:
#: Found by asking what the imported-base restriction leaves open, and both
#: answers were reachable on merged code: ``run.__globals__["_TEMPLATE"] = ...``
#: where ``run`` is a function *in the same module* (no import to restrict
#: against), and ``inspect.currentframe().f_globals["_TEMPLATE"] = ...``, which
#: is not a call-of-a-call either so that rule does not see it. Measured at
#: zero occurrences across every shipped package, so the ban is free.
NAMESPACE_ATTRIBUTES = frozenset({"__globals__", "f_globals", "f_locals", "f_builtins"})

#: Calls that can hand back a module object named by a string, so the module
#: arrives under a name no ``import`` statement bound and no rule below
#: watches. Measured at zero occurrences across every shipped package.
#: ``getmodule`` and ``__import__`` joined after review: ``inspect.getmodule(
#: run)`` hands back the *current* module from an ordinary same-module
#: function, and ``builtins.__import__("pkg.mod", fromlist=[...])`` is a
#: *qualified* ``__import__``, which :data:`MODULE_FACTORY_NAMES` cannot see
#: because that set matches a bare ``Name``. Both were measured accepted.
MODULE_FACTORY_ATTRIBUTES = frozenset({"import_module", "reload", "getmodule", "__import__"})
MODULE_FACTORY_NAMES = frozenset({"__import__", "__builtins__"})

#: The attribute-access dunders. Ordinary attribute syntax is what this
#: repository writes, so these are refused on any base: ``events.__setattr__(
#: "_TEMPLATE", clause)`` is an assignment the assignment clause cannot see
#: (it is a ``Call``), and ``events.__getattribute__("__dict__").update(...)``
#: reaches a namespace through a receiver that is a ``Call`` rather than an
#: ``Attribute``. Both were measured accepted. Zero occurrences shipped.
ATTRIBUTE_ACCESS_DUNDERS = frozenset(
    {"__setattr__", "__getattribute__", "__getattr__", "__delattr__"}
)

#: Namespace names used as *strings* rather than as attributes, which is how
#: ``__getattribute__("__dict__")`` evades :data:`NAMESPACE_ATTRIBUTES`.
NAMESPACE_STRINGS = frozenset({"__dict__"}) | NAMESPACE_ATTRIBUTES


def _attribute_base(expression: ast.expr) -> str | None:
    """The bare name an attribute/subscript chain hangs off, if any."""
    while isinstance(expression, (ast.Attribute, ast.Subscript)):
        expression = expression.value
    return expression.id if isinstance(expression, ast.Name) else None


def _module_bases(
    nodes: Iterable[ast.AST], module: str, swept: frozenset[str]
) -> tuple[set[str], set[str]]:
    """``(every imported module base, bases that bind a SWEPT module)``.

    The distinction is the whole correction this function carries, and it runs
    in both directions.

    **Wider**, because a ``from`` import binds a module too. The previous rule
    collected bases from ``ast.Import`` aliases only — its docstring said so —
    and ``store/`` binds every sibling with ``from store.schema import
    <names>``, so no sibling *module* was ever bound by a plain ``import``
    anywhere in the package. Three of the six routes that rule claimed to
    forbid therefore needed a binding the package does not use, and
    "measured at zero occurrences" was true of them for that reason. Measured
    on merged code: ``from store import events`` followed by
    ``events._COUNT_BEFORE = "SELECT ... WHERE " + clause`` planted in
    ``store/schema.py`` was **accepted** by both the lattice and the shape
    rule, while the ``import store.events as events`` spelling of the same
    line was refused. Aliased, unaliased and relative (``from . import
    events``) spellings all evaded; all four are pinned now.

    **Narrower**, because only a swept module's globals can carry provenance.
    The lattice trusts exactly one thing: a bare name bound in a module of the
    swept set. A cross-module *attribute* read is ``OTHER`` by default
    (:func:`provenance` has no ``ast.Attribute`` branch), so corrupting what
    the lattice trusts means writing ``<swept module>.<name> = ...``.
    Mutating a stdlib or third-party namespace cannot do it, and the previous
    rule flagged those anyway: measured, ``scripts/`` carries fifteen
    ``sys.path.insert(0, str(REPO_ROOT))`` calls, ``compliance/`` one, and
    ``dashboard/`` one ``st.session_state[...] = ...``. Every one of the
    seventeen is a false positive of a rule about SQL provenance, and under
    the old form the first ``conn.execute`` added to ``scripts/`` would have
    made a gate demand their removal. The registry clause below is the
    exception and keeps *any* module base, because ``sys.modules`` reaches
    every module whether it is swept or not.

    One more thing the narrowing had to get right, found by re-reading this
    function rather than by a planted route: **a dotted name reaches a whole
    subtree.** ``import store.events`` binds ``store``, not ``store.events``,
    and the swept set is keyed by *file* — it holds ``store.events`` and never
    the bare ``store``. A membership test on the bound name therefore made
    ``import store.events`` followed by ``store.events._COUNT_BEFORE = clause``
    a non-base, which the old ``ast.Import``-only rule had caught; the
    narrowing would have traded one evasion for another. The same hole opened
    for a package: ``from agents import tools`` binds a package whose swept
    members are ``agents.tools.*`` and whose own name is never a key. So the
    test is equals-*or-prefix* on the namespace a binding reaches, for both
    statement forms, and both spellings are pinned.
    """
    package = module.rsplit(".", 1)[0] if "." in module else ""

    def _reaches_swept(dotted: str) -> bool:
        """Does ``dotted`` name a swept module, or a package holding one?

        Keyed by file, so ``store`` and ``agents.tools`` are never themselves
        keys while everything under them is. A binding that reaches the
        subtree can rebind any global in it.
        """
        return any(name == dotted or name.startswith(f"{dotted}.") for name in swept)

    imported: set[str] = set()
    swept_bases: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                # `import a.b` binds `a` and reaches `a.*`; `import a.b as c`
                # binds `c` and reaches `a.b.*`. Either way the namespace the
                # binding reaches is named by `alias.name` or an ancestor of
                # it, so probing `alias.name` answers both.
                bound = alias.asname or alias.name.split(".")[0]
                imported.add(bound)
                if _reaches_swept(alias.name if alias.asname else alias.name.split(".")[0]):
                    swept_bases.add(bound)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative: resolve against this module's package
                parts = package.split(".") if package else []
                root = ".".join(parts[: len(parts) - node.level + 1]) if parts else ""
                prefix = f"{root}.{node.module}" if node.module else root
            else:
                prefix = node.module or ""
            for alias in node.names:
                # `from a import b` binds a MODULE OR PACKAGE iff `a.b` names
                # one, or holds one; otherwise `b` is an ordinary value and
                # not a namespace at all.
                if _reaches_swept(f"{prefix}.{alias.name}"):
                    bound = alias.asname or alias.name
                    imported.add(bound)
                    swept_bases.add(bound)
    return imported, swept_bases


def _written_attribute(expression: ast.expr) -> str | None:
    """The attribute name a write actually lands on, past any subscripts.

    ``mod._EQUALITY["vendor"] = clause`` writes *into* ``_EQUALITY``, so the
    name that matters is ``_EQUALITY`` and not the subscript.
    """
    probe = expression
    while isinstance(probe, ast.Subscript):
        probe = probe.value
    return probe.attr if isinstance(probe, ast.Attribute) else None


def _swept_imports_in(scope: ast.AST, module: str, swept: frozenset[str]) -> set[str]:
    """Names bound to a swept module by an import **in this scope only**.

    :func:`_module_bases` takes nodes rather than a tree precisely so this can
    hand it ``_scope_nodes(scope)``, which stops at a nested scope.
    """
    return _module_bases(_scope_nodes(scope), module, swept)[1]


def _scoped_swept_bases(
    scope: ast.AST, module: str, swept: frozenset[str], inherited: frozenset[str]
) -> frozenset[str]:
    """Which names name a swept module *in this scope*, honouring shadowing.

    Review filed this as a P2 and it was right. The bases were collected with
    one module-wide ``ast.walk``, so a ``from ingest import identity`` anywhere
    in a file made **every** ``identity`` load in that file a swept-module
    binding — and an unrelated ``def f(identity): return identity`` was then
    refused for a load that is a parameter and cannot be the module. That is
    not hypothetical: the swept bindings measured in ``ingest/normalize.py``
    are ``cloud``, ``email``, ``endpoint``, ``identity``, ``keyvalue`` and
    ``network``, every one of them a plausible parameter name.

    A scope's own imports bind; everything :func:`_opaque_names` reports
    shadows, which is parameters, ``for``/``with``/``except`` targets, a
    walrus, a plain ``import``, a ``def``/``class`` name, pattern captures and
    other ``from`` imports. A plain ``Assign`` deliberately does **not**
    shadow: AST order is not flow order, so a single per-scope set cannot tell
    ``events = 3`` before a write from one after it, and keeping the name a
    module binding is the fail-closed reading.
    """
    bound_here = _swept_imports_in(scope, module, swept)
    shadowed = _opaque_names(scope) - bound_here
    return frozenset((inherited - shadowed) | bound_here)


def _scoped_module_findings(
    scope: ast.AST,
    module: str,
    swept: frozenset[str],
    attribute_bases: set[int],
    inherited: frozenset[str],
) -> list[str]:
    """The three swept-module rules, applied per lexical scope."""
    active = _scoped_swept_bases(scope, module, swept, inherited)
    findings: list[str] = []
    for node in _scope_nodes(scope):
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in active
            and id(node) not in attribute_bases
        ):
            findings.append(
                f"{module}:{node.lineno}: the swept module bound to {node.id!r} is taken "
                f"as a value rather than used as an attribute base, from which it can be "
                f"rebound to a name no rule here watches: {ast.unparse(node)[:120]}"
            )
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete)):
            targets = node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
            for target in targets:
                if (
                    isinstance(target, (ast.Attribute, ast.Subscript))
                    and _attribute_base(target) in active
                ):
                    findings.append(
                        f"{module}:{node.lineno}: writing into a swept module's namespace "
                        f"rebinds a constant that module believes is sealed: "
                        f"{ast.unparse(target)[:120]}"
                    )
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in MUTATORS
            and isinstance(node.func.value, (ast.Attribute, ast.Subscript))
            and _attribute_base(node.func.value) in active
        ):
            findings.append(
                f"{module}:{node.lineno}: mutating a container held in a swept module "
                f"skips every demotion pass, which needs a bare name receiver: "
                f"{ast.unparse(node)[:120]}"
            )
    for child in _nested_scopes(scope):
        findings += _scoped_module_findings(child, module, swept, attribute_bases, active)
    return findings


def _nested_scopes(scope: ast.AST) -> list[ast.AST]:
    """The scopes directly inside ``scope``, without descending past them."""
    found: list[ast.AST] = []
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            found.append(node)
            continue
        stack.extend(ast.iter_child_nodes(node))
    return found


def namespace_findings(sources: dict[str, str]) -> list[str]:
    """Routes by which a swept module's global can be rebound. Closed by shape.

    This is the one class of route that **analysis cannot close**, and the
    reason is a language property rather than a gap in the lattice: a module's
    globals are an ordinary mutable mapping that any other module can reach.
    An adversarial pass measured six spellings of it against merged code, each
    leaving a constant classified as a literal while the executed statement
    carried a caller's value:

    * ``globals()["_TEMPLATE"] = "SELECT ... WHERE " + clause`` —
      :func:`target_names` walks the target, finds the ``Name`` ``globals``,
      and dutifully demotes *that*.
    * ``sys.modules[__name__].__dict__.update(OVERRIDES)`` — the same thing
      respelled, and it walked past the narrower version of this very rule.
    * ``events.WHERE_VENDOR = clause`` from a sibling module. Note what this
      defeats: :func:`demote_escaped` exempts strings because a string is
      immutable, which is true of the *object* and false of the *binding*.
    * ``setattr(events, name, clause)`` — the same route with a computed name,
      so no analysis could know which constant it hits.
    * ``schema._EQUALITY[column] = clause`` and
      ``schema._EQUALITY.update(extra)`` — ``update`` is in :data:`MUTATORS`,
      but both demotion passes require a bare ``Name`` receiver, so an
      attribute receiver skipped the check entirely.
    * ``from schema import *`` layered over a locally declared literal, which
      binds the name ``"*"`` and meets with nothing.

    Each is forbidden outright instead. Unlike the lattice it is *sound*:
    there is no provenance argument to get wrong. See :func:`_module_bases`
    for the correction that made three of those six reachable in the spelling
    this repository actually writes — and for why ordinary instance state
    (``self._conn``, ``self._cache.append(...)``) and stdlib namespaces
    (``sys.path.insert``) are deliberately untouched.

    **Three further rules close module *identity*, which review showed the six
    above do not.** Codex filed a P1: narrowing the assignment clause to swept
    module bases dropped ``import math as sink; from sample import events; sink
    = events; sink._SQL = clause``, which the old ast.Import-only rule refused
    only because ``sink`` happened to have been bound by an ``import``.
    Measuring the class rather than the example showed the report understated
    it — **nine sibling spellings were accepted by the baseline rule too** (a
    plain alias, a chained assignment, tuple unpacking, the module passed to a
    helper, the module in a container, ``importlib.import_module`` by string,
    ``__globals__`` of an imported module's function, ``__globals__`` of a
    same-module function, and ``f_globals`` of a frame). So this was mostly
    open before the narrowing, which widened it by one spelling; restoring "any
    imported base" would have re-closed one of the ten. No name-keyed lattice
    can follow module identity through an assignment, a container or a call, so
    the closure is by shape, which is this analysis's answer wherever identity
    is not decidable:

    * a swept module's binding may appear **only** as the base of an attribute
      access — the same rule shape as "an executor may appear only as a call's
      function";
    * nothing may hand back a module named by a string
      (:data:`MODULE_FACTORY_ATTRIBUTES`, :data:`MODULE_FACTORY_NAMES`);
    * :data:`NAMESPACE_ATTRIBUTES` are refused whatever they hang off, because
      none of them means anything but "the globals of something". ``__dict__``
      is deliberately NOT among them and keeps the imported-base restriction:
      banning it outright was measured at one real occurrence
      (``compliance/evidence.py`` on a dataclass record).

    Measured at **zero** findings across every shipped package — and not
    vacuously so: eleven live swept-module bindings exist across four shipped
    modules, which ``test_the_three_module_identity_rules_are_not_vacuous``
    asserts.
    """
    swept = frozenset(sources)
    # The trusted set is what makes the first rule below base-INDEPENDENT:
    # instead of asking "could this expression be a module?", which is what
    # review walked past twice, it asks "could this write land on a constant
    # the lattice trusts?" — a closed, computable set. Measured at 72 names
    # across the shipped packages, every one an UPPER_SNAKE or
    # underscore-prefixed constant, with zero attribute writes to any of them.
    trusted = {
        name
        for env in package_envs(sources).values()
        for name, kind in env.items()
        if kind != OTHER
        # Constant-shaped only, and the shape test is load-bearing. Measured on
        # the full set: `log` and `sample` earn provenance, both assigned inside
        # an ``if __name__ == "__main__":`` block (an ``if`` is not a scope, so
        # they are module-level bindings). Without this filter the rule below
        # would refuse ``anything.log = x`` across the repository, which is a
        # gate nobody would keep. The residual — a trusted name in ordinary
        # lowercase is not protected by THIS rule — is covered by the others:
        # a swept-module base by the scoped write clause, a factory call by
        # :data:`MODULE_FACTORY_ATTRIBUTES` (which refuses the call itself, not
        # the write), and a dunder by :data:`ATTRIBUTE_ACCESS_DUNDERS`. The two
        # belts each cover the other's hole, and
        # ``test_the_trusted_set_is_constants_and_nothing_wider`` pins the list
        # of lowercase names so a third one is looked at rather than absorbed.
        and (name.startswith("_") or name.isupper())
    }
    findings: list[str] = []
    for module, text in sorted(sources.items()):
        tree = ast.parse(text)
        imported, _module_wide = _module_bases(ast.walk(tree), module, swept)
        # Every node that is the receiver of an attribute access, by identity.
        # A swept module may appear ONLY here; see the escape clause.
        attribute_bases = {
            id(node.value) for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in NAMESPACE_BUILTINS
            ):
                findings.append(
                    f"{module}:{node.lineno}: {node.func.id}() reads or writes a namespace "
                    f"as a mutable mapping, through which a module constant can be rebound "
                    f"past the provenance check: {ast.unparse(node)[:120]}"
                )
            if isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
                findings.append(
                    f"{module}:{node.lineno}: a star import can replace a locally declared "
                    f"literal with a name this package cannot see: {ast.unparse(node)[:120]}"
                )
            if (
                isinstance(node, ast.Attribute)
                and node.attr in {"modules", "__dict__"}
                and _attribute_base(node) in imported
            ):
                findings.append(
                    f"{module}:{node.lineno}: reaching a module's namespace directly "
                    f"bypasses every provenance rule here: {ast.unparse(node)[:120]}"
                )
            if isinstance(node, ast.Attribute) and node.attr in NAMESPACE_ATTRIBUTES:
                findings.append(
                    f"{module}:{node.lineno}: {node.attr} IS a namespace, whatever it hangs "
                    f"off, so this reaches module globals without naming a module: "
                    f"{ast.unparse(node)[:120]}"
                )
            if isinstance(node, ast.Attribute) and node.attr in ATTRIBUTE_ACCESS_DUNDERS:
                findings.append(
                    f"{module}:{node.lineno}: {node.attr} performs an attribute read or "
                    f"write that the assignment and mutator clauses cannot see, because it "
                    f"is a call: {ast.unparse(node)[:120]}"
                )
            if isinstance(node, ast.Call) and (
                (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in MODULE_FACTORY_ATTRIBUTES
                )
                or (isinstance(node.func, ast.Name) and node.func.id in MODULE_FACTORY_NAMES)
            ):
                findings.append(
                    f"{module}:{node.lineno}: this hands back a module, so the module "
                    f"arrives under a name no import bound and no rule here watches: "
                    f"{ast.unparse(node)[:120]}"
                )
            if isinstance(node, ast.Call):
                for argument in node.args:
                    if (
                        isinstance(argument, ast.Constant)
                        and isinstance(argument.value, str)
                        and argument.value in NAMESPACE_STRINGS | trusted
                    ):
                        findings.append(
                            f"{module}:{node.lineno}: a namespace or a trusted constant is "
                            f"named as a STRING here, which reaches it without an attribute "
                            f"for any rule to match: {ast.unparse(node)[:120]}"
                        )
            # ---- base-independent: nothing may write a trusted constant ----
            if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete)):
                targets = (
                    node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
                )
                for target in targets:
                    if _written_attribute(target) in trusted:
                        findings.append(
                            f"{module}:{node.lineno}: this writes an attribute spelled like a "
                            f"constant the lattice trusts, whatever the base evaluates to: "
                            f"{ast.unparse(target)[:120]}"
                        )
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in MUTATORS
                and _written_attribute(node.func.value) in trusted
            ):
                findings.append(
                    f"{module}:{node.lineno}: this mutates an attribute spelled like a "
                    f"constant the lattice trusts, whatever the base evaluates to: "
                    f"{ast.unparse(node)[:120]}"
                )
        # ---- the swept-module rules, per lexical scope ----
        findings += _scoped_module_findings(tree, module, swept, attribute_bases, frozenset())
    return findings


def executor_as_value_findings(sources: dict[str, str]) -> list[str]:
    """An executor mentioned as a *value* rather than called. Closed by shape.

    :func:`executed_statements` recognises a sink only where ``node.func`` is
    an ``Attribute`` named in :data:`EXECUTORS`. An adversarial pass measured
    seven ``func`` shapes that are neither that nor the call-of-a-call
    :func:`call_of_call_findings` forbids — every one accepted with **zero**
    statement sites, and every one injecting at runtime:

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
    no-call-of-a-call rule, reaching a connection's ``execute`` without naming
    it as a call's function requires ``getattr``, ``methodcaller`` or
    ``__getattribute__`` — each of which is a call whose result is called, and
    so already refused.

    What held is worth recording too, because it says where the fail-closed
    default earned its keep. Every attempt to reshape the *arguments* was
    refused: ``conn.execute(*[built])``, ``conn.execute(**{"sql": built})``,
    ``conn.execute(statement := built)``, ``executemany``/``executescript``
    with a built statement, ``await conn.execute(built)``,
    ``conn.cursor().execute(built)``, a subclass overriding ``execute``, and
    even ``self.execute = conn.execute`` followed by ``self.execute(built)``
    — which is still an attribute call named ``execute``.

    And one hypothesis is **refuted**: ``sqlite3.Connection.execute(conn,
    statement)`` does make this analysis read the wrong argument — the finding
    it emits names ``conn``, and the statement at argument 1 is never
    classified — but it is refused anyway, because no expression evaluating to
    a connection can carry literal provenance. Reading the wrong argument is
    real and is not an evasion.

    Measured at **zero** findings across every shipped package: all
    twenty-five sites are already ``X.execute(...)``.
    """
    findings: list[str] = []
    for module, text in sorted(sources.items()):
        tree = ast.parse(text)
        called = {id(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and node.attr in EXECUTORS
                and id(node) not in called
            ):
                findings.append(
                    f"{module}:{node.lineno}: {ast.unparse(node)[:60]} is taken as a value "
                    f"rather than called. A sink reached through a later expression is "
                    f"invisible to the provenance check, which finds sinks in the "
                    f"function position of a call."
                )
    return findings


def call_of_call_findings(sources: dict[str, str]) -> list[str]:
    """A call whose function is itself a call. Closed by shape.

    :func:`executed_statements` looks for an ``Attribute`` call named
    ``execute``, ``executemany`` or ``executescript``. Measured: ``getattr(
    conn, "execute")(_TEMPLATE + before)`` is **not detected**, because the
    sink is a call's result rather than a named attribute. Rather than chase
    attribute names through a dataflow, forbid the shape: nothing in a shipped
    package calls the result of a call.

    This does **not** close the other residual, which is stated and not fixed:
    a statement handed to a differently *named* method —
    ``conn.run_sql(_TEMPLATE + before)`` — is not detected either, and closing
    that means deciding statically whether an arbitrary expression is SQL.
    What stands against it is that such a wrapper would have to be added to a
    swept package, where it is a reviewable change next to the only module
    holding a connection, not a configuration.

    Measured at **zero** findings across every shipped package, and at 72 in
    ``tests/`` — which is why :data:`UNSWEPT` exists and names only that
    directory.
    """
    findings: list[str] = []
    for module, text in sorted(sources.items()):
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Call):
                findings.append(
                    f"{module}:{node.lineno}: a call's result is called, which can dispatch "
                    f"a statement past the provenance check: {ast.unparse(node)[:120]}"
                )
    return findings
