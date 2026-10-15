# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the evidence allow-list: what an excerpt is allowed to keep.

``raw_excerpt`` used to be a copy of the record. The store is append-only and
``event_id`` is a digest over the projection, so a copy is a permanent copy —
there is no later redaction pass to rely on, which makes the question "what
does ``ingest`` write?" the whole of the retention posture.

It is now rebuilt from the paths a signature declared it reads. These tests
hold the mechanics of that rebuild (:func:`ingest._coerce.project`) and the
declarations themselves. The *guarantee* — that un-modelled content cannot
reach a stored event — is asserted behaviourally in
``tests/security/test_ingest_hardening.py``, because a structural test of a
declaration can only ever be a proxy for it.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

from ingest import MAX_FIELD_LEN, SIGNATURES, detect_source, normalize
from ingest._coerce import project
from ingest.normalize import MODELLED_FIELDS
from ingest.parsers import cloud, email, endpoint, identity, network
from ingest.schema import MAX_NESTING_DEPTH, MAX_PROJECTED_ITEMS

_FIXTURES = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "ingest_fixtures.json").read_text(
        encoding="utf-8"
    )
)

#: The five domain modules, each owning its own signatures and declarations.
_MODULES = (cloud, email, endpoint, identity, network)


def _records() -> list[tuple[str, dict[str, Any]]]:
    return sorted((name, case) for name, case in _FIXTURES.items())


# --------------------------------------------------------------------------
# project() — the mechanics
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_an_undeclared_key_is_not_carried() -> None:
    """The whole point: a field nobody modelled has no route into the result."""
    payload = {"declared": "kept", "undeclared": "dropped"}
    assert project(payload, [("declared",)]) == {"declared": "kept"}


@pytest.mark.unit
def test_an_absent_path_is_omitted_rather_than_nulled() -> None:
    """Absent is not empty — the same rule ``text()`` enforces on every field."""
    assert project({"a": "1"}, [("a",), ("b",), ("c", "d")]) == {"a": "1"}


@pytest.mark.unit
def test_a_present_but_uncoercible_value_is_reported_as_present() -> None:
    """A key the source carried and left blank is a claim; it is not absence."""
    assert project({"a": "", "b": "  "}, [("a",), ("b",)]) == {"a": None, "b": None}


@pytest.mark.unit
def test_a_declared_path_landing_on_an_object_yields_its_shape_not_its_values() -> None:
    """An over-broad declaration may reveal which keys existed, never what was in them."""
    withheld = "a-value-no-declared-path-names"
    payload = {"userIdentity": {"arn": "arn:aws:iam::1:user/x", "accessKeyId": withheld}}
    projected = project(payload, [("userIdentity",)])
    assert projected == {"userIdentity": ["accessKeyId", "arn"]}
    assert withheld not in json.dumps(projected)


@pytest.mark.unit
def test_a_deeper_declaration_supersedes_the_shape_of_its_parent() -> None:
    """Azure declares both ``status`` and ``status.value``; the named leaf wins."""
    payload = {"status": {"value": "Succeeded", "unread": "hidden"}}
    for order in ([("status",), ("status", "value")], [("status", "value"), ("status",)]):
        projected = project(payload, order)
        assert projected == {"status": {"value": "Succeeded"}}, order
        assert "hidden" not in json.dumps(projected)


@pytest.mark.unit
def test_a_path_continuing_through_a_list_applies_to_each_element() -> None:
    """Entra's ``authenticationDetails`` is a list of method objects."""
    payload = {
        "authenticationDetails": [
            {"authenticationMethod": "Password", "unread": "hidden"},
            {"authenticationMethod": "SMS"},
            {"somethingElse": "x"},
        ]
    }
    projected = project(payload, [("authenticationDetails", "authenticationMethod")])
    assert projected == {"authenticationDetails": {"authenticationMethod": ["Password", "SMS"]}}
    assert "hidden" not in json.dumps(projected)


@pytest.mark.unit
def test_declaration_order_does_not_change_the_result() -> None:
    """Determinism: the digests and fixtures downstream depend on it."""
    payload = {"a": "1", "b": {"c": "2"}, "d": ["3", "4"]}
    paths = [("a",), ("b", "c"), ("b",), ("d",)]
    assert project(payload, paths) == project(payload, list(reversed(paths)))


@pytest.mark.unit
@pytest.mark.parametrize("shape", ["list", "mapping"])
def test_a_container_contributes_a_bounded_number_of_entries(shape: str) -> None:
    """A record carrying a thousand of something must not inflate an excerpt."""
    oversized: Any = (
        [str(index) for index in range(1000)]
        if shape == "list"
        else {f"k{index}": index for index in range(1000)}
    )
    projected = project({"field": oversized}, [("field",)])
    assert len(projected["field"]) == MAX_PROJECTED_ITEMS


def _depth(value: Any) -> int:
    """Deepest container nesting in a projected result, measured iteratively."""
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        node, level = stack.pop()
        deepest = max(deepest, level)
        if isinstance(node, dict):
            stack.extend((child, level + 1) for child in node.values())
        elif isinstance(node, list):
            stack.extend((child, level + 1) for child in node)
    return deepest


@pytest.mark.unit
def test_the_walk_stops_at_the_nesting_bound_rather_than_recursing_away() -> None:
    """Bounded by construction, not by trusting the caller to have checked.

    ``depth_within`` runs first in ``normalize``, but ``project`` is reachable
    on its own and a recursive walk is exactly what deep nesting attacks. The
    input here is nested past CPython's own recursion limit, so an unbounded
    walk does not merely produce a deep result — it raises before producing
    one. The depth assertion is what states the bound; the first version of
    this test only checked that the result serialized, which a 128-level
    walk does perfectly well, and an unbounded walk passed it.
    """
    nested: Any = "leaf"
    for _ in range(MAX_NESTING_DEPTH * 100):
        nested = [nested]
    projected = project({"field": nested}, [("field",)])
    assert json.dumps(projected)
    assert _depth(projected) <= MAX_NESTING_DEPTH + 2


@pytest.mark.unit
def test_following_a_path_through_nested_sequences_is_bounded_too() -> None:
    """The *walk* needs its own bound, not only the leaf rendering.

    A path that continues through a sequence is applied to each element, so
    nested sequences drive the walk itself — a separate recursion from the
    one that renders a leaf. Both guards were in the first draft and only
    the leaf's was load-bearing against any test, which is how a plant that
    deleted the walk's guard went unnoticed until it was looked for.
    """
    nested: Any = [{"b": "leaf"}]
    for _ in range(MAX_NESTING_DEPTH * 100):
        nested = [nested]
    projected = project({"a": nested}, [("a", "b")])
    assert json.dumps(projected)
    assert _depth(projected) <= MAX_NESTING_DEPTH + 2


@pytest.mark.unit
def test_an_attacker_chosen_key_name_is_coerced_before_it_is_rendered() -> None:
    """Keys are untrusted too: a shape listing must not carry control characters."""
    payload = {"outer": {"ok": 1, "bad\x00\x1bname": 2, "x" * (MAX_FIELD_LEN * 4): 3}}
    shape = project(payload, [("outer",)])["outer"]
    assert "\x00" not in json.dumps(shape)
    assert "\x1b" not in json.dumps(shape)
    assert all(len(name) <= MAX_FIELD_LEN for name in shape)


@pytest.mark.unit
def test_a_non_mapping_mid_path_yields_nothing_rather_than_raising() -> None:
    """Telemetry routinely disagrees with its own documented schema."""
    assert project({"a": 5}, [("a", "b")]) == {}
    assert project({"a": None}, [("a", "b")]) == {}
    assert project({}, [("a",), ()]) == {}


# --------------------------------------------------------------------------
# The declarations
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_every_signature_declares_a_non_empty_allow_list() -> None:
    """A signature with no declared fields would store no evidence at all."""
    for signature in SIGNATURES:
        assert signature.fields, signature.vendor
        for path in signature.fields:
            assert path, f"{signature.vendor}: empty path"
            assert all(isinstance(key, str) and key for key in path), signature.vendor


def _literals_outside_the_declarations(module: Any) -> set[str]:
    """Every string constant in a module, minus the ``_*_FIELDS`` tuples themselves.

    Excluding the declarations is what gives the test teeth: otherwise a path
    would corroborate itself, since the declaration *is* a string literal in
    the module.
    """
    path = Path(module.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    declarations: set[int] = set()
    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        assigned: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, assigned = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign):
            targets, assigned = [node.target], node.value
        if assigned is None:
            continue
        if not any(isinstance(t, ast.Name) and t.id.endswith("FIELDS") for t in targets):
            continue
        declarations.update(id(child) for child in ast.walk(assigned))
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in declarations
    }


@pytest.mark.unit
@pytest.mark.parametrize("module", _MODULES, ids=lambda module: Path(module.__file__).stem)
def test_every_declared_key_is_one_its_own_module_mentions(module: Any) -> None:
    """A declared key the parser never names is a typo or an invention.

    Either way the excerpt would be built on a key nobody reads, and the
    declaration would quietly claim coverage the parser does not provide.
    This checks the weaker, cheap direction; the leak itself is asserted
    behaviourally in ``tests/security``.
    """
    mentioned = _literals_outside_the_declarations(module)
    for signature in module.SIGNATURES:
        for path in signature.fields:
            for key in path:
                assert key in mentioned, (
                    f"{signature.vendor} declares {key!r}, which "
                    f"{Path(module.__file__).name} never mentions"
                )


@pytest.mark.unit
def test_the_declaration_check_would_notice_an_invented_key() -> None:
    """The guard above is only worth having if a bad declaration fails it."""
    mentioned = _literals_outside_the_declarations(email)
    assert "Subject" in mentioned
    assert "ThisKeyIsNowhereInThatModule" not in mentioned


@pytest.mark.unit
def test_modelled_fields_is_the_deduplicated_union_of_every_signature() -> None:
    expected = sorted({path for signature in SIGNATURES for path in signature.fields})
    assert list(MODELLED_FIELDS) == expected
    assert len(set(MODELLED_FIELDS)) == len(MODELLED_FIELDS)


@pytest.mark.unit
def test_a_parser_that_raises_still_gets_its_own_projection_not_the_raw_text() -> None:
    """A claimed record whose parse failed is the one case a debugger reads.

    The signature claimed it, so its declared fields are modelled whether or
    not reading them worked: the excerpt is that signature's projection, not
    the union and not the record. This branch was uncovered before this
    change, and it is reached here by a real hostile input rather than a
    patched signature — ``normalize`` accepts a mapping directly, and a
    non-string key makes ``_execve_command``'s ``re.match`` raise
    ``TypeError`` on the most common auditd record type.
    """
    record: dict[Any, Any] = {
        "type": "EXECVE",
        "exe": "/bin/sh",
        "node": "app-01",
        "undeclared": "must-not-appear",
        1: "a non-string key",
    }
    event = normalize(record)
    assert event.vendor == "unrecognized"
    assert any("auditd parser could not read this record" in note for note in event.notes)
    assert event.raw_excerpt == '{"exe": "/bin/sh", "node": "app-01", "type": "EXECVE"}'
    assert "must-not-appear" not in json.dumps(event.to_dict())


@pytest.mark.unit
def test_a_circular_record_degrades_rather_than_raising_out_of_normalize() -> None:
    """Rule 2 outranks the excerpt: no record may take the pipeline down.

    A mapping cannot be circular if it came from JSON, but ``normalize``
    accepts a mapping directly, and the serializer is shared with the
    indicator scan — which reads the record itself rather than a projection.
    """
    record: dict[str, Any] = {"host": "app-01"}
    record["self"] = record
    event = normalize(record)
    assert event.source_type == "unknown"
    assert event.raw_excerpt


@pytest.mark.unit
@pytest.mark.parametrize("name,case", _records(), ids=lambda value: value)
def test_each_fixture_still_yields_evidence_through_its_own_signature(name: str, case: Any) -> None:
    """Declarations must be live, not decorative: a real record still projects."""
    if not isinstance(case, dict):
        return
    record = case["record"]
    signature = detect_source(record)
    assert signature is not None, name
    projected = project(record, signature.fields)
    assert projected, f"{name}: the allow-list retained nothing at all"
    event = normalize(record)
    assert event.raw_excerpt == json.dumps(projected, sort_keys=True, default=str), name
