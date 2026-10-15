# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""A principal is an identity in the hash chain — hold its shape closed.

``Principal`` exists so that an audit record says *who* asked, not just which
component. That only means something because it rides in ``actor``, which is
inside the hash preimage; a principal recorded outside the preimage would be
editable on disk without breaking the chain or the head signature.

Two properties therefore matter more than the rest, and both are asserted
against the real audit module rather than a restatement of it:

* the alphabet cannot admit the preimage delimiter, or a principal becomes a
  forgery primitive;
* there is no ambient path to an identity — no environment read, no
  module-level default, no ``default_factory``. The repository already
  contains that idiom four times in ``agents/tools/llm.py``, so an
  ``IANUA_PRINCIPAL`` key would read as idiomatic here while being an
  unauthenticated claim.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from agents.policies import AUDIT_FIELD_DELIMITER, Principal, PrincipalError, coerce
from agents.policies.principal import _PART, MAX_PART, MAX_RENDERED, SEPARATOR

_MODULE = Path(__file__).resolve().parents[2] / "agents" / "policies" / "principal.py"


# --------------------------------------------------------------------------
# The alphabet cannot carry the delimiter
# --------------------------------------------------------------------------


@pytest.mark.security
def test_the_alphabet_excludes_the_audit_delimiter() -> None:
    """Read from the audit module, not restated, so the two cannot drift.

    If someone widens the principal alphabet to admit ``|``, this fails rather
    than a forgery quietly becoming possible again.
    """
    assert _PART.fullmatch(AUDIT_FIELD_DELIMITER) is None
    with pytest.raises(PrincipalError):
        Principal(f"svc{AUDIT_FIELD_DELIMITER}x")
    with pytest.raises(PrincipalError):
        Principal("svc", f"ivan{AUDIT_FIELD_DELIMITER}root")


@pytest.mark.security
def test_the_separator_is_not_in_the_alphabet() -> None:
    """Otherwise a rendered principal would not split back into two parts."""
    assert _PART.fullmatch(SEPARATOR) is None
    with pytest.raises(PrincipalError):
        Principal(f"a{SEPARATOR}b")


@pytest.mark.security
@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        "a b",
        "a\tb",
        "a\nb",
        "../etc",
        "a/b",
        "a|b",
        "-leading",
        ".leading",
        "a" * 200,
        "a\x00b",
        "a;b",
        "a$(id)",
        "a`id`",
    ],
)
def test_a_value_that_is_not_an_identifier_is_refused(value: str) -> None:
    """Shell metacharacters, control characters, traversal, whitespace, length."""
    with pytest.raises(PrincipalError):
        Principal(value)


@pytest.mark.security
@pytest.mark.parametrize(
    "component,caller",
    [
        ("containment", None),
        ("mcp", "ivan"),
        ("tool", "svc-deploy@corp.example"),
        ("compliance-engine", "ci_runner"),
        ("a", "b"),
    ],
)
def test_legitimate_identities_are_accepted(component: str, caller: str | None) -> None:
    rendered = Principal(component, caller).render()
    assert AUDIT_FIELD_DELIMITER not in rendered
    assert len(rendered) <= MAX_RENDERED


# --------------------------------------------------------------------------
# Rendering and compatibility
# --------------------------------------------------------------------------


@pytest.mark.security
def test_a_component_only_principal_renders_exactly_as_the_legacy_string() -> None:
    """So old records and new ones stay directly comparable.

    This is what makes riding in ``actor`` a non-migration: a principal with
    no caller is byte-identical to the bare component string the field carried
    before this type existed.
    """
    assert Principal("containment").render() == "containment"
    assert Principal("mcp").render() == "mcp"


@pytest.mark.security
def test_rendering_round_trips_into_two_parts() -> None:
    rendered = Principal("containment", "ivan").render()
    assert rendered == "containment/ivan"
    assert rendered.split(SEPARATOR) == ["containment", "ivan"]


@pytest.mark.security
def test_coerce_passes_through_legacy_actors_and_the_report_only_marker() -> None:
    """``guarded.enforce`` appends ``[report-only]`` after rendering.

    A strict allow-list applied to the whole string would have rejected that
    existing marker and broken the staged-rollout path, so it is tolerated
    explicitly rather than by accident.
    """
    assert coerce("tool") == "tool"
    assert coerce("containment/ivan") == "containment/ivan"
    assert coerce("tool[report-only]") == "tool[report-only]"
    assert coerce(Principal("tool", "ivan")) == "tool/ivan"


@pytest.mark.security
def test_coerce_refuses_a_legacy_actor_that_could_forge() -> None:
    """Compatibility must not become a bypass of the thing being enforced."""
    for bad in ("svc|x", "a b", "", "../etc"):
        with pytest.raises(PrincipalError):
            coerce(bad)


# --------------------------------------------------------------------------
# No ambient authority
# --------------------------------------------------------------------------


@pytest.mark.security
def test_the_module_reads_no_environment_and_has_no_default_identity() -> None:
    """An identity must be supplied explicitly, never inherited from a process.

    Asserted over the AST because the repository already contains the exact
    idiom this forbids — ``field(default_factory=lambda: os.environ.get(...))``
    appears four times in ``agents/tools/llm.py``, and env-reading helpers
    exist in ``audit.py`` and ``signing.py``. A ``principal_from_env`` here
    would look idiomatic and would be an unauthenticated claim of identity.
    """
    tree = ast.parse(_MODULE.read_text(encoding="utf-8"), filename=str(_MODULE))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] != "os", "principal.py imports os"
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] != "os", "principal.py imports from os"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in {"getenv", "environ"}, "reads the environment"
        if isinstance(node, ast.Name):
            assert not node.id.endswith("_from_env"), "an env-sourced identity helper exists"


@pytest.mark.security
def test_principal_has_no_default_component() -> None:
    """Constructing one with no argument must fail, not invent an identity."""
    with pytest.raises(TypeError):
        Principal()  # type: ignore[call-arg]


@pytest.mark.security
def test_a_principal_is_immutable() -> None:
    """An identity that can be reassigned after a policy decision is not one."""
    principal = Principal("containment", "ivan")
    with pytest.raises((AttributeError, TypeError)):
        principal.caller = "root"  # type: ignore[misc]


@pytest.mark.security
def test_the_rendered_length_is_bounded_by_construction() -> None:
    """No runtime length check exists, because none could ever fire.

    Each part is capped at ``MAX_PART`` by the alphabet, so two parts plus a
    one-character separator cannot exceed ``MAX_RENDERED``. Asserted here
    rather than guarded at runtime: a check that cannot trigger reads like
    protection while providing none. If the alphabet is ever widened, this
    fails and the guard question reopens.
    """
    longest = "a" + "b" * (MAX_PART - 1)
    assert _PART.fullmatch(longest), "MAX_PART disagrees with the alphabet"
    assert _PART.fullmatch(longest + "c") is None, "the alphabet admits a longer part"
    rendered = Principal(longest, longest).render()
    assert len(rendered) == MAX_RENDERED
    assert MAX_PART * 2 + len(SEPARATOR) == MAX_RENDERED


@pytest.mark.security
def test_str_renders_the_audit_form() -> None:
    """So an accidental f-string interpolation produces the safe scalar."""
    assert f"{Principal('containment', 'ivan')}" == "containment/ivan"
    assert str(Principal("mcp")) == "mcp"
