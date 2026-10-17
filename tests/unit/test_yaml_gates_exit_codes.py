# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Malformed YAML must exit the two YAML gates with their documented code.

`build_attack_navigator.py` and `build_behavior_index.py` both document
"exit 2: bad input" and both caught `(ValueError, OSError)`. `yaml.YAMLError`
is neither, so a rule with unbalanced brackets escaped `main()` as a
`ParserError` traceback: non-zero by accident of the interpreter, not by the
gate's own decision, and with no `error:` line for the author to act on.
Both gates are fail-closed either way; this pins that they fail closed
deliberately.

An earlier version of this docstring said the navigator also let
`AttackError` escape. Measured by review, it did not: `AttackError` is a
`ValueError` (attack/errors.py), so that case passed on the unpatched script
and pinned nothing; the premise is now asserted instead. Review also found
rule input that escaped as `RecursionError` or `MemoryError` and an
unreadable committed output that escaped `--check`; those are pinned below.
"""

from __future__ import annotations

import functools
from pathlib import Path
from types import ModuleType

import pytest
import yaml

import scripts.build_attack_navigator as navigator
import scripts.build_behavior_index as behaviors
from attack import AttackError
from scripts._rule_yaml import MAX_RULE_BYTES, MAX_RULE_DEPTH, load_rule

_BROKEN = "title: broken\ntags: [attack.t1059\n"


@pytest.mark.unit
def test_the_premise_a_yaml_error_is_not_a_value_error(tmp_path: Path) -> None:
    """If PyYAML ever reparents YAMLError the extra clause becomes redundant; say so."""
    (tmp_path / "broken.yml").write_text(_BROKEN, encoding="utf-8")
    for build in (navigator.build_layer, behaviors.build_index):
        with pytest.raises(yaml.YAMLError) as caught:
            build(tmp_path)
        assert not isinstance(caught.value, (ValueError, OSError))


def _raise(exc: BaseException):  # type: ignore[no-untyped-def]
    def boom() -> dict[str, object]:
        raise exc

    return boom


@pytest.mark.unit
def test_the_premise_an_attack_error_is_a_value_error() -> None:
    """Why neither handler needs an `AttackError` entry for exit 2."""
    assert issubclass(AttackError, ValueError)


@pytest.mark.unit
def test_navigator_exits_two_with_a_message(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(navigator, "build_layer", _raise(yaml.YAMLError("probe")))
    assert navigator.main(["--check"]) == 2
    assert "error: probe" in capsys.readouterr().err


@pytest.mark.unit
def test_behavior_index_exits_two_with_a_message(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(behaviors, "build_index", _raise(yaml.YAMLError("probe")))
    assert behaviors.main(["--check"]) == 2
    assert "error: probe" in capsys.readouterr().err


def _alias_chain(links: int) -> str:
    chain = "".join(f"x{i}: &x{i} [*x{i - 1}]\n" for i in range(1, links))
    return f"x0: &x0 []\n{chain}title: *x{links - 1}\ndescription: *x{links - 1}\n"


# Measured on 965e4cd: each escaped both gates as an exit-1 RecursionError
# traceback with no `error:` line. Both fail fast if the fix regresses.
_HOSTILE_RULES = {
    "flow-depth-493": "title: probe\ntags: " + "[" * 493 + "]" * 493 + "\n",
    "alias-chain-3000": _alias_chain(3000),
}


@pytest.mark.unit
@pytest.mark.parametrize("gate", [navigator, behaviors], ids=["navigator", "behaviors"])
@pytest.mark.parametrize("content", list(_HOSTILE_RULES.values()), ids=list(_HOSTILE_RULES))
def test_hostile_rule_input_exits_two_with_a_message(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    gate: ModuleType,
    content: str,
) -> None:
    (tmp_path / "zz_probe.yml").write_text(content, encoding="utf-8")
    name = "build_layer" if gate is navigator else "build_index"
    monkeypatch.setattr(gate, name, functools.partial(getattr(gate, name), tmp_path))
    assert gate.main(["--check"]) == 2
    assert "error: " in capsys.readouterr().err


_LAUGHS = (
    'a0: &a0 "lol"\n'
    + "".join(f"a{i}: &a{i} [" + ", ".join([f"*a{i - 1}"] * 10) + "]\n" for i in range(1, 10))
    + "title: *a9\n"
)


@pytest.mark.unit
def test_load_rule_refuses_what_would_recurse_or_exhaust_memory(tmp_path: Path) -> None:
    """Each bound directly. Under a 1.5 GB cap on 965e4cd, a billion-laughs
    title and a rule symlinked to `/dev/zero` raised MemoryError; `/dev/null`
    stands in for the device here, since a regressed read of `/dev/zero`
    would exhaust memory instead of failing."""
    cases = {
        "laughs": _LAUGHS,
        "deep": "k: " + "[" * MAX_RULE_DEPTH + "]" * MAX_RULE_DEPTH + "\n",
        "big": "#" * MAX_RULE_BYTES + "\n",
    }
    for name, content in cases.items():
        (tmp_path / f"{name}.yml").write_text(content, encoding="utf-8")
    (tmp_path / "latin1.yml").write_bytes(b"title: caf\xe9\n")
    (tmp_path / "device.yml").symlink_to("/dev/null")
    for name in (*cases, "latin1", "device"):
        with pytest.raises((ValueError, yaml.YAMLError)):
            load_rule(tmp_path / f"{name}.yml")
    edge = tmp_path / "edge.yml"
    edge.write_text("k: " + "[" * (MAX_RULE_DEPTH - 1) + "]" * (MAX_RULE_DEPTH - 1) + "\n")
    assert isinstance(load_rule(edge), dict), "the depth bound must admit its own limit"


@pytest.mark.unit
@pytest.mark.parametrize("gate", [navigator, behaviors], ids=["navigator", "behaviors"])
def test_an_unreadable_committed_output_exits_two_with_a_message(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    gate: ModuleType,
) -> None:
    """Measured on 965e4cd: a non-UTF-8 committed output escaped `--check` as a traceback."""
    output = tmp_path / "output.json"
    output.write_bytes(b"\xff\xfe")
    builder, target = ("build_layer", "_OUTPUT") if gate is navigator else ("build_index", "OUTPUT")
    monkeypatch.setattr(gate, builder, lambda: {"techniques": [], "behaviors": []})
    monkeypatch.setattr(gate, target, output)
    assert gate.main(["--check"]) == 2
    assert "error: " in capsys.readouterr().err
