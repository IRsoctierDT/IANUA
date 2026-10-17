# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Malformed YAML must exit the two YAML gates with their documented code.

`build_attack_navigator.py` and `build_behavior_index.py` both document
"exit 2: bad input" and both caught `(ValueError, OSError)`. `yaml.YAMLError`
is neither, so a rule with unbalanced brackets escaped `main()` as a
`ParserError` traceback: non-zero by accident of the interpreter, not by the
gate's own decision, and with no `error:` line for the author to act on. The
navigator additionally let `AttackError` (corpus unavailable or tampered)
escape the same way. Both gates are fail-closed either way; this pins that
they fail closed deliberately.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

import scripts.build_attack_navigator as navigator
import scripts.build_behavior_index as behaviors
from attack import AttackError

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
@pytest.mark.parametrize(
    "exc", [yaml.YAMLError("probe"), AttackError("probe")], ids=["yaml", "attack"]
)
def test_navigator_exits_two_with_a_message(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], exc: Exception
) -> None:
    monkeypatch.setattr(navigator, "build_layer", _raise(exc))
    assert navigator.main(["--check"]) == 2
    assert "error: probe" in capsys.readouterr().err


@pytest.mark.unit
def test_behavior_index_exits_two_with_a_message(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(behaviors, "build_index", _raise(yaml.YAMLError("probe")))
    assert behaviors.main(["--check"]) == 2
    assert "error: probe" in capsys.readouterr().err
