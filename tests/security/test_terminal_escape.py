# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""``scripts._terminal.printable``: what it escapes, and that there is one of it.

The route tests live with each CLI (``test_sli_hardening.py`` and
``test_backup_manifest_shape.py``). These pin the function's own contract and
the one-copy rule, because a second private escaper is how one CLI keeps the
fix and the other does not.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from scripts._terminal import printable

_SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"

#: Characters a terminal or a reader can be misled by, with the escape each
#: must become. One per class ``str.isprintable`` rejects.
_ESCAPED: dict[str, tuple[str, str]] = {
    "escape": ("\x1b", "\\x1b"),
    "carriage_return": ("\r", "\\r"),
    "newline": ("\n", "\\n"),
    "bell": ("\x07", "\\x07"),
    "delete": ("\x7f", "\\x7f"),
    "c1_csi": ("\x9b", "\\x9b"),
    "bidi_override": ("\u202e", "\\u202e"),
    "zero_width_joiner": ("\u200d", "\\u200d"),
    "line_separator": ("\u2028", "\\u2028"),
    "no_break_space": ("\xa0", "\\xa0"),
    "lone_surrogate": ("\udcff", "\\udcff"),
}


@pytest.mark.security
@pytest.mark.parametrize("case", sorted(_ESCAPED), ids=lambda value: value)
def test_every_non_printable_class_is_escaped_not_dropped(case: str) -> None:
    character, escaped = _ESCAPED[case]
    assert not character.isprintable(), "the precondition: this case tests nothing otherwise"
    result = printable(f"a{character}b")
    assert result == f"a{escaped}b"
    assert result.isprintable()


@pytest.mark.security
@pytest.mark.parametrize(
    "text",
    ["plain ascii", "r\u00e9sum\u00e9 \u6771\u4eac \u2014 ok", "back\\slash 'quote' \"dq\""],
    ids=["ascii", "non_ascii", "quotes_and_backslash"],
)
def test_printable_text_passes_through_unchanged(text: str) -> None:
    """The control: a layer that escaped too much would pass the test above."""
    assert printable(text) == text


@pytest.mark.security
def test_both_report_clis_print_through_the_one_function() -> None:
    """``run_backup.py`` keeps its old name for it, and both resolve to this module's."""
    import scripts.report_sli as report_sli
    import scripts.run_backup as run_backup

    assert run_backup._printable is printable
    assert report_sli.printable is printable


@pytest.mark.security
def test_no_other_script_defines_its_own_escaper() -> None:
    """A second private copy is how the next fix lands in one CLI and not the other.

    Matched on the predicate rather than a name: any call to ``isprintable``
    in ``scripts/`` outside ``_terminal.py`` is a new escaper or a check that
    belongs beside the one here.
    """
    offenders = []
    for path in sorted(_SCRIPTS.rglob("*.py")):
        if path.name == "_terminal.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Attribute) and node.attr == "isprintable":
                offenders.append(f"{path.relative_to(_SCRIPTS.parent)}:{node.lineno}")
    assert not offenders, offenders
