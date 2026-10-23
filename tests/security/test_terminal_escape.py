# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""``scripts._terminal``: what each layer escapes, and that there is one of each.

The route tests live with each CLI (``test_sli_hardening.py`` and
``test_backup_manifest_shape.py``). These pin the functions' own contracts and
the one-copy rule, because a second private escaper is how one CLI keeps the
fix and the other does not.
"""

from __future__ import annotations

import ast
import io
import sys
from pathlib import Path

import pytest

from scripts._terminal import escape_unencodable, printable

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


# ------------------------------------------------- escape_unencodable: the encoding

_UNENCODABLE = "a \u2014 r\u00e9sum\u00e9 \u6771\u4eac\n"


def _stream(encoding: str) -> tuple[io.BytesIO, io.TextIOWrapper]:
    raw = io.BytesIO()
    return raw, io.TextIOWrapper(raw, encoding=encoding, errors="strict")


@pytest.mark.security
@pytest.mark.parametrize("name", ["stdout", "stderr"])
def test_an_unencodable_character_is_escaped_not_raised(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    raw, stream = _stream("ascii")
    with pytest.raises(UnicodeEncodeError):
        stream.write(_UNENCODABLE)  # the precondition: this case tests nothing otherwise
    monkeypatch.setattr(sys, name, stream)
    escape_unencodable()
    stream.write(_UNENCODABLE)
    stream.flush()
    assert raw.getvalue() == b"a \\u2014 r\\xe9sum\\xe9 \\u6771\\u4eac\n"
    assert stream.encoding == "ascii", "the encoding must be left as it was"


@pytest.mark.security
def test_an_encodable_stream_writes_the_same_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control: a handler that also changed the encoding would pass the test above."""
    raw, stream = _stream("utf-8")
    monkeypatch.setattr(sys, "stdout", stream)
    escape_unencodable()
    stream.write(_UNENCODABLE)
    stream.flush()
    assert raw.getvalue() == _UNENCODABLE.encode("utf-8")
    assert stream.encoding == "utf-8"


@pytest.mark.security
def test_a_stream_without_reconfigure_is_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """A test's ``StringIO`` takes any ``str``, and ``None`` (no console) discards writes."""
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    monkeypatch.setattr(sys, "stderr", None)
    escape_unencodable()


@pytest.mark.security
def test_both_report_clis_set_the_handler_through_the_one_function() -> None:
    import scripts.report_sli as report_sli
    import scripts.run_backup as run_backup

    assert run_backup.escape_unencodable is escape_unencodable
    assert report_sli.escape_unencodable is escape_unencodable


@pytest.mark.security
@pytest.mark.parametrize("script", ["report_sli.py", "run_backup.py"])
def test_the_handler_is_set_before_anything_can_print(script: str) -> None:
    """First in ``main``, ahead of argparse, which prints ``--help`` and its own errors.

    ``report_sli.py``'s ``--help`` is not ASCII, and the subprocess test in
    ``test_sli_hardening.py`` pins it behaviourally. ``run_backup.py``'s is,
    so for that CLI only the order can be pinned.
    """
    tree = ast.parse((_SCRIPTS / script).read_text(encoding="utf-8"))
    (main,) = (n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    body = main.body[1:] if ast.get_docstring(main) is not None else main.body
    first = body[0]
    assert isinstance(first, ast.Expr) and isinstance(first.value, ast.Call), ast.dump(first)
    assert isinstance(first.value.func, ast.Name), ast.dump(first)
    assert first.value.func.id == "escape_unencodable", ast.dump(first)


@pytest.mark.security
def test_no_other_script_sets_a_stream_error_handler() -> None:
    """The second layer's one-copy rule, matched on ``reconfigure`` in either spelling.

    The copy that moved here was written ``getattr(stream, "reconfigure", None)``,
    so the string is matched as well as the attribute.
    """
    offenders = []
    for path in sorted(_SCRIPTS.rglob("*.py")):
        if path.name == "_terminal.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Attribute) and node.attr == "reconfigure") or (
                isinstance(node, ast.Constant) and node.value == "reconfigure"
            ):
                offenders.append(f"{path.relative_to(_SCRIPTS.parent)}:{node.lineno}")
    assert not offenders, offenders
