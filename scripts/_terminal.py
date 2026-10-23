# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Escaping for a terminal, for the CLIs that print text they did not write — one copy.

``scripts/run_backup.py`` and ``scripts/report_sli.py`` both print lines that
carry text from outside the program: a manifest's paths and a pass's errors in
the first, an indicator's detail in the second. That detail quotes a backup
directory's name, a store refusal and an exception message. A line that
reaches a terminal raw can rewrite what the operator sees, so each CLI escapes
where the line is printed rather than at each place the text enters. One
escape at the print covers every echo site behind it, including the ones
added later.

The function lived in ``run_backup.py`` as ``_printable`` until
``report_sli.py`` needed it too. It moved here rather than being copied,
because copies of a control drift. ``scripts/_locking.py`` records the
measured case: four copies of one lock, two fixes each applied to a subset.

Measured on ``report_sli.py`` before it used this, in text mode:

* A backup directory named ``"2026-10-23\\x1b[2J\\x1b[Hok: every objective
  met\\r"`` and holding an empty ``manifest.json`` put the raw ESC and CR on
  stdout through ``backup-present``'s detail. That cleared the terminal and
  wrote a forged "ok" line above a report that exited 1. ``measure_backup_present``
  names the newest entry under ``data/backups`` and never reads the manifest,
  so anyone who can create a directory there chooses the name.
* A name holding U+202E (RIGHT-TO-LEFT OVERRIDE) reached stdout raw, so the
  name displayed reversed.
* A name that is not valid UTF-8 reached ``print`` as lone surrogates
  (``os.scandir`` decodes with ``surrogateescape``). On a stdout with
  ``errors="strict"``, the ``en_US.UTF-8`` default, the report died with a
  traceback partway through. It survived only where the interpreter's UTF-8
  mode makes stdout ``surrogateescape``.

``--json`` needs none of this: ``json.dumps`` escapes every control character
and, with ``ensure_ascii``, everything outside ASCII. It also keeps the exact
value, which an escaped line does not.

A second layer, :func:`escape_unencodable`, covers a different fault: a
printable character the stream's encoding cannot represent. That one is the
environment's, not the text's, so it is a setting on the stream rather than a
function of the line. It lived in ``run_backup.py``'s ``main`` as a loop until
``report_sli.py`` needed it too, and moved here for the same reason.
"""

from __future__ import annotations

import sys


def printable(text: str) -> str:
    """``text`` with every non-printable character escaped as Python would spell it.

    The predicate is ``str.isprintable``. It is false for control characters
    (ESC, CR, LF, BEL, DEL and the C1 range), format characters (the bidi
    overrides, zero-width joiners), separators other than ASCII space,
    surrogates and unassigned code points. Each is replaced by the body of its
    ``repr`` (``\\x1b``, ``\\u202e``, ``\\udcff``), which is printable, so the
    result is one line of printable text whatever the input held.

    Two limits, both deliberate:

    * **Escaped, not dropped.** The operator sees that something was there,
      and where. Dropping it would show a forged name as an ordinary one.
    * **Not reversible.** A literal backslash is printable and passes through,
      so ``\\x1b`` in the output may be an escaped ESC or four printable
      characters. This is a display safeguard. ``--json`` carries the exact
      value.

    It does not make the text encodable. A printable non-ASCII character
    (``é``, or the ``—`` every ``Indicator.summary`` line carries) still
    reaches the stream as itself. :func:`escape_unencodable` is the layer for
    a stream that cannot encode it.
    """
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in text)


def escape_unencodable() -> None:
    """Make stdout and stderr escape what their encoding cannot represent, not raise.

    Sets each stream's error handler to ``backslashreplace``, so ``—`` reaches
    an ASCII stdout as ``\\u2014`` and ``é`` as ``\\xe9``. The encoding is left
    alone, so a stream that could already encode a character writes exactly
    the bytes it wrote before: a UTF-8 stdout is unchanged.

    Call it first in ``main``, before the arguments are parsed. ``--help``
    prints the module docstring, and the docstrings here are not ASCII either.

    Measured, each a traceback and none needing planted data:

    * ``run_backup.py`` (#255): an accented letter in a manifest path cut the
      report off on a non-UTF-8 stdout.
    * ``report_sli.py``, on an ASCII stdout (``LANG`` naming a locale the host
      never generated, which Python falls back from to ASCII, or
      ``PYTHONIOENCODING=ascii``): every text report died on the U+2014 that
      ``Indicator.summary`` emits. A fully healthy root printed ``ok: all 8
      objective(s) met`` and then the traceback, at exit 1, which is the code
      for a breach. ``--help`` died on the U+00B7 in its docstring, which a
      helper applied at each ``print`` would not have reached.

    stderr is included although CPython already gives it ``backslashreplace``
    whatever ``PYTHONIOENCODING`` asks for (measured), so the rule does not
    rest on that default. A stream with no ``reconfigure`` is left as it is:
    an ``io.StringIO`` a test swapped in takes any ``str``, and ``None``, when
    there is no console, discards every write.

    Process-wide by nature: this changes the interpreter's streams, not one
    write. It is not an escape for untrusted text; :func:`printable` is.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")
