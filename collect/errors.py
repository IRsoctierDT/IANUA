# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Collection error taxonomy.

Imports nothing first-party, so the layering is structural and nothing below
this module can create an import cycle — the same discipline as
``ingest/errors.py``, ``store/errors.py`` and ``pipeline/errors.py``.

Every failure here is fail-closed by intent. A collector that silently skips
an unreadable source, follows a planted link, or loses its place in a file
produces a store that *looks* complete while missing whatever it could not
read — and a partial view presented as complete is the blind spot this whole
platform exists to close.
"""

from __future__ import annotations


class CollectError(Exception):
    """Base class for collection failures."""


class SourceError(CollectError):
    """A declared log source is not something safe to read.

    Raised before the file is opened: a relative path (whose meaning depends
    on a scheduler's working directory), a path that is not a regular file, a
    symlink at the final component, or a path matching the credential
    deny-list. Refused rather than skipped, because an operator who declared a
    source is entitled to know it is not being collected — a source silently
    dropped is a blind spot nobody is told about.
    """


class OffsetError(CollectError):
    """The stored read offsets are unreadable, or the file holding them is unsafe.

    Distinct from "no offsets yet", which is a legitimate first run and reads
    as an empty set. A *corrupt* offsets file is refused instead, because the
    two plausible recoveries are both wrong: starting from zero re-ingests
    every line in every source, and starting from the end silently skips
    everything written since the last run.
    """


class CollectPathError(OffsetError):
    """The offsets file would land outside the lab-data root.

    A subclass of :class:`OffsetError` so a caller handling "offsets unusable"
    catches both without having to know which of the two it got.
    """
