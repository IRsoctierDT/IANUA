# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Pipeline error taxonomy. Imports nothing first-party, so layering is structural."""

from __future__ import annotations


class PipelineError(Exception):
    """Base class for continuous-execution failures."""


class CursorError(PipelineError):
    """The processing cursor is missing, unreadable, or not in the expected shape.

    Fails closed, and the reason is worth stating: the two silent alternatives
    are both wrong. Treating an unreadable cursor as "start from the
    beginning" reprocesses the entire store on every cycle; treating it as
    "start from now" skips every event between the last good cycle and this
    one — in a security pipeline that is a window of blindness nobody is told
    about. Refusing to run is the only honest option, because a human can then
    decide which of those they actually want.
    """


class CursorPathError(CursorError):
    """The cursor path escapes the permitted root, or is unusable.

    Separate from :class:`CursorError` because the remedy differs: a bad shape
    means the file is corrupt, a bad path means the caller asked for the wrong
    place.
    """
