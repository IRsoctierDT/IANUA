# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Ingest error taxonomy.

Deliberately imports nothing first-party, so the layering is structural: a
parser can raise these without reaching back into the platform, and nothing
below this module can create an import cycle (same discipline as
``attack/errors.py``).

The distinction that matters here is between *malformed telemetry* and *a
programming error*. Malformed telemetry is expected — sources are messy, and
losing an event because one field was wrong would create exactly the blind
spot this layer exists to close. So it does not raise: it degrades to a
``partial``/``text`` event carrying a note. Only inputs that cannot be
telemetry at all (wrong Python type) raise, because those signal a caller
bug rather than a bad log line.
"""

from __future__ import annotations


class IngestError(ValueError):
    """Base class for ingest failures."""


class UnsupportedInputError(IngestError):
    """The input is not a shape this layer accepts at all.

    Raised for a wrong Python type — not for malformed or unrecognized
    telemetry, which degrades visibly instead of raising.
    """


class MalformedProjectionError(IngestError):
    """A stored event projection is not the shape :meth:`to_dict` writes.

    Distinct from :class:`UnsupportedInputError` because the provenance is
    different, and so is the correct response. Raw telemetry is messy by
    nature, so it degrades to a ``partial``/``text`` event. A *projection* is
    a record this platform serialized itself: if it comes back missing a key,
    carrying an undeclared one, or past a declared bound, the row was damaged
    or edited after it was written. There is no honest degradation of that —
    rebuilding a plausible event would launder the damage — so it raises.
    """
