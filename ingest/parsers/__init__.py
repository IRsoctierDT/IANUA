"""Domain parsers — one module per telemetry domain.

Each module exports a ``SIGNATURES`` tuple. A signature pairs a *recognizer*
with a *parser*: the recognizer answers "is this record mine?" from
distinctive keys, and only then does the parser read it.

Recognition is deliberately conservative and never ordered by luck. A
signature that would also match another vendor's records is a bug, and the
parity test in ``tests/unit/test_ingest_parsers.py`` asserts that every
fixture is claimed by exactly one signature. Anything unclaimed becomes an
``unknown`` event rather than being fed to the closest-looking parser —
mis-attributing a cloud record to an endpoint parser would produce a
confident, wrong analysis, which is worse than no analysis.

This package's ``__init__`` intentionally imports no submodule: the parser
modules import ``Signature`` from here, so importing them from here too would
close a cycle.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from ingest.schema import NormalizedEvent, SourceType

__all__ = ["Signature"]


@dataclass(frozen=True, slots=True)
class Signature:
    """One recognizable telemetry format."""

    #: Product name recorded on every event this signature parses.
    vendor: str
    source_type: SourceType
    #: Cheap, side-effect-free predicate over the decoded record.
    recognizes: Callable[[Mapping[str, Any]], bool]
    #: Reads a record this signature has already claimed.
    parse: Callable[[Mapping[str, Any]], NormalizedEvent]
