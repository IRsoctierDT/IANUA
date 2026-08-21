"""Multi-source telemetry ingest — the XDR front door.

Translates endpoint, network, cloud, identity, and email telemetry into one
canonical :class:`~ingest.schema.NormalizedEvent`, so every layer above
(classification, ATT&CK mapping, behavioral matching, response planning)
stops caring which product emitted a record.

Typical use::

    from ingest import normalize

    event = normalize(cloudtrail_record)
    event.source_type    # "cloud"
    event.to_match_view()  # flat dict for sigma_eval / the mapping engine

The package is pure: no clock, no filesystem, no network, no subprocess, and
no third-party runtime dependency. See ``ingest/normalize.py`` for the three
rules that govern it (recognize-never-guess, degrade-visibly, no ambient
authority) and ``DESIGN.md`` §5 boundary 9 for the trust argument.
"""

from __future__ import annotations

from ingest.errors import IngestError, UnsupportedInputError
from ingest.normalize import SIGNATURES, SOURCE_TYPES, detect_source, normalize, normalize_many
from ingest.schema import (
    MAX_FIELD_LEN,
    MAX_NESTING_DEPTH,
    MAX_OBSERVABLES,
    MAX_RAW_BYTES,
    MAX_RAW_EXCERPT,
    Actor,
    CloudContext,
    Device,
    EmailContext,
    Endpoint,
    NormalizedEvent,
    ParseStatus,
    SourceType,
)

__all__ = [
    "MAX_FIELD_LEN",
    "MAX_NESTING_DEPTH",
    "MAX_OBSERVABLES",
    "MAX_RAW_BYTES",
    "MAX_RAW_EXCERPT",
    "SIGNATURES",
    "SOURCE_TYPES",
    "Actor",
    "CloudContext",
    "Device",
    "EmailContext",
    "Endpoint",
    "IngestError",
    "NormalizedEvent",
    "ParseStatus",
    "SourceType",
    "UnsupportedInputError",
    "detect_source",
    "normalize",
    "normalize_many",
]
