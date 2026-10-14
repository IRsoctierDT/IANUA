# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Continuous execution — run the detection pipeline on a schedule.

``ingest/`` normalizes, ``store/`` remembers, ``correlation/`` decides which
events were one story. This package is what runs them when nobody is watching.

Typical use is through the CLI, which a cron entry or systemd timer invokes::

    python scripts/run_pipeline.py --root . --batch 500

Programmatically::

    from pipeline import Cursor, run_cycle, load_cursor, save_cursor, cursor_path
    from store import EventStore

    path = cursor_path(root)
    cursor = load_cursor(path)
    with EventStore.open(root) as events:
        result = run_cycle(events, cursor=cursor)
    if result.cursor is not None:          # only advance after success
        save_cursor(path, result.cursor)
    for incident in result.fresh:          # `incidents` includes re-seen ones
        ...

Four properties worth knowing before relying on it:

* **Two windows, never one.** The cursor advances over the new events; the
  correlator sees those *plus* a trailing ``lookback`` of already-consumed
  history. A cursor partitions the stream, and cross-domain correlation is
  windowed — without the overlap an incident whose steps arrive in different
  cycles is never assembled, and nothing can recover it afterwards.
  ``CycleResult.fresh`` marks the incidents that are actually news, derived
  from event ids rather than remembered state.

* **At-least-once.** The cursor advances only after a cycle succeeds, so a
  crash re-reads rather than skips. Duplicate incidents are noise; a skipped
  window is a blind spot nobody is told about.
* **Keyset paging, not a timestamp.** ``append_many`` stamps one ingestion
  time across a batch, so a timestamp cursor would skip the rest of a batch or
  reprocess it forever.
* **One cycle per invocation.** No daemon. The operating system's scheduler is
  more reliable than a hand-rolled loop and leaves nothing to supervise.

See ``DESIGN.md`` §5 boundary 13 for the trust argument.
"""

from __future__ import annotations

from pipeline.cursor import CURSOR_SUBDIR, CURSOR_VERSION, Cursor
from pipeline.cursor import load as load_cursor
from pipeline.cursor import resolve as cursor_path
from pipeline.cursor import save as save_cursor
from pipeline.cycle import (
    DEFAULT_BATCH,
    DEFAULT_LOOKBACK,
    CycleResult,
    reference,
    run_cycle,
)
from pipeline.errors import CursorError, CursorPathError, PipelineError

__all__ = [
    "CURSOR_SUBDIR",
    "CURSOR_VERSION",
    "DEFAULT_BATCH",
    "DEFAULT_LOOKBACK",
    "Cursor",
    "CursorError",
    "CursorPathError",
    "CycleResult",
    "PipelineError",
    "cursor_path",
    "load_cursor",
    "reference",
    "run_cycle",
    "save_cursor",
]
