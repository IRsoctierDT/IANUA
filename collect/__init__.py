# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Collection — getting this node's own logs into the event store.

``ingest/`` normalizes a record a caller hands it, ``store/`` remembers,
``correlation/`` decides which events were one story and ``pipeline/`` runs
that on a schedule. None of them get telemetry *in*: until this package,
nothing in the repository wrote an event anybody had not typed.

**This is the stage that crosses a boundary.** Every other package keeps its
filesystem reach inside the project and the gitignored lab-data root; a
collector reaches out to ``/var/log``. That crossing was approved for stage 5
specifically, and `DESIGN.md` §5 boundary 14 records what it does and does not
license. Three narrower choices keep it small:

* **Local files only.** No listener, no poller, no egress. The repository has
  twice refused to add outbound network access — the ``attack/`` corpus and the
  ``intel/`` feed — because ``guarded.enforce()`` cannot express per-invocation
  human approval, and the only ways to make it pass are permanent unscoped
  downgrades of default-deny. Reading this node's own logs needs no network at
  all, so it does not reopen that argument.
* **Declared, never discovered.** No glob, no directory walk, no heuristic.
  See ``collect.sources``.
* **No subprocess.** Which is why ``journald`` is out of scope: reading it
  means running ``journalctl``, and a collector that can spawn a process is a
  much larger thing to review. Plain text files only.

Typical use is through the CLI, which a cron entry or systemd timer invokes::

    python scripts/run_collector.py --root . --source /var/log/auth.log

Programmatically::

    from collect import declare_all, load_offsets, offsets_path, read_new, save_offsets
    from ingest import normalize_many
    from store import EventStore

    sources = declare_all(("/var/log/auth.log",))
    path = offsets_path(root)
    positions = load_offsets(path)
    with EventStore.open(root) as events:
        for source in sources:
            result = read_new(source, positions.get(source.key))
            if result.lines:
                events.append_many(normalize_many(result.lines), ingested_at=stamp)
            if result.position is not None:        # only after the events are stored
                positions[source.key] = result.position
    save_offsets(path, positions)

Four properties worth knowing before relying on it:

* **At-least-once.** Offsets advance only after the events are stored, so a
  crash re-reads rather than skips. Safe because the store is
  content-addressed: a re-read line hashes to the same ``event_id`` and
  re-appending it is a no-op.
* **Rotation and truncation are detected, not guessed** — by ``(device,
  inode)`` and by size against offset. The tail of a file rotated away
  *between* runs is unreachable by name and is a stated, bounded gap; see
  ``collect.tail``.
* **A first run reads from the beginning**, not the end. The conventional
  tailer default would silently skip the history a SOC most wants on the day
  it is switched on.
* **No clock.** Positions are byte offsets and file identities. Time enters
  only at ``scripts/run_collector.py``, which also stamps ``ingested_at`` at or
  after the store's high-water mark so ingestion order stays monotone across a
  clock that steps backwards.

See ``DESIGN.md`` §5 boundary 14 for the trust argument.
"""

from __future__ import annotations

from collect.errors import CollectError, CollectPathError, OffsetError, SourceError
from collect.offsets import OFFSETS_SUBDIR, OFFSETS_VERSION, Position
from collect.offsets import load as load_offsets
from collect.offsets import resolve as offsets_path
from collect.offsets import save as save_offsets
from collect.sources import (
    MAX_BYTES_PER_RUN,
    MAX_LINE_BYTES,
    Source,
    declare,
    declare_all,
)
from collect.tail import TailResult, read_new

__all__ = [
    "MAX_BYTES_PER_RUN",
    "MAX_LINE_BYTES",
    "OFFSETS_SUBDIR",
    "OFFSETS_VERSION",
    "CollectError",
    "CollectPathError",
    "OffsetError",
    "Position",
    "Source",
    "SourceError",
    "TailResult",
    "declare",
    "declare_all",
    "load_offsets",
    "offsets_path",
    "read_new",
    "save_offsets",
]
