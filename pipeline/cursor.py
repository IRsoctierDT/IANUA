# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Where the pipeline got to — a durable keyset position, written atomically.

The cursor is the pipeline's only persistent state, and it is a
``(ingested_at, event_id)`` pair rather than a timestamp because
``EventStore.append_many`` stamps one ingestion time across a whole batch, so
ties are the normal case. See ``store.Query.ingested_after`` for why a
timestamp-only cursor must either skip the rest of a batch or reprocess it
forever.

Security considerations (AGENTS.md §3, §5):

* **Fail closed on damage.** A cursor that will not parse raises rather than
  defaulting. The two defaults available are both silently wrong: starting
  from zero reprocesses everything, starting from "now" creates an
  unannounced blind spot across the gap.
* **Atomic writes.** Written to a temporary file in the same directory and
  renamed, so a crash mid-write cannot leave a half-written cursor that then
  fails to parse on the next cycle. The rename is atomic within a
  filesystem.
* **Confined path.** Lives under the gitignored lab-data root; a filename that
  escapes it is refused rather than normalized, and a symlinked directory or
  file is refused rather than followed — the same rules ``store/`` applies,
  for the same reason.
* **No clock.** The cursor records a position, never reads one. Time enters
  this system in exactly one place (``scripts/run_pipeline.py``), which is
  what keeps every layer below it reproducible.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from pipeline.errors import CursorError, CursorPathError
from store.paths import confine

#: Fixed location under the repository's gitignored lab-data root, mirroring
#: ``store.EVENTS_SUBDIR``. Not a caller knob: pipeline state is lab data.
CURSOR_SUBDIR = Path("data") / "pipeline"

DEFAULT_FILENAME = "cursor.json"

#: A filename, not a path. No separators, no traversal, no leading dot.
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

#: Schema marker, so a future shape change is an explicit decision rather than
#: a silently misread file.
CURSOR_VERSION = 1

#: Owner-only, matching ``agents/policies/audit.py`` and
#: ``compliance/evidence.py``. The cursor names a stored event, so it is
#: evidence metadata and gets the same posture as the evidence itself.
_FILE_MODE = 0o600
_DIR_MODE = 0o700


@dataclass(frozen=True, slots=True)
class Cursor:
    """The last event this pipeline finished processing."""

    ingested_at: float
    event_id: str

    def as_keyset(self) -> tuple[float, str]:
        """The pair ``store.Query.ingested_after`` expects."""
        return (self.ingested_at, self.event_id)


def resolve(root: Path, *, filename: str = DEFAULT_FILENAME) -> Path:
    """Confine the cursor to the pipeline directory under the lab-data root.

    Delegates to :func:`store.paths.confine`, shared with ``store/`` and
    ``collect/``. This module carried its own copy with two defects that
    ``store/`` had as well: it checked only the leaf directory and the file, so
    a link at ``data`` was never examined while ``mkdir(parents=True)`` built
    the leaf through it; and the check was gated on ``exists()``, which is
    ``False`` for the dangling link that mkdir then materializes. Fixing one
    copy and not the other is how that recurs.
    """
    return confine(root, CURSOR_SUBDIR, filename, error=CursorPathError, what="cursor")


def load(path: Path) -> Cursor | None:
    """Read the cursor, or ``None`` when the pipeline has never run.

    ``None`` is returned only for a genuinely absent file — an unparseable or
    incomplete one raises, because "we have never run" and "our position was
    lost" demand different responses and must not look alike.
    """
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise CursorError(f"{path}: cursor is unreadable ({exc})") from exc
    if not isinstance(payload, dict):
        raise CursorError(f"{path}: cursor must be a JSON object")
    version = payload.get("version")
    if version != CURSOR_VERSION:
        raise CursorError(
            f"{path}: cursor version {version!r} is not {CURSOR_VERSION}; migration is explicit"
        )
    at, identifier = payload.get("ingested_at"), payload.get("event_id")
    if isinstance(at, bool) or not isinstance(at, int | float):
        raise CursorError(f"{path}: ingested_at must be a number, got {at!r}")
    if not isinstance(identifier, str) or not identifier:
        raise CursorError(f"{path}: event_id must be a non-empty string")
    return Cursor(ingested_at=float(at), event_id=identifier)


def save(path: Path, cursor: Cursor) -> None:
    """Write the cursor atomically and owner-only: temp file, chmod, rename.

    Three properties, each load-bearing:

    * **Same directory.** ``Path.replace`` is atomic only within one
      filesystem, so a temp file elsewhere could land on another mount and
      degrade to a copy — which is exactly the non-atomic write this avoids.
    * **Owner-only before the rename, not after.** The cursor names stored
      evidence, so it carries the 0o600 posture the audit log and the
      compliance evidence chain already use. Permissions are set on the
      temporary file *before* it is renamed into place, so the cursor never
      exists **at its real path** in a wider mode — a ``chmod`` after the
      rename would leave exactly that window. ``chmod`` rather than a creation
      mode, because a creation mode is masked by ``umask`` and this must not
      depend on how the scheduler was configured.

      Stated precisely, because the obvious stronger claim would be false: the
      temporary file is created by ``write_text`` at the umask default, so for
      the moment between the write and the ``chmod`` *that* file may be
      group-readable. What makes the contents unreachable throughout is the
      enclosing directory being ``0o700`` — the file mode is defence in depth
      on top of it, not the thing doing the work.
    * **A temp name derived from the payload.** Two overlapping runs — a slow
      cycle and a five-minute timer — would otherwise interleave writes to one
      fixed temp path and could rename a half-written file into place, halting
      the pipeline on the next load. Keying the name to the content means two
      different cursors never share a temp file, and two identical ones can
      share one *because* the bytes are the same — the loser of that race finds
      its temp file already renamed into place, which is the outcome it wanted,
      so it verifies the destination and returns rather than reporting a
      failure that did not happen.
    """
    path.parent.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
    payload = {
        "version": CURSOR_VERSION,
        "ingested_at": cursor.ingested_at,
        "event_id": cursor.event_id,
    }
    body = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    tag = hashlib.sha256(body.encode("utf-8")).hexdigest()[:12]
    temporary = path.with_name(f"{path.name}.{tag}.tmp")
    try:
        temporary.write_text(body, encoding="utf-8")
        temporary.chmod(_FILE_MODE)
        temporary.replace(path)
    except FileNotFoundError:
        # The temp file vanished between our write and our rename. Because the
        # name is keyed to a digest of the content, the only writer that could
        # have taken it was one writing *byte-identical* content — and it
        # renamed it into place, which is precisely the outcome this call
        # wanted. Raising here would be a lie: the caller's cursor is on disk,
        # and the CLI would report "cursor was not advanced" and exit 1 for a
        # cycle that advanced correctly.
        #
        # Verified rather than assumed, so a genuine failure still fails: the
        # destination must actually hold what we meant to write.
        try:
            landed = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CursorError(
                f"{path}: the temporary file disappeared and no cursor was written ({exc})"
            ) from exc
        if landed != body:
            raise CursorError(
                f"{path}: the temporary file disappeared and the cursor on disk is not "
                "the one this call wrote"
            ) from None
    finally:
        # A crash between write and rename would otherwise leave the temp file
        # behind, and the next run would accumulate another one.
        temporary.unlink(missing_ok=True)
