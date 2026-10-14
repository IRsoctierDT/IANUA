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
    """Validate the filename and confine the cursor to the pipeline directory."""
    if filename in {".", ".."} or not _SAFE_FILENAME.fullmatch(filename):
        raise CursorPathError(
            f"cursor filename must match {_SAFE_FILENAME.pattern!r}, got {filename!r}"
        )
    # Resolve the ROOT then append, so a symlink planted at the pipeline
    # directory cannot resolve to its own target and pass the check.
    base = root.resolve()
    directory = base / CURSOR_SUBDIR
    candidate = directory / filename
    # EVERY component between the root and the file, not just the leaf
    # directory: ``CURSOR_SUBDIR`` is two deep, so checking only
    # ``data/pipeline`` leaves ``data`` unexamined, and ``mkdir(parents=True)``
    # then creates the leaf *through* a link planted there — putting the cursor
    # outside the lab root while every name still looks valid.
    #
    # ``is_symlink`` rather than ``exists() and resolve() != path``: a link
    # whose target does not exist yet reports ``exists() is False``, so the
    # existence-gated form skipped precisely the case that mkdir goes on to
    # create. Refused rather than followed — relocating the pipeline's state
    # to another volume is a deployment decision (``docs/PRODUCTION_SOC_PLAN``
    # stage 9), not something a planted link should accomplish silently.
    walked = base
    for part in (*CURSOR_SUBDIR.parts, filename):
        walked = walked / part
        if walked.is_symlink():
            raise CursorPathError(
                f"{walked} is a symlink (-> {walked.readlink()}); refusing to "
                "follow it out of the lab-data root"
            )
    if not candidate.is_relative_to(directory):  # pragma: no cover
        # Unreachable while _SAFE_FILENAME holds; kept so loosening that regex
        # does not silently open a traversal.
        raise CursorPathError(f"cursor path {candidate} escapes {directory}")
    return candidate


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
      different cursors never share a temp file, and two identical ones share
      one harmlessly because the bytes are the same.
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
    finally:
        # A crash between write and rename would otherwise leave the temp file
        # behind, and the next run would accumulate another one.
        temporary.unlink(missing_ok=True)
