# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Where this collector had got to in each file, durably.

The same shape as ``pipeline/cursor.py`` and for the same reason: a scheduled
one-shot process keeps no memory between runs, so its position has to live on
disk. What is stored per source is a *triple*, not just a byte offset, and the
extra two fields are what make rotation detectable:

* ``offset`` — bytes consumed, always landing just past a newline.
* ``inode`` and ``device`` — the file's identity. A rotated log keeps its
  *name* and changes its identity, so an offset without identity would be
  applied to a brand-new file and skip its first ``offset`` bytes.
* ``size`` — so truncation in place (``: > file``) is distinguishable from a
  file that has simply not grown.

**Advanced only after the events are stored.** The collector persists offsets
after ``append_many`` returns, so a crash re-reads the same lines rather than
stepping over them. That is the same at-least-once trade ``pipeline/`` makes,
and it is safe for the same reason: the store is content-addressed, so a
re-read line produces an identical ``event_id`` and re-appending it is a no-op.
Duplicate reads cost nothing; a skipped region is a blind spot nobody is told
about.

**No clock.** Positions are byte offsets and file identities, never times, so
nothing here depends on the host's clock being sane. Time enters only at
``scripts/run_collector.py``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from store.paths import confine

from collect.errors import CollectPathError, OffsetError

#: Under the gitignored lab-data root, beside the store and the pipeline cursor.
OFFSETS_SUBDIR = Path("data") / "collect"

#: Default filename inside that directory.
DEFAULT_FILENAME = "offsets.json"

#: Format version. A reader that does not recognise it refuses rather than
#: guessing, because both guesses lose data — see :class:`OffsetError`.
OFFSETS_VERSION = 1

#: Owner-only, matching the audit log, the compliance evidence chain and the
#: pipeline cursor. The offsets name paths on this host, which is operational
#: detail worth not publishing.
_FILE_MODE = 0o600
_DIR_MODE = 0o700


@dataclass(frozen=True, slots=True)
class Position:
    """How far into one file the collector has read, and which file that was."""

    offset: int
    inode: int
    device: int
    size: int

    def matches(self, stat_result: tuple[int, int]) -> bool:
        """Whether a (device, inode) pair is still the file this position describes."""
        return (self.device, self.inode) == stat_result


def resolve(root: Path, *, filename: str = DEFAULT_FILENAME) -> Path:
    """Confine the offsets file to the collect directory under the lab-data root."""
    return confine(root, OFFSETS_SUBDIR, filename, error=CollectPathError, what="offsets")


def load(path: Path) -> dict[str, Position]:
    """Read stored positions, or an empty mapping on a genuine first run.

    The distinction that matters: *absent* means "never collected", and an
    empty mapping is the right answer. *Corrupt* is refused, because the two
    plausible recoveries both lose: starting from zero re-ingests every line of
    every source, and starting from the end skips everything written since the
    last run.
    """
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise OffsetError(f"{path}: offsets are unreadable ({exc})") from exc
    if not isinstance(payload, dict):
        raise OffsetError(f"{path}: offsets must be a JSON object, got {type(payload).__name__}")
    version = payload.get("version")
    if version != OFFSETS_VERSION:
        raise OffsetError(
            f"{path}: offsets are version {version!r}, this build speaks "
            f"{OFFSETS_VERSION!r}; migration is explicit, never implicit"
        )
    sources = payload.get("sources")
    if not isinstance(sources, dict):
        raise OffsetError(f"{path}: offsets have no 'sources' object")
    return {key: _position(path, key, value) for key, value in sources.items()}


def _position(path: Path, key: str, value: object) -> Position:
    """Rebuild and validate one stored position, fail-closed on any bad field."""
    if not isinstance(value, dict):
        raise OffsetError(f"{path}: position for {key!r} is not an object")
    fields = {}
    for name in ("offset", "inode", "device", "size"):
        raw = value.get(name)
        # bool is an int subclass and would otherwise pass silently as 0 or 1.
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise OffsetError(f"{path}: position for {key!r} has a bad {name}: {raw!r}")
        if raw < 0:
            raise OffsetError(f"{path}: position for {key!r} has a negative {name}: {raw!r}")
        fields[name] = raw
    return Position(**fields)


def save(path: Path, positions: dict[str, Position]) -> None:
    """Write positions atomically and owner-only.

    Identical mechanics to ``pipeline/cursor.save`` and for identical reasons:
    same-directory temporary file (``Path.replace`` is atomic only within one
    filesystem), ``chmod`` *before* the rename so the file never exists at its
    real path in a wider mode, and a content-keyed temporary name so two
    overlapping runs cannot interleave writes into one fixed path. Losing the
    race to a writer with byte-identical content is success, not failure — the
    intended bytes are on disk.
    """
    path.parent.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
    payload = {
        "version": OFFSETS_VERSION,
        "sources": {
            key: {
                "offset": position.offset,
                "inode": position.inode,
                "device": position.device,
                "size": position.size,
            }
            for key, position in sorted(positions.items())
        },
    }
    body = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    tag = hashlib.sha256(body.encode("utf-8")).hexdigest()[:12]
    temporary = path.with_name(f"{path.name}.{tag}.tmp")
    try:
        temporary.write_text(body, encoding="utf-8")
        temporary.chmod(_FILE_MODE)
        temporary.replace(path)
    except FileNotFoundError:
        # Another writer with identical content renamed it into place first,
        # which is the outcome this call wanted. Verified, not assumed, so a
        # genuine failure still fails.
        try:
            landed = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise OffsetError(
                f"{path}: the temporary file disappeared and no offsets were written ({exc})"
            ) from exc
        if landed != body:
            raise OffsetError(
                f"{path}: the temporary file disappeared and the offsets on disk are "
                "not the ones this call wrote"
            ) from None
    finally:
        temporary.unlink(missing_ok=True)
