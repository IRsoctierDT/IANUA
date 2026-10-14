# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Read what is new in a log file, exactly once, without trusting it.

One function, :func:`read_new`, and most of its body is the three cases that
make file tailing harder than ``seek`` and ``read``:

* **Rotation.** A rotated log keeps its *name* and changes its *identity*, so
  applying the old byte offset to the new file would skip its first ``offset``
  bytes — silently, and in the most interesting moment, since rotation usually
  follows volume. Detected by comparing ``(device, inode)``, not by heuristics
  on the name.
* **Truncation in place.** ``: > file`` leaves the identity intact and resets
  the size. An offset-only reader would then seek past the end and report
  "nothing new" forever. Detected by ``size < offset``.
* **Partial writes.** A reader can arrive mid-line. Consuming a partial line
  gives ``ingest/`` a truncated record *and* loses the rest when the offset
  advances past it, so the read stops at the last newline and the remainder is
  left for the next run.

What this does **not** recover: the tail of a file that was rotated away
between two runs. A one-shot process holds no file descriptor across
invocations, so once the old inode is unlinked and the name points elsewhere,
its final lines are unreachable by name. That is a real, bounded gap — bounded
by how often the collector runs — and it is stated here rather than discovered
later. A daemon holding an fd would close it; the plan's stage 9 is where that
trade gets revisited.

**Nothing here trusts the file's contents.** Lines go to ``ingest/``, which
bounds every field, strips control characters and degrades visibly rather than
dropping. This module's only content decision is the line length cap, and it
*truncates* rather than drops for the same reason.

**No clock, no socket, no subprocess.** Positions are byte offsets and file
identities. Time enters only at ``scripts/run_collector.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from collect.offsets import Position
from collect.sources import MAX_BYTES_PER_RUN, MAX_LINE_BYTES, Source


@dataclass(frozen=True, slots=True)
class TailResult:
    """What one source yielded, in enough detail to audit and to resume."""

    #: The raw lines read, newlines stripped, in file order. Bytes rather than
    #: ``str``: ``ingest.normalize`` decodes with replacement and bounds the
    #: result, so decoding here would duplicate that and lose the original.
    lines: tuple[bytes, ...] = field(default_factory=tuple)
    #: Where to resume. ``None`` when the source could not be positioned at
    #: all, in which case the caller must leave the stored position untouched.
    position: Position | None = None
    #: Why the position was reset, for the operator's report: ``"rotated"``,
    #: ``"truncated"``, ``"first-run"``, or ``""`` when it simply advanced.
    reset: str = ""
    #: Lines that exceeded :data:`MAX_LINE_BYTES` and were truncated. Counted
    #: rather than silent, because a truncated record is a degraded record.
    truncated: int = 0
    #: Whether the cap stopped this read short, so a backlog is visible as a
    #: backlog instead of looking like a quiet file.
    capped: bool = False

    @property
    def count(self) -> int:
        """How many lines were read."""
        return len(self.lines)


def read_new(
    source: Source,
    previous: Position | None,
    *,
    max_bytes: int = MAX_BYTES_PER_RUN,
    max_line: int = MAX_LINE_BYTES,
) -> TailResult:
    """Read the complete lines appended to ``source`` since ``previous``.

    Args:
        source: A validated source — construct it with ``sources.declare``.
        previous: The stored position, or ``None`` on a first run.
        max_bytes: Cap on bytes read in this call. A backlog is worked through
            over several runs; ``capped`` reports when that happened.
        max_line: Cap on one line. Longer lines are truncated and counted.

    Raises:
        ValueError: for a non-positive cap, rather than clamping — a collector
            configured to read zero bytes would appear to run forever while
            collecting nothing, which is worse than a refusal at startup.
        OSError: if the file cannot be read. Left to the caller, which turns it
            into an exit code; swallowing it here would drop a source silently.
    """
    if max_bytes < 1:
        raise ValueError(f"max_bytes must be >= 1, got {max_bytes}")
    if max_line < 1:
        raise ValueError(f"max_line must be >= 1, got {max_line}")

    status = source.path.stat()
    identity = (status.st_dev, status.st_ino)

    start, reset = _resume_from(previous, identity, status.st_size)

    if status.st_size <= start:
        # Nothing appended. The position is still refreshed, because a rotation
        # or truncation detected above has to be recorded even when the new
        # file is empty — otherwise the next run detects it all over again.
        return TailResult(
            position=Position(
                offset=start, inode=status.st_ino, device=status.st_dev, size=status.st_size
            ),
            reset=reset,
        )

    budget = min(max_bytes, status.st_size - start)
    with source.path.open("rb") as handle:
        handle.seek(start)
        chunk = handle.read(budget)

    # Stop at the last newline: a trailing fragment is a partial write, and
    # consuming it would hand ingest/ a truncated record and lose the rest.
    cut = chunk.rfind(b"\n")
    if cut == -1:
        # No complete line in the whole budget. Either a very long line still
        # being written, or one longer than the cap. Advancing past it would
        # lose it, so hold position and let the next run see it finished; the
        # line cap below handles the genuinely-too-long case once it ends.
        return TailResult(
            position=Position(
                offset=start, inode=status.st_ino, device=status.st_dev, size=status.st_size
            ),
            reset=reset,
            capped=budget < status.st_size - start,
        )

    consumed = chunk[: cut + 1]
    lines: list[bytes] = []
    truncated = 0
    for line in consumed.split(b"\n"):
        if not line:
            continue  # blank line, or the empty tail after the final newline
        if len(line) > max_line:
            truncated += 1
            line = line[:max_line]
        lines.append(line)

    end = start + len(consumed)
    return TailResult(
        lines=tuple(lines),
        position=Position(
            offset=end, inode=status.st_ino, device=status.st_dev, size=status.st_size
        ),
        reset=reset,
        truncated=truncated,
        capped=end < status.st_size,
    )


def _resume_from(
    previous: Position | None, identity: tuple[int, int], size: int
) -> tuple[int, str]:
    """Decide where to start reading, and name why if it is not where we stopped.

    The three resets are kept separate in the return value rather than collapsed
    into a boolean, because an operator reading the report needs to tell a
    routine rotation from a truncation nobody expected.
    """
    if previous is None:
        # A first run starts at the beginning, not the end. Starting at the end
        # is the conventional tailer default and it is wrong here: it would
        # silently skip everything already in the file, which is exactly the
        # history a SOC wants on the day it is switched on.
        return 0, "first-run"
    if not previous.matches(identity):
        return 0, "rotated"
    if size < previous.offset:
        return 0, "truncated"
    return previous.offset, ""
