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
* **Truncation in place, and truncation followed by regrowth.** ``: > file``
  leaves the identity intact and resets the size, so an offset-only reader
  seeks past the end and reports "nothing new" forever. Worse, a file truncated
  and then regrown *past* the old offset has the same inode and a larger size,
  so size-and-identity checks all pass and the reader resumes mid-stream,
  silently skipping the head of the new content — which is logrotate's
  ``copytruncate`` mode, the standard option for a file a writer holds open.
  Reproduced before the fix: four of six new lines lost with no reset reported.
  Both are caught by re-reading the trailing bytes at the stored offset and
  comparing a digest, which also closes inode reuse after delete-and-recreate.
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
from typing import BinaryIO

from collect.offsets import FINGERPRINT_BYTES, Position, fingerprint_of
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
    #: ``"truncated"``, ``"replaced"``, ``"first-run"``, or ``""`` when it
    #: simply advanced.
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

    # One descriptor for every byte this call reads. The continuity digest and
    # the data used to be two separate opens by path, so the digest could be
    # of one file and the data of another, and a fingerprint match proved
    # nothing about the bytes that were then consumed. They now come from the
    # same handle, which is what makes the continuity check mean what it says.
    #
    # The identity stat above is still by path, so a name repointed between it
    # and this open is read under the previous ``(device, inode)``. That window
    # is left open deliberately rather than silently: closing it needs
    # ``os.fstat``, and ``os`` is on this package's banned-import list for
    # reasons (no spawn, no clock, no environment) that outweigh a race whose
    # precondition — write access to the log's directory — already permits
    # writing whatever content the attacker wants into the log itself.
    with source.path.open("rb") as handle:
        start, reset = _resume_from(handle, previous, identity, status.st_size)

        if status.st_size <= start:
            # Nothing appended. The position is still refreshed, because a
            # rotation or truncation detected above has to be recorded even
            # when the new file is empty — otherwise the next run detects it
            # all over again.
            return TailResult(
                position=Position(
                    offset=start,
                    inode=status.st_ino,
                    device=status.st_dev,
                    size=status.st_size,
                    fingerprint=_trailing(handle, start),
                ),
                reset=reset,
            )

        available = status.st_size - start
        handle.seek(start)
        chunk = handle.read(min(max_bytes, available))
        # Stop at the last newline: a trailing fragment is a partial write, and
        # consuming it would hand ingest/ a truncated record and lose the rest.
        cut = chunk.rfind(b"\n")
        if cut == -1 and len(chunk) < available:
            # No complete line inside the throughput cap, but the file has more.
            # Extend this one read — and ONLY this one — far enough to hold a
            # line of the maximum permitted length. Without that, a line longer
            # than max_bytes wedges the source **forever**: hold position, same
            # budget next run, no progress, reported as "nothing new".
            # Reproduced over five consecutive passes at offset 0.
            #
            # The extension is deliberately not a floor on max_bytes. Raising
            # the cap unconditionally would silently override an operator's
            # explicit --max-bytes on every read; exceeding it only when a
            # legal line cannot otherwise fit keeps the cap meaningful and the
            # pathological case unblocked.
            extra = min(max_line + 1, available) - len(chunk)
            if extra > 0:
                chunk += handle.read(extra)
            cut = chunk.rfind(b"\n")

        if cut == -1:
            if len(chunk) > max_line:
                # No newline, and already longer than one record may be. Holding is
                # what wedged the source, so emit what fits — counted as truncated,
                # which is visible — and advance past it. The remainder may arrive
                # as further truncated records; that is degradation, not loss.
                end = start + len(chunk)
                return TailResult(
                    lines=(chunk[:max_line],),
                    position=Position(
                        offset=end,
                        inode=status.st_ino,
                        device=status.st_dev,
                        size=status.st_size,
                        fingerprint=_trailing(handle, end),
                    ),
                    reset=reset,
                    truncated=1,
                    capped=end < status.st_size,
                )
            # A partial line still being written, and within the record cap. Hold
            # position so it arrives whole next time.
            return TailResult(
                position=Position(
                    offset=start,
                    inode=status.st_ino,
                    device=status.st_dev,
                    size=status.st_size,
                    fingerprint=_trailing(handle, start),
                ),
                reset=reset,
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
                offset=end,
                inode=status.st_ino,
                device=status.st_dev,
                size=status.st_size,
                fingerprint=_trailing(handle, end),
            ),
            reset=reset,
            truncated=truncated,
            capped=end < status.st_size,
        )


def _trailing(handle: BinaryIO, offset: int) -> str:
    """Digest the bytes just before ``offset``, for the continuity check.

    **The only place a fingerprint is computed**, used both when storing a
    position and when verifying one. An earlier version hashed the
    just-consumed chunk when storing and read back from the file when
    verifying, which agreed only while the chunk was at least
    ``FINGERPRINT_BYTES`` long — and disagreed on every smaller read, so each
    page saw a mismatch, reset to zero, and re-read the file from the start.
    Caught by the monotone-progress assertion: 1709 lines read from a 200-line
    file. Making both sides call this makes them agree by construction rather
    than by two code paths happening to match.

    Takes the caller's open descriptor rather than the path, so the digest is
    of the same file that was stat'ed and read. It leaves the handle's position
    wherever it finished; every caller seeks before reading.

    Returns ``""`` at offset 0, where there is no consumed context to prove
    anything about.
    """
    if offset <= 0:
        return ""
    back = min(FINGERPRINT_BYTES, offset)
    handle.seek(offset - back)
    return fingerprint_of(handle.read(back))


def _resume_from(
    handle: BinaryIO, previous: Position | None, identity: tuple[int, int], size: int
) -> tuple[int, str]:
    """Decide where to start reading, and name why if it is not where we stopped.

    The four resets are kept separate rather than collapsed into a boolean,
    because an operator reading the report needs to tell a routine rotation
    from a truncation nobody expected, and both from a file that was replaced
    under a reused inode.
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
    # Identity matches and the file is long enough — and that is still not
    # enough. A file truncated and regrown past the old offset passes both
    # checks above while holding entirely different content, so the bytes just
    # before the offset are re-read and compared. Without this, logrotate's
    # copytruncate silently skips the head of every new window.
    if previous.fingerprint and _trailing(handle, previous.offset) != previous.fingerprint:
        return 0, "replaced"
    return previous.offset, ""
