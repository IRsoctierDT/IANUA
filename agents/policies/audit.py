"""Structured, tamper-evident audit log — implements AGENTS.md §3 auditability.

Security-relevant decisions (e.g. policy-gate evaluations) are appended as JSON
lines with a **hash chain**: each entry's ``entry_hash`` covers the previous
entry's hash, so any insertion, deletion, or edit breaks the chain and is caught
by :meth:`AuditLogger.verify`.

Retention & rotation (AGENTS.md §3; Hardening Roadmap #2)
--------------------------------------------------------
Set ``max_bytes`` to roll the active log into a numbered archive
(``audit.log.1``, ``audit.log.2``, …) once it reaches that size, and
``retain_segments`` to keep only the most recent *N* archives. **The hash chain
is continuous across rotation**: the first entry of a new segment carries the
previous segment's last hash and the next sequence number, so a whole archive
cannot be silently dropped without breaking the chain. When retention prunes old
segments, a ``.checkpoint`` sidecar records the last pruned ``(seq, hash)`` so
the oldest *retained* entry is still anchored — truncating the retained window is
therefore detectable. Verifying the whole retained set is a single call to
:meth:`AuditLogger.verify`.

> Residual limit: history that retention has *legitimately* pruned cannot be
> re-verified (it is gone by design). Set ``retain_segments`` to cover the
> window your compliance posture requires, or ``None`` to never prune.

Security notes:
- **Append-only.** The logger only ever appends or rotates; it never rewrites
  the contents of a segment.
- **No sensitive payloads.** Callers pass decisions and short reasons — never
  secrets, credentials, or raw log/PII content (AGENTS.md §5).
- **Deterministic for tests.** The timestamp source is injectable.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

_GENESIS_HASH = "0" * 64


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class AuditEvent:
    """A single, hash-chained audit record."""

    seq: int
    timestamp: str
    actor: str
    action: str
    action_class: str
    decision: str
    reason: str
    prev_hash: str
    entry_hash: str


def _compute_hash(
    *,
    seq: int,
    timestamp: str,
    actor: str,
    action: str,
    action_class: str,
    decision: str,
    reason: str,
    prev_hash: str,
) -> str:
    payload = "|".join(
        [str(seq), timestamp, actor, action, action_class, decision, reason, prev_hash]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _last_nonempty_line(text: str) -> str:
    last = ""
    for line in text.splitlines():
        if line.strip():
            last = line
    return last


class AuditLogger:
    """Append security-relevant events to a hash-chained JSONL audit log.

    Optional rotation/retention (both default off, preserving the plain
    append-only behavior):

    * ``max_bytes`` — rotate the active log to a numbered archive once it reaches
      this size, before the next append.
    * ``retain_segments`` — keep at most this many archived segments; older ones
      are pruned, with a tamper-evident ``.checkpoint`` recording what was cut.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        clock: Callable[[], str] | None = None,
        max_bytes: int | None = None,
        retain_segments: int | None = None,
    ) -> None:
        if max_bytes is not None and max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        if retain_segments is not None and retain_segments < 0:
            raise ValueError("retain_segments must be non-negative")
        self.path = Path(path)
        self._clock = clock or _utc_now
        self.max_bytes = max_bytes
        self.retain_segments = retain_segments
        self._checkpoint_path = self.path.with_name(self.path.name + ".checkpoint")
        self._archive_re = re.compile(rf"^{re.escape(self.path.name)}\.(\d+)$")

    # ---------------------------------------------------------------- segments
    def _archive_paths(self) -> list[Path]:
        """Archived segments, oldest → newest (ascending numeric suffix)."""
        parent = self.path.parent
        if not parent.exists():
            return []
        indexed: list[tuple[int, Path]] = []
        for child in parent.iterdir():
            m = self._archive_re.match(child.name)
            if m:
                indexed.append((int(m.group(1)), child))
        return [p for _, p in sorted(indexed)]

    def _segments_in_order(self) -> list[Path]:
        """All chain segments oldest → newest: archives then the active log."""
        segments = self._archive_paths()
        if self.path.exists():
            segments.append(self.path)
        return segments

    def _last_event(self, segment: Path) -> AuditEvent | None:
        if not segment.exists():
            return None
        line = _last_nonempty_line(segment.read_text(encoding="utf-8"))
        if not line:
            return None
        return AuditEvent(**json.loads(line))

    def _last(self) -> tuple[int, str]:
        """``(last_seq, last_entry_hash)`` across segments, or ``(-1, genesis)``.

        Falls back from the active log to the newest archive so the chain
        continues seamlessly after a rotation (when the active log is empty).
        """
        for segment in (self.path, *reversed(self._archive_paths())):
            event = self._last_event(segment)
            if event is not None:
                return event.seq, event.entry_hash
        return -1, _GENESIS_HASH

    # ---------------------------------------------------------------- checkpoint
    def _read_checkpoint(self) -> tuple[int, str] | None:
        if not self._checkpoint_path.exists():
            return None
        data = json.loads(self._checkpoint_path.read_text(encoding="utf-8"))
        return int(data["pruned_through_seq"]), str(data["pruned_through_hash"])

    def _write_checkpoint(self, seq: int, entry_hash: str) -> None:
        self._checkpoint_path.write_text(
            json.dumps({"pruned_through_seq": seq, "pruned_through_hash": entry_hash}),
            encoding="utf-8",
        )

    # ---------------------------------------------------------------- rotation
    def _rotate(self) -> None:
        """Archive the active log to the next numbered segment and prune."""
        indices = [
            int(m.group(1)) for p in self._archive_paths() if (m := self._archive_re.match(p.name))
        ]
        next_index = max(indices) + 1 if indices else 1
        self.path.rename(self.path.with_name(f"{self.path.name}.{next_index}"))
        self._prune()

    def _prune(self) -> None:
        if self.retain_segments is None:
            return
        archives = self._archive_paths()
        while len(archives) > self.retain_segments:
            oldest = archives.pop(0)
            last = self._last_event(oldest)
            if last is not None:
                # Advance the checkpoint to the newest entry being pruned so the
                # oldest retained entry stays anchored to a known hash.
                self._write_checkpoint(last.seq, last.entry_hash)
            oldest.unlink()

    def _should_rotate(self) -> bool:
        return (
            self.max_bytes is not None
            and self.path.exists()
            and self.path.stat().st_size >= self.max_bytes
        )

    # ---------------------------------------------------------------- append
    def record(
        self, *, actor: str, action: str, action_class: str, decision: str, reason: str
    ) -> AuditEvent:
        """Append one audit event and return it. Rotates first if configured."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self._should_rotate():
            self._rotate()
        last_seq, prev_hash = self._last()
        seq = last_seq + 1
        timestamp = self._clock()
        entry_hash = _compute_hash(
            seq=seq,
            timestamp=timestamp,
            actor=actor,
            action=action,
            action_class=action_class,
            decision=decision,
            reason=reason,
            prev_hash=prev_hash,
        )
        event = AuditEvent(
            seq=seq,
            timestamp=timestamp,
            actor=actor,
            action=action,
            action_class=action_class,
            decision=decision,
            reason=reason,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(event)) + "\n")
        return event

    # ---------------------------------------------------------------- verify
    def verify(self) -> bool:
        """Recompute the chain across all retained segments; True iff intact.

        Verification spans the archived segments (oldest first) and the active
        log as one continuous chain. Without any rotation this is exactly the
        original single-file, genesis-anchored check. With retention, the oldest
        retained entry must continue from the ``.checkpoint`` (seq + hash of the
        last pruned entry); a missing checkpoint means the chain must start at
        genesis. Any gap, edit, reordering, or dropped segment breaks it.
        """
        segments = self._segments_in_order()
        if all(self._last_event(s) is None for s in segments):
            return True  # empty log is trivially intact

        checkpoint = self._read_checkpoint()
        if checkpoint is None:
            expected_seq, expected_prev = 0, _GENESIS_HASH
        else:
            prev_seq, prev_hash = checkpoint
            expected_seq, expected_prev = prev_seq + 1, prev_hash

        for segment in segments:
            for line in segment.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                if int(record["seq"]) != expected_seq or record["prev_hash"] != expected_prev:
                    return False
                recomputed = _compute_hash(
                    seq=int(record["seq"]),
                    timestamp=record["timestamp"],
                    actor=record["actor"],
                    action=record["action"],
                    action_class=record["action_class"],
                    decision=record["decision"],
                    reason=record["reason"],
                    prev_hash=record["prev_hash"],
                )
                if recomputed != record["entry_hash"]:
                    return False
                expected_prev = record["entry_hash"]
                expected_seq += 1
        return True
