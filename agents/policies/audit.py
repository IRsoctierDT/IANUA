"""Structured, tamper-evident audit log — implements AGENTS.md §3 auditability.

Security-relevant decisions (e.g. policy-gate evaluations) are appended as JSON
lines with a **hash chain**: each entry's ``entry_hash`` covers the previous
entry's hash, so any insertion, deletion, or edit breaks the chain and is caught
by :meth:`AuditLogger.verify`.

Security notes:
- **Append-only.** The logger only ever appends; it never rewrites history.
- **No sensitive payloads.** Callers pass decisions and short reasons — never
  secrets, credentials, or raw log/PII content (AGENTS.md §5). The logger records
  what it is given; keeping payloads out is the caller's responsibility.
- **Deterministic for tests.** The timestamp source is injectable.
"""

from __future__ import annotations

import hashlib
import json
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


class AuditLogger:
    """Append security-relevant events to a hash-chained JSONL audit log."""

    def __init__(self, path: Path | str, *, clock: Callable[[], str] | None = None) -> None:
        self.path = Path(path)
        self._clock = clock or _utc_now

    def _last(self) -> tuple[int, str]:
        """Return ``(last_seq, last_entry_hash)`` or ``(-1, genesis)`` if empty."""
        if not self.path.exists():
            return -1, _GENESIS_HASH
        last_line = ""
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last_line = line
        if not last_line:
            return -1, _GENESIS_HASH
        record = json.loads(last_line)
        return int(record["seq"]), str(record["entry_hash"])

    def record(
        self, *, actor: str, action: str, action_class: str, decision: str, reason: str
    ) -> AuditEvent:
        """Append one audit event and return it. Creates the log file if needed."""
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
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(event)) + "\n")
        return event

    def verify(self) -> bool:
        """Recompute the chain end-to-end; return True iff it is intact."""
        if not self.path.exists():
            return True  # an empty log is trivially intact
        prev_hash = _GENESIS_HASH
        expected_seq = 0
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if int(record["seq"]) != expected_seq or record["prev_hash"] != prev_hash:
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
            prev_hash = record["entry_hash"]
            expected_seq += 1
        return True
