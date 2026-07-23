"""Read-only view over the Agent Trust Broker's escalation queue.

Surfaces the broker's outstanding human approvals in the dashboard by reading
its hash-chained audit file (JSONL, one record per line — the format written
by the broker's ``JsonlAuditStore``). The integration contract is the file
format, not the broker package: IANUA takes no dependency on ``atb``.

Security considerations:
- **Verify before trusting.** The chain is recomputed here, independently,
  before any record is displayed; a broken chain raises ``AuditChainError``
  rather than rendering a plausible-but-tampered queue (THR-0003 posture).
- **Read-only by design.** This module never writes: approvals are resolved
  through the broker's own tooling, and a second chain-writer would be a
  corruption risk. The dashboard makes the gate *visible*, not operable.
- ``load_chain_view`` validates its input path and fails closed on malformed
  records.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_GENESIS = "sha256:" + "0" * 64
_SUBMITTED = "escalation_submitted"
_RESOLVED = "escalation_resolved"
_CONSUMED = "approval_consumed"


class AuditChainError(Exception):
    """The audit chain is malformed or fails hash verification (fail closed)."""


@dataclass(frozen=True)
class PendingApproval:
    """One escalation awaiting a human decision, as recorded in the chain."""

    ref: str
    subject: str
    action: str
    resource: str
    reason: str


@dataclass(frozen=True)
class ChainView:
    """Verified summary of the broker's audit chain for display."""

    records: int
    pending: tuple[PendingApproval, ...]
    resolved: int
    consumed: int


def _digest(prev_hash: str, decision_id: str, payload: dict[str, Any]) -> str:
    """Recompute one record hash (mirrors the broker's canonical algorithm)."""
    canonical = json.dumps(
        {"decision_id": decision_id, "payload": payload, "prev": prev_hash},
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_chain_view(path: Path) -> ChainView:
    """Parse and verify the broker audit chain; derive outstanding approvals.

    Raises ``AuditChainError`` on any malformed line, hash mismatch, or break
    in the chain — a tampered queue must never render as a healthy one.
    Raises ``FileNotFoundError`` if the file does not exist (callers decide
    how to present "no broker configured").
    """
    if not isinstance(path, Path):
        raise AuditChainError("path must be a pathlib.Path")

    submitted: dict[str, dict[str, Any]] = {}
    resolved: set[str] = set()
    consumed: set[str] = set()
    prev = _GENESIS
    count = 0

    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditChainError(f"{path.name}:{line_number}: not valid JSON") from exc
        if not isinstance(record, dict):
            raise AuditChainError(f"{path.name}:{line_number}: record is not an object")

        decision_id = record.get("decision_id")
        payload = record.get("payload")
        if not isinstance(decision_id, str) or not isinstance(payload, dict):
            raise AuditChainError(f"{path.name}:{line_number}: missing decision_id/payload")
        if record.get("prev_hash") != prev:
            raise AuditChainError(f"{path.name}:{line_number}: chain break (prev_hash mismatch)")
        if record.get("record_hash") != _digest(prev, decision_id, payload):
            raise AuditChainError(f"{path.name}:{line_number}: record hash mismatch")
        prev = str(record["record_hash"])
        count += 1

        kind = payload.get("type")
        ref = str(payload.get("ref", ""))
        if kind == _SUBMITTED:
            submitted[ref] = payload
        elif kind == _RESOLVED:
            resolved.add(ref)
        elif kind == _CONSUMED:
            consumed.add(ref)

    pending = tuple(
        PendingApproval(
            ref=ref,
            subject=str(entry.get("subject", "")),
            action=str(entry.get("action", "")),
            resource=str(entry.get("resource", "")),
            reason=str(entry.get("reason", "")),
        )
        for ref, entry in submitted.items()
        if ref not in resolved
    )
    return ChainView(records=count, pending=pending, resolved=len(resolved), consumed=len(consumed))
