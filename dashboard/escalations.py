# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

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

import errno
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_GENESIS = "sha256:" + "0" * 64
_SUBMITTED = "escalation_submitted"
_RESOLVED = "escalation_resolved"
_CONSUMED = "approval_consumed"

#: The most bytes ``load_chain_view`` reads; past it the chain is refused
#: unverified (``AuditChainError``). The read was unbounded, so a 2 GB sparse
#: file raised ``MemoryError``; at this bound peak RSS measured 96-143 MB. A
#: legitimate chain past it (~54,000 short records) fails closed too: the
#: figure is a choice for the owner to revisit, not a measured need.
MAX_CHAIN_BYTES = 16 * 1024 * 1024


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


def _read_chain(path: Path) -> str:
    """Return the chain's text without blocking on, or reading whole, a hostile path.

    ``O_NONBLOCK`` lets the open return on a FIFO with no writer, where a plain
    open blocked until one appeared; ``fstat`` on that descriptor then refuses anything
    that is not a regular file with an ``OSError`` (``IsADirectoryError`` for a
    directory). Symlinks are followed, as ``read_text`` did. At most
    ``MAX_CHAIN_BYTES + 1`` bytes are read, so an oversized file is refused
    before it is decoded.
    """
    with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)), "rb") as handle:
        mode = os.fstat(handle.fileno()).st_mode
        if not stat.S_ISREG(mode):
            code = errno.EISDIR if stat.S_ISDIR(mode) else errno.EINVAL
            raise OSError(code, "not a regular file", path.name)
        data = handle.read(MAX_CHAIN_BYTES + 1)
    if len(data) > MAX_CHAIN_BYTES:
        raise AuditChainError(f"{path.name}: larger than {MAX_CHAIN_BYTES} bytes; not verified")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuditChainError(f"{path.name}: not valid UTF-8") from exc


def load_chain_view(path: Path) -> ChainView:
    """Parse and verify the broker audit chain; derive outstanding approvals.

    Raises ``AuditChainError`` on any malformed line, hash mismatch, or break
    in the chain — a tampered queue must never render as a healthy one — and
    on content that is not UTF-8 or exceeds ``MAX_CHAIN_BYTES``. Malformed
    includes every ``ValueError`` (``JSONDecodeError``, an integer past 4300
    digits) and ``RecursionError`` (nesting near the interpreter's limit, in
    ``json.loads`` or in re-hashing a correctly hashed record) raised while
    verifying or deriving the view. Raises ``FileNotFoundError`` if the file
    does not exist (callers decide how to present "no broker configured"); a
    path that is not a regular file (directory, FIFO, socket, device) raises
    ``OSError`` without blocking, and any other ``OSError`` (a permission
    denial) propagates for the caller to surface. ``MemoryError`` is not
    caught; the read is bounded by ``MAX_CHAIN_BYTES``.
    """
    if not isinstance(path, Path):
        raise AuditChainError("path must be a pathlib.Path")
    text = _read_chain(path)
    try:
        return _verify(path, text)
    except (ValueError, RecursionError) as exc:
        raise AuditChainError(f"{path.name}: malformed record ({exc.__class__.__name__})") from exc


def _verify(path: Path, text: str) -> ChainView:
    """Verify ``text`` record by record and derive the view (see ``load_chain_view``)."""
    submitted: dict[str, dict[str, Any]] = {}
    resolved: set[str] = set()
    consumed: set[str] = set()
    prev = _GENESIS
    count = 0

    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except (ValueError, RecursionError) as exc:  # JSONDecodeError is a ValueError
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
