"""Security tests: the dashboard's read-only escalation-queue view.

The view must verify the broker's hash chain before trusting any record —
an edited, truncated, or reordered chain must raise, never render. Chains
here are built with the same canonical algorithm the broker documents, so
these tests need no dependency on the broker package.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from dashboard.escalations import AuditChainError, load_chain_view

_GENESIS = "sha256:" + "0" * 64


def _digest(prev_hash: str, decision_id: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"decision_id": decision_id, "payload": payload, "prev": prev_hash},
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _write_chain(path: Path, payloads: list[dict[str, Any]]) -> None:
    prev = _GENESIS
    lines = []
    for i, payload in enumerate(payloads, 1):
        decision_id = f"ATB-DEC-{i:06d}"
        record_hash = _digest(prev, decision_id, payload)
        lines.append(
            json.dumps(
                {
                    "decision_id": decision_id,
                    "payload": payload,
                    "prev_hash": prev,
                    "record_hash": record_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        prev = record_hash
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


_LIFECYCLE: list[dict[str, Any]] = [
    {"subject": "agent:soc-analyst", "action": "net:egress", "effect": "escalate"},
    {
        "type": "escalation_submitted",
        "ref": "ATB-DEC-000001",
        "subject": "agent:soc-analyst",
        "action": "net:egress",
        "resource": "host:intel.example",
        "reason": "human_approval_required",
    },
    {
        "type": "escalation_submitted",
        "ref": "ATB-DEC-000900",
        "subject": "agent:knowledge-curator",
        "action": "rag:corpus.ingest",
        "resource": "rag:corpus:security",
        "reason": "human_approval_required",
    },
    {
        "type": "escalation_resolved",
        "ref": "ATB-DEC-000900",
        "approver": "ivan",
        "approved": True,
        "reason": "reviewed source",
    },
    {"type": "approval_consumed", "ref": "ATB-DEC-000900"},
]


def test_pending_derived_from_verified_chain(tmp_path: Path) -> None:
    """Only unresolved submissions appear; counts reflect the whole chain."""
    chain = tmp_path / "audit.jsonl"
    _write_chain(chain, _LIFECYCLE)
    view = load_chain_view(chain)
    assert view.records == 5
    assert view.resolved == 1
    assert view.consumed == 1
    assert [p.ref for p in view.pending] == ["ATB-DEC-000001"]
    assert view.pending[0].resource == "host:intel.example"


def test_edited_record_fails_closed(tmp_path: Path) -> None:
    """Rewriting a payload (deny -> approve) must break verification."""
    chain = tmp_path / "audit.jsonl"
    _write_chain(chain, _LIFECYCLE)
    lines = chain.read_text().splitlines()
    tampered = json.loads(lines[3])
    tampered["payload"]["approver"] = "mallory"
    lines[3] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    chain.write_text("\n".join(lines) + "\n")
    with pytest.raises(AuditChainError, match="hash mismatch"):
        load_chain_view(chain)


def test_deleted_record_fails_closed(tmp_path: Path) -> None:
    """Dropping a record (hiding an escalation) must break the chain."""
    chain = tmp_path / "audit.jsonl"
    _write_chain(chain, _LIFECYCLE)
    lines = chain.read_text().splitlines()
    del lines[1]
    chain.write_text("\n".join(lines) + "\n")
    with pytest.raises(AuditChainError, match="chain break"):
        load_chain_view(chain)


def test_malformed_line_fails_closed(tmp_path: Path) -> None:
    chain = tmp_path / "audit.jsonl"
    _write_chain(chain, _LIFECYCLE[:1])
    with chain.open("a", encoding="utf-8") as fh:
        fh.write("not json\n")
    with pytest.raises(AuditChainError, match="not valid JSON"):
        load_chain_view(chain)


def test_missing_file_raises_file_not_found(tmp_path: Path) -> None:
    """Absent chain is 'broker not run yet', distinct from tampering."""
    with pytest.raises(FileNotFoundError):
        load_chain_view(tmp_path / "absent.jsonl")


def test_empty_chain_is_a_healthy_empty_queue(tmp_path: Path) -> None:
    chain = tmp_path / "audit.jsonl"
    chain.write_text("", encoding="utf-8")
    view = load_chain_view(chain)
    assert view.records == 0
    assert view.pending == ()
