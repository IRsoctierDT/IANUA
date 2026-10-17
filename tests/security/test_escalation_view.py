# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Security tests: the dashboard's read-only escalation-queue view.

The view must verify the broker's hash chain before trusting any record —
an edited, truncated, or reordered chain must raise, never render. Chains
here are built with the same canonical algorithm the broker documents, so
these tests need no dependency on the broker package.
"""

from __future__ import annotations

import ast
import contextlib
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from dashboard.escalations import MAX_CHAIN_BYTES, AuditChainError, load_chain_view

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


def test_non_utf8_chain_is_a_chain_error(tmp_path: Path) -> None:
    """Bytes that are not UTF-8 are a malformed chain, not a traceback.

    Measured on the base commit: ``read_text`` raised ``UnicodeDecodeError``,
    which neither ``except`` in the dashboard's approvals tab caught, and a
    directory at the path raised ``IsADirectoryError`` the same way.
    """
    chain = tmp_path / "audit.jsonl"
    chain.write_bytes(b"\xff\xfe\x00garbage")
    with pytest.raises(AuditChainError, match="not valid UTF-8"):
        load_chain_view(chain)
    with pytest.raises(IsADirectoryError):  # an I/O failure stays an OSError for the caller
        load_chain_view(tmp_path)


def test_approvals_tab_catches_every_read_failure() -> None:
    """The one ``try`` around ``load_chain_view`` in app.py handles OSError, after the narrower two."""
    app = Path(__file__).resolve().parents[2] / "dashboard" / "app.py"
    tries = [
        node
        for node in ast.walk(ast.parse(app.read_text(encoding="utf-8")))
        if isinstance(node, ast.Try)
        and any(
            isinstance(n, ast.Name) and n.id == "load_chain_view"
            for stmt in node.body
            for n in ast.walk(stmt)
        )
    ]
    assert len(tries) == 1
    handlers = [h.type.id for h in tries[0].handlers if isinstance(h.type, ast.Name)]
    assert "AuditChainError" in handlers
    assert handlers.index("FileNotFoundError") < handlers.index("OSError"), handlers


def _hashed_deep_record(depth: int) -> str:
    """A correctly hashed record whose ``ref`` nests ``depth`` lists, built as text.

    The chain hash is unkeyed, so whoever can append can compute it; building
    by text keeps the builder clear of the recursion limit it probes.
    """
    body = f'"decision_id":"d1","payload":{{"ref":{"[" * depth}{"]" * depth},"type":"t"}}'
    digest = hashlib.sha256(f'{{{body},"prev":"{_GENESIS}"}}'.encode()).hexdigest()
    return f'{{{body},"prev_hash":"{_GENESIS}","record_hash":"sha256:{digest}"}}\n'


def test_content_json_refuses_otherwise_is_a_chain_error(tmp_path: Path) -> None:
    """Every content failure is an ``AuditChainError``, which the approvals tab catches.

    Measured on 909914e through that tab's ``try``: a 4301-digit integer escaped
    as ``ValueError`` and 100000 brackets as ``RecursionError``, and on 3.11 a
    correctly hashed record one level short of ``json.loads``'s limit escaped
    from the re-hash. The sweep straddles that limit wherever this interpreter
    and this stack put it (996 deep at top level on 3.11, 9998 on 3.12).
    """
    chain = tmp_path / "audit.jsonl"
    chain.write_text(_hashed_deep_record(3), encoding="utf-8")
    assert load_chain_view(chain).records == 1  # the builder hashes correctly
    ok, fails = 1, 1 << 20  # bisect the deepest nesting json.loads accepts here
    while fails - ok > 1:
        mid = (ok + fails) // 2
        try:
            json.loads("[" * mid + "]" * mid)
            ok = mid
        except RecursionError:
            fails = mid
    hostile = [_hashed_deep_record(depth) for depth in range(ok - 20, fails + 3)]
    hostile += ['{"decision_id":"d","payload":{"ref":' + "9" * 4301 + "}}", "[" * 100_000]
    for content in hostile:
        chain.write_text(content, encoding="utf-8")
        with contextlib.suppress(AuditChainError):  # anything else escapes and fails
            load_chain_view(chain)


def test_non_regular_chain_is_refused_without_blocking(tmp_path: Path) -> None:
    """On 909914e a FIFO blocked the read and ``/dev/null`` read as a verified, empty chain."""
    fifo = tmp_path / "fifo.jsonl"
    os.mkfifo(fifo)
    device = tmp_path / "device.jsonl"
    device.symlink_to(os.devnull)
    for path in (fifo, device):
        with pytest.raises(OSError, match="not a regular file"):
            load_chain_view(path)


def test_chain_read_is_bounded(tmp_path: Path) -> None:
    """The read was unbounded; one byte past the bound is refused before decoding."""
    chain = tmp_path / "audit.jsonl"
    chain.write_bytes(b" " * MAX_CHAIN_BYTES)  # at the bound: read, blank, empty chain
    assert load_chain_view(chain).records == 0
    with chain.open("ab") as handle:
        handle.write(b" ")
    with pytest.raises(AuditChainError, match="larger than"):
        load_chain_view(chain)
