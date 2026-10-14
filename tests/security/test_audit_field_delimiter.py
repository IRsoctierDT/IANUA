# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The audit preimage is an unescaped join — prove the forgery, then close it.

``_compute_hash`` joins eight fields with ``|`` and hashes the result. Nothing
escapes the fields, so a value containing ``|`` shifts where one field ends and
the next begins: two records with *different meanings* produce the same
preimage, and the chain cannot tell them apart. The head signature does not
help — it covers only ``f"{seq}|{head_hash}"``.

The first test demonstrates the collision against the real hash function, so
the defect is recorded as a fact rather than an assertion. The rest prove that
``record`` now refuses to write such a value, in every hashed field, because
the forgery works whichever field holds the stray character.

Reachability, established by reading the call sites rather than assumed:

* ``actor`` — caller-supplied at every ``record`` site and previously
  unvalidated. The widest path.
* ``action`` via ``quarantine_file``/``release_file`` — a filename may contain
  ``|``; ``_resolve_no_symlink`` confines the path but does not restrict its
  alphabet.
* ``action`` via ``stop_process``/``resume_process`` — not reachable, the
  target is ``pid: int``.
* ``action`` via the hostname/account/hash capabilities — not reachable,
  ``_HOSTNAME_RE``/``_ACCOUNT_RE``/``_HEX_HASH_RE`` exclude it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from agents.policies import (
    AUDIT_FIELD_DELIMITER,
    AuditFieldError,
    AuditLogger,
    escape_delimiter,
    reject_delimiter,
)
from agents.policies.audit import _compute_hash

_T = "2026-10-14T00:00:00Z"
_PREV = "sha256:" + "0" * 64


@pytest.mark.security
def test_an_unescaped_delimiter_makes_a_deny_hash_like_an_allow() -> None:
    """The defect this module exists to close, demonstrated not asserted.

    Both calls go through the production hash function. A is a ``deny`` whose
    ``reason`` carries a pipe; B is an ``allow`` whose ``actor`` carries one.
    Different fields, different decisions, identical hash.
    """
    deny = _compute_hash(
        seq=1,
        timestamp=_T,
        actor="svc",
        action="x",
        action_class="read_only",
        decision="deny",
        reason="allow|s",
        prev_hash=_PREV,
    )
    allow = _compute_hash(
        seq=1,
        timestamp=_T,
        actor="svc|x",
        action="read_only",
        action_class="deny",
        decision="allow",
        reason="s",
        prev_hash=_PREV,
    )
    assert deny == allow, (
        "the premise of this module no longer holds: the preimage now "
        "distinguishes these records, so the delimiter may have been escaped "
        "or length-prefixed. If so, reject_delimiter may be relaxable — but "
        "verify against the verifier too (it re-derives the preimage "
        "independently and has no per-record version branch)."
    )


@pytest.mark.security
@pytest.mark.parametrize("field", ["actor", "action", "action_class", "decision", "reason"])
def test_record_refuses_a_delimiter_in_any_hashed_field(tmp_path: Path, field: str) -> None:
    """Every field, because the forgery works through whichever one carries it."""
    logger = AuditLogger(tmp_path / "audit.jsonl")
    fields = {
        "actor": "svc",
        "action": "tool:x",
        "action_class": "read_only",
        "decision": "allow",
        "reason": "ok",
    }
    fields[field] = f"forged{AUDIT_FIELD_DELIMITER}split"
    with pytest.raises(AuditFieldError, match="delimiter"):
        logger.record(**fields)
    assert not (tmp_path / "audit.jsonl").exists(), (
        "a record that cannot be hashed unambiguously must not be written at all"
    )


@pytest.mark.security
def test_a_valid_record_still_writes(tmp_path: Path) -> None:
    """The guard must not be so strict that the normal path breaks."""
    logger = AuditLogger(tmp_path / "audit.jsonl")
    event = logger.record(
        actor="containment/ivan",
        action="containment:quarantine_file:/lab/sample.bin",
        action_class="containment",
        decision="allow",
        reason="quarantined",
    )
    assert event.actor == "containment/ivan"
    assert (tmp_path / "audit.jsonl").exists()


@pytest.mark.security
def test_the_report_only_marker_still_round_trips(tmp_path: Path) -> None:
    """``guarded.enforce`` appends ``[report-only]`` to the rendered actor.

    Pinned because the validation added here could plausibly have been written
    as a narrow allow-list, which would have rejected that existing marker and
    broken the staged-rollout path.
    """
    logger = AuditLogger(tmp_path / "audit.jsonl")
    event = logger.record(
        actor="tool/ivan[report-only]",
        action="tool:x",
        action_class="read_only",
        decision="deny",
        reason="observed",
    )
    assert event.actor.endswith("[report-only]")


@pytest.mark.security
def test_escape_renders_attacker_text_safe_rather_than_rejecting_it() -> None:
    """A filename may legitimately contain ``|``.

    Containment writes its outcome record *after* the file has moved, so
    rejecting there would leave the effect done and the trail missing.
    Descriptive fields are escaped; identity fields are not.
    """
    escaped = escape_delimiter("evil|containment|allow|ok")
    assert AUDIT_FIELD_DELIMITER not in escaped, (
        "the escape must REMOVE the delimiter, not merely mark it: a "
        "backslash escape still contains the character, so the preimage would "
        "stay ambiguous and reject_delimiter would refuse the escaped form"
    )
    assert escaped == "evil%7Ccontainment%7Callow%7Cok"
    # Reversible, and the escaped form passes the guard — which is the point.
    reject_delimiter(action=escaped)
    # `%` is encoded first, so pre-existing %7C cannot be confused with a pipe.
    assert escape_delimiter("already%7Chere") == "already%257Chere"


@pytest.mark.security
def test_containment_escapes_a_piped_filename_instead_of_crashing(tmp_path: Path) -> None:
    """End to end: the reachable path no longer raises after the effect."""
    from agents.policies import PolicyEngine
    from agents.tools.containment import ContainmentToolkit

    logger = AuditLogger(tmp_path / "audit.jsonl")
    root = tmp_path / "lab"
    root.mkdir()
    victim = root / "evil|containment|allow.bin"
    victim.write_bytes(b"payload")
    toolkit = ContainmentToolkit(
        root=root, engine=PolicyEngine(), audit=logger, actor="containment"
    )
    action = toolkit.quarantine_file(victim.name)
    assert action.executed
    written = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "%7C" in written, "the pipe should have been percent-encoded into the record"
    assert "evil%7Ccontainment%7Callow.bin" in written
