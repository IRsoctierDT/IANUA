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
import os
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from agents.policies.signing import HmacSigner, Signer

_GENESIS_HASH = "0" * 64
#: Default environment variable holding the audit-log HMAC signing key.
_SIGNING_KEY_ENV = "AUDIT_HMAC_KEY"


def signing_key_from_env(var: str = _SIGNING_KEY_ENV) -> bytes | None:
    """Return the HMAC signing key from ``var``, or ``None`` if unset/empty.

    Keys live only in the environment (AGENTS.md §5) — never in source or the
    repo. Pass the result to :class:`AuditLogger(signing_key=...)`.
    """
    value = os.environ.get(var, "")
    return value.encode("utf-8") if value else None


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


@dataclass(frozen=True)
class VerificationReport:
    """Structured outcome of a full chain verification (see ``verify_report``).

    ``intact`` is the overall verdict. On failure, ``failure`` pinpoints the
    first break — segment file, line number, sequence, and kind — so an
    operator can go straight to the tampered/corrupted region instead of
    learning only "False". ``signature`` is one of ``valid`` / ``invalid`` /
    ``stale`` / ``missing`` / ``malformed`` (signer configured) or
    ``unsigned`` (no signer) / ``empty`` (nothing to sign).
    """

    intact: bool
    entries: int
    segments: int
    head_seq: int
    head_hash: str
    checkpoint_seq: int | None
    signature: str
    failure: str | None


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
        signing_key: bytes | None = None,
        signer: Signer | None = None,
    ) -> None:
        if max_bytes is not None and max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        if retain_segments is not None and retain_segments < 0:
            raise ValueError("retain_segments must be non-negative")
        if signing_key is not None and signer is not None:
            raise ValueError("pass either signing_key or signer, not both")
        if signing_key is not None and not signing_key:
            raise ValueError("signing_key must be non-empty")
        self.path = Path(path)
        self._clock = clock or _utc_now
        self.max_bytes = max_bytes
        self.retain_segments = retain_segments
        # A ``signing_key`` is sugar for an HMAC signer; ``signer`` allows any
        # scheme (e.g. Ed25519). ``None`` disables signing (default).
        self._signer: Signer | None = (
            signer if signer is not None else (HmacSigner(signing_key) if signing_key else None)
        )
        self._checkpoint_path = self.path.with_name(self.path.name + ".checkpoint")
        self._sig_path = self.path.with_name(self.path.name + ".sig")
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

    def apply_retention(self) -> dict[str, int | bool]:
        """Apply the size/retention policy on demand (for a scheduled job).

        Rotates the active log if it has reached ``max_bytes``, then prunes
        archived segments beyond ``retain_segments``. Idempotent and safe to run
        repeatedly; it does **not** append an entry, so the chain head — and its
        signature — are unchanged. Returns ``{"rotated": ..., "archives": ...}``.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        rotated = self._should_rotate()
        if rotated:
            self._rotate()  # archives the active log, then prunes
        else:
            self._prune()
        return {"rotated": rotated, "archives": len(self._archive_paths())}

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
        if self._signer is not None:
            self._sign_head(seq, entry_hash)
        return event

    # ---------------------------------------------------------------- signing
    @staticmethod
    def _head_message(seq: int, head_hash: str) -> bytes:
        """The bytes signed over the chain head: ``seq|hash``."""
        return f"{seq}|{head_hash}".encode()

    def _sign_head(self, seq: int, head_hash: str) -> None:
        """Write a detached signature over the current chain head.

        The head hash chains over every prior entry, so one signature attests the
        whole log. An attacker without the signing key can recompute a
        self-consistent chain but cannot forge this signature, so tampering is
        detectable by any holder of the (public) key — offline, without trusting
        the file. The scheme (HMAC or Ed25519) is recorded in ``algo``.
        """
        if self._signer is None:
            raise ValueError("no signer configured")
        self._sig_path.write_text(
            json.dumps(
                {
                    "seq": seq,
                    "head_hash": head_hash,
                    "algo": self._signer.algo,
                    "signature": self._signer.sign(self._head_message(seq, head_hash)),
                }
            ),
            encoding="utf-8",
        )

    def verify_signature(self) -> bool:
        """True iff the detached head signature is present, valid, and current.

        Requires a ``signer`` (or ``signing_key``). Fails closed: a missing/garbled
        signature, one that does not verify, or one that covers a stale head (i.e.
        the log changed after signing) all return ``False``. With an Ed25519
        verifier this needs only the public key.
        """
        if self._signer is None:
            raise ValueError("verify_signature requires a signer")
        last_seq, head_hash = self._last()
        return self._signature_status(last_seq, head_hash) in {"valid", "empty"}

    def _signature_status(self, head_seq: int, head_hash: str) -> str:
        """Granular status of the detached head signature against a known head.

        Returns ``unsigned`` (no signer configured), ``empty`` (nothing to
        sign), ``missing``, ``malformed``, ``invalid`` (does not verify),
        ``stale`` (verifies but covers an older head), or ``valid``.
        """
        if self._signer is None:
            return "unsigned"
        if head_seq < 0:
            return "empty"
        if not self._sig_path.exists():
            return "missing"
        try:
            sig = json.loads(self._sig_path.read_text(encoding="utf-8"))
            stored_seq = int(sig["seq"])
            stored_hash = str(sig["head_hash"])
            stored_signature = str(sig["signature"])
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            return "malformed"
        # The signature must verify AND cover the *current* head.
        message = self._head_message(stored_seq, stored_hash)
        if not self._signer.verify(message, stored_signature):
            return "invalid"
        if stored_seq != head_seq or stored_hash != head_hash:
            return "stale"
        return "valid"

    # ---------------------------------------------------------------- verify
    def verify(self) -> bool:
        """Recompute the chain across all retained segments; True iff intact.

        Thin wrapper over :meth:`verify_report` — identical semantics, boolean
        result. See the report for what "intact" covers (chain continuity,
        checkpoint anchoring, per-entry hashes, and — when a signer is
        configured — a present, valid, current head signature).
        """
        return self.verify_report().intact

    def verify_report(self) -> VerificationReport:
        """Recompute the chain and return a structured diagnosis.

        Verification spans the archived segments (oldest first) and the active
        log as one continuous chain. Without any rotation this is exactly the
        original single-file, genesis-anchored check. With retention, the oldest
        retained entry must continue from the ``.checkpoint`` (seq + hash of the
        last pruned entry); a missing checkpoint means the chain must start at
        genesis. Any gap, edit, reordering, dropped segment, or malformed line
        breaks it — malformed/corrupted entries are a *verdict* (fail-closed
        with a located failure), never an exception.

        When a signer (``signing_key`` or ``signer``) is configured, the
        detached head signature must also be ``valid`` (present, verifying, and
        covering the current head) for the report to be ``intact`` — so a
        recomputed-but-unsigned chain is rejected. On failure, ``failure``
        names the first broken segment, line, and kind of break.
        """
        segments = self._segments_in_order()
        checkpoint = self._read_checkpoint()
        if checkpoint is None:
            expected_seq, expected_prev = 0, _GENESIS_HASH
            checkpoint_seq: int | None = None
        else:
            checkpoint_seq, prev_hash = checkpoint
            expected_seq, expected_prev = checkpoint_seq + 1, prev_hash

        entries = 0
        head_seq, head_hash = -1, _GENESIS_HASH

        def _report(failure: str | None, signature: str) -> VerificationReport:
            return VerificationReport(
                intact=failure is None and signature in {"valid", "unsigned", "empty"},
                entries=entries,
                segments=len(segments),
                head_seq=head_seq,
                head_hash=head_hash,
                checkpoint_seq=checkpoint_seq,
                signature=signature,
                failure=failure,
            )

        for segment in segments:
            for line_no, line in enumerate(
                segment.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if not line.strip():
                    continue
                where = f"{segment.name}:{line_no}"
                try:
                    record = json.loads(line)
                    seq = int(record["seq"])
                    prev = str(record["prev_hash"])
                    recomputed = _compute_hash(
                        seq=seq,
                        timestamp=record["timestamp"],
                        actor=record["actor"],
                        action=record["action"],
                        action_class=record["action_class"],
                        decision=record["decision"],
                        reason=record["reason"],
                        prev_hash=prev,
                    )
                    stored_hash = str(record["entry_hash"])
                except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                    # Corruption is tampering until proven otherwise: locate it,
                    # fail closed, never raise out of verification. The head
                    # signature is not consulted past a break ("unchecked").
                    return _report(f"malformed entry at {where}", "unchecked")
                if seq != expected_seq or prev != expected_prev:
                    return _report(
                        f"chain break at {where}: expected seq {expected_seq} "
                        f"continuing from {expected_prev[:12]}…, found seq {seq} "
                        f"with prev {prev[:12]}…",
                        "unchecked",
                    )
                if recomputed != stored_hash:
                    return _report(f"entry hash mismatch at {where} (seq {seq})", "unchecked")
                entries += 1
                head_seq, head_hash = seq, stored_hash
                expected_prev = stored_hash
                expected_seq += 1

        if entries == 0:
            # Empty (or fully pruned) log: trivially intact; nothing to sign.
            signature = "empty" if self._signer is not None else "unsigned"
            return _report(None, signature)

        signature = self._signature_status(head_seq, head_hash)
        if self._signer is not None and signature != "valid":
            return _report(f"head signature {signature}", signature)
        return _report(None, signature)
