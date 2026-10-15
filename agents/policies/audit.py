# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

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

import contextlib
import fcntl
import hashlib
import json
import os
import re
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from agents.policies.signing import HmacSigner, Signer, ed25519_verifier_from_env

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


def verifier_from_env() -> Signer | None:
    """Pick the head-signature scheme from the environment, or ``None``.

    HMAC (``AUDIT_HMAC_KEY``) wins when both are set — holding the shared secret
    also detects a *wrong* key — and the Ed25519 path (``AUDIT_ED25519_PUBLIC_KEY``)
    needs only the **public** key, so an auditor or CI can verify a log signed
    elsewhere without ever holding a key that could forge it.

    ``None`` means no key material is available at all: the caller falls back to
    chain-only verification (reported as ``unsigned``) or refuses outright. It is
    deliberately *not* a silent fallback for key material that exists but cannot
    be used — a bad hex key, or Ed25519 without the ``.[crypto]`` extra, raises
    (``ValueError`` / ``RuntimeError``) so a caller cannot mistake an unusable
    key for an unsigned log and proceed as if it had verified one.

    **Every tool that *reads* a chain resolves its verifier here**, so a log the
    read-only verifier would reject cannot be rotated or pruned by a maintenance
    job that resolved a weaker scheme — nor recorded as ``intact`` in a backup
    manifest by one. The readers are :mod:`scripts.audit_verify`,
    :mod:`scripts.audit_maintenance`, ``scripts.run_backup._verify_chains`` and
    :func:`compliance.evidence.verify_chain`; the first draft of this sentence
    claimed all of them and only the first two were true, which is how the
    third kept reporting a stale Ed25519 head signature as intact.

    *Writers* do **not** use this: they need a key that can sign, and
    :class:`Ed25519Verifier` deliberately cannot. They resolve
    :func:`signing_key_from_env` instead, which is HMAC-only — so an Ed25519
    deployment's chains are written unsigned. That is a real gap and a wider
    one than this function; it is recorded rather than implied here, because
    closing it means deciding whether the platform wants an Ed25519 *signing*
    posture at all (``ed25519_signer_from_env`` exists and no writer calls it).
    """
    hmac_key = signing_key_from_env()
    if hmac_key is not None:
        return HmacSigner(hmac_key)
    return ed25519_verifier_from_env()


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


# Audit artifacts are sensitive by default (AGENTS.md §5): create them
# owner-only. 0o600 files / 0o700 directories apply at *creation*; permissions
# of pre-existing files are deliberately left untouched (an operator may have
# chosen a group-readable scheme — we never silently widen OR narrow it).
_FILE_MODE = 0o600
_DIR_MODE = 0o700


def _opener_owner_only(path: str, flags: int) -> int:
    """``open()`` opener creating files 0o600 (no-op for existing files)."""
    return os.open(path, flags, _FILE_MODE)


def _write_text_owner_only(path: Path, text: str) -> None:
    """Replace ``path`` with ``text`` atomically, owner-read/write only.

    Written to a temporary file in the same directory and ``os.replace``d, so a
    reader never observes a half-written sidecar. It used to be a plain
    ``open(path, "w")``, which truncates first — and the signature sidecar is
    read by :meth:`AuditLogger.verify_report` on a cadence. Measured on an
    intact chain with **one** writer and one reader: 151 of 606 verifications
    reported the chain broken (137 ``malformed``, 14 ``stale``) with no defect
    present at all, which the ``audit-chains-intact`` objective grades against
    a target of 1.0 every five minutes.

    The lock in :meth:`AuditLogger.record` does not help here: the reader holds
    no lock and the window is inside a single writer's own call. Atomicity is
    the fix, and ``Path.replace`` is atomic within a filesystem — the temporary
    file is created beside the target for exactly that reason.
    """
    directory = path.parent
    directory.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
    temporary = directory / f".{path.name}.tmp"
    try:
        with open(temporary, "w", encoding="utf-8", opener=_opener_owner_only) as fh:
            fh.write(text)
        temporary.replace(path)  # atomic within a filesystem
    except BaseException:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise


#: The field separator in the hash preimage below. Named because it is
#: load-bearing: the join is *unescaped*, so a value containing this character
#: shifts where one field ends and the next begins. Two records with different
#: meanings then produce the same preimage — a ``deny`` record can be made to
#: hash identically to an ``allow`` record. :func:`reject_delimiter` is what
#: prevents that, and ``tests/security/test_audit_field_delimiter.py``
#: demonstrates the collision it closes.
AUDIT_FIELD_DELIMITER = "|"


class AuditFieldError(ValueError):
    """A field value would corrupt the hash preimage.

    A :class:`ValueError` subclass because every other guard in this module
    raises ``ValueError``; the subclass lets a caller catch this case
    specifically without breaking existing handlers.

    Fails closed rather than escaping or truncating: a record that cannot be
    hashed unambiguously must not be written at all, because the whole value
    of the chain is that a stored record means exactly one thing. Callers that
    carry attacker-influenced text into a field are expected to escape it
    *before* calling :meth:`AuditLogger.record` — see
    ``containment._record_outcome`` — so this is a backstop, not the first
    line of defence.
    """


def reject_delimiter(**fields: str) -> None:
    """Raise :class:`AuditFieldError` if any field carries the delimiter.

    Checked for every hashed field, not just the caller-supplied ones: the
    forgery works whichever field holds the stray character, so excluding any
    field from the check would leave the hole open through that field.
    """
    for name, value in fields.items():
        if AUDIT_FIELD_DELIMITER in value:
            raise AuditFieldError(
                f"audit field {name!r} contains the preimage delimiter "
                f"{AUDIT_FIELD_DELIMITER!r}, which would make this record "
                f"hash-ambiguous with a differently-meaning one: {value!r}"
            )


def escape_delimiter(value: str) -> str:
    """Render attacker-influenced text safe for a hashed field.

    For *descriptive* fields only — an action string or a reason, where the
    value documents what happened rather than asserting who did it. A filename
    may legitimately contain ``|``, and quarantining such a file must not fail:
    ``containment._record_outcome`` writes its record *after* the file has
    moved, so raising there would mean the effect succeeded and the audit
    write did not. Escaping keeps the record writable and unambiguous.

    Identity fields are **not** escaped. A principal is validated and rejected
    (see ``agents/policies/principal.py``), because silently rewriting who did
    something is not a repair.

    **Percent-encoded, not backslash-escaped.** A ``\\|`` escape still
    *contains* the delimiter, so :func:`reject_delimiter` would refuse it and
    the preimage would stay ambiguous — ``\\|`` is indistinguishable from a
    literal backslash followed by a field break. Percent-encoding removes the
    character entirely while staying reversible and ASCII. ``%`` is encoded
    first, so an input that already contained ``%7C`` cannot be confused with
    an encoded pipe.
    """
    return value.replace("%", "%25").replace(AUDIT_FIELD_DELIMITER, "%7C")


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
    payload = AUDIT_FIELD_DELIMITER.join(
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
        #: Beside the chain, and **not** the chain itself. A lock on the log's
        #: own descriptor stops excluding the instant ``_rotate`` renames that
        #: inode away: measured, a second writer acquired ``LOCK_EX`` on the new
        #: inode in 0.0 s while the first still held the old one, both wrote the
        #: same ``seq``, and the chain read ``intact=False``. The sidecar is a
        #: file rotation never touches. It is invisible to ``_archive_re``
        #: (``^audit\.log\.(\d+)$``), so ``exists()``, ``verify_report()`` and
        #: the archive accounting are unaffected.
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self._archive_re = re.compile(rf"^{re.escape(self.path.name)}\.(\d+)$")

    @contextlib.contextmanager
    def _exclusive(self) -> Iterator[None]:
        """Serialise this chain's whole read-modify-write across processes.

        **Blocking, deliberately.** The four scheduled CLIs use
        ``LOCK_EX | LOCK_NB`` and print "skipped" because an overlapping pass is
        expected; dropping an *audit record* is the opposite case — AGENTS.md §3
        requires security-relevant actions to emit evidence, and a fork is
        permanent in a way a wait is not. Measured: after a four-way fork plus
        200 perfectly serial records, ``verify_report().entries`` was 2 of 204,
        because verification stops at the first break — so one fork voids the
        evidentiary weight of everything after it. The cost of waiting instead
        is ~7 µs median on a call that already costs ~98 µs on a fresh chain,
        and ``flock`` has no stale-lock failure mode: the kernel releases it
        when the holder dies.

        Created lazily, by the caller that needs it, and never in ``__init__``.
        Four call sites construct an ``AuditLogger`` purely to read
        (``sli/indicators.py``, ``scripts/audit_verify.py``,
        ``compliance/evidence.py``, ``scripts/run_backup.py``), and
        ``tests/security/test_sli_hardening.py`` asserts that a measurement
        creates nothing — eager creation costs seven tests instead of one.

        Not reentrant: ``flock`` is scoped to the open file description, so a
        second ``open()`` of this path in the same process blocks forever. No
        method holding this may call another that takes it.
        """
        self._lock_path.parent.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        with open(self._lock_path, "a", encoding="utf-8", opener=_opener_owner_only) as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    @contextlib.contextmanager
    def _shared(self) -> Iterator[None]:
        """Read the chain and its signature as one pair, when a lock exists.

        Shared, not exclusive, so concurrent readers never serialise against
        each other — only against a writer mid-append.

        **Never creates the lock file.** Four call sites build an
        ``AuditLogger`` purely to read, and
        ``tests/security/test_sli_hardening.py`` asserts a measurement creates
        nothing; a reader that materialised a lock would break that and would
        also make ``exists()`` answer differently on a bare path. With no lock
        present there is by definition no writer holding one, so proceeding
        unsynchronised is the correct reading rather than a fallback.

        What this buys, measured on an intact chain with one writer and one
        reader. Making the sidecar writes atomic removed every ``malformed``
        verdict (137 → 0) but left 130 ``stale`` ones: the reader read the
        chain, the writer advanced the head, and then the reader read a
        signature for a head it had not seen. That is a read-side consistency
        problem no write-side lock can fix, and it matters because
        ``audit-chains-intact`` grades these against a target of 1.0 every five
        minutes.
        """
        if not self._lock_path.is_file():
            yield
            return
        with self._lock_path.open(encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    # ---------------------------------------------------------------- segments
    @staticmethod
    def _is_segment(path: Path) -> bool:
        """True iff ``path`` could be a chain segment: a real, regular file.

        **A chain is made of files, and this is the only thing that said so.**
        Every discovery below used :meth:`Path.exists`, which is true of a
        *directory* — and :meth:`apply_retention` acts on what it discovers.
        Measured on the version of this file before this check existed: a
        mistyped ``--log /srv/ianua/data/pipeline`` (one path component short
        of ``…/pipeline/audit.log``) made ``_rotate`` **rename the whole
        subsystem directory** to ``pipeline.1``, carrying the audit chain and
        the pipeline cursor with it, and reported ``{"rotated": true,
        "archives": 1}`` at exit ``0``. ``--log …/data`` renamed the entire
        lab-data root — event store included — the same way. The run after
        that tracebacked out of ``_prune``'s ``unlink()`` with exit 1, so an
        operator learns of it only once the damage is a commit behind them.

        ``is_symlink()`` is excluded as well, which is the discipline §5 of the
        charter already states for the log files ``collect/`` reads: a link at
        the chain means the chain is not where it is believed to be. It does
        **not** close :meth:`record`'s append-through-a-symlink path, which
        never consults this predicate — a separate concern, recorded rather
        than implied.
        """
        return path.is_file() and not path.is_symlink()

    def _archive_paths(self) -> list[Path]:
        """Archived segments, oldest → newest (ascending numeric suffix)."""
        parent = self.path.parent
        if not parent.is_dir():
            return []
        indexed: list[tuple[int, Path]] = []
        for child in parent.iterdir():
            m = self._archive_re.match(child.name)
            if m and self._is_segment(child):
                indexed.append((int(m.group(1)), child))
        return [p for _, p in sorted(indexed)]

    def _segments_in_order(self) -> list[Path]:
        """All chain segments oldest → newest: archives then the active log."""
        segments = self._archive_paths()
        if self._is_segment(self.path):
            segments.append(self.path)
        return segments

    def exists(self) -> bool:
        """True iff any trace of the log exists on disk, as a chain.

        Checks the active file, archived segments, and the retention
        checkpoint — each of which must be a regular, non-symlink file (see
        :meth:`_is_segment`). Lets a verifier distinguish a wrong/missing path
        (nothing was ever logged here — a monitor must fail closed) from a
        legitimately empty existing log, and refuses to call a *directory* a
        log, which is what made rotation rename one.
        """
        return bool(self._segments_in_order()) or self._is_segment(self._checkpoint_path)

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
        if not self._is_segment(self._checkpoint_path):
            return None
        data = json.loads(self._checkpoint_path.read_text(encoding="utf-8"))
        return int(data["pruned_through_seq"]), str(data["pruned_through_hash"])

    def _write_checkpoint(self, seq: int, entry_hash: str) -> None:
        _write_text_owner_only(
            self._checkpoint_path,
            json.dumps({"pruned_through_seq": seq, "pruned_through_hash": entry_hash}),
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
        # ``_is_segment`` rather than ``exists()``: a directory's ``st_size``
        # is its own block size — 4096 on ext4 — so any ``max_bytes`` below
        # that made a mistyped path "due for rotation".
        return (
            self.max_bytes is not None
            and self._is_segment(self.path)
            and self.path.stat().st_size >= self.max_bytes
        )

    def apply_retention(self) -> dict[str, int | bool]:
        """Apply the size/retention policy on demand (for a scheduled job).

        Rotates the active log if it has reached ``max_bytes``, then prunes
        archived segments beyond ``retain_segments``. Idempotent and safe to run
        repeatedly; it does **not** append an entry, so the chain head — and its
        signature — are unchanged. Returns ``{"rotated": ..., "archives": ...}``.
        """
        self.path.parent.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        if not self._is_segment(self.path) and not self._archive_paths():
            # Nothing here is a chain, so there is nothing to rotate or prune
            # and nothing to serialise — return the no-op answer *without*
            # taking the lock, because taking it would create the lock file.
            # A mistyped path must not materialise artifacts: that is the
            # ``--root ""`` shadow-tree class, it is why ``_should_rotate``
            # tests ``_is_segment`` rather than ``exists()``, and
            # ``tests/security`` asserts this call changes nothing when handed
            # a directory. Found by that test, not by review.
            #
            # Not a fail-open: a writer creating the chain between this check
            # and the return would only mean this pass did nothing, which is
            # what it reports.
            return {"rotated": False, "archives": 0}
        # The same lock ``record`` takes, for the same reason and then one more.
        # ``_rotate`` computes ``max(index) + 1`` and *then* renames, so two
        # concurrent rotations choose the same destination and the second
        # silently replaces a whole archived segment. And two concurrent
        # ``apply_retention`` passes raise an unhandled ``FileNotFoundError``
        # out of that rename, which would give ``audit_maintenance`` an exit
        # code its own contract does not document.
        with self._exclusive():
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
        reject_delimiter(
            actor=actor,
            action=action,
            action_class=action_class,
            decision=decision,
            reason=reason,
        )
        self.path.parent.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        with self._exclusive():
            return self._record_locked(
                actor=actor,
                action=action,
                action_class=action_class,
                decision=decision,
                reason=reason,
            )

    def _record_locked(
        self, *, actor: str, action: str, action_class: str, decision: str, reason: str
    ) -> AuditEvent:
        """The append itself. Caller holds :meth:`_exclusive`.

        The lock has to span **all** of this, not merely the write. ``_last``
        builds ``(self.path, *reversed(self._archive_paths()))``, so the archive
        list is evaluated *before* the active log is read — and a rotation
        landing in that window makes it fall through to a stale, empty list and
        return ``(-1, genesis)``. Measured, **20 of 20** trials: the next entry
        was written at ``seq=0`` with ``prev_hash`` = genesis, restarting the
        chain, on a single writer. ``scripts/audit_maintenance.py`` rotates and
        takes no lock of its own, so every chain in the platform sits on that
        path, not only the one with two scheduled writers.
        """
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
        with open(self.path, "a", encoding="utf-8", opener=_opener_owner_only) as fh:
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
        _write_text_owner_only(
            self._sig_path,
            json.dumps(
                {
                    "seq": seq,
                    "head_hash": head_hash,
                    "algo": self._signer.algo,
                    "signature": self._signer.sign(self._head_message(seq, head_hash)),
                }
            ),
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

        Takes a *shared* lock while it reads, when one exists — see
        :meth:`_shared`. Without it a reader racing a single writer reported
        the chain broken 22.4% of the time with no defect present.
        """
        with self._shared():
            return self._verify_report_locked()

    def _verify_report_locked(self) -> VerificationReport:
        """The verification itself. Caller holds :meth:`_shared` if available."""
        segments = self._segments_in_order()
        try:
            checkpoint = self._read_checkpoint()
        except (json.JSONDecodeError, KeyError, ValueError, TypeError, OSError):
            # A truncated/garbled checkpoint sidecar is diagnosed exactly like a
            # malformed entry: a located fail-closed verdict, never an exception.
            return VerificationReport(
                intact=False,
                entries=0,
                segments=len(segments),
                head_seq=-1,
                head_hash=_GENESIS_HASH,
                checkpoint_seq=None,
                signature="unchecked",
                failure=f"malformed checkpoint sidecar at {self._checkpoint_path.name}",
            )
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
            try:
                text = segment.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                # Non-UTF-8 corruption (or an unreadable file) is a located
                # fail-closed verdict, not an exception out of verification.
                return _report(
                    f"unreadable segment {segment.name} (undecodable or inaccessible)",
                    "unchecked",
                )
            for line_no, line in enumerate(text.splitlines(), start=1):
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
