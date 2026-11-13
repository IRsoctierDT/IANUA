# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Signed, expiring, single-use, per-target execution approval.

``docs/RESPONSE_LAYER.md`` closes the plan→execution boundary until an
"explicit, signed, expiring, per-target approval primitive" exists, and names
four reasons nothing already here could serve as one. This module is that
primitive. It **executes nothing**: it answers one question — *did a named
human authorize exactly this capability, against exactly this target, for
exactly this plan, recently, and has that authorization not been used?* — and
records the answer. An executor adapter (stage 8, phase 2) must obtain a
:class:`VerifiedApproval` from :func:`authorize` before it may act; this phase
ships the gate and no adapter, so ``tests/security/test_response_no_executor.py``
holds unchanged.

How each of the four named gaps is answered:

* **"An allow-list entry is a standing, permanent, unscoped grant."** An
  approval names one capability, one target and one plan, and carries an
  expiry no more than :data:`MAX_TTL_SECONDS` after issue. There is no
  wildcard target and no capability not in :data:`CAPABILITIES`.
* **"report_only bypasses the raise."** :func:`authorize` has no reporting
  mode. It returns a :class:`VerifiedApproval` or raises; there is no third
  outcome and no flag that produces one.
* **"AuditLogger.record has no payload slot."** The approval's sha256 digest is
  written into ``reason``, which is inside the audit hash preimage, so the
  audit record names the exact signed bytes and an edit to either breaks the
  chain or the digest.
* **"No caller identity."** :mod:`agents.policies.principal` records who a
  caller *says* they are. Here the approver is **verified**: the identity is
  whoever holds the private key registered under that id in the committed
  ``approvers.json``. That file ships empty, so the default answer is no — the
  same declared-never-discovered shape as ``egress.json``.

Security considerations (AGENTS.md §3, §5):

* **Ed25519 only.** An HMAC verifier holds the key that forges, so an executor
  able to verify an HMAC approval could mint its own. Only an
  :class:`~agents.policies.signing.Ed25519Verifier` built from a committed
  public key is accepted; the private key lives with the human approver and
  never in this repository, its environment files or its logs.
* **Domain-separated, canonical bytes.** The signed message is
  :data:`DOMAIN` followed by sorted-key, separator-fixed, ASCII-only JSON, so a
  signature over an audit chain head or any other message this repository
  signs cannot be replayed as an approval, and no two encodings of one approval
  verify differently.
* **Strict parse.** Exact key sets, exact types (``bool`` is refused where an
  integer is expected, since it is an ``int`` subclass), duplicate JSON keys
  refused, a size ceiling before parsing. Malformed input is rejected, never
  repaired.
* **Exact binding.** The caller states what it is about to do and every field
  must equal the signed one; nothing is normalised on the way, because a
  normalising comparison is one more place for two spellings to meet.
* **Single use, durably.** A verified approval is consumed in an owner-only,
  symlink-refusing ledger under an exclusive lock *before* it is returned, so
  a crash after consumption fails closed (the approval is spent and the action
  did not happen) rather than open (replayable).
* **Time is bounded on both sides.** Issued no more than
  :data:`CLOCK_SKEW_SECONDS` in the future, not expired, and a lifetime no
  longer than :data:`MAX_TTL_SECONDS`.

Residuals, stated rather than implied: the ledger keeps each consumed approval
for :data:`PRUNE_GRACE_SECONDS` after it expired, so a clock set back further
than that could revive a pruned one; a compromised approver key
authorizes anything inside :data:`CAPABILITIES` until it is removed from
``approvers.json``; and this module cannot know whether the action the caller
then performs is the one it described — that is the adapter's obligation, and
phase 2's security tests.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agents.policies.audit import AuditLogger, escape_delimiter
from agents.policies.signing import Ed25519Signer, Ed25519Verifier

#: Wire and signature format version. A change to any field or to the
#: canonical encoding bumps it, and an old verifier refuses the new version.
APPROVAL_VERSION = 1

#: Prefixed to every signed message. The NUL bytes cannot occur in the JSON
#: that follows, so no other message this repository signs can collide.
DOMAIN = b"IANUA-EXECUTION-APPROVAL\x00v1\x00"

#: The executor capabilities ``agents/tools/containment.py`` routes to a
#: ``ContainmentExecutor``. Every one is reversible and has its inverse here,
#: so rolling an action back needs its own approval rather than none.
CAPABILITIES = frozenset(
    {
        "isolate_host",
        "restore_host",
        "block_indicator",
        "unblock_indicator",
        "disable_account",
        "enable_account",
    }
)

#: Longest lifetime an approval may declare. Fifteen minutes is long enough for
#: a human to approve and an adapter to act during an active incident, and
#: short enough that a leaked token is stale before it is useful.
MAX_TTL_SECONDS = 900

#: Tolerated clock difference between the approver's machine and this node.
CLOCK_SKEW_SECONDS = 30

#: Ceiling on a serialized token, checked before parsing.
MAX_TOKEN_BYTES = 4096

#: Approval file, committed, shipping empty (deny by default).
DEFAULT_APPROVERS = Path(__file__).with_name("approvers.json")

_FIELDS = frozenset(
    {"version", "approver", "capability", "target", "plan_id", "issued_at", "expires_at", "nonce"}
)
_ENVELOPE = frozenset({"approval", "algo", "signature"})
_APPROVER_ID = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
#: Printable ASCII with no whitespace and no ``|`` (the audit delimiter). Shape
#: checks per capability belong to the adapter, which knows what a host is;
#: this bound only guarantees the value is safe to sign, log and compare.
_TARGET = re.compile(r"^[!-{}~]{1,253}$")
_PLAN_ID = re.compile(r"^plan-[0-9a-f]{16}$")
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_SIGNATURE = re.compile(r"^[0-9a-f]{128}$")
_PUBLIC_KEY = re.compile(r"^[0-9a-f]{64}$")


class ApprovalError(ValueError):
    """Raised when an approval is absent, malformed, unverifiable or spent (fail closed)."""


@dataclass(frozen=True, slots=True)
class VerifiedApproval:
    """Proof that :func:`authorize` accepted and consumed one approval.

    Only :func:`authorize` constructs one in the shipped code, and an adapter
    must require it as an argument rather than accept the fields separately.
    """

    approver: str
    capability: str
    target: str
    plan_id: str
    expires_at: int
    digest: str


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ApprovalError("approval token repeats a JSON key")
    return dict(pairs)


def _is_int(value: object) -> bool:
    return type(value) is int


def _canonical(fields: dict[str, Any]) -> bytes:
    body = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return DOMAIN + body.encode("ascii")


def _validate_fields(fields: object) -> dict[str, Any]:
    """Structural validation of the signed fields. Raises on the first defect."""
    if not isinstance(fields, dict) or set(fields) != _FIELDS:
        raise ApprovalError(f"approval fields must be exactly {sorted(_FIELDS)}")
    if not _is_int(fields["version"]) or fields["version"] != APPROVAL_VERSION:
        raise ApprovalError(f"unsupported approval version {fields['version']!r}")
    checks: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("approver", _APPROVER_ID),
        ("target", _TARGET),
        ("plan_id", _PLAN_ID),
        ("nonce", _NONCE),
    )
    for name, pattern in checks:
        value = fields[name]
        if type(value) is not str or not pattern.fullmatch(value):
            raise ApprovalError(f"approval {name} is malformed")
    if type(fields["capability"]) is not str or fields["capability"] not in CAPABILITIES:
        raise ApprovalError(f"capability {fields['capability']!r} is not approvable")
    issued, expires = fields["issued_at"], fields["expires_at"]
    if not (_is_int(issued) and _is_int(expires)) or issued < 0:
        raise ApprovalError("approval timestamps must be non-negative integers")
    if not 0 < expires - issued <= MAX_TTL_SECONDS:
        raise ApprovalError(f"approval lifetime must be 1..{MAX_TTL_SECONDS} seconds")
    return fields


def load_approvers(path: Path = DEFAULT_APPROVERS) -> dict[str, Ed25519Verifier]:
    """Load the committed approver registry: id → Ed25519 public-key verifier.

    A missing, unreadable or malformed file **raises** rather than resolving to
    "nobody", for the reason ``egress.py`` gives: both refuse, but only one
    tells the operator the file is broken. Each entry must record an
    ``authorization`` basis, as a lab host must.
    """
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates
        )
    except ApprovalError:
        raise
    except (OSError, ValueError) as exc:
        raise ApprovalError(f"cannot load approver registry {path}: {exc}") from exc
    if not isinstance(document, dict) or set(document) != {"version", "approvers"}:
        raise ApprovalError("approver registry must hold exactly 'version' and 'approvers'")
    if document["version"] != 1 or not isinstance(document["approvers"], list):
        raise ApprovalError("approver registry version must be 1 with a list of approvers")
    registry: dict[str, Ed25519Verifier] = {}
    keys_seen: set[str] = set()
    for entry in document["approvers"]:
        if not isinstance(entry, dict) or set(entry) != {"id", "public_key", "authorization"}:
            raise ApprovalError("each approver needs exactly id, public_key, authorization")
        ident, key, basis = entry["id"], entry["public_key"], entry["authorization"]
        if type(ident) is not str or not _APPROVER_ID.fullmatch(ident):
            raise ApprovalError(f"approver id {ident!r} is malformed")
        if type(key) is not str or not _PUBLIC_KEY.fullmatch(key):
            raise ApprovalError(f"approver {ident!r}: public_key must be 64 lowercase hex")
        if type(basis) is not str or not basis.strip():
            raise ApprovalError(f"approver {ident!r} records no authorization basis")
        if ident in registry or key in keys_seen:
            raise ApprovalError(f"approver {ident!r} duplicates an id or a key")
        registry[ident] = Ed25519Verifier(bytes.fromhex(key))
        keys_seen.add(key)
    return registry


def issue_approval(
    signer: Ed25519Signer,
    *,
    approver: str,
    capability: str,
    target: str,
    plan_id: str,
    ttl_seconds: int,
    now: int | None = None,
) -> str:
    """Sign one approval and return the serialized token.

    Run by the human approver, on their machine, with their private key. The
    nonce is drawn here from :mod:`secrets` and is never caller-supplied, so
    two approvals for the same action are still distinct and individually
    consumable.
    """
    if not isinstance(signer, Ed25519Signer):
        raise ApprovalError("approvals are signed with Ed25519 only")
    issued = int(time.time()) if now is None else now
    fields = _validate_fields(
        {
            "version": APPROVAL_VERSION,
            "approver": approver,
            "capability": capability,
            "target": target,
            "plan_id": plan_id,
            "issued_at": issued,
            "expires_at": issued + ttl_seconds,
            "nonce": secrets.token_hex(16),
        }
    )
    envelope = {"algo": "ed25519", "approval": fields, "signature": signer.sign(_canonical(fields))}
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"))


#: An entry is kept this long after its approval expired before it may be
#: pruned. An expired approval is refused by :func:`authorize` before the ledger
#: is consulted, so a pruned entry can only be replayed by setting this node's
#: clock back by more than this. Thirty days of entries cost a few kilobytes,
#: so the margin is set generously rather than tuned.
PRUNE_GRACE_SECONDS = 30 * 86_400
#: Rewrite the ledger only once it holds more entries than this.
PRUNE_THRESHOLD = 1024

_LEDGER_LINE = re.compile(r"^([0-9a-f]{64})(?: ([0-9]{1,12}))?$")


class ApprovalLedger:
    """Durable record of consumed approvals, so each one authorizes once.

    One line per consumed approval: its digest and, since pruning, its expiry
    (``<digest> <expires_at>``). A line with no expiry predates pruning and is
    kept forever, because nothing says when it stops mattering.

    **The lock is a separate file**, ``<ledger>.lock``, held exclusively across
    every read, check, append and rewrite. That is what makes pruning safe: the
    rewrite replaces the ledger atomically with :func:`os.replace`, and a lock
    taken on the ledger's own descriptor would then guard an unlinked file, so a
    process waiting on it would append its consumption somewhere nobody reads —
    and that approval could be presented again. Both files are opened
    owner-only and ``O_NOFOLLOW``, and refused unless they are regular files
    owned by this process's user with no group or other permissions.

    **A malformed ledger refuses**, rather than skipping the line it cannot read:
    a skipped line is a forgotten consumption.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock_path = path.with_name(path.name + ".lock")

    @staticmethod
    def _open_owned(path: Path, flags: int) -> int:
        try:
            fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except OSError as exc:
            raise ApprovalError(f"cannot open approval ledger {path}: {exc}") from exc
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            os.close(fd)
            raise ApprovalError(f"approval ledger {path} is not a regular file we own")
        if info.st_mode & 0o077:
            os.close(fd)
            raise ApprovalError(f"approval ledger {path} is readable by others")
        return fd

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock = self._open_owned(self.lock_path, os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield
        finally:
            os.close(lock)

    def _read(self) -> list[tuple[str, int | None]]:
        fd = self._open_owned(self.path, os.O_RDONLY | os.O_CREAT)
        try:
            chunks: list[bytes] = []
            while chunk := os.read(fd, 65536):
                chunks.append(chunk)
        finally:
            os.close(fd)
        try:
            text = b"".join(chunks).decode("ascii")
        except UnicodeDecodeError as exc:
            raise ApprovalError(f"approval ledger {self.path} is corrupt") from exc
        entries: list[tuple[str, int | None]] = []
        for number, line in enumerate(text.splitlines(), start=1):
            match = _LEDGER_LINE.fullmatch(line)
            if match is None:
                raise ApprovalError(f"approval ledger {self.path} is corrupt at line {number}")
            expiry = match.group(2)
            entries.append((match.group(1), int(expiry) if expiry is not None else None))
        return entries

    def _append(self, digest: str, expires_at: int) -> None:
        fd = self._open_owned(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
        try:
            os.write(fd, f"{digest} {expires_at}\n".encode("ascii"))
            os.fsync(fd)
        finally:
            os.close(fd)

    def _rewrite(self, entries: list[tuple[str, int | None]]) -> None:
        staged = self.path.with_name(self.path.name + ".staged")
        fd = self._open_owned(staged, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        try:
            body = "".join(
                f"{digest}\n" if expiry is None else f"{digest} {expiry}\n"
                for digest, expiry in entries
            )
            os.write(fd, body.encode("ascii"))
            os.fsync(fd)
        finally:
            os.close(fd)
        staged.replace(self.path)
        directory = os.open(self.path.parent, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def consume(self, digest: str, *, expires_at: int, now: int) -> None:
        """Record ``digest`` as spent, or raise if it already is; prune when large.

        ``expires_at`` is the approval's own expiry and ``now`` the clock
        :func:`authorize` used, so pruning and the expiry check read one clock.
        """
        with self._locked():
            entries = self._read()
            if any(seen == digest for seen, _ in entries):
                raise ApprovalError("approval has already been used")
            self._append(digest, expires_at)
            entries.append((digest, expires_at))
            if len(entries) > PRUNE_THRESHOLD:
                kept = [
                    (seen, expiry)
                    for seen, expiry in entries
                    if expiry is None or expiry + PRUNE_GRACE_SECONDS > now
                ]
                if len(kept) < len(entries):
                    self._rewrite(kept)


def authorize(
    token: str,
    *,
    capability: str,
    target: str,
    plan_id: str,
    approvers: dict[str, Ed25519Verifier],
    ledger: ApprovalLedger,
    audit: AuditLogger | None = None,
    now: int | None = None,
) -> VerifiedApproval:
    """Verify ``token`` authorizes exactly this action, consume it, and return proof.

    Raises :class:`ApprovalError` on any defect. Every outcome — accepted or
    refused — is recorded when ``audit`` is given, with the refusal's reason,
    because refusals are what reveal probing.
    """
    try:
        verified = _verify(token, capability, target, plan_id, approvers, ledger, now)
    except ApprovalError as exc:
        if audit is not None:
            audit.record(
                actor="approval",
                # Caller-supplied and possibly hostile: made delimiter-safe and
                # bounded, so recording a refusal cannot itself raise and mask it.
                action=_audit_safe(f"{capability} {target}"),
                action_class="containment",
                decision="deny",
                reason=_audit_safe(str(exc)),
            )
        raise
    if audit is not None:
        audit.record(
            actor=f"approval/{verified.approver}",
            action=f"{verified.capability} {verified.target}",
            action_class="containment",
            decision="allow",
            reason=f"approval {verified.digest} plan {verified.plan_id}",
        )
    return verified


def _audit_safe(text: str) -> str:
    """Bound and delimiter-escape caller-influenced text for a descriptive audit field."""
    return escape_delimiter(text[:256])


def _verify(
    token: str,
    capability: str,
    target: str,
    plan_id: str,
    approvers: dict[str, Ed25519Verifier],
    ledger: ApprovalLedger,
    now: int | None,
) -> VerifiedApproval:
    if type(token) is not str or not token or len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise ApprovalError("approval token is missing or oversized")
    try:
        envelope = json.loads(token, object_pairs_hook=_reject_duplicates)
    except ApprovalError:
        raise  # a ValueError subclass: keep its specific reason, do not relabel it
    except ValueError as exc:
        raise ApprovalError("approval token is not valid JSON") from exc
    if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE:
        raise ApprovalError(f"approval envelope must be exactly {sorted(_ENVELOPE)}")
    if envelope["algo"] != "ed25519":
        raise ApprovalError("approvals are verified with Ed25519 only")
    signature = envelope["signature"]
    if type(signature) is not str or not _SIGNATURE.fullmatch(signature):
        raise ApprovalError("approval signature is malformed")
    fields = _validate_fields(envelope["approval"])
    verifier = approvers.get(fields["approver"])
    if verifier is None:
        raise ApprovalError(f"approver {fields['approver']!r} is not registered")
    message = _canonical(fields)
    if not verifier.verify(message, signature):
        raise ApprovalError("approval signature does not verify")
    for name, expected in (("capability", capability), ("target", target), ("plan_id", plan_id)):
        if fields[name] != expected:
            raise ApprovalError(f"approval was issued for a different {name}")
    current = int(time.time()) if now is None else now
    if fields["issued_at"] > current + CLOCK_SKEW_SECONDS:
        raise ApprovalError("approval is issued in the future")
    if current >= fields["expires_at"]:
        raise ApprovalError("approval has expired")
    digest = hashlib.sha256(message).hexdigest()
    ledger.consume(digest, expires_at=fields["expires_at"], now=current)
    return VerifiedApproval(
        approver=fields["approver"],
        capability=fields["capability"],
        target=fields["target"],
        plan_id=fields["plan_id"],
        expires_at=fields["expires_at"],
        digest=digest,
    )
