# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The head signature is staged before the chain append, so a sidecar that cannot
be written refuses before any byte of the chain is.

``_record_locked`` was a two-step write — chain line, then ``.sig`` through a
scratch file and a rename — and 48bfa47 moved the *signing* ahead of the append
without moving the sidecar write. Review measured what that left: a full 64 KiB
tmpfs appended records 178-180 and then raised ``ENOSPC`` from the sidecar,
three retries leaving three unsigned entries; a directory planted at either
sidecar name did the same. Every other step that can fail for want of space or
a writable name now runs before the append; what follows it is one
same-directory rename. ``_stage_head_signature``'s docstring says what that
leaves open: the rename, and the append's own ``write(2)``, which a full disk
can tear anywhere — up to a complete entry with only its newline missing, which
the head read used to accept and glue the next record onto. The torn-tail tests
pin both cuts as refused and located, not a repair.

Keys here are generated per run (``os.urandom``), never literals.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from agents.policies import audit
from agents.policies.audit import AuditLogger
from agents.policies.signing import HmacSigner

_RECORD = {
    "actor": "t",
    "action": "a",
    "action_class": "read_only",
    "decision": "allow",
    "reason": "r",
}


def _lines(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines()) if path.is_file() else 0


class _VerifyOnly:
    """A stdlib stand-in for ``Ed25519Verifier``: ``sign`` always raises."""

    algo = "stub"

    def sign(self, message: bytes) -> str:
        raise RuntimeError("verify-only")

    def verify(self, message: bytes, signature: str) -> bool:
        return False


class _ReturnsNone:
    """A non-conforming signer whose ``sign`` returns nothing at all."""

    algo = "stub"

    def sign(self, message: bytes) -> str:
        return None  # type: ignore[return-value]  # the non-conformance under test

    def verify(self, message: bytes, signature: str) -> bool:
        return True


@pytest.mark.security
def test_a_directory_at_the_sidecar_path_appends_nothing(tmp_path: Path) -> None:
    sig = tmp_path / "audit.log.sig"
    sig.mkdir()
    log = AuditLogger(tmp_path / "audit.log", signer=HmacSigner(os.urandom(32)))
    for _ in range(3):
        with pytest.raises(IsADirectoryError):
            log.record(**_RECORD)
    assert _lines(log.path) == 0, "entries were appended by calls that raised"
    assert not (tmp_path / ".audit.log.sig.tmp").exists()
    sig.rmdir()
    log.record(**_RECORD)
    assert log.verify_report().signature == "valid"


@pytest.mark.security
def test_a_directory_at_the_scratch_name_appends_nothing(tmp_path: Path) -> None:
    log = AuditLogger(tmp_path / "audit.log", signer=HmacSigner(os.urandom(32)))
    log.record(**_RECORD)
    log.record(**_RECORD)
    assert log.verify_report().signature == "valid"
    (tmp_path / ".audit.log.sig.tmp").mkdir()
    for _ in range(3):
        with pytest.raises(OSError):
            log.record(**_RECORD)
    assert _lines(log.path) == 2, "entries were appended by calls that raised"
    report = log.verify_report()  # measured before: intact=False, 5 entries, stale
    assert (report.intact, report.entries, report.signature) == (True, 2, "valid")


@pytest.mark.security
def test_a_sidecar_write_failing_for_want_of_space_appends_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The order, pinned without a mount: ``ENOSPC`` out of the staging step must
    find no chain byte written. Measured for real on a 64 KiB tmpfs (commit)."""
    log = AuditLogger(tmp_path / "audit.log", signer=HmacSigner(os.urandom(32)))
    log.record(**_RECORD)

    def no_space(path: Path, text: str) -> Path:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(audit, "_stage_text_owner_only", no_space)
    with pytest.raises(OSError, match="No space"):
        log.record(**_RECORD)
    assert _lines(log.path) == 1, "an entry was appended by a call that raised"
    monkeypatch.undo()
    assert log.verify_report().signature == "valid"


@pytest.mark.security
def test_a_link_at_the_scratch_name_never_reaches_its_target(tmp_path: Path) -> None:
    """Measured by review: a symlink or a hard link at ``.audit.log.sig.tmp`` had
    its target overwritten with the sidecar JSON. The scratch file is now
    created ``O_EXCL`` on an inode of its own."""
    victim = tmp_path / "victim"
    victim.write_text("keep", encoding="utf-8")
    scratch = tmp_path / ".audit.log.sig.tmp"
    log = AuditLogger(tmp_path / "audit.log", signer=HmacSigner(os.urandom(32)))
    scratch.symlink_to(victim)
    log.record(**_RECORD)
    assert victim.read_text(encoding="utf-8") == "keep"
    os.link(victim, scratch)
    log.record(**_RECORD)
    assert victim.read_text(encoding="utf-8") == "keep"
    assert victim.stat().st_nlink == 1
    assert not (tmp_path / "audit.log.sig").is_symlink()
    assert log.verify_report().signature == "valid"


@pytest.mark.security
def test_a_signer_returning_no_signature_appends_nothing(tmp_path: Path) -> None:
    """``None`` out of ``sign`` is a failed signer, not an unsigned chain: measured
    by review, ``if signature is not None`` let it append and skip the sidecar."""
    log = AuditLogger(tmp_path / "audit.log", signer=_ReturnsNone())
    with pytest.raises(TypeError, match="returned no signature"):
        log.record(**_RECORD)
    assert not log.path.exists()
    assert not (tmp_path / "audit.log.sig").exists()


@pytest.mark.security
def test_a_verify_only_signer_appends_nothing_without_cryptography(tmp_path: Path) -> None:
    """The 48bfa47 regression test runs only where ``cryptography`` is installed;
    this pins the same path with a stdlib stub, everywhere."""
    log = AuditLogger(tmp_path / "audit.log", signer=_VerifyOnly())
    for _ in range(2):
        with pytest.raises(RuntimeError, match="verify-only"):
            log.record(**_RECORD)
    assert not log.path.exists()
    assert not (tmp_path / "audit.log.sig").exists()
    report = log.verify_report()
    assert (report.entries, report.intact) == (0, True)


def _tear(log: AuditLogger, cut: str) -> None:
    """Leave ``log`` as a failing append on a full disk does, cut at ``cut``.

    ``"newline"`` is the geometry review measured on a tmpfs: the failing call's
    whole entry landed except its ``\\n``, and the sidecar was never committed,
    so it still signs the previous head.
    """
    if cut == "mid-json":
        with log.path.open("ab") as fh:
            fh.write(b'{"seq": 1, "timestamp": "2026-')
        return
    sidecar = (log.path.parent / "audit.log.sig").read_bytes()
    log.record(**_RECORD)
    (log.path.parent / "audit.log.sig").write_bytes(sidecar)
    log.path.write_bytes(log.path.read_bytes()[:-1])


@pytest.mark.security
@pytest.mark.parametrize("cut", ["mid-json", "newline"])
def test_a_torn_tail_refuses_every_later_record_and_is_a_located_verdict(
    tmp_path: Path, cut: str
) -> None:
    """Measured on a 64 KiB tmpfs: the append's ``write(2)`` was cut short. Cut on
    the newline, the tail was a complete entry: the head read accepted it, keyed
    verify said ``stale``, unkeyed said intact, and the first record after space
    was freed returned success glued onto it. Both cuts are now refused before
    any byte is written and located by every verifier; not repaired here."""
    key = os.urandom(32)
    log = AuditLogger(tmp_path / "audit.log", signer=HmacSigner(key))
    log.record(**_RECORD)
    _tear(log, cut)
    size = log.path.stat().st_size
    for _ in range(3):
        with pytest.raises(ValueError, match=r"unterminated final line at audit\.log:2;"):
            log.record(**_RECORD)
    assert log.path.stat().st_size == size, "a retry wrote past the torn tail"
    for reader in (log, AuditLogger(log.path)):
        report = reader.verify_report()
        assert (report.intact, report.entries) == (False, 1)
        assert report.failure == "malformed entry at audit.log:2 (unterminated line)"
    data = log.path.read_bytes()
    log.path.write_bytes(data[: data.rfind(b"\n") + 1])  # the operator's repair
    assert log.verify_report().signature == "valid"
    log.record(**_RECORD)
    report = log.verify_report()
    assert (report.intact, report.entries, report.signature) == (True, 2, "valid")
