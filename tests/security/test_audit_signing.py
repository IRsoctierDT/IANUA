"""Security tests for HMAC head-hash signing of the audit log (Hardening #2).

Signing closes the "recompute a fresh valid chain" gap: without the key an
attacker can rebuild a self-consistent hash chain, but cannot forge the head
signature, so a key holder still detects the tampering.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from agents.policies import AuditLogger, signing_key_from_env

_KEY = b"unit-test-key-not-a-real-secret"


def _log(path: Path, **kw: object) -> AuditLogger:
    return AuditLogger(path, **kw)  # type: ignore[arg-type]


def _emit(logger: AuditLogger, n: int) -> None:
    for i in range(n):
        logger.record(
            actor="mcp", action=f"a{i}", action_class="read_only", decision="allow", reason="ok"
        )


# ---------------------------------------------------------------- round-trip
@pytest.mark.security
def test_signed_log_verifies(tmp_path: Path) -> None:
    log = _log(tmp_path / "audit.log", signing_key=_KEY)
    _emit(log, 3)
    assert log.verify() is True
    assert log.verify_signature() is True
    assert (tmp_path / "audit.log.sig").exists()


@pytest.mark.security
def test_unsigned_log_writes_no_signature(tmp_path: Path) -> None:
    log = _log(tmp_path / "audit.log")  # back-compat: no key
    _emit(log, 2)
    assert log.verify() is True
    assert not (tmp_path / "audit.log.sig").exists()


# ------------------------------------------- the core property: no forging
@pytest.mark.security
def test_valid_chain_without_signature_update_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "audit.log"
    signed = _log(path, signing_key=_KEY)
    _emit(signed, 2)
    assert signed.verify() is True

    # An attacker without the key appends a chain-VALID entry (no .sig update).
    attacker = _log(path)  # no key
    _emit(attacker, 1)
    assert attacker.verify() is True  # the chain alone still checks out...

    # ...but a key holder sees the head moved past the signature.
    assert signed.verify() is False
    assert signed.verify_signature() is False


@pytest.mark.security
def test_wrong_key_fails_verification(tmp_path: Path) -> None:
    path = tmp_path / "audit.log"
    _emit(_log(path, signing_key=_KEY), 2)
    other = _log(path, signing_key=b"a-different-key")
    assert other.verify_signature() is False
    assert other.verify() is False


@pytest.mark.security
def test_missing_signature_file_fails_closed(tmp_path: Path) -> None:
    log = _log(tmp_path / "audit.log", signing_key=_KEY)
    _emit(log, 2)
    (tmp_path / "audit.log.sig").unlink()
    assert log.verify_signature() is False
    assert log.verify() is False


@pytest.mark.security
def test_garbled_signature_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "audit.log"
    log = _log(path, signing_key=_KEY)
    _emit(log, 2)
    sig = json.loads((tmp_path / "audit.log.sig").read_text(encoding="utf-8"))
    sig["signature"] = "0" * len(sig["signature"])
    (tmp_path / "audit.log.sig").write_text(json.dumps(sig), encoding="utf-8")
    assert log.verify() is False


# ------------------------------------------- edges / config / helpers
@pytest.mark.security
def test_verify_signature_requires_key(tmp_path: Path) -> None:
    log = _log(tmp_path / "audit.log")
    with pytest.raises(ValueError, match="requires a signer"):
        log.verify_signature()


@pytest.mark.security
def test_empty_signed_log_is_valid(tmp_path: Path) -> None:
    log = _log(tmp_path / "audit.log", signing_key=_KEY)
    assert log.verify() is True
    assert log.verify_signature() is True


@pytest.mark.security
def test_empty_signing_key_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="non-empty"):
        AuditLogger(tmp_path / "audit.log", signing_key=b"")


@pytest.mark.security
def test_signing_key_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    assert signing_key_from_env() is None
    monkeypatch.setenv("AUDIT_HMAC_KEY", "s3cret")
    assert signing_key_from_env() == b"s3cret"


@pytest.mark.security
def test_signing_survives_rotation(tmp_path: Path) -> None:
    # Head signature tracks the latest entry across rotation.
    log = _log(tmp_path / "audit.log", signing_key=_KEY, max_bytes=1)
    _emit(log, 4)
    assert list(tmp_path.glob("audit.log.[0-9]*"))  # rotation happened
    assert log.verify() is True
