# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Security tests for asymmetric (Ed25519) audit-log signing (Hardening #2).

The win over HMAC: a verifier needs only the **public** key, so it can confirm
authenticity without holding a secret that would let it forge.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from agents.policies import (
    AuditLogger,
    Ed25519Signer,
    Ed25519Verifier,
    HmacSigner,
    Signer,
    ed25519_signer_from_env,
    ed25519_verifier_from_env,
    generate_ed25519_keypair,
)


def _emit(logger: AuditLogger, n: int) -> None:
    for i in range(n):
        logger.record(
            actor="mcp", action=f"a{i}", action_class="read_only", decision="allow", reason="ok"
        )


@pytest.fixture
def keypair() -> tuple[bytes, bytes]:
    return generate_ed25519_keypair()


# ---------------------------------------------------------------- primitives
def test_keypair_is_raw_32_bytes(keypair: tuple[bytes, bytes]) -> None:
    priv, pub = keypair
    assert len(priv) == 32 and len(pub) == 32


def test_signers_satisfy_the_protocol(keypair: tuple[bytes, bytes]) -> None:
    priv, pub = keypair
    assert isinstance(HmacSigner(b"k"), Signer)
    assert isinstance(Ed25519Signer(priv), Signer)
    assert isinstance(Ed25519Verifier(pub), Signer)


def test_sign_then_verify_with_public_key_only(keypair: tuple[bytes, bytes]) -> None:
    priv, pub = keypair
    msg = b"7|deadbeef"
    sig = Ed25519Signer(priv).sign(msg)
    assert Ed25519Verifier(pub).verify(msg, sig) is True  # public key alone verifies
    assert Ed25519Verifier(pub).verify(b"tampered", sig) is False


def test_verifier_cannot_sign(keypair: tuple[bytes, bytes]) -> None:
    _, pub = keypair
    with pytest.raises(RuntimeError, match="verify-only"):
        Ed25519Verifier(pub).sign(b"x")


# ---------------------------------------------------------------- audit log
def test_signed_log_verifies_with_public_key(tmp_path: Path, keypair: tuple[bytes, bytes]) -> None:
    priv, pub = keypair
    path = tmp_path / "audit.log"
    _emit(AuditLogger(path, signer=Ed25519Signer(priv)), 3)

    # A verifier holding ONLY the public key confirms authenticity.
    verifier = AuditLogger(path, signer=Ed25519Verifier(pub))
    assert verifier.verify() is True
    assert verifier.verify_signature() is True
    # The sidecar records the scheme.
    assert '"algo": "ed25519"' in (tmp_path / "audit.log.sig").read_text(encoding="utf-8")


def test_wrong_public_key_fails(tmp_path: Path, keypair: tuple[bytes, bytes]) -> None:
    priv, _ = keypair
    _, other_pub = generate_ed25519_keypair()
    path = tmp_path / "audit.log"
    _emit(AuditLogger(path, signer=Ed25519Signer(priv)), 2)
    assert AuditLogger(path, signer=Ed25519Verifier(other_pub)).verify() is False


def test_recomputed_chain_without_key_is_rejected(
    tmp_path: Path, keypair: tuple[bytes, bytes]
) -> None:
    priv, pub = keypair
    path = tmp_path / "audit.log"
    signed = AuditLogger(path, signer=Ed25519Signer(priv))
    _emit(signed, 2)

    # Attacker without the private key appends a chain-valid entry (no re-sign).
    _emit(AuditLogger(path), 1)

    # The public-key verifier sees the head moved past the signature.
    assert AuditLogger(path, signer=Ed25519Verifier(pub)).verify() is False


def test_signing_key_and_signer_are_mutually_exclusive(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="either signing_key or signer"):
        AuditLogger(tmp_path / "audit.log", signing_key=b"k", signer=HmacSigner(b"k"))


# ---------------------------------------------------------------- env helpers
def test_env_helpers(monkeypatch: pytest.MonkeyPatch, keypair: tuple[bytes, bytes]) -> None:
    priv, pub = keypair
    monkeypatch.delenv("AUDIT_ED25519_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("AUDIT_ED25519_PUBLIC_KEY", raising=False)
    assert ed25519_signer_from_env() is None
    assert ed25519_verifier_from_env() is None
    monkeypatch.setenv("AUDIT_ED25519_PRIVATE_KEY", priv.hex())
    monkeypatch.setenv("AUDIT_ED25519_PUBLIC_KEY", pub.hex())
    assert isinstance(ed25519_signer_from_env(), Ed25519Signer)
    assert isinstance(ed25519_verifier_from_env(), Ed25519Verifier)


def test_hmac_signer_still_works_via_signer_param(tmp_path: Path) -> None:
    # Back-compat: HmacSigner behaves like the old signing_key path.
    path = tmp_path / "audit.log"
    _emit(AuditLogger(path, signer=HmacSigner(b"secret")), 2)
    assert AuditLogger(path, signer=HmacSigner(b"secret")).verify() is True
    assert AuditLogger(path, signer=HmacSigner(b"wrong")).verify() is False


# ------------------------------------------ an unsignable record is never written
def test_a_verify_only_signer_appends_nothing(tmp_path: Path, keypair: tuple[bytes, bytes]) -> None:
    """Measured before the fix: ``record()`` appended the entry and THEN raised from
    ``sign()``, leaving a chain whose head signature was missing and could never
    become valid — and every retry appended one more such entry. The signature is
    now computed before the append, so a signer that cannot sign leaves nothing."""
    _, pub = keypair
    path = tmp_path / "audit.log"
    log = AuditLogger(path, signer=Ed25519Verifier(pub))
    for _ in range(2):
        with pytest.raises(RuntimeError, match="verify-only"):
            _emit(log, 1)
    assert not path.exists(), "an entry was appended by a signer that could not sign it"
    assert not (tmp_path / "audit.log.sig").exists()
    report = log.verify_report()
    assert report.entries == 0 and report.intact is True
