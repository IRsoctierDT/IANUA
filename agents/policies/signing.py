"""Pluggable signers for the audit log's chain head (Hardening #2).

The audit log signs its chain head so tampering is detectable even by someone who
recomputes a self-consistent chain (see :mod:`agents.policies.audit`). Two schemes,
behind one :class:`Signer` protocol:

- :class:`HmacSigner` — **symmetric**, standard-library only. Fast and simple, but
  a verifier needs the shared secret (so it can also forge).
- :class:`Ed25519Signer` / :class:`Ed25519Verifier` — **asymmetric**. Sign with a
  private key; verify with only the **public** key. A verifier (auditor, CI, an
  external party) can confirm authenticity offline without holding a secret that
  would let them forge. Ed25519 requires the optional ``[crypto]`` extra
  (``pip install -e '.[crypto]'``) and is imported lazily, so the core audit
  module keeps **no hard cryptography dependency**.

Keys never live in the repo (AGENTS.md §5): load raw 32-byte Ed25519 keys from the
environment via :func:`ed25519_signer_from_env` / :func:`ed25519_verifier_from_env`.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any, Protocol, runtime_checkable

_ED25519_PRIVATE_ENV = "AUDIT_ED25519_PRIVATE_KEY"  # hex-encoded 32-byte raw key
_ED25519_PUBLIC_ENV = "AUDIT_ED25519_PUBLIC_KEY"  # hex-encoded 32-byte raw key


@runtime_checkable
class Signer(Protocol):
    """Signs and verifies a byte message, producing a hex-encoded signature."""

    algo: str

    def sign(self, message: bytes) -> str: ...
    def verify(self, message: bytes, signature: str) -> bool: ...


class HmacSigner:
    """Symmetric HMAC-SHA256 signer (standard library)."""

    algo = "hmac-sha256"

    def __init__(self, key: bytes) -> None:
        if not key:
            raise ValueError("signing key must be non-empty")
        self._key = key

    def sign(self, message: bytes) -> str:
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def verify(self, message: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(message), signature)


def _load_ed25519() -> tuple[Any, Any, Any]:
    """Lazy-import the Ed25519 primitives, or raise an actionable error."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "Ed25519 signing requires the optional 'cryptography' dependency; "
            "install it with:  pip install -e '.[crypto]'"
        ) from exc
    return Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature


def _ed25519_verify(public_key: Any, message: bytes, signature: str) -> bool:
    _, _, invalid_signature = _load_ed25519()
    try:
        public_key.verify(bytes.fromhex(signature), message)
    except (invalid_signature, ValueError):
        return False
    return True


class Ed25519Signer:
    """Asymmetric Ed25519 signer. Requires the private key (32 raw bytes)."""

    algo = "ed25519"

    def __init__(self, private_key: bytes) -> None:
        private_cls, _, _ = _load_ed25519()
        self._key = private_cls.from_private_bytes(private_key)

    def sign(self, message: bytes) -> str:
        signature: bytes = self._key.sign(message)
        return signature.hex()

    def verify(self, message: bytes, signature: str) -> bool:
        return _ed25519_verify(self._key.public_key(), message, signature)


class Ed25519Verifier:
    """Verify-only Ed25519 signer holding only the public key (32 raw bytes).

    Cannot :meth:`sign` — use it to *verify* a log signed elsewhere without ever
    handling the private key.
    """

    algo = "ed25519"

    def __init__(self, public_key: bytes) -> None:
        _, public_cls, _ = _load_ed25519()
        self._public = public_cls.from_public_bytes(public_key)

    def sign(self, message: bytes) -> str:
        raise RuntimeError("Ed25519Verifier is verify-only (no private key)")

    def verify(self, message: bytes, signature: str) -> bool:
        return _ed25519_verify(self._public, message, signature)


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate a new keypair, returned as ``(private_raw, public_raw)`` (32 bytes each).

    Persist the private key to a secret store and distribute only the public key
    to verifiers. Never commit either to the repo.
    """
    private_cls, _, _ = _load_ed25519()
    key = private_cls.generate()
    private_raw: bytes = key.private_bytes_raw()
    public_raw: bytes = key.public_key().public_bytes_raw()
    return private_raw, public_raw


def ed25519_signer_from_env(var: str = _ED25519_PRIVATE_ENV) -> Ed25519Signer | None:
    """Build an :class:`Ed25519Signer` from a hex private key in ``var``, or ``None``."""
    value = os.environ.get(var, "")
    return Ed25519Signer(bytes.fromhex(value)) if value else None


def ed25519_verifier_from_env(var: str = _ED25519_PUBLIC_ENV) -> Ed25519Verifier | None:
    """Build an :class:`Ed25519Verifier` from a hex public key in ``var``, or ``None``."""
    value = os.environ.get(var, "")
    return Ed25519Verifier(bytes.fromhex(value)) if value else None
