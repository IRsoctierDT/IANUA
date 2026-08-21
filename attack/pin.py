"""Fail-closed parser for the committed ATT&CK pin manifest.

The pin (``attack/pins/enterprise-attack.pin.json``) is the single source of
truth for which ATT&CK release the corpus represents and what the staged
bundle and every committed shard must hash to. Parsing follows the
``compliance/attestations.py`` posture: exact field set, strict shapes, and
whole-manifest rejection on any anomaly — a pin that does not validate is a
pin that does not exist.

Security consideration: hash pinning alone detects *corruption*; the optional
Ed25519 signature over the pin body is what upgrades the claim to detecting
*tampering* (pin and shards are writable by the same actor). Signature
**verification lives in ``scripts/update_attack.py --check``**, not here —
``attack/`` imports no first-party module and carries no crypto dependency;
this module only validates the signature block's *shape* and exposes the
canonical signing payload.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from attack.errors import AttackError, AttackUnavailableError

_SCHEMA_VERSION = 1
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^\d+\.\d+$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SHARD_NAME_RE = re.compile(r"^[a-z0-9_-]+\.json$")
_HEX_KEY_RE = re.compile(r"^[0-9a-f]{64}$")

#: Maximum pin file size — a pin is a small manifest; anything larger is hostile.
_MAX_PIN_BYTES = 64 * 1024

DEFAULT_PIN_PATH = Path(__file__).resolve().parent / "pins" / "enterprise-attack.pin.json"

_TOP_FIELDS = {"schema", "attack_version", "retrieved", "bundle", "shards", "signature"}
_BUNDLE_FIELDS = {"file_name", "size_bytes", "sha256"}
_SIGNATURE_FIELDS = {"algorithm", "public_key", "signature"}


@dataclass(frozen=True, slots=True)
class PinSignature:
    """Shape-validated signature block (verified by the gate script)."""

    algorithm: str
    public_key: str
    signature: str


@dataclass(frozen=True, slots=True)
class Pin:
    """The validated pin manifest."""

    attack_version: str
    retrieved: str
    bundle_file_name: str
    bundle_size_bytes: int
    bundle_sha256: str
    shards: dict[str, str]
    signature: PinSignature | None


def signing_payload(pin_document: dict[str, object]) -> bytes:
    """Canonical bytes the pin signature covers: everything but ``signature``.

    Deterministic (sorted keys, compact separators) so signing and verifying
    reproduce the identical byte stream regardless of on-disk formatting.
    """
    body = {key: value for key, value in pin_document.items() if key != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _reject(reason: str) -> AttackError:
    return AttackError(f"invalid ATT&CK pin: {reason}")


def parse_pin(document: object) -> Pin:
    """Validate a parsed pin document fail-closed; return the typed pin."""
    if not isinstance(document, dict):
        raise _reject("top level must be an object")
    if set(document) != _TOP_FIELDS:
        raise _reject(f"unexpected field set: {sorted(document)}")
    if document["schema"] != _SCHEMA_VERSION:
        raise _reject(f"unsupported schema: {document['schema']!r}")
    version = document["attack_version"]
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
        raise _reject(f"attack_version must look like '19.2', got {version!r}")
    retrieved = document["retrieved"]
    if not isinstance(retrieved, str) or not _DATE_RE.fullmatch(retrieved):
        raise _reject(f"retrieved must be an ISO date, got {retrieved!r}")

    bundle = document["bundle"]
    if not isinstance(bundle, dict) or set(bundle) != _BUNDLE_FIELDS:
        raise _reject("bundle must carry exactly file_name/size_bytes/sha256")
    file_name = bundle["file_name"]
    if not isinstance(file_name, str) or "/" in file_name or "\\" in file_name or not file_name:
        raise _reject(f"bundle file_name invalid: {file_name!r}")
    size_bytes = bundle["size_bytes"]
    if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes <= 0:
        raise _reject("bundle size_bytes must be a positive integer")
    sha256 = bundle["sha256"]
    if not isinstance(sha256, str) or not _SHA256_RE.fullmatch(sha256):
        raise _reject("bundle sha256 must be 64 lowercase hex characters")

    shards_raw = document["shards"]
    if not isinstance(shards_raw, dict) or not shards_raw:
        raise _reject("shards must be a non-empty object")
    shards: dict[str, str] = {}
    for name, digest in shards_raw.items():
        if not isinstance(name, str) or not _SHARD_NAME_RE.fullmatch(name):
            raise _reject(f"shard name invalid: {name!r}")
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise _reject(f"shard digest for {name!r} must be 64 lowercase hex characters")
        shards[name] = digest

    signature_raw = document["signature"]
    signature: PinSignature | None
    if signature_raw is None:
        signature = None
    else:
        if not isinstance(signature_raw, dict) or set(signature_raw) != _SIGNATURE_FIELDS:
            raise _reject("signature must be null or carry algorithm/public_key/signature")
        algorithm = signature_raw["algorithm"]
        if algorithm != "ed25519":
            raise _reject(f"unsupported signature algorithm: {algorithm!r}")
        public_key = signature_raw["public_key"]
        if not isinstance(public_key, str) or not _HEX_KEY_RE.fullmatch(public_key):
            raise _reject("signature public_key must be 64 lowercase hex characters")
        sig_value = signature_raw["signature"]
        if not isinstance(sig_value, str) or not re.fullmatch(r"^[0-9a-f]{128}$", sig_value):
            raise _reject("signature value must be 128 lowercase hex characters")
        signature = PinSignature(algorithm=algorithm, public_key=public_key, signature=sig_value)

    return Pin(
        attack_version=version,
        retrieved=retrieved,
        bundle_file_name=file_name,
        bundle_size_bytes=size_bytes,
        bundle_sha256=sha256,
        shards=shards,
        signature=signature,
    )


def load_pin(path: Path | None = None) -> Pin:
    """Read and validate the pin manifest from disk (fail closed)."""
    pin_path = DEFAULT_PIN_PATH if path is None else path
    if not pin_path.is_file():
        raise AttackUnavailableError(f"ATT&CK pin not found: {pin_path}")
    raw = pin_path.read_bytes()
    if len(raw) > _MAX_PIN_BYTES:
        raise _reject(f"pin exceeds {_MAX_PIN_BYTES} bytes")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _reject(f"pin is not valid JSON ({exc})") from exc
    return parse_pin(document)


def load_pin_document(path: Path | None = None) -> dict[str, object]:
    """Read the raw pin document (already validated) for signing/verification."""
    pin_path = DEFAULT_PIN_PATH if path is None else path
    pin = load_pin(pin_path)  # fail-closed validation first
    del pin
    result = json.loads(pin_path.read_bytes())
    if not isinstance(result, dict):  # unreachable after parse, kept fail-closed
        raise _reject("top level must be an object")
    return result
