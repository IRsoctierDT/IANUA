"""Security contracts for ATT&CK corpus integrity (DESIGN.md §5 boundary 5).

Tampering hard-fails; absence degrades soft to an explicit unavailable state;
a rejected bundle leaves the committed corpus untouched. These are the
fail-closed guarantees the whole vocabulary layer rests on.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest
from attack.errors import AttackIntegrityError, AttackUnavailableError
from attack.pin import Pin, load_pin, parse_pin
from attack.store import DATA_DIR, load_corpus, read_shard

_REPO = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "update_attack", _REPO / "scripts" / "update_attack.py"
)
assert _SPEC and _SPEC.loader
_upd = importlib.util.module_from_spec(_SPEC)
sys.modules["update_attack"] = _upd
_SPEC.loader.exec_module(_upd)


def _pin_with_shard_digest(name: str, digest: str) -> Pin:
    document = json.loads((_REPO / "attack" / "pins" / "enterprise-attack.pin.json").read_text())
    document["shards"][name] = digest
    return parse_pin(document)


@pytest.mark.security
def test_tampered_shard_hard_fails(tmp_path: Path) -> None:
    # Copy the real shards, flip one byte in the catalog, keep the real pin.
    workdir = tmp_path / "data"
    shutil.copytree(DATA_DIR, workdir)
    catalog = workdir / "catalog.json"
    raw = catalog.read_bytes()
    catalog.write_bytes(raw.replace(b"Brute Force", b"Brute Farce", 1))
    with pytest.raises(AttackIntegrityError, match="sha256 mismatch"):
        load_corpus(data_dir=workdir)


@pytest.mark.security
def test_absent_corpus_is_unavailable_never_a_guess(tmp_path: Path) -> None:
    with pytest.raises(AttackUnavailableError):
        load_corpus(data_dir=tmp_path / "empty")


@pytest.mark.security
def test_hash_matching_but_malformed_shard_is_integrity_error(tmp_path: Path) -> None:
    # A shard whose digest IS in the pin but whose content is hostile JSON:
    # parse failures surface as integrity errors, not raw ValueErrors.
    workdir = tmp_path / "data"
    workdir.mkdir()
    hostile = b'{"items": "not-a-map"}'
    (workdir / "relationships-01.json").write_bytes(hostile)
    pin = _pin_with_shard_digest("relationships-01.json", hashlib.sha256(hostile).hexdigest())
    # read_shard passes (valid JSON, matching digest) — the structural check
    # in the merge layer is what must convert the bad shape to a domain error.
    assert read_shard("relationships-01.json", pin=pin, data_dir=workdir)
    from attack.store import _merge_parts

    with pytest.raises(AttackIntegrityError, match="items"):
        _merge_parts(["relationships-01.json"], pin=pin, data_dir=workdir)
    invalid = b'{"items": {'
    (workdir / "relationships-01.json").write_bytes(invalid)
    broken_pin = _pin_with_shard_digest(
        "relationships-01.json", hashlib.sha256(invalid).hexdigest()
    )
    with pytest.raises(AttackIntegrityError, match="invalid JSON"):
        read_shard("relationships-01.json", pin=broken_pin, data_dir=workdir)


@pytest.mark.security
def test_nesting_bomb_rejected_before_parse(tmp_path: Path) -> None:
    bomb = tmp_path / "bomb.json"
    bomb.write_bytes(b"[" * 5000 + b"]" * 5000)
    with pytest.raises(Exception, match="nesting"):
        _upd._scan_depth(bomb, 100)
    # Bracket characters inside strings do not count toward depth.
    ok = tmp_path / "ok.json"
    ok.write_bytes(json.dumps({"text": "[[[[[" * 100}).encode())
    _upd._scan_depth(ok, 10)  # must not raise


@pytest.mark.security
def test_rejected_bundle_leaves_marker_and_committed_corpus_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    bad = staging / "enterprise-attack-99.9.json"
    bad.write_bytes(b"{not json at all")
    monkeypatch.setattr(_upd, "STAGING_DIR", staging)
    before = {p.name: p.read_bytes() for p in DATA_DIR.glob("*.json")}
    assert _upd.build("enterprise-attack-99.9.json", "2026-08-21") == 1
    assert bad.with_suffix(".json.REJECTED").is_file(), "forensic marker missing"
    after = {p.name: p.read_bytes() for p in DATA_DIR.glob("*.json")}
    assert before == after, "a rejected bundle must not touch committed shards"


@pytest.mark.security
def test_oversized_bundle_rejected_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    big = staging / "enterprise-attack-99.9.json"
    with big.open("wb") as handle:
        handle.seek(300_000_000)
        handle.write(b"\0")
    monkeypatch.setattr(_upd, "STAGING_DIR", staging)
    assert _upd.build("enterprise-attack-99.9.json", "2026-08-21") == 1
    assert big.with_suffix(".json.REJECTED").is_file()


@pytest.mark.security
def test_tombstone_ledger_refuses_to_shrink(tmp_path: Path) -> None:
    previous = tmp_path / "tombstones.json"
    previous.write_text(json.dumps({"entries": {"T0001": {"status": "deprecated", "name": "Old"}}}))
    merged = _upd._merge_tombstones({"T0002": {"status": "deprecated", "name": "New"}}, previous)
    assert set(merged["entries"]) == {"T0001", "T0002"}, "prior entries must survive"
    assert merged["parent_count"] == 1
    assert merged["parent_sha256"] == hashlib.sha256(previous.read_bytes()).hexdigest()


@pytest.mark.security
def test_check_fails_on_drifted_shard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workdir = tmp_path / "data"
    shutil.copytree(DATA_DIR, workdir)
    (workdir / "catalog.json").write_bytes(b'{"attack_version": "19.2"}')
    monkeypatch.setattr(_upd, "DATA_DIR", workdir)
    monkeypatch.setattr("attack.store.DATA_DIR", workdir)
    assert _upd.check() == 1


@pytest.mark.security
def test_pin_signature_shape_is_validated() -> None:
    document = json.loads((_REPO / "attack" / "pins" / "enterprise-attack.pin.json").read_text())
    document["signature"] = {"algorithm": "ed25519", "public_key": "zz", "signature": "0" * 128}
    with pytest.raises(Exception, match="public_key"):
        parse_pin(document)


@pytest.mark.security
def test_signed_pin_round_trip_verifies_and_detects_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Full ceremony on a throwaway key: sign, verify via --check, then prove a
    # post-signature edit fails. The private key never touches the repo.
    from agents.policies.signing import generate_ed25519_keypair
    from attack.pin import signing_payload

    private_key, public_key = generate_ed25519_keypair()
    pin_copy = tmp_path / "pin.json"
    shutil.copyfile(_REPO / "attack" / "pins" / "enterprise-attack.pin.json", pin_copy)
    monkeypatch.setattr(_upd, "DEFAULT_PIN_PATH", pin_copy)
    monkeypatch.setattr("attack.pin.DEFAULT_PIN_PATH", pin_copy)
    monkeypatch.setenv("ATTACK_PIN_ED25519_PRIVATE_KEY", private_key.hex())
    monkeypatch.setenv("ATTACK_PIN_ED25519_PUBLIC_KEY", public_key.hex())
    assert _upd.sign() == 0
    signed = json.loads(pin_copy.read_text())
    assert signed["signature"]["public_key"] == public_key.hex()

    from agents.policies.signing import Ed25519Verifier

    verifier = Ed25519Verifier(public_key)
    assert verifier.verify(signing_payload(signed), signed["signature"]["signature"])
    tampered = dict(signed)
    tampered["attack_version"] = "20.0"
    assert not verifier.verify(signing_payload(tampered), signed["signature"]["signature"])


@pytest.mark.security
def test_wrong_public_key_refused_at_signing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agents.policies.signing import generate_ed25519_keypair

    private_key, _ = generate_ed25519_keypair()
    _, other_public = generate_ed25519_keypair()
    pin_copy = tmp_path / "pin.json"
    shutil.copyfile(_REPO / "attack" / "pins" / "enterprise-attack.pin.json", pin_copy)
    monkeypatch.setattr(_upd, "DEFAULT_PIN_PATH", pin_copy)
    monkeypatch.setattr("attack.pin.DEFAULT_PIN_PATH", pin_copy)
    monkeypatch.setenv("ATTACK_PIN_ED25519_PRIVATE_KEY", private_key.hex())
    monkeypatch.setenv("ATTACK_PIN_ED25519_PUBLIC_KEY", other_public.hex())
    assert _upd.sign() == 2
    assert json.loads(pin_copy.read_text())["signature"] is None, "pin must stay unsigned"


@pytest.mark.security
def test_committed_pin_loads(tmp_path: Path) -> None:
    pin = load_pin()
    assert pin.attack_version == "19.2"
    assert (
        pin.bundle_sha256
        == hashlib.sha256(
            (_REPO / "data" / "attack" / pin.bundle_file_name).read_bytes()
        ).hexdigest()
        if (_REPO / "data" / "attack" / pin.bundle_file_name).is_file()
        else True
    )
