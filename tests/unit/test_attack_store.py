"""Unit contracts for the attack/ corpus loader and pin parser."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from attack.errors import AttackError, AttackIntegrityError, AttackUnavailableError
from attack.pin import DEFAULT_PIN_PATH, load_pin, parse_pin, signing_payload
from attack.store import DATA_DIR, load_corpus, read_shard


@pytest.mark.unit
def test_committed_corpus_loads_and_matches_pin() -> None:
    corpus = load_corpus()
    pin = load_pin()
    assert corpus.attack_version == pin.attack_version
    assert len(corpus.techniques) > 500
    assert len(corpus.tactics) >= 14
    assert corpus.tombstones, "a real release always has revoked/deprecated entries"


@pytest.mark.unit
def test_lookup_shapes() -> None:
    corpus = load_corpus()
    technique = corpus.techniques["T1110"]
    assert technique.name == "Brute Force"
    assert technique.status == "active"
    assert technique.tactics
    for shortname in technique.tactics:
        assert shortname in corpus.tactics
    sub = corpus.techniques["T1110.001"]
    assert sub.parent_id == "T1110"
    assert technique.url.startswith("https://attack.mitre.org/techniques/")
    assert technique.description, "verbatim descriptions ship with the corpus"


@pytest.mark.unit
def test_detection_and_relationships_are_populated() -> None:
    corpus = load_corpus()
    detection = corpus.detection.get("T1110")
    assert detection is not None and detection.strategies
    assert any(s.analytics for s in detection.strategies)
    rels = corpus.relationships.get("T1110")
    assert rels is not None and rels.mitigations and rels.groups


@pytest.mark.unit
def test_pin_parser_rejects_malformed_documents() -> None:
    valid = json.loads(DEFAULT_PIN_PATH.read_text(encoding="utf-8"))
    parse_pin(valid)  # sanity: the committed pin parses

    for mutate in (
        lambda d: d.pop("schema"),
        lambda d: d.update(schema=2),
        lambda d: d.update(attack_version="nineteen"),
        lambda d: d.update(retrieved="21/08/2026"),
        lambda d: d.update(extra_field=1),
        lambda d: d["bundle"].pop("sha256"),
        lambda d: d["bundle"].update(sha256="zz"),
        lambda d: d["bundle"].update(size_bytes=-1),
        lambda d: d["bundle"].update(file_name="../escape.json"),
        lambda d: d.update(shards={}),
        lambda d: d["shards"].update({"../evil.json": "0" * 64}),
        lambda d: d["shards"].update({"catalog.json": "not-hex"}),
        lambda d: d.update(signature={"algorithm": "rsa"}),
    ):
        document = json.loads(json.dumps(valid))
        mutate(document)
        with pytest.raises(AttackError):
            parse_pin(document)


@pytest.mark.unit
def test_signing_payload_excludes_signature_and_is_deterministic() -> None:
    document = json.loads(DEFAULT_PIN_PATH.read_text(encoding="utf-8"))
    payload = signing_payload(document)
    document["signature"] = {"algorithm": "ed25519", "public_key": "0" * 64, "signature": "0" * 128}
    assert signing_payload(document) == payload


@pytest.mark.unit
def test_missing_pin_is_unavailable_not_integrity(tmp_path: Path) -> None:
    with pytest.raises(AttackUnavailableError):
        load_pin(tmp_path / "no-such-pin.json")


@pytest.mark.unit
def test_unlisted_shard_is_an_integrity_error() -> None:
    pin = load_pin()
    with pytest.raises(AttackIntegrityError, match="not listed in the pin"):
        read_shard("ghost.json", pin=pin)


@pytest.mark.unit
def test_shard_ceiling_and_hashes_hold_on_disk() -> None:
    pin = load_pin()
    for name, expected in pin.shards.items():
        raw = (DATA_DIR / name).read_bytes()
        assert len(raw) <= 1024 * 1024, f"{name} exceeds the per-shard ceiling"
        assert hashlib.sha256(raw).hexdigest() == expected
