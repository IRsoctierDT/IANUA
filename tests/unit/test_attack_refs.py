"""Reference validation: revocation surfaces loudly, never silently."""

from __future__ import annotations

import pytest
from attack import load_corpus, resolve_current, validate_reference
from attack.errors import AttackError
from attack.model import Corpus, Tactic, Tombstone
from attack.refs import check_references


@pytest.fixture(scope="module")
def corpus() -> Corpus:
    return load_corpus()


@pytest.mark.unit
def test_active_reference_ok(corpus: Corpus) -> None:
    verdict = validate_reference("T1110", corpus)
    assert verdict.ok and verdict.status == "active" and verdict.name == "Brute Force"


@pytest.mark.unit
def test_deprecated_reference_names_itself(corpus: Corpus) -> None:
    verdict = validate_reference("T1064", corpus)
    assert not verdict.ok
    assert verdict.status == "deprecated"
    assert verdict.successor is None, "deprecation carries no replacement pointer"
    assert "deprecated" in verdict.problems[0]


@pytest.mark.unit
def test_revoked_reference_names_successor(corpus: Corpus) -> None:
    revoked = next(t for t in corpus.tombstones.values() if t.status == "revoked")
    verdict = validate_reference(revoked.technique_id, corpus)
    assert not verdict.ok and verdict.status == "revoked"
    assert verdict.successor == revoked.successor
    resolved = resolve_current(revoked.technique_id, corpus)
    assert resolved.technique_id == revoked.successor or resolved.status != "revoked"


@pytest.mark.unit
def test_unknown_reference_is_a_verdict_not_none(corpus: Corpus) -> None:
    verdict = validate_reference("T9999", corpus)
    assert verdict.status == "unknown" and not verdict.ok
    assert "does not exist" in verdict.problems[0]


@pytest.mark.unit
def test_malformed_id_raises(corpus: Corpus) -> None:
    for bad in ("1110", "T11", "t1110", "T1110.1", "", "T1110; DROP"):
        with pytest.raises(AttackError):
            validate_reference(bad, corpus)


@pytest.mark.unit
def test_check_references_returns_only_failures(corpus: Corpus) -> None:
    failures = check_references(["T1110", "T1064", "T9999"], corpus)
    assert [v.technique_id for v in failures] == ["T1064", "T9999"]


def _tiny(tombstones: dict[str, Tombstone]) -> Corpus:
    return Corpus(
        attack_version="19.2",
        tactics={"discovery": Tactic("discovery", "Discovery", "TA0007")},
        techniques={},
        tombstones=tombstones,
    )


@pytest.mark.unit
def test_successor_cycle_raises() -> None:
    corpus = _tiny(
        {
            "T1001": Tombstone("T1001", "revoked", "A", "T1002"),
            "T1002": Tombstone("T1002", "revoked", "B", "T1001"),
        }
    )
    with pytest.raises(AttackError, match="cycle"):
        resolve_current("T1001", corpus)
