# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The image-digest drift check, driven without touching a registry.

``scripts/check_action_image_digest.py`` exists because a 40-hex ``uses:`` pin
does not fix the code a **Docker** action runs: the pin fixes ``action.yml``, and
``action.yml`` names an image. ``ossf/scorecard-action`` names
``docker://ghcr.io/ossf/scorecard-action:v2.5.0`` — a mutable tag.

Every test here is offline. The reference parser is pure, and the comparison is
driven with a stub resolver, so the suite proves the decision logic without
depending on ``ghcr.io`` being reachable or on what the tag resolves to today.
The networked form runs in CI (``.github/workflows/scorecard.yml``, the
``image-pin`` job) and against the live registry during review.

The three outcomes are deliberately distinguished, and that is what most of
these tests pin: a **moved** tag exits 1, an **undetermined** answer exits 2,
and only agreement exits 0. A gate that conflated the first two would teach an
operator to ignore the one that matters.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts.check_action_image_digest import (
    ImageRef,
    check,
    docker_records,
    main,
    parse_image_reference,
)

_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64


def _record(**execution: Any) -> dict[str, Any]:
    """One minimal record carrying the ``execution`` block under test."""
    base = {
        "using": "docker",
        "entrypoint": "docker://ghcr.io/ossf/scorecard-action:v2.5.0",
        "hooks": [],
        "pinned_by_sha": False,
        "pin_gap": "x" * 50,
        "image_digest": _DIGEST_A,
        "measured_on": "2026-11-05",
    }
    base.update(execution)
    return {
        "version": 1,
        "actions": [
            {
                "action": "vendor/thing",
                "status": "accepted_unreviewed",
                "reviewed_version": "1",
                "reviewed_sha": "0" * 40,
                "reviewed_in": "",
                "reason": "test fixture",
                "execution": base,
                "properties_verified": [],
                "not_reviewed": ["fixture"],
                "bounded_by": ["fixture"],
            }
        ],
    }


# --------------------------------------------------------------------------- #
# The reference parser
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("image", "expected"),
    [
        (
            "docker://ghcr.io/ossf/scorecard-action:v2.5.0",
            ImageRef("ghcr.io", "ossf/scorecard-action", "v2.5.0"),
        ),
        # No tag is the registry's implicit `latest` — the most mutable
        # reference there is, so it is checked rather than waved through.
        (
            "docker://ghcr.io/ossf/scorecard-action",
            ImageRef("ghcr.io", "ossf/scorecard-action", "latest"),
        ),
        (
            "  docker://ghcr.io/a/b/c:1.2.3  ",
            ImageRef("ghcr.io", "a/b/c", "1.2.3"),
        ),
    ],
)
def test_the_parser_reads_tag_references(image: str, expected: ImageRef) -> None:
    assert parse_image_reference(image) == expected


@pytest.mark.parametrize(
    "image",
    [
        # Already digest-pinned: there is no tag that can move.
        "docker://ghcr.io/ossf/scorecard-action@sha256:" + "c" * 64,
        # A Dockerfile path is built from the tree the SHA already pins.
        "Dockerfile",
        "build/Dockerfile",
        # Composite and node entrypoints are not image references at all.
        "inline steps in action.yml",
        "dist/index.js",
    ],
)
def test_the_parser_skips_what_needs_no_check(image: str) -> None:
    assert parse_image_reference(image) is None


@pytest.mark.parametrize(
    "image",
    [
        "docker://ghcr.io:443/ossf/scorecard-action:v2.5.0",  # a port
        "docker://ghcr.io",  # no repository
        "docker://ghcr.io/Ossf/Scorecard-Action:v2.5.0",  # uppercase is not an OCI name
        "docker://ghcr.io/ossf/scorecard-action:" + "v" * 200,  # tag over the bound
        "docker://ghcr.io/ossf/scorecard-action:bad tag",  # space in the tag
    ],
)
def test_an_unreadable_tag_reference_raises_rather_than_being_skipped(image: str) -> None:
    """A reference it cannot read is one it cannot check.

    Returning ``None`` here would make the check silently pass over a real
    Docker action — the vacuous guard `AGENTS.md` names as a failure mode in
    its own terms. It raises, and ``check`` turns that into exit 2.
    """
    with pytest.raises(ValueError):
        parse_image_reference(image)


# --------------------------------------------------------------------------- #
# The three outcomes
# --------------------------------------------------------------------------- #


def test_a_matching_digest_is_the_only_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("scripts.check_action_image_digest.resolve_digest", lambda _ref: _DIGEST_A)
    results = check(_record(), offline=False)
    assert len(results) == 1
    assert (results[0].moved, results[0].undetermined) == (False, False)
    assert results[0].observed == _DIGEST_A


def test_a_moved_tag_is_reported_as_moved_and_not_as_undetermined(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("scripts.check_action_image_digest.resolve_digest", lambda _ref: _DIGEST_B)
    results = check(_record(), offline=False)
    assert (results[0].moved, results[0].undetermined) == (True, False)


@pytest.mark.parametrize(
    "boom",
    [
        OSError("connection reset"),
        ValueError("returned no usable Docker-Content-Digest"),
        json.JSONDecodeError("bad", "{", 0),
    ],
)
def test_a_registry_failure_is_undetermined_and_never_a_pass(
    monkeypatch: pytest.MonkeyPatch, boom: Exception
) -> None:
    """The failure that must not look like success.

    An outage, a rewritten response and a malformed token all land here. If any
    of them read as agreement, the gate would go quiet exactly when it stopped
    working.
    """

    def _raise(_ref: ImageRef) -> str:
        raise boom

    monkeypatch.setattr("scripts.check_action_image_digest.resolve_digest", _raise)
    results = check(_record(), offline=False)
    assert (results[0].moved, results[0].undetermined) == (False, True)


@pytest.mark.parametrize("digest", ["", "sha256:short", "deadbeef" * 8, "SHA256:" + "a" * 64])
def test_a_missing_or_malformed_committed_digest_is_undetermined(digest: str) -> None:
    """A tag-referenced Docker action with no usable digest cannot be checked."""
    results = check(_record(image_digest=digest), offline=False)
    assert (results[0].moved, results[0].undetermined) == (False, True)
    assert "image_digest" in results[0].detail


def test_an_unparseable_reference_is_undetermined() -> None:
    results = check(_record(entrypoint="docker://ghcr.io:443/a/b:1"), offline=False)
    assert results[0].undetermined is True


def test_a_non_docker_record_is_not_checked_at_all() -> None:
    record = _record()
    record["actions"][0]["execution"]["using"] = "node24"
    assert docker_records(record) == []
    assert check(record, offline=False) == []


def test_the_offline_form_validates_the_record_without_resolving(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Offline must not reach the registry, and must not claim it did."""

    def _never(_ref: ImageRef) -> str:  # pragma: no cover - must not be called
        raise AssertionError("offline mode contacted the registry")

    monkeypatch.setattr("scripts.check_action_image_digest.resolve_digest", _never)
    results = check(_record(), offline=True)
    assert len(results) == 1
    assert results[0].observed is None
    assert (results[0].moved, results[0].undetermined) == (False, False)


def test_the_offline_form_still_catches_an_absent_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _never(_ref: ImageRef) -> str:  # pragma: no cover - must not be called
        raise AssertionError("offline mode contacted the registry")

    monkeypatch.setattr("scripts.check_action_image_digest.resolve_digest", _never)
    execution = dict(_record()["actions"][0]["execution"])
    del execution["image_digest"]
    record = _record()
    record["actions"][0]["execution"] = execution
    assert check(record, offline=True)[0].undetermined is True


# --------------------------------------------------------------------------- #
# The shipped record, and the CLI's exit codes
# --------------------------------------------------------------------------- #


def test_the_shipped_record_passes_the_offline_gate() -> None:
    """The live assertion: every tag-referenced Docker action carries a digest.

    This is the form §7 runs. A new Docker action pinned without a committed
    digest turns this red before CI's networked job does.
    """
    assert main(["--offline"]) == 0


def test_the_shipped_record_still_has_a_tag_reference_to_check() -> None:
    """A guard over zero references proves nothing, so assert there is one.

    If upstream ever references its image by digest, this test is the one to
    delete — and deleting it should be a deliberate act, because at that point
    the whole mechanism is unnecessary rather than merely quiet.
    """
    record = json.loads(
        (Path(__file__).resolve().parents[2] / "security" / "third-party-actions.json").read_text(
            encoding="utf-8"
        )
    )
    tagged = [
        entry
        for entry in docker_records(record)
        if parse_image_reference(str(entry["execution"]["entrypoint"])) is not None
    ]
    assert tagged, (
        "no tag-referenced Docker action remains in the record; the image-pin job is now "
        "vacuous and this mechanism can be removed deliberately"
    )
