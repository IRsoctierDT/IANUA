# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Every third-party action must carry a review record, and majors must match.

A third-party GitHub Action runs over this repository with a token on every pull
request, so accepting one is a §5 boundary decision. #305 made that decision for
`danoszz/penthera` by reading the action's own definition at a pinned SHA and
enumerating what it checked — and then nothing held the result. Measured on
#314: Dependabot moved the pin from v1.9.0 to v2.2.0, two majors, and the only
thing that objected was the vendor's own `penthera-version` input. That input is
a courtesy. A vendor who drops it in a later release silently removes this
repository's control, which means the control was never ours.

So the record moves in-tree. ``security/third-party-actions.json`` names every
third-party action, the version a human reviewed, what they verified, **what
they did not**, and what bounds the blast radius. This module fails when a
pinned action is missing from it, or when the pinned major has moved past the
reviewed one.

**Why major and not every SHA.** `.github/dependabot.yml` bumps actions daily.
A record per SHA would fire on routine patches, and AGENTS.md names that failure
mode in terms — a rule that fires too often gets switched off rather than
obeyed. A major is where an action's internals change, which is also why #316
made majors arrive as their own pull request. Patch and minor bumps pass here;
a major does not.

**The first-party owner list lives in this module, not in the JSON.** If it sat
in the declaration file, the bypass would be to add an owner to it, and the gate
would approve its own exemption. `actions/`, `github/` and `dependabot/` are
GitHub's own platform; everything else is a vendor, `astral-sh` included.

**`accepted_unreviewed` is deliberate.** Three of the four third-party actions
in this repository predate this file and nobody has read them. Recording them as
reviewed would assert what was never measured, so they carry that status with a
reason, and this module requires the reason. The debt is now enumerable instead
of invisible, which is the whole gain — not that the debt is gone.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parents[2]
_WORKFLOWS = _REPO / ".github" / "workflows"
_RECORD = _REPO / "security" / "third-party-actions.json"

#: Owners that are GitHub's own platform and need no vendor review record.
#: Deliberately in code: in the JSON, adding an owner here would be a bypass.
FIRST_PARTY_OWNERS = frozenset({"actions", "github", "dependabot"})

#: ``uses: owner/repo[/path]@<40 hex> # vX[.Y[.Z]]`` — the shape
#: ``test_workflow_permissions.py`` already requires of every pin, so this can
#: rely on the comment being present rather than re-proving it.
_USES = re.compile(
    r"^\s*-?\s*uses:\s*(?P<ref>(?P<owner>[A-Za-z0-9._-]+)/[^@\s]+)@(?P<sha>[0-9a-f]{40})"
    r"\s+#\s*v?(?P<version>\d[\w.\-]*)",
    re.M,
)

#: Statuses a record may carry. Anything else is a typo that must not pass.
_STATUSES = frozenset({"reviewed", "accepted_unreviewed"})


def _record() -> dict[str, Any]:
    data = json.loads(_RECORD.read_text(encoding="utf-8"))
    assert isinstance(data, dict), "third-party-actions.json must parse to a mapping"
    assert data.get("version") == 1, 'third-party-actions.json must declare "version": 1'
    actions = data.get("actions")
    assert isinstance(actions, list), 'third-party-actions.json must hold an "actions" list'
    return data


def _records_by_action() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for entry in _record()["actions"]:
        assert isinstance(entry, dict), "each record must be an object"
        name = entry.get("action")
        assert isinstance(name, str) and name, "each record must name its action"
        assert name not in out, f"duplicate record for {name}"
        out[name] = entry
    return out


def pinned_actions(text: str) -> list[dict[str, str]]:
    """Every pinned ``uses:`` in one workflow file, as owner/ref/sha/version."""
    return [m.groupdict() for m in _USES.finditer(text)]


def third_party(pins: list[dict[str, str]]) -> list[dict[str, str]]:
    """The pins whose owner is not GitHub's own platform."""
    return [p for p in pins if p["owner"] not in FIRST_PARTY_OWNERS]


def _major(version: str) -> str:
    return version.split(".")[0]


def _all_pins() -> list[tuple[Path, dict[str, str]]]:
    found: list[tuple[Path, dict[str, str]]] = []
    for path in sorted(_WORKFLOWS.glob("*.yml")):
        for pin in pinned_actions(path.read_text(encoding="utf-8")):
            found.append((path, pin))
    return found


# --------------------------------------------------------------------------- #
# The gate
# --------------------------------------------------------------------------- #


@pytest.mark.security
def test_the_workflows_contain_pins_to_check() -> None:
    """A guard over zero pins is vacuous, so assert the corpus is non-empty."""
    pins = _all_pins()
    assert len(pins) >= 10, f"expected the workflows to pin many actions, found {len(pins)}"
    assert third_party([p for _, p in pins]), "expected at least one third-party pin"


@pytest.mark.security
def test_every_third_party_action_has_a_review_record() -> None:
    """A pinned vendor action with no record is an undeclared §5 acceptance."""
    records = _records_by_action()
    missing = {
        f"{path.name}: {pin['ref']}"
        for path, pin in _all_pins()
        if pin["owner"] not in FIRST_PARTY_OWNERS and pin["ref"] not in records
    }
    assert not missing, (
        "third-party actions pinned with no record in security/third-party-actions.json"
        f": {sorted(missing)}"
    )


@pytest.mark.security
def test_no_third_party_major_moves_past_its_reviewed_version() -> None:
    """#314's shape: the pin jumped 1.9.0 -> 2.2.0 and only the vendor objected."""
    records = _records_by_action()
    drifted = []
    for path, pin in _all_pins():
        if pin["owner"] in FIRST_PARTY_OWNERS:
            continue
        entry = records.get(pin["ref"])
        if entry is None:
            continue  # the previous test owns this failure
        reviewed = str(entry["reviewed_version"])
        if _major(pin["version"]) != _major(reviewed):
            drifted.append(
                f"{path.name}: {pin['ref']} is pinned at v{pin['version']}"
                f" but the record reviewed v{reviewed}"
            )
    assert not drifted, (
        "a third-party action's major moved past its reviewed version; a human must"
        f" read the action at the new ref and update the record: {drifted}"
    )


@pytest.mark.security
def test_first_party_owners_are_not_declarable_in_the_json() -> None:
    """The exemption list must not be editable from the declaration file.

    If the JSON could name first-party owners, the bypass for any vendor action
    would be to add its owner there — the gate approving its own exemption.
    """
    raw = _RECORD.read_text(encoding="utf-8")
    data = _record()
    for key in ("first_party_owners", "first_party", "exempt_owners", "exempt"):
        assert key not in data, (
            f"security/third-party-actions.json declares {key!r}; the exemption list"
            " belongs in this module, where widening it is a reviewed code change"
        )
    assert "FIRST_PARTY_OWNERS" not in raw, "the JSON must not restate the code's constant"


# --------------------------------------------------------------------------- #
# Record hygiene: a record that says nothing is not a review
# --------------------------------------------------------------------------- #


@pytest.mark.security
def test_every_record_declares_a_known_status_and_a_reason() -> None:
    for name, entry in _records_by_action().items():
        status = entry.get("status")
        assert status in _STATUSES, f"{name}: status {status!r} is not one of {sorted(_STATUSES)}"
        for field in ("reviewed_version", "reviewed_sha", "reason"):
            value = entry.get(field)
            assert isinstance(value, str) and value.strip(), (
                f"{name}: {field} must be a non-empty string"
            )
        assert re.fullmatch(r"[0-9a-f]{40}", entry["reviewed_sha"]), (
            f"{name}: reviewed_sha must be a 40-hex commit"
        )
        assert isinstance(entry.get("bounded_by"), list) and entry["bounded_by"], (
            f"{name}: bounded_by must list what limits the blast radius"
        )


@pytest.mark.security
def test_a_reviewed_record_names_what_was_verified_and_what_was_not() -> None:
    """'reviewed' is a claim, so it has to carry its evidence and its limits."""
    for name, entry in _records_by_action().items():
        if entry["status"] != "reviewed":
            continue
        verified = entry.get("properties_verified")
        assert isinstance(verified, list) and len(verified) >= 3, (
            f"{name}: a reviewed record must enumerate what was verified"
        )
        not_reviewed = entry.get("not_reviewed")
        assert isinstance(not_reviewed, list) and not_reviewed, (
            f"{name}: a reviewed record must state what was NOT reviewed; silence there"
            " reads as a stronger claim than anyone made"
        )
        assert isinstance(entry.get("reviewed_in"), str) and entry["reviewed_in"].strip(), (
            f"{name}: a reviewed record must say where the review is recorded"
        )


@pytest.mark.security
def test_an_unreviewed_record_claims_nothing_verified() -> None:
    """Grandfathered debt must not quietly accumulate verified-sounding prose."""
    for name, entry in _records_by_action().items():
        if entry["status"] != "accepted_unreviewed":
            continue
        assert not entry.get("properties_verified"), (
            f"{name}: status is accepted_unreviewed but properties_verified is non-empty;"
            " promote it to 'reviewed' with a reference, or drop the claims"
        )
        assert entry.get("not_reviewed"), (
            f"{name}: an unreviewed record must say so in not_reviewed"
        )


@pytest.mark.security
def test_the_record_has_no_entry_for_an_action_no_workflow_pins() -> None:
    """A stale record is a review nobody can act on, and hides a removal."""
    pinned = {p["ref"] for _, p in _all_pins()}
    stale = sorted(set(_records_by_action()) - pinned)
    assert not stale, f"security/third-party-actions.json records actions no workflow pins: {stale}"


# --------------------------------------------------------------------------- #
# The parser itself, driven against planted hostile workflow text
# --------------------------------------------------------------------------- #


@pytest.mark.security
@pytest.mark.parametrize(
    ("line", "expected_owner"),
    [
        ("      - uses: vendor/thing@" + "a" * 40 + " # v1.2.3", "vendor"),
        ("      uses: vendor/thing@" + "b" * 40 + " # 2.0.0", "vendor"),
        ("        - uses: vendor/thing/sub@" + "c" * 40 + " # v4", "vendor"),
    ],
)
def test_the_parser_reads_realistic_pin_spellings(line: str, expected_owner: str) -> None:
    pins = pinned_actions(line + "\n")
    assert len(pins) == 1, f"expected one pin from {line!r}"
    assert pins[0]["owner"] == expected_owner


@pytest.mark.security
def test_a_planted_unrecorded_vendor_action_is_caught() -> None:
    """The gate's own bypass case: a new vendor pin with no record."""
    planted = "      - uses: evilcorp/backdoor@" + "d" * 40 + " # v1.0.0\n"
    pins = third_party(pinned_actions(planted))
    assert len(pins) == 1
    assert pins[0]["ref"] == "evilcorp/backdoor"
    assert pins[0]["ref"] not in _records_by_action()


@pytest.mark.security
def test_a_first_party_owner_is_not_treated_as_a_vendor() -> None:
    first_party = "      - uses: actions/checkout@" + "e" * 40 + " # v7\n"
    assert third_party(pinned_actions(first_party)) == []


@pytest.mark.security
def test_a_lookalike_owner_is_still_a_vendor() -> None:
    """`actions-rs` is not `actions`; prefix matching would exempt a vendor."""
    for owner in ("actions-rs", "actionsx", "github-actions", "dependabot-bot"):
        line = f"      - uses: {owner}/thing@" + "f" * 40 + " # v1\n"
        pins = third_party(pinned_actions(line))
        assert len(pins) == 1, f"{owner} must be treated as a vendor"


@pytest.mark.security
def test_the_majors_of_the_shipped_pins_match_their_records() -> None:
    """The live assertion, stated separately so a failure reads unambiguously."""
    records = _records_by_action()
    for path, pin in _all_pins():
        if pin["owner"] in FIRST_PARTY_OWNERS:
            continue
        entry = records.get(pin["ref"])
        if entry is None:
            continue  # test_every_third_party_action_has_a_review_record owns this
        assert _major(pin["version"]) == _major(str(entry["reviewed_version"])), (
            f"{path.name}: {pin['ref']} v{pin['version']} vs reviewed v{entry['reviewed_version']}"
        )
