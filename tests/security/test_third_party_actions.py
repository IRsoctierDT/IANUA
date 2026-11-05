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

**A 40-hex pin does not always fix the code that runs, so each record declares
what executes.** The first version of this module treated the SHA as the whole
control, which is true for a composite action (the steps are in the file) and a
node action (the `dist/` bundle is in the tree at that commit) — and false for a
**Docker** action, where the pin fixes `action.yml` and `action.yml` names an
image. Measured at the pinned SHAs on 2026-11-05: `danoszz/penthera` is
composite; `gitleaks/gitleaks-action` and `astral-sh/setup-uv` are `node24`,
the latter with a `post:` hook nobody has read; and `ossf/scorecard-action`
is `runs.using: "docker"` with
`image: "docker://ghcr.io/ossf/scorecard-action:v2.5.0"` — a **mutable tag**.
Whoever can push that tag chooses the container this repository executes, and
no SHA pin, Dependabot bump or permissions gate can see a tag move. So every
record declares an `execution` block, this module **derives** whether the pin
suffices from the entrypoint and compares it with the declaration, and a record
with a gap must state it in `pin_gap`. The gap itself is upstream's to close;
what this buys is that it is enumerable and cannot be quietly dropped.

**And the scan reads both extensions GitHub accepts.** `*.yml` alone was a
bypass of the same shape this repository keeps finding in its own controls — a
rule written to match one spelling that the thing it stops can simply spell
differently. A vendor action added in `foo.yaml` was invisible to every test
here. `test_workflow_permissions.py` already read both; this module did not.
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

#: Both spellings GitHub accepts for a workflow file. `*.yml` alone let a vendor
#: action in `foo.yaml` past every test in this module;
#: `test_workflow_permissions.py` already read both, so this matches its idiom.
_WORKFLOW_SUFFIXES = (".yml", ".yaml")

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


def workflow_files(directory: Path) -> list[Path]:
    """Every workflow file in ``directory``, in both spellings GitHub accepts."""
    return sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and path.suffix.lower() in _WORKFLOW_SUFFIXES
    )


def _all_pins() -> list[tuple[Path, dict[str, str]]]:
    found: list[tuple[Path, dict[str, str]]] = []
    for path in workflow_files(_WORKFLOWS):
        for pin in pinned_actions(path.read_text(encoding="utf-8")):
            found.append((path, pin))
    return found


def sha_pin_is_sufficient(using: str, entrypoint: str) -> bool:
    """Does a 40-hex pin on the action fix the code that will actually run?

    For ``composite`` it does: the steps are in ``action.yml`` at that commit.
    For ``nodeNN`` it does: the bundled entrypoint is in the vendor's tree at
    that commit. For ``docker`` it depends on the image reference — a
    ``docker://`` registry reference is pinned only by a ``@sha256:`` digest,
    and a **tag** is what most Docker actions ship, so the pin fixes
    ``action.yml`` while the code it names can be replaced underneath it. An
    ``image:`` that is not a ``docker://`` reference is a Dockerfile path, built
    from the pinned tree, so the pin holds.

    **Residual, stated rather than implied:** a Dockerfile built from the pinned
    tree can still carry an unpinned ``FROM``, which this derivation reads as
    sufficient. Closing that would mean reading the vendor's Dockerfile, which
    no test here can do offline; it is a reviewer's question, recorded in the
    record's ``not_reviewed`` list rather than enforced.
    """
    if using != "docker":
        return True
    ref = entrypoint.strip()
    if not ref.startswith("docker://"):
        return True  # a Dockerfile path: built from the tree the SHA pins
    return "@sha256:" in ref.removeprefix("docker://")


#: ``runs.using`` values a record may declare. ``nodeNN`` covers the versions
#: GitHub has shipped and the ones it has not shipped yet.
_USING = re.compile(r"^(?:composite|docker|node\d+)$")

#: The fields an ``execution`` block must carry. Each one is a question a
#: reviewer of a vendor action has to answer, made mechanical.
_EXECUTION_FIELDS = ("using", "entrypoint", "hooks", "pinned_by_sha", "measured_on")


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


# --------------------------------------------------------------------------- #
# What actually executes, and whether our SHA pin fixes it
# --------------------------------------------------------------------------- #


@pytest.mark.security
def test_every_record_declares_how_the_action_executes() -> None:
    """A record that does not say what runs cannot say what was pinned."""
    for name, entry in _records_by_action().items():
        execution = entry.get("execution")
        assert isinstance(execution, dict), (
            f"{name}: must declare an execution block — runs.using, the entrypoint,"
            " any pre/post hook, and whether the SHA pin fixes the code that runs"
        )
        for field in _EXECUTION_FIELDS:
            assert field in execution, f"{name}: execution is missing {field!r}"
        assert _USING.fullmatch(str(execution["using"])), (
            f"{name}: execution.using {execution['using']!r} is not composite, docker or nodeNN"
        )
        assert isinstance(execution["entrypoint"], str) and execution["entrypoint"].strip(), (
            f"{name}: execution.entrypoint must name what runs"
        )
        assert isinstance(execution["hooks"], list), (
            f"{name}: execution.hooks must be a list, empty when there is no pre:/post: hook"
        )
        assert isinstance(execution["pinned_by_sha"], bool), (
            f"{name}: execution.pinned_by_sha must be a bool, not {execution['pinned_by_sha']!r}"
        )
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(execution["measured_on"])), (
            f"{name}: execution.measured_on must be an ISO date; this block is measured"
            " at the pinned SHA, not inferred"
        )


@pytest.mark.security
def test_a_record_cannot_claim_a_pin_it_does_not_have() -> None:
    """``pinned_by_sha`` is derived from the entrypoint, never trusted."""
    for name, entry in _records_by_action().items():
        execution = entry["execution"]
        derived = sha_pin_is_sufficient(str(execution["using"]), str(execution["entrypoint"]))
        assert execution["pinned_by_sha"] == derived, (
            f"{name}: the record declares pinned_by_sha={execution['pinned_by_sha']!r} but"
            f" {execution['using']} + {execution['entrypoint']!r} derives {derived!r}"
        )


@pytest.mark.security
def test_the_pin_gap_is_stated_exactly_when_the_sha_does_not_pin_the_code() -> None:
    """Symmetric on purpose: an unstated gap hides it, a stale one misleads."""
    for name, entry in _records_by_action().items():
        execution = entry["execution"]
        gap = execution.get("pin_gap", "")
        if execution["pinned_by_sha"]:
            assert not str(gap).strip(), (
                f"{name}: the SHA pin fixes the code that runs, so pin_gap must be absent;"
                " stale gap prose reads as a live finding"
            )
        else:
            assert isinstance(gap, str) and len(gap.strip()) >= 40, (
                f"{name}: the SHA pin does NOT fix the code that runs, so pin_gap must say"
                " what is unpinned and what bounds it"
            )


@pytest.mark.security
@pytest.mark.parametrize(
    ("using", "entrypoint", "sufficient"),
    [
        ("composite", "inline steps in action.yml", True),
        ("node24", "dist/index.js", True),
        ("node20", "dist/setup/index.cjs", True),
        # The shipped scorecard case: a mutable tag.
        ("docker", "docker://ghcr.io/ossf/scorecard-action:v2.5.0", False),
        ("docker", "docker://alpine:latest", False),
        ("docker", "docker://alpine", False),
        # A digest fixes it, in either position.
        ("docker", "docker://ghcr.io/ossf/scorecard-action@sha256:" + "a" * 64, True),
        ("docker", "docker://alpine:3.20@sha256:" + "b" * 64, True),
        # A Dockerfile is built from the tree the SHA pins.
        ("docker", "Dockerfile", True),
        ("docker", "build/Dockerfile", True),
    ],
)
def test_the_derivation_reads_planted_entrypoints(
    using: str, entrypoint: str, sufficient: bool
) -> None:
    assert sha_pin_is_sufficient(using, entrypoint) is sufficient


@pytest.mark.security
def test_a_planted_record_that_lies_about_its_pin_is_caught() -> None:
    """The bypass this contract exists to close, driven rather than asserted."""
    planted = {
        "using": "docker",
        "entrypoint": "docker://ghcr.io/vendor/thing:v1",
        "pinned_by_sha": True,  # the lie
    }
    derived = sha_pin_is_sufficient(str(planted["using"]), str(planted["entrypoint"]))
    assert derived is False, "a tag-referenced image must not derive as pinned"
    assert planted["pinned_by_sha"] != derived, "the plant must disagree with the derivation"


@pytest.mark.security
def test_a_hook_declaration_is_not_mistaken_for_a_review() -> None:
    """``execution`` is measured; it must not smuggle verified-sounding claims.

    ``astral-sh/setup-uv`` carries a ``post:`` hook that runs after the job with
    the same token, and the penthera record verifies the *absence* of such a
    hook — so the property matters here. Declaring the hook records a fact; it
    does not promote the entry out of ``accepted_unreviewed``.
    """
    for name, entry in _records_by_action().items():
        if entry["status"] != "accepted_unreviewed":
            continue
        assert not entry.get("properties_verified"), (
            f"{name}: an execution block is a measurement, not a review"
        )


# --------------------------------------------------------------------------- #
# The scan's own reach
# --------------------------------------------------------------------------- #


@pytest.mark.security
def test_the_pin_scan_reads_both_workflow_extensions(tmp_path: Path) -> None:
    """``*.yml`` alone let a vendor action in ``foo.yaml`` past every test here."""
    (tmp_path / "a.yml").write_text("on: push\n", encoding="utf-8")
    (tmp_path / "b.yaml").write_text("on: push\n", encoding="utf-8")
    (tmp_path / "c.YAML").write_text("on: push\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("not a workflow\n", encoding="utf-8")
    (tmp_path / "nested").mkdir()
    names = [p.name for p in workflow_files(tmp_path)]
    assert names == ["a.yml", "b.yaml", "c.YAML"], names


@pytest.mark.security
def test_a_vendor_action_hidden_in_a_yaml_workflow_is_still_scanned(tmp_path: Path) -> None:
    """The bypass, driven end to end against a planted directory."""
    planted = "jobs:\n  j:\n    steps:\n      - uses: evilcorp/backdoor@" + "d" * 40 + " # v1\n"
    (tmp_path / "sneaky.yaml").write_text(planted, encoding="utf-8")
    pins = [
        pin
        for path in workflow_files(tmp_path)
        for pin in third_party(pinned_actions(path.read_text(encoding="utf-8")))
    ]
    assert len(pins) == 1, "a vendor pin in a .yaml workflow must be seen"
    assert pins[0]["ref"] == "evilcorp/backdoor"
    assert pins[0]["ref"] not in _records_by_action()


@pytest.mark.security
def test_the_shipped_workflow_scan_is_not_empty() -> None:
    """A reach fix over zero files would be vacuous."""
    assert len(workflow_files(_WORKFLOWS)) >= 10
