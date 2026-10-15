# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for scripts/build_trust_page.py — parse, build, drift gate."""

import json
from pathlib import Path
from typing import TypedDict

import pytest

from scripts.build_trust_page import (
    ATTESTATION_WARNING_DAYS,
    TrustDataError,
    _emit_warnings,
    build,
    check,
    expiring_soon,
    main,
    parse_report,
    render_html,
    render_json,
    snapshot,
)

_VALID = {
    "as_of": "2026-07-24",
    "score": 92,
    "controls": [
        {"id": "POL-01", "title": "Default deny", "category": "Policy", "status": "pass"},
        {"id": "MAN-01", "title": "Branch protection", "category": "CI/CD", "status": "manual"},
    ],
    "frameworks": [{"name": "SOC 2", "passing": 11, "total": 12}],
}


class _Paths(TypedDict):
    """The three path keywords ``build`` and ``check`` share.

    A TypedDict rather than ``dict[str, Path]`` so ``check(**paths)`` keeps
    type-checking now that ``check`` also takes a ``clock`` keyword — a plain
    str-keyed dict unpacks against *every* parameter, including that one.
    """

    data_path: Path
    html_path: Path
    json_path: Path


def _paths(tmp_path: Path) -> _Paths:
    data = tmp_path / "trust.data.json"
    data.write_text(json.dumps(_VALID), encoding="utf-8")
    return {
        "data_path": data,
        "html_path": tmp_path / "trust.html",
        "json_path": tmp_path / "trust.json",
    }


#: A synthetic attestation window, fixed forever. Every date-sensitive test
#: below is written against THIS, never against compliance/attestations.json —
#: a regression test that reads the live store breaks the moment a control is
#: re-attested, which would turn the maintenance action this gate exists to
#: prompt into a red build.
_FIXTURE_OPENS = "2026-01-01"
_FIXTURE_EXPIRES = "2026-06-30"


def _attestation_root(
    tmp_path: Path, *, opens: str = _FIXTURE_OPENS, expires: str = _FIXTURE_EXPIRES
) -> Path:
    """Write an isolated attestation store and return its repository root."""
    store = tmp_path / "compliance"
    store.mkdir(exist_ok=True)
    (store / "attestations.json").write_text(
        json.dumps(
            {
                "version": 1,
                "attestations": [
                    {
                        "control_id": "FIX-01",
                        "attested_by": "test fixture",
                        "date": opens,
                        "expires": expires,
                        "note": "synthetic attestation for deterministic expiry tests",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return tmp_path


def test_parse_valid_report() -> None:
    report = parse_report(_VALID)
    assert report.score == 92
    assert report.tally()["pass"] == 1
    assert report.frameworks[0].percent == 92


@pytest.mark.parametrize(
    "mutation",
    [
        {"score": "high"},
        {"score": 101},
        {"controls": []},
        {"controls": [{"id": "X", "title": "t", "category": "c", "status": "green"}]},
        {"frameworks": [{"name": "F", "passing": 3, "total": 2}]},
    ],
)
def test_bad_snapshot_fails_closed(mutation: dict[str, object]) -> None:
    with pytest.raises(TrustDataError):
        parse_report({**_VALID, **mutation})


def test_build_then_check_is_in_sync(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    build(**paths)
    # root= pins an isolated store: check() consults the clock now, so reading
    # the committed attestations would make this pass or fail by calendar date.
    assert check(**paths, root=_attestation_root(tmp_path), clock=lambda: "2026-03-01") == []


def test_check_detects_drift(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    build(**paths)
    paths["html_path"].write_text("tampered", encoding="utf-8")
    problems = check(**paths, root=_attestation_root(tmp_path), clock=lambda: "2026-03-01")
    assert problems and "trust.html" in problems[0]


def test_expiry_gate_fires_on_a_lapsed_attestation(tmp_path: Path) -> None:
    """The regression this gate exists for, and could not previously catch.

    It compared ``attestation.expires < report.as_of``, where ``as_of`` is the
    frozen committed snapshot date. Every attestation expires *after* the
    snapshot that recorded it, so the comparison was False — and stayed False
    past the expiry date, because ``as_of`` only moves when a human runs
    ``--snapshot``. The gate was inert in exactly the case its own comment
    promised it defended.
    """
    paths = _paths(tmp_path)
    build(**paths)
    root = _attestation_root(tmp_path)
    # Inside the fixture window: in sync, no complaints.
    assert check(**paths, root=root, clock=lambda: "2026-03-01") == []
    # One day past the inclusive expiry: the gate must go red.
    lapsed = check(**paths, root=root, clock=lambda: "2026-07-01")
    assert lapsed, "a lapsed attestation must fail the gate"
    assert any("FIX-01" in msg and "expired" in msg for msg in lapsed)
    assert all("re-attest" in msg for msg in lapsed)


def test_expiry_gate_does_not_depend_on_the_snapshot_date(tmp_path: Path) -> None:
    """Lapse is judged against today, never against the snapshot's as_of.

    Pinning as_of far in the past — the shape that neutered the old check —
    must not stop a lapsed attestation from firing.
    """
    paths = _paths(tmp_path)
    paths["data_path"].write_text(json.dumps({**_VALID, "as_of": "2020-01-01"}), encoding="utf-8")
    build(**paths)
    problems = check(**paths, root=_attestation_root(tmp_path), clock=lambda: "2026-07-01")
    assert any("expired" in msg for msg in problems), "as_of must not be able to suppress a lapse"


def test_expiry_gate_rejects_a_post_dated_attestation(tmp_path: Path) -> None:
    """The window's lower bound is checked too, which the old comparison ignored."""
    paths = _paths(tmp_path)
    build(**paths)
    problems = check(**paths, root=_attestation_root(tmp_path), clock=lambda: "2025-12-31")
    assert problems
    assert all("not yet in force" in msg for msg in problems)


def test_expiry_gate_reads_a_real_clock_by_default(tmp_path: Path) -> None:
    """With no clock injected the gate uses today, so CI needs no wiring."""
    from datetime import UTC, datetime

    from scripts.build_trust_page import _utc_today

    today = _utc_today()
    assert today == datetime.now(tz=UTC).date().isoformat()
    paths = _paths(tmp_path)
    build(**paths)
    root = _attestation_root(tmp_path)
    # Same verdict with the default clock as with today injected explicitly.
    assert check(**paths, root=root) == check(**paths, root=root, clock=lambda: today)


@pytest.mark.parametrize(
    "day,expect_warning",
    [
        ("2026-05-30", False),  # 31 days out — outside the window, stay quiet
        ("2026-05-31", True),  # exactly 30 days — inclusive edge
        ("2026-06-29", True),  # 1 day out
        ("2026-06-30", True),  # the expiry date itself: still valid, warn loudly
    ],
)
def test_warning_window_boundaries(tmp_path: Path, day: str, expect_warning: bool) -> None:
    """The fixture window closes 2026-06-30; the warning window is inclusive."""
    notices = expiring_soon(root=_attestation_root(tmp_path), clock=lambda: day)
    assert bool(notices) is expect_warning
    if expect_warning:
        assert any("FIX-01" in msg for msg in notices)
        assert all("re-attest before it lapses" in msg for msg in notices)


def test_expiry_date_itself_warns_rather_than_fails(tmp_path: Path) -> None:
    """``expires`` is inclusive, so the control is still attested that day."""
    paths = _paths(tmp_path)
    build(**paths)
    root = _attestation_root(tmp_path)
    on_expiry = _FIXTURE_EXPIRES
    assert check(**paths, root=root, clock=lambda: on_expiry) == []
    notices = expiring_soon(root=root, clock=lambda: on_expiry)
    assert any("expires today" in msg for msg in notices)


def test_a_lapse_is_a_problem_and_never_also_a_warning(tmp_path: Path) -> None:
    """The channel-separation invariant: no control appears in both.

    Warnings exist in their own return value precisely so they can never fail
    the build. If a lapsed attestation also showed up as a warning, the two
    would double-report and the distinction would be cosmetic.
    """
    paths = _paths(tmp_path)
    build(**paths)
    root = _attestation_root(tmp_path)
    lapsed = "2026-07-01"
    problems = [m for m in check(**paths, root=root, clock=lambda: lapsed) if "attestation" in m]
    notices = expiring_soon(root=root, clock=lambda: lapsed)
    assert problems, "a lapsed attestation must be a problem"
    assert notices == [], "a lapsed attestation must not also be a warning"


def test_expiry_tests_are_isolated_from_the_committed_store(tmp_path: Path) -> None:
    """Re-attesting a real control must never break these tests.

    The prescribed remedy for a lapse is to re-attest and refresh the
    snapshot. If the date-sensitive tests read compliance/attestations.json,
    that remedy would shift the live dates out from under their fixed clocks
    and keep CI red — the gate punishing the maintenance it exists to prompt.
    So the fixture root must genuinely override the committed store.
    """
    root = _attestation_root(tmp_path)
    fixture_only = expiring_soon(root=root, clock=lambda: "2026-05-31")
    assert fixture_only and all("FIX-01" in msg for msg in fixture_only)
    assert not any("MAN-0" in msg for msg in fixture_only), "live store leaked into the fixture"
    # And an empty root yields nothing at all, rather than silently falling back.
    assert expiring_soon(root=tmp_path / "empty", clock=lambda: "2026-05-31") == []


def test_warnings_never_change_the_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An approaching lapse is advisory — it must not fail the gate."""
    monkeypatch.setattr(
        "scripts.build_trust_page.expiring_soon", lambda **_: ["FIX-01 expires in 1 day(s)"]
    )
    monkeypatch.setattr("scripts.build_trust_page.REPO_ROOT", _attestation_root(tmp_path))
    monkeypatch.setattr("scripts.build_trust_page._utc_today", lambda: "2026-03-01")
    paths = _paths(tmp_path)
    argv = [
        "--data",
        str(paths["data_path"]),
        "--out-html",
        str(paths["html_path"]),
        "--out-json",
        str(paths["json_path"]),
    ]
    assert main(argv) == 0
    assert main([*argv, "--check"]) == 0, "a warning must not fail --check"
    paths["json_path"].write_text("stale", encoding="utf-8")
    assert main([*argv, "--check"]) == 1, "real drift must still fail"


def test_warning_surfaces_as_a_ci_annotation_under_actions(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A warning buried in a green log is not a warning."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    _emit_warnings(["FIX-01 expires in 1 day(s)"])
    assert capsys.readouterr().err.startswith("::warning::")

    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    _emit_warnings(["FIX-01 expires in 1 day(s)"])
    assert capsys.readouterr().err.startswith("warning: ")

    _emit_warnings([])
    assert capsys.readouterr().err == "", "no notices must print nothing"


def test_warning_window_is_a_reviewed_constant(tmp_path: Path) -> None:
    """The threshold is committed data, not a magic number buried in a branch."""
    assert ATTESTATION_WARNING_DAYS == 30
    root = _attestation_root(tmp_path)
    assert expiring_soon(root=root, clock=lambda: "2026-05-31", within_days=0) == []


def test_render_json_carries_disclaimer_and_summary() -> None:
    payload = json.loads(render_json(parse_report(_VALID)))
    assert "not an audit" in payload["disclaimer"]
    assert payload["summary"]["manual"] == 1


def test_render_html_contains_score_and_controls() -> None:
    page = render_html(parse_report(_VALID))
    assert "92%" in page
    assert "Default deny" in page


def test_snapshot_carries_no_detail_fields(tmp_path: Path) -> None:
    """The public snapshot schema must not leak check details."""
    data_path = tmp_path / "trust.data.json"
    repo_root = Path(__file__).resolve().parents[2]
    report = snapshot(data_path, root=repo_root)
    written = json.loads(data_path.read_text(encoding="utf-8"))
    assert report.controls  # engine ran
    assert all("detail" not in control for control in written["controls"])


def test_main_check_exit_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("scripts.build_trust_page.REPO_ROOT", _attestation_root(tmp_path))
    monkeypatch.setattr("scripts.build_trust_page._utc_today", lambda: "2026-03-01")
    paths = _paths(tmp_path)
    argv_common = [
        "--data",
        str(paths["data_path"]),
        "--out-html",
        str(paths["html_path"]),
        "--out-json",
        str(paths["json_path"]),
    ]
    assert main(argv_common) == 0
    assert main([*argv_common, "--check"]) == 0
    paths["json_path"].write_text("stale", encoding="utf-8")
    assert main([*argv_common, "--check"]) == 1


def test_main_check_fails_on_a_lapsed_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: a lapsed attestation fails `--check` through main().

    Patching REPO_ROOT is the only lever here, since main() takes no --root —
    which is precisely why `check`/`expiring_soon` default root to None.
    """
    monkeypatch.setattr("scripts.build_trust_page.REPO_ROOT", _attestation_root(tmp_path))
    paths = _paths(tmp_path)
    argv = [
        "--data",
        str(paths["data_path"]),
        "--out-html",
        str(paths["html_path"]),
        "--out-json",
        str(paths["json_path"]),
    ]
    monkeypatch.setattr("scripts.build_trust_page._utc_today", lambda: "2026-03-01")
    assert main(argv) == 0
    assert main([*argv, "--check"]) == 0, "inside the window the gate passes"
    monkeypatch.setattr("scripts.build_trust_page._utc_today", lambda: "2026-07-01")
    assert main([*argv, "--check"]) == 1, "past the window the gate must fail"


def test_main_bad_input_exit_code(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert main(["--data", str(bad)]) == 2


# --------------------------------------------------------------------------
# The published snapshot must describe the controls that actually exist
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_the_trust_snapshot_lists_every_control_in_the_registry() -> None:
    """Nothing tied the committed snapshot to ``registry()`` until this.

    The trust page is built offline from ``docs/trust.data.json`` — a committed
    snapshot, deliberately, so that no check internals can leak into a
    published artifact and so the build is reproducible. But nothing asserted
    that the snapshot still *describes* the control set, so adding a control
    left the published page quietly understating the posture. For a page whose
    whole subject is trust, silently claiming fewer controls than exist is the
    wrong direction to be wrong in; it was found by adding CFG-02 and noticing
    the snapshot said 16.

    Deliberately asserts identity and labels, **not** status: the statuses in
    the snapshot are recorded evidence of a past evaluation, and re-deriving
    them here would couple a unit test to a live posture run and to whatever
    the host's filesystem looks like.
    """
    from compliance.controls import registry

    repo_root = Path(__file__).resolve().parents[2]
    snapshot = json.loads((repo_root / "docs" / "trust.data.json").read_text(encoding="utf-8"))
    published = {control["id"]: control for control in snapshot["controls"]}
    live = {control.id: control for control in registry()}

    assert set(published) == set(live), (
        f"the trust snapshot and the control registry disagree; "
        f"only in the registry: {sorted(set(live) - set(published))}; "
        f"only in the snapshot: {sorted(set(published) - set(live))}"
    )
    for identifier, control in live.items():
        assert published[identifier]["title"] == control.title
        assert published[identifier]["category"] == control.category.value


@pytest.mark.unit
def test_the_trust_snapshots_framework_totals_match_the_registry() -> None:
    """A framework's ``total`` is how many controls carry a ref to it.

    Checked separately from the control list because the two drift
    independently: adding a control without refs would keep the ids in step
    while leaving the rollups wrong.
    """
    from compliance.controls import registry
    from compliance.frameworks import Framework

    repo_root = Path(__file__).resolve().parents[2]
    snapshot = json.loads((repo_root / "docs" / "trust.data.json").read_text(encoding="utf-8"))
    controls = registry()
    by_name = {framework.value: framework for framework in Framework}
    for entry in snapshot["frameworks"]:
        framework = by_name[entry["name"]]
        expected = sum(
            1
            for control in controls
            if any(ref.framework is framework for ref in control.framework_refs)
        )
        assert entry["total"] == expected, (
            f"{entry['name']}: snapshot says {entry['total']} controls, registry has {expected}"
        )
        assert entry["passing"] <= entry["total"]
