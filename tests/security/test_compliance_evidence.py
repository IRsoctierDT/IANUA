# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Security tests for compliance evidence recording (AGENTS.md §5).

Evidence must never leak secrets or environment values, must stay inside the
repository's data/ directory, must be created owner-only, and its audit chain
must detect tampering.
"""

import json
import os
import secrets
import stat
from pathlib import Path

import pytest

from compliance.controls import Category, CheckResult, Control, ControlStatus, Severity
from compliance.engine import run_controls
from compliance.evidence import export_bundle, load_recent, record_run, verify_chain

_CLOCK = "2026-07-24T00:00:00+00:00"


def _report(tmp_path: Path):  # type: ignore[no-untyped-def]
    control = Control(
        id="T-01",
        title="Test control",
        description="d",
        category=Category.POLICY,
        severity=Severity.LOW,
        check=lambda root: CheckResult(ControlStatus.PASS, "ok"),
    )
    return run_controls(tmp_path, clock=lambda: _CLOCK, controls=(control,))


@pytest.mark.security
def test_evidence_contains_no_environment_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = "SUPER-SECRET-CANARY-VALUE-123456"
    monkeypatch.setenv("API_TOKEN", canary)
    record_run(_report(tmp_path), root=tmp_path, clock=lambda: _CLOCK)
    evidence = (tmp_path / "data" / "compliance" / "evidence.jsonl").read_text(encoding="utf-8")
    audit = (tmp_path / "data" / "compliance" / "audit.log").read_text(encoding="utf-8")
    assert canary not in evidence
    assert canary not in audit


@pytest.mark.security
def test_evidence_files_are_owner_only(tmp_path: Path) -> None:
    record_run(_report(tmp_path), root=tmp_path, clock=lambda: _CLOCK)
    for name in ("evidence.jsonl", "audit.log"):
        mode = stat.S_IMODE((tmp_path / "data" / "compliance" / name).stat().st_mode)
        assert mode == 0o600, f"{name} mode is {oct(mode)}"


@pytest.mark.security
def test_export_bundle_refuses_path_escape(tmp_path: Path) -> None:
    report = _report(tmp_path)
    with pytest.raises(ValueError):
        export_bundle(report, root=tmp_path, dest=tmp_path / ".." / "outside.json")


@pytest.mark.security
def test_chain_detects_tampered_evidence_history(tmp_path: Path) -> None:
    record_run(_report(tmp_path), root=tmp_path, clock=lambda: _CLOCK)
    record_run(_report(tmp_path), root=tmp_path, clock=lambda: _CLOCK)
    assert verify_chain(tmp_path).intact

    audit_path = tmp_path / "data" / "compliance" / "audit.log"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["decision"] = "pass-definitely"  # rewrite history
    lines[0] = json.dumps(entry)
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not verify_chain(tmp_path).intact


@pytest.mark.security
def test_malformed_evidence_lines_are_skipped_not_trusted(tmp_path: Path) -> None:
    record_run(_report(tmp_path), root=tmp_path, clock=lambda: _CLOCK)
    path = tmp_path / "data" / "compliance" / "evidence.jsonl"
    with path.open("a", encoding="utf-8") as fh:
        fh.write("{not json}\n")
        fh.write(json.dumps({"unexpected": "shape"}) + "\n")
    records = load_recent(tmp_path)
    assert len(records) == 1
    assert records[0].control_id == "T-01"


@pytest.mark.security
def test_export_bundle_content_is_declared_and_bounded(tmp_path: Path) -> None:
    report = _report(tmp_path)
    dest = tmp_path / "reports" / "bundle.json"
    written = export_bundle(report, root=tmp_path, dest=dest)
    payload = json.loads(written.read_text(encoding="utf-8"))
    assert payload["disclaimer"].startswith("Automated posture evidence")
    assert {c["id"] for c in payload["controls"]} == {"T-01"}


@pytest.mark.security
def test_a_symlinked_evidence_file_cannot_redirect_the_write(tmp_path: Path) -> None:
    """The directory was confined; the file in it was not.

    ``_evidence_dir`` resolves ``data/compliance`` and refuses an escape, but
    ``evidence.jsonl`` itself was opened with a plain ``os.open``, which
    follows a symlink. Measured before the fix: a link planted at that name
    carried the whole append — 449 bytes of evidence lines — to a file
    outside the root, with no error. The check is explicit so the operator
    reads why, and the opener carries ``O_NOFOLLOW`` so the check cannot be
    raced between the ``lstat`` and the ``open``.
    """
    root = tmp_path / "root"
    (root / "data" / "compliance").mkdir(parents=True)
    outside = tmp_path / "outside.jsonl"
    outside.write_text("", encoding="utf-8")
    (root / "data" / "compliance" / "evidence.jsonl").symlink_to(outside)

    with pytest.raises(ValueError, match="symlink"):
        record_run(_report(root), root=root, clock=lambda: _CLOCK)

    assert outside.read_text(encoding="utf-8") == "", "the append followed the link"


@pytest.mark.security
def test_a_run_over_no_automated_controls_is_not_chained_as_a_pass(tmp_path: Path) -> None:
    """``0 == 0`` is the empty-conjunction shape, and the chain is what an
    auditor reads.

    Measured before the fix: a run whose registry held only manual controls
    chained ``decision=pass`` with the reason "0/0 automated controls passing".
    ``ComplianceReport.score`` already answers 0 for that report; the audit
    record disagreed with it.
    """
    manual = Control(
        id="T-02",
        title="Manual control",
        description="d",
        category=Category.POLICY,
        severity=Severity.LOW,
    )
    report = run_controls(tmp_path, clock=lambda: _CLOCK, controls=(manual,))
    assert len(report.automated) == 0 and report.score == 0

    record_run(report, root=tmp_path, clock=lambda: _CLOCK)

    chain = (tmp_path / "data" / "compliance" / "audit.log").read_text(encoding="utf-8")
    entry = json.loads(chain.splitlines()[-1])
    assert entry["decision"] == "attention", entry
    assert "0/0" in entry["reason"]


@pytest.mark.security
@pytest.mark.parametrize("name", ["audit.log", "audit.log.lock", ".audit.log.sig.tmp"])
@pytest.mark.parametrize("dangling", [False, True])
def test_a_link_beside_the_evidence_file_cannot_redirect_the_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, dangling: bool
) -> None:
    """The evidence file was guarded; the chain's own files beside it were not.

    Measured before the fix: a link at ``audit.log`` appended the run's chain
    record to any file — another chain included, which then verified intact —
    and a dangling one created its target; ``.audit.log.sig.tmp`` truncated its
    target when a signing key was set. Refused before anything is written.
    """
    monkeypatch.setenv("AUDIT_HMAC_KEY", secrets.token_hex(32))  # throwaway
    root = tmp_path / "root"
    (root / "data" / "compliance").mkdir(parents=True)
    outside = tmp_path / "outside"
    if not dangling:
        outside.write_text("kept\n", encoding="utf-8")
    (root / "data" / "compliance" / name).symlink_to(outside)

    with pytest.raises(ValueError, match="symlink"):
        record_run(_report(root), root=root, clock=lambda: _CLOCK)

    assert outside.exists() is not dangling, "a dangling link's target was created"
    assert dangling or outside.read_text(encoding="utf-8") == "kept\n"
    assert not (root / "data" / "compliance" / "evidence.jsonl").exists()


@pytest.mark.security
@pytest.mark.parametrize(("link", "inside"), [("data/compliance", True), ("data", False)])
def test_a_symlinked_evidence_directory_is_refused(tmp_path: Path, link: str, inside: bool) -> None:
    """Resolve-and-compare accepted a link back inside the root (into ``docs/``)."""
    root = tmp_path / "root"
    target = root / "docs" if inside else tmp_path / "elsewhere"
    (target / "compliance").mkdir(parents=True)
    (root / link).parent.mkdir(parents=True, exist_ok=True)
    (root / link).symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        record_run(_report(root), root=root, clock=lambda: _CLOCK)

    assert [p for p in target.rglob("*") if p.is_file()] == []


@pytest.mark.security
def test_a_directory_swapped_after_the_walk_cannot_carry_the_evidence_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reviewer's race, made deterministic: ``data/compliance`` swapped for
    a link out of the root after it was checked. Measured before the fix: the
    evidence landed outside before a later re-resolve raised. The append now
    goes through the walked descriptor, and the re-check refuses the chain."""
    root, outside = tmp_path / "root", tmp_path / "outside"
    (root / "data" / "compliance").mkdir(parents=True)
    outside.mkdir()
    real_open = os.open

    def swapping_open(
        path: str, flags: int, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> int:
        if path == "evidence.jsonl" and dir_fd is not None:
            monkeypatch.setattr(os, "open", real_open)
            (root / "data" / "compliance").rename(root / "data" / "moved")
            (root / "data" / "compliance").symlink_to(outside, target_is_directory=True)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", swapping_open)
    with pytest.raises(ValueError):
        record_run(_report(root), root=root, clock=lambda: _CLOCK)

    assert list(outside.iterdir()) == [], "a write followed the swapped directory"
    assert (root / "data" / "moved" / "evidence.jsonl").is_file()
