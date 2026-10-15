# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Boundary properties of the self-monitoring package.

A monitor is a privileged reader of everything the platform produces, and it
runs unattended on a schedule, so the three claims in :mod:`sli`'s docstring
are the ones worth pinning: it touches nothing outside the lab-data root, it
creates nothing inside it, and it has no ambient authority — no clock, no
network, no subprocess.

Each is asserted **at runtime** as well as by reading the source. An
AST-only version of this file would be evadable by name and by attribute
call, which is a finding already recorded against the equivalent tests in
``tests/security/test_ingest_hardening.py``; the runtime probes are what
carry the weight here, and the AST scan is the cheap second opinion.
"""

from __future__ import annotations

import ast
import builtins
import contextlib
import io
import os
import time
from pathlib import Path
from typing import Any

import pytest

from compliance.controls import check_self_monitoring_defined
from compliance.engine import run_controls
from sli import CHAIN_FILES, measure
from tests.security.test_cli_startup_failclosed import RELATIVE_ROOTS

_SLI_ROOT = Path(__file__).resolve().parents[2] / "sli"

_AUDITD = "type=SYSCALL msg=audit(1760000001.200:2): node=web-01 auid=svc-deploy comm=bash"

#: Modules that would give this package authority it must not have. ``os`` and
#: ``pathlib`` are absent from the list deliberately: reading state under the
#: root is the whole job, and the constraint on *where* it reads is asserted
#: at runtime below rather than by banning the module that reads.
_BANNED_IMPORTS = {
    "subprocess",
    "socket",
    "requests",
    "httpx",
    "urllib",
    "shutil",
    "pickle",
    "marshal",
    "ctypes",
    "importlib",
    "time",
    "datetime",
}
_BANNED_CALLS = {"eval", "exec", "compile", "__import__", "input"}


def _sli_modules() -> list[Path]:
    modules = sorted(_SLI_ROOT.rglob("*.py"))
    assert modules, "no sli modules found; this file would assert nothing"
    return modules


def _root(tmp_path: Path) -> Path:
    """A lab root under ``tmp_path``, which may itself not exist yet.

    ``parents=True`` because two tests build *two* roots under subdirectories
    of ``tmp_path`` to compare a bare tree against a populated one.
    """
    root = tmp_path / "lab"
    root.mkdir(parents=True)
    return root


def _collected(tmp_path: Path) -> Path:
    """A root with a store, a cursor, offsets and audit chains in it."""
    from scripts.run_collector import main as collect_main
    from scripts.run_pipeline import main as pipeline_main

    root = _root(tmp_path)
    log = tmp_path / "app.log"
    log.write_text(f"{_AUDITD}\n", encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        assert collect_main(["--root", str(root), "--source", str(log)]) == 0
        assert pipeline_main(["--root", str(root)]) == 0
    return root


def _tree(directory: Path) -> set[Path]:
    return {path.relative_to(directory) for path in directory.rglob("*")}


# ------------------------------------------------------- no ambient authority


@pytest.mark.security
def test_sli_imports_nothing_that_could_reach_out_or_read_a_clock() -> None:
    """``now`` is a parameter, so the package has no clock of its own.

    That is not tidiness: a measurement whose clock is a parameter can be
    placed anywhere by a test, which is how the "event stamped in the future"
    and "cursor ahead of the store" traps in ``tests/unit/test_sli.py`` are
    reachable at all.
    """
    for path in _sli_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in _BANNED_IMPORTS, (
                        f"{path.name}: imports {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in _BANNED_IMPORTS, (
                    f"{path.name}: imports from {node.module}"
                )
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in _BANNED_CALLS, f"{path.name}: calls {node.func.id}()"


@pytest.mark.security
def test_a_measurement_runs_with_the_clock_taken_away(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The load-bearing version of the test above, and it is not evadable.

    An AST scan can be defeated by an attribute call on a module imported for
    another reason, or by a name the list does not hold — a finding already
    recorded against the equivalent ingest tests. Breaking the clock and
    requiring the measurement to complete anyway cannot be defeated that way.
    """
    root = _collected(tmp_path)
    measure(root, now=1_760_000_000.0)  # warm every lazy import before patching

    def refuse(*args: object, **kwargs: object) -> float:
        raise AssertionError("sli read the clock")

    monkeypatch.setattr(time, "time", refuse)
    monkeypatch.setattr(time, "monotonic", refuse)
    monkeypatch.setattr(time, "time_ns", refuse)

    report = measure(root, now=1_760_000_000.0)
    assert report.measured_at == 1_760_000_000.0
    assert len(report.indicators) == 7


# ------------------------------------------------------ nothing outside the root


@pytest.mark.security
def test_a_measurement_opens_and_stats_nothing_outside_the_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§5 licenses reaching outside the project for ``collect/`` and nothing else.

    The obvious way to measure collection backlog is to compare each declared
    source's recorded offset against the file's current size, which means
    stat'ing log paths wherever the operator's logs live. §5's filesystem
    amendment grants that reach to ``collect/`` specifically — declared,
    absolute, read-only, no symlink — and extending it to a new package would
    be a charter amendment rather than an implementation detail.

    It is not needed: ``Position`` already records the ``size`` the collector
    itself observed, so the backlog comes from a file under ``data/``. This
    test is what makes that a property rather than a present-tense fact about
    the code — and the declared source here is outside the root, so a probe
    that reached for it would be caught.
    """
    root = _collected(tmp_path)
    log_outside = tmp_path / "app.log"
    assert log_outside.is_file() and not log_outside.is_relative_to(root), (
        "the declared source must sit outside the root or this test is toothless"
    )
    measure(root, now=1_760_000_000.0)  # warm lazy imports

    seen: list[str] = []
    real_open, real_stat, real_lstat = builtins.open, os.stat, os.lstat
    real_scandir = os.scandir

    def record(fn: Any, label: str) -> Any:
        def wrapper(path: Any, *args: Any, **kwargs: Any) -> Any:
            with contextlib.suppress(TypeError, ValueError):
                seen.append(f"{label}:{os.fspath(path)}")
            return fn(path, *args, **kwargs)

        return wrapper

    monkeypatch.setattr(builtins, "open", record(real_open, "open"))
    monkeypatch.setattr(os, "stat", record(real_stat, "stat"))
    monkeypatch.setattr(os, "lstat", record(real_lstat, "lstat"))
    monkeypatch.setattr(os, "scandir", record(real_scandir, "scandir"))

    measure(root, now=1_760_000_000.0)

    monkeypatch.undo()
    assert seen, "nothing was recorded; the probe did not intercept anything"

    # The root's own ancestors are allowed, and the allowance is narrow rather
    # than convenient: ``Path.resolve()`` lstats every component on the way to
    # a path, so resolving the root at all records ``/`` and each directory
    # above it. Those are the only paths excluded. A declared log source — the
    # thing §5's amendment is about, and the one this fixture puts outside the
    # root on purpose — is not an ancestor of the root, so a probe reaching
    # for it is still caught. Measured: without this exclusion the test fails
    # on ``/tmp`` and the pytest temp directories.
    allowed = {root.resolve(), *root.resolve().parents}
    outside = sorted(
        {
            entry
            for entry in seen
            if (resolved := Path(entry.split(":", 1)[1]).resolve()) not in allowed
            and not resolved.is_relative_to(root.resolve())
        }
    )
    assert not outside, f"a measurement reached outside the lab-data root: {outside[:6]}"
    assert str(log_outside) not in " ".join(seen), (
        "the declared source lives outside the root and was touched"
    )


@pytest.mark.security
def test_a_measurement_creates_nothing(tmp_path: Path) -> None:
    """``EventStore.open`` creates the database, which a monitor must not.

    Correct for a collector and wrong for a measurement: combined with the
    ``--root`` spellings below, a monitor that initialised what it measures
    would build a shadow tree in the working directory and then report it.
    So the store's existence is checked before it is opened, and this asserts
    the artifact snapshot is unchanged — on a bare root *and* on a populated
    one, because a probe that creates a lock, a journal or a WAL sidecar on a
    root that already has a store is the same defect one layer in.
    """
    bare = _root(tmp_path / "bare")
    before = _tree(bare)
    measure(bare, now=1_760_000_000.0)
    assert _tree(bare) == before, f"created {sorted(_tree(bare) - before)}"

    populated = _collected(tmp_path / "full")
    before = _tree(populated)
    measure(populated, now=1_760_000_000.0)
    assert _tree(populated) == before, f"created {sorted(_tree(populated) - before)}"


@pytest.mark.security
def test_the_cli_appends_to_no_audit_chain(tmp_path: Path) -> None:
    """Every other scheduled CLI records its run; this one deliberately does not.

    At the documented ``*/5`` cadence it would write more chain entries than
    everything else combined, and ``audit-chains-intact`` is one of the
    objectives it measures — a monitor whose own writes dominate what it
    monitors is measuring itself. Nothing is mutated, so there is no state
    change for a chain to be evidence of.
    """
    from scripts.report_sli import main

    root = _collected(tmp_path)
    before = {
        relative: (root / relative).read_bytes()
        for relative in CHAIN_FILES
        if (root / relative).is_file()
    }
    assert before, "no chain exists, so this test would assert nothing"

    with contextlib.redirect_stdout(io.StringIO()):
        main(["--root", str(root), "--caller", "soc-test"])

    after = {
        relative: (root / relative).read_bytes()
        for relative in CHAIN_FILES
        if (root / relative).is_file()
    }
    assert after == before, "the SLI report appended to an audit chain"


# ----------------------------------------------------------- fail-closed roots


@pytest.mark.security
@pytest.mark.parametrize("relative", RELATIVE_ROOTS)
def test_the_cli_refuses_a_relative_root(relative: str, tmp_path: Path) -> None:
    """``--root ""`` built a shadow SOC in three of four CLIs; a fifth must not.

    The spellings come from ``test_cli_startup_failclosed.py`` rather than
    being retyped, so the two cannot drift. This CLI is correctly absent from
    that file's ``CLIS`` table — that table's rows carry a lock path and this
    CLI takes no lock, and its completeness assertion is keyed on
    ``_single_instance``, which this CLI does not define.
    """
    from scripts.report_sli import main

    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        code = main(["--root", relative, "--caller", "soc-test"])
    assert code == 2, f"{relative!r} was accepted"
    assert "absolute" in err.getvalue() or "filesystem root" in err.getvalue()


@pytest.mark.security
def test_a_degraded_platform_exits_non_zero(tmp_path: Path) -> None:
    """A monitor that exits 0 on a signal it could not read is the whole defect.

    The opposite choice from ``run_pipeline.py``, which exits ``0`` for
    "nothing new" because a quiet SOC is the common case. Here the common case
    is healthy, so the exception is the thing worth waking someone for.
    """
    from scripts.report_sli import main

    root = _root(tmp_path)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(["--root", str(root), "--caller", "soc-test"])
    assert code == 1
    assert "DEGRADED" in out.getvalue()
    assert "unmeasurable" in out.getvalue()


# -------------------------------------------------------------- the chains


@pytest.mark.security
def test_a_tampered_chain_is_reported_broken(tmp_path: Path) -> None:
    """And the fraction drops, so ``audit-chains-intact`` cannot stay at 1.0."""
    root = _collected(tmp_path)
    present = [relative for relative in CHAIN_FILES if (root / relative).is_file()]
    assert present, "no chain to tamper with"

    report = measure(root, now=1_760_000_000.0)
    before = next(i for i in report.indicators if i.objective.id == "audit-chains-intact")
    assert before.value == 1.0, before.detail

    # Verified to land, because a tamper that does not is indistinguishable
    # from a test that works — the first version of this replaced ``soc-``,
    # which the chain's own ``actor`` field does not contain in this fixture,
    # and the indicator stayed at 1.0 for the right reason.
    target = root / present[0]
    original = target.read_text(encoding="utf-8")
    lines = original.splitlines()
    lines[0] = lines[0].replace('"decision": "allow"', '"decision": "deny"')
    tampered = "\n".join(lines) + "\n"
    assert tampered != original, "the tamper did not change the chain"
    target.write_text(tampered, encoding="utf-8")

    report = measure(root, now=1_760_000_000.0)
    after = next(i for i in report.indicators if i.objective.id == "audit-chains-intact")
    assert after.value is not None and after.value < 1.0, after.detail
    assert after.status.healthy is False


@pytest.mark.security
def test_a_missing_chain_is_never_reported_intact(tmp_path: Path) -> None:
    """The contract ``audit_verify`` states, and the one place that forgot it.

    ``scripts/audit_maintenance.py`` treated an absent chain as a valid empty
    chain and printed ``{"verified": true}`` at exit ``0`` — the only job in
    the platform that *deletes* evidence. So: with no chain anywhere, the
    indicator is unmeasurable rather than perfect.
    """
    root = _root(tmp_path)
    report = measure(root, now=1_760_000_000.0)
    chains = next(i for i in report.indicators if i.objective.id == "audit-chains-intact")
    assert chains.value is None, chains.detail
    assert chains.status.healthy is False


# ------------------------------------------------------------- the controls


@pytest.mark.security
def test_the_operational_control_is_manual_and_names_the_cli() -> None:
    """``AUD-03`` is an expiring attestation, and the reason is worth pinning.

    It was written as an automated check first, and the check could not pass
    anywhere the control suite actually runs: the objectives measure a
    *running* platform and a repository checkout is not one, so
    ``test_live_repository_passes_every_automated_control`` went red and the
    published trust snapshot would have carried its first ``fail`` — one that
    misreports "this is a checkout, not a deployment" as a security failure.
    A control that can never pass is a control people learn to ignore.

    So it is manual, with the same reasoning ``MAN-03`` gives for corpus
    freshness, and the hint must name the CLI that produces the evidence —
    otherwise the attestation is a signature over nothing.
    """
    from compliance.controls import registry

    control = next(c for c in registry() if c.id == "AUD-03")
    assert control.automated is False
    assert control.attestation_hint, "a manual control with no hint is unattestable"
    assert "report_sli.py" in control.attestation_hint
    assert "--root" in control.attestation_hint


@pytest.mark.security
def test_the_definitional_control_passes_on_the_committed_table() -> None:
    """``AUD-02`` is structural, so it must pass wherever the code is checked out."""
    from compliance.controls import ControlStatus

    result = check_self_monitoring_defined(Path("/nonexistent"))
    assert result.status is ControlStatus.PASS
    assert "unmeasurable indicator is not a pass" in result.detail


@pytest.mark.security
def test_the_diagnostic_names_the_stalled_source_and_compliance_does_not_read_it(
    tmp_path: Path,
) -> None:
    """Two halves of one boundary, and the second is a guard rather than a check.

    A declared log source is an internal path, which §5 treats as sensitive by
    default, and ``compliance/controls.py`` promises its details carry
    "relative paths and counts only — never file contents, environment
    values, or secrets". The indicator detail names the source **on purpose**:
    that is the diagnostic that tells an operator which source stalled, and it
    is read locally.

    The first assertion is live — remove the name from the detail and this
    fails. The second is a guard: with ``AUD-03`` manual, no control reads a
    measurement at all, so "no detail names a source" is currently true for a
    structural reason rather than a filtering one. Saying so is the point —
    and the structural reason is what the third assertion pins, because a
    future control that wants the live verdict must summarise ids and numbers
    rather than forwarding the diagnostic. Measured while the check *was*
    automated: forwarding the details put ``acme-prod-db01-internal.log`` into
    the compliance report.
    """
    from collect import Position, offsets_path, save_offsets

    root = _root(tmp_path)
    secret_name = "acme-prod-db01-internal.log"
    save_offsets(
        offsets_path(root),
        {f"/var/log/{secret_name}": Position(offset=1, inode=1, device=1, size=9_000_000)},
    )

    indicator_details = " ".join(
        item.detail for item in measure(root, now=1_760_000_000.0).indicators
    )
    assert secret_name in indicator_details, "the diagnostic no longer names the stalled source"

    details = " ".join(result.detail for result in run_controls(root).results)
    assert secret_name not in details, "a declared log source reached the compliance evidence"
    assert "/var/log" not in details

    # The structural reason, asserted rather than assumed: the compliance layer
    # imports the SLI *definition* (AUD-02 reads the objective table) and must
    # not call a measurement.
    controls_source = Path(__file__).resolve().parents[2] / "compliance" / "controls.py"
    tree = ast.parse(controls_source.read_text(encoding="utf-8"), filename=str(controls_source))
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "measure" not in called, (
        "a control calls sli.measure; its detail must summarise ids and numbers, "
        "never the indicator text, which names declared log sources"
    )
