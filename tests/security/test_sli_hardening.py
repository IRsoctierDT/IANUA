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
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from compliance.controls import check_self_monitoring_defined
from compliance.engine import run_controls
from ingest import normalize
from pipeline import Cursor, cursor_path, save_cursor
from sli import CHAIN_FILES, OBJECTIVES, Indicator, Status, measure
from sli.indicators import READABILITY_SAMPLE
from store import SIDECAR_SUFFIXES, EventStore, Query, StoreCorruptionError, canonical_json
from store.schema import VERSION_KEY
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
    assert len(report.indicators) == len(OBJECTIVES), "a probe was lost with the clock taken away"


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
def test_an_aborted_copy_cannot_produce_a_healthy_report(tmp_path: Path) -> None:
    """A 0-byte store opens as a valid, attestable, EMPTY one — measured.

    This is what an interrupted copy leaves behind, and every *local* signal
    says it is fine:

        destination size : 0 bytes
        EventStore.open  : SUCCEEDED (it creates the schema)
        count()          : 0
        high_water_mark(): None
        attest()         : events=0 observables=0, digest 0f2795bd…
        integrity_check  : ok

    So an aborted copy is indistinguishable from a healthy fresh deployment
    unless something compares against an **expected** attestation — which
    ``scripts/run_backup.py``'s manifest does, and a bare ``cp`` or a future
    replication loop does not.

    The compensating control on this side is that the SLI report must not call
    such a store healthy. It does not, and the reason is the three-state
    grading rather than anything about backups: ``ingest-freshness`` returns
    ``UNKNOWN`` for a store that holds no events, and ``UNKNOWN`` is not a
    pass. Pinned here because that is the property, and because
    ``path.is_file()`` — which is how the SLI package avoids *creating* a
    store — is satisfied by a 0-byte file and so cannot be what catches this.
    """
    root = _root(tmp_path)
    (root / "data" / "events").mkdir(parents=True)
    aborted = root / "data" / "events" / "events.sqlite3"
    aborted.touch()
    assert aborted.stat().st_size == 0, "the fixture is not the aborted-copy shape"

    report = measure(root, now=1_760_000_000.0)
    assert report.healthy is False, "an aborted copy reported a healthy platform"

    by_id = {item.objective.id: item for item in report.indicators}
    freshness = by_id["ingest-freshness"]
    assert freshness.status is Status.UNKNOWN, freshness.detail
    assert "no events" in freshness.detail

    # And the empty store really did open and read cleanly, so the verdict
    # rests on the grading rather than on the probe failing.
    assert by_id["store-readable"].value == 1.0, by_id["store-readable"].detail


@pytest.mark.security
def test_every_cursor_reading_indicator_refuses_a_cursor_ahead_of_the_store(
    tmp_path: Path,
) -> None:
    """The cursor-sensitive indicators are *discovered*, so a third one is covered.

    Naming them would pin the two that exist. The fix this guards came from
    finding that ``detection-backlog`` failed open in a state
    ``detection-lag`` already refused, and a list of names is exactly the
    artifact that would have let the next indicator repeat it. So the set is
    derived by differential — measure the same root twice, once with the
    cursor the cycle wrote and once with it a day ahead of the newest stored
    row, and take the indicators whose reading moved.

    The property asserted of that set is the one that matters: a cursor past
    the store's high-water mark is the one unrecoverable skew
    ``docs/RESTORE.md`` records, so an indicator that *notices* it and still
    grades ``MET`` is reporting an unrecoverable platform as healthy.

    Non-vacuity is asserted in three places, because each of them has been
    the way a test like this measured nothing: the control readings must be
    ``MET`` (or "not MET afterwards" is free), the discovered set must contain
    the two known members (or an empty set passes the loop), and the detail
    text must change (or the two states stay indistinguishable to the operator
    reading the report, which is how this defect survived its first test).
    """
    root = _collected(tmp_path)
    with EventStore.open(root) as store:
        mark = store.high_water_mark()
    assert mark is not None, "the fixture stored no events"
    now = mark + 1.0

    def readings() -> dict[str, tuple[Status, float | None, str]]:
        return {
            item.objective.id: (item.status, item.value, item.detail)
            for item in measure(root, now=now).indicators
        }

    control = readings()
    assert control["detection-lag"][0] is Status.MET, control["detection-lag"]
    assert control["detection-backlog"][0] is Status.MET, control["detection-backlog"]

    save_cursor(cursor_path(root), Cursor(ingested_at=mark + 86_400.0, event_id="z" * 64))
    skewed = readings()

    sensitive = {name for name, reading in control.items() if reading != skewed[name]}
    assert {"detection-lag", "detection-backlog"} <= sensitive, (
        f"an indicator stopped reading the cursor; discovered {sorted(sensitive)}"
    )
    for name in sorted(sensitive):
        assert skewed[name][0] is not Status.MET, (
            f"{name} graded {skewed[name][0].value} with the cursor a day ahead "
            f"of the store: {skewed[name][2]}"
        )
        assert skewed[name][2] != control[name][2], (
            f"{name} prints the same sentence caught up and skewed"
        )


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
def test_the_attestation_does_not_rest_on_the_exit_code() -> None:
    """The hint used to nominate an exit code that an emptied store satisfies.

    ``AUD-03`` is HIGH severity and manual, so its ``attestation_hint`` *is*
    the procedure — and for an unattested manual control the hint becomes the
    evidence ``detail`` verbatim (measured: equal, 235 characters as shipped),
    so every word of it lands in ``data/compliance/evidence.jsonl``.

    It said "Exit 0 means every objective is met ... Attest with that output
    as evidence". Measured on a node with a real collector pass, a real cycle
    and a real backup: ``report_sli.py --json`` read exit 0, ``healthy: true``
    and ``met=8`` **both before and after a prune removed 24 of 24 events**,
    with the status map byte-identical. So an operator following the control
    as written files a passing HIGH-severity SLO attestation for a node whose
    evidence base has just been destroyed.

    The indicator set is **not** what is wrong here, and the hint must not
    imply it is: ``sli/indicators.py`` states that an emptied store beneath a
    live cursor reads ``met`` and should, and
    ``test_a_retention_pass_that_empties_the_store_still_measures_met`` pins
    it. What *does* move across a prune is detail rather than status —
    measured, ``store-readable`` went from "read 24 newest and 24 oldest
    row(s) without error" to "read 0 newest and 0 oldest row(s) without
    error" while its status stayed ``met`` — and that reading is already in
    the JSON the attester runs, needing no backup directory. A second backup
    manifest corroborates it, but only where backups exist, which the same
    report may be reporting as breached.
    """
    from compliance.controls import registry

    hint = next(c for c in registry() if c.id == "AUD-03").attestation_hint

    # The exit code must not be offered as the thing attested to.
    assert "Attest with that output as evidence" not in hint
    assert "Exit 0 means" not in hint
    assert "per-indicator" in hint

    # The reading that actually moves when the evidence does. `detection-backlog`
    # is deliberately NOT required here: measured on a caught-up node it read 0
    # both before and after the same total prune, so naming it as the signal was
    # useless exactly where this control is needed.
    assert "store-readable" in hint

    # And it must not read as "the indicator set is broken".
    assert "sli/indicators.py" in hint

    # THE DECISION, which is the part that makes this a procedure rather than a
    # note. Review caught the first version of this fix without it: a hint that
    # only says *record* leaves the operator no rule for when to *withhold*, and
    # nothing downstream supplies one — `attestations._FIELDS` makes `note` free
    # text and `compliance.engine` marks any current attestation `ATTESTED`
    # whatever it says, so an operator could follow the hint exactly and still
    # file the passing attestation this control exists to prevent.
    assert "DO NOT ATTEST" in hint, "the hint must say when to withhold, not only what to record"
    assert "account for the drop" in hint


@pytest.mark.security
def test_nothing_downstream_enforces_the_withholding_rule() -> None:
    """Pinned because the control's own description now claims exactly this.

    It would be easy to read "do not attest" as something the engine checks. It
    is not: the attestation schema fixes its field set, so the figures live in
    free-text ``note``, and a current attestation grades ``ATTESTED`` on dates
    alone. The enforcement is review of the committed ``attestations.json``.

    Asserting it keeps the description honest in both directions — if a future
    change *does* make the engine refuse an unreconciled zero-row attestation,
    this test fails and the description has to be rewritten rather than left
    understating a control that now exists.
    """
    from compliance.attestations import _FIELDS
    from compliance.controls import registry

    assert "note" in _FIELDS, "the figures have nowhere else to go"
    engine_source = (Path(__file__).resolve().parents[2] / "compliance" / "engine.py").read_text(
        encoding="utf-8"
    )
    assert "store-readable" not in engine_source, (
        "the engine now reads an indicator; AUD-03's description says it does not"
    )
    description = next(c for c in registry() if c.id == "AUD-03").description
    assert "Nothing enforces that rule" in description


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


@pytest.mark.security
def test_a_symlinked_backup_is_neither_counted_nor_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``backup-present`` reached outside the root through a planted link.

    Measured before the fix: ``data/backups/linked -> <directory outside the
    root>`` holding a ``manifest.json`` graded ``1.0`` — a backup that is not
    this node's — and the probe ``stat``ed the manifest on the far side, the
    one reach :mod:`sli` promises never to make. ``scripts/run_backup.py``
    confines the directory it writes with the same symlink walk the store and
    the cursor use, so a link here was planted, not written. Two cases: a
    linked entry is skipped before anything beyond it is touched, and a link
    at ``data/backups`` itself is ``UNKNOWN`` with the reason.

    The tracer labels any ``follow_symlinks=False`` call ``lstat``: on 3.12
    ``Path.is_symlink`` reaches ``os.stat`` that way, and an ``lstat`` of the
    link *is* inside the root even though resolving the link is not.
    """
    from sli.indicators import BACKUP_SUBDIR, MANIFEST_FILE, measure_backup_present

    root = _root(tmp_path)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / MANIFEST_FILE).write_text("{}", encoding="utf-8")
    (root / BACKUP_SUBDIR).mkdir(parents=True)
    (root / BACKUP_SUBDIR / "linked").symlink_to(outside)

    seen: list[str] = []
    real_open, real_stat, real_scandir = builtins.open, os.stat, os.scandir
    real_lstat = os.lstat

    def record(fn: Any, label: str) -> Any:
        def wrapper(path: Any, *args: Any, **kwargs: Any) -> Any:
            tag = "lstat" if kwargs.get("follow_symlinks", True) is False else label
            with contextlib.suppress(TypeError, ValueError):
                seen.append(f"{tag}:{os.fspath(path)}")
            return fn(path, *args, **kwargs)

        return wrapper

    monkeypatch.setattr(builtins, "open", record(real_open, "open"))
    monkeypatch.setattr(os, "stat", record(real_stat, "stat"))
    monkeypatch.setattr(os, "lstat", record(real_lstat, "lstat"))
    monkeypatch.setattr(os, "scandir", record(real_scandir, "scandir"))
    measurement = measure_backup_present(root, now=1_760_000_000.0)
    monkeypatch.undo()

    assert measurement.value == 0.0, measurement.detail
    assert "no backup manifest" in measurement.detail
    allowed = {root.resolve(), *root.resolve().parents}
    reached = sorted(
        {
            entry
            for entry in seen
            if not entry.startswith("lstat:")
            and (resolved := Path(entry.split(":", 1)[1]).resolve()) not in allowed
            and not resolved.is_relative_to(root.resolve())
        }
    )
    assert not reached, f"the probe reached beyond the root through the link: {reached[:4]}"

    elsewhere = tmp_path / "backups-elsewhere"
    (elsewhere / "b1").mkdir(parents=True)
    (elsewhere / "b1" / MANIFEST_FILE).write_text("{}", encoding="utf-8")
    linked_root = tmp_path / "lab2"
    (linked_root / "data").mkdir(parents=True)
    (linked_root / BACKUP_SUBDIR).symlink_to(elsewhere)
    measurement = measure_backup_present(linked_root, now=1_760_000_000.0)
    assert measurement.value is None, measurement.detail
    assert "symlink" in measurement.detail


@pytest.mark.security
def test_a_backup_entry_swapped_for_a_link_mid_probe_is_neither_counted_nor_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fix above checked each entry by path and then ``stat``ed it by path.

    Measured against it: a thread flipping ``data/backups/victim`` between an
    empty directory and a link to an outside directory holding a manifest made
    the probe count that manifest 510 times in 29,581 probes, and follow-stat
    the far side. The walk is now by descriptor with ``O_NOFOLLOW``, so the far
    side is unreachable rather than unlikely: a count, or any ``open``/``stat``
    whose result is the outside inode, fails here. One-directional by design —
    a correct probe cannot trip it however the threads interleave.
    """
    import threading

    from sli.indicators import BACKUP_SUBDIR, MANIFEST_FILE, measure_backup_present

    root = _root(tmp_path)
    backups = root / BACKUP_SUBDIR
    (backups / "victim").mkdir(parents=True)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / MANIFEST_FILE).write_text("{}", encoding="utf-8")
    far = {(st.st_dev, st.st_ino) for st in (outside.stat(), (outside / MANIFEST_FILE).stat())}
    reached: list[str] = []
    real_stat, real_open = os.stat, os.open

    def stat_spy(path: Any, *args: Any, **kwargs: Any) -> Any:
        result = real_stat(path, *args, **kwargs)
        if (result.st_dev, result.st_ino) in far:
            reached.append(f"stat:{path}")
        return result

    def open_spy(path: Any, *args: Any, **kwargs: Any) -> int:
        fd = real_open(path, *args, **kwargs)
        if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) in far:
            reached.append(f"open:{path}")
        return fd

    stop = threading.Event()

    def flip() -> None:
        victim, spare = backups / "victim", backups / ".spare"
        while not stop.is_set():
            with contextlib.suppress(OSError):
                victim.rename(spare)
                victim.symlink_to(outside)
                victim.unlink()
                spare.rename(victim)

    monkeypatch.setattr(os, "stat", stat_spy)
    monkeypatch.setattr(os, "open", open_spy)
    flipper = threading.Thread(target=flip, daemon=True)
    flipper.start()
    try:
        values = [measure_backup_present(root, now=1_760_000_000.0).value for _ in range(3000)]
    finally:
        stop.set()
        flipper.join()
    monkeypatch.undo()

    assert 1.0 not in values, f"counted the far side's manifest {values.count(1.0)} times"
    assert not reached, f"the probe reached beyond the root: {reached[:4]}"


# ------------------------------------------------ a refused open is not damage

_RECORD = 'type=USER_AUTH msg=audit(1760000000.1:1): acct="svc-%d" addr=203.0.113.9 res=failed'
_STORE = Path("data") / "events" / "events.sqlite3"
_REPO_ROOT = Path(__file__).resolve().parents[2]
#: ``store-intact``'s damage sentence and the refusal sentence both store
#: measurers use. Matched as phrases rather than bare words, so no temporary
#: path can satisfy or defeat an assertion by containing one.
_DAMAGED = "database is damaged"
_REFUSED = "the store could not be opened"
#: Generous for a loaded runner. What it bounds is a hang, not a slow run.
_CLI_TIMEOUT = 60.0


def _stored(tmp_path: Path) -> Path:
    """A root holding a closed 12-event store and nothing else, so no sidecar is left."""
    root = _root(tmp_path)
    now = time.time() - 3600
    with EventStore.open(root) as store:
        for index in range(12):
            store.append(normalize(_RECORD % index), ingested_at=store.next_stamp(now + index))
    return root


def _store_objectives(root: Path) -> dict[str, Indicator]:
    """The two store objectives from one full measurement, by id."""
    report = measure(root, now=time.time())
    return {
        item.objective.id: item
        for item in report.indicators
        if item.objective.id in ("store-intact", "store-readable")
    }


def _symlinked_data(root: Path, tmp_path: Path) -> None:
    outside = tmp_path / "elsewhere"
    shutil.move(root / "data", outside)
    (root / "data").symlink_to(outside, target_is_directory=True)


def _hardlinked_shm(root: Path, tmp_path: Path) -> None:
    # In-process is safe here: the sidecar check refuses before ``connect``, and
    # the FIFO case, which would hang if that regressed, runs in a subprocess below.
    victim = tmp_path / "victim.bin"
    victim.write_bytes(b"\x01" * 4096)
    os.link(victim, (root / _STORE).with_name(_STORE.name + "-shm"))


def _rewrite_meta(sql: str, *params: str) -> Callable[[Path, Path], None]:
    def plant(root: Path, _tmp_path: Path) -> None:
        conn = sqlite3.connect(root / _STORE)
        try:
            with conn:
                conn.execute(sql, params)
        finally:
            conn.close()

    return plant


#: Each refusal ``EventStore.open`` makes without judging a page: the plant,
#: the class it raises, and a fragment of the store's own reason, which the
#: detail must carry because it is what tells an operator what to do instead.
_REFUSALS: dict[str, tuple[Callable[[Path, Path], None], str, str]] = {
    "symlinked-data": (_symlinked_data, "StorePathError", "is a symlink"),
    "hardlinked-shm": (
        _hardlinked_shm,
        "StoreSidecarError",
        "-shm beside it that has 2 hard links",
    ),
    "schema-version": (
        _rewrite_meta("UPDATE meta SET value = ? WHERE key = ?", "999", VERSION_KEY),
        "SchemaVersionError",
        "schema version 999",
    ),
    "version-row-removed": (
        _rewrite_meta("DELETE FROM meta WHERE key = ?", VERSION_KEY),
        "SchemaVersionError",
        "no recorded schema version",
    ),
    # The removed row's sibling: rewritten, with bytes that are not UTF-8. The
    # store refuses it as a row written outside the platform, and it read
    # "damaged" here until the damage verdict became the corruption class alone.
    "version-row-not-utf8": (
        _rewrite_meta(
            "UPDATE meta SET value = CAST(x'504c414e544544ff' AS TEXT) WHERE key = ?",
            VERSION_KEY,
        ),
        "StoreIntegrityError",
        "is not valid UTF-8",
    ),
}


@pytest.mark.security
@pytest.mark.parametrize("refusal", sorted(_REFUSALS))
def test_a_refused_open_is_unmeasured_on_both_store_objectives(
    tmp_path: Path, refusal: str
) -> None:
    """A store that will not open is ``UNKNOWN`` with its reason, never "damaged".

    Measured before the open was classified: every one of these read
    ``store-intact: breached`` with "the store's database is damaged", and
    ``store-readable: breached`` with "the store cannot be read". None of them is
    damage — the path and sidecar refusals come before SQLite reads a byte, a
    schema refusal reads a sound file of another version, and a tampered
    version row is a row to investigate — while "damaged" sends an operator to
    restore from a backup, which replaces the SOC's memory with an older copy.
    Still not a pass: ``UNKNOWN`` is unhealthy, so the CLI must still exit
    ``1``, and that is asserted rather than assumed.
    """
    from scripts.report_sli import main

    plant, raised, reason = _REFUSALS[refusal]
    root = _stored(tmp_path)
    plant(root, tmp_path)

    by_id = _store_objectives(root)

    for objective in ("store-intact", "store-readable"):
        indicator = by_id[objective]
        assert indicator.status is Status.UNKNOWN, indicator.summary()
        assert indicator.value is None
        assert indicator.detail.startswith(_REFUSED), indicator.detail
        assert f"{raised}: " in indicator.detail, indicator.detail
        assert reason in indicator.detail, indicator.detail
        assert _DAMAGED not in indicator.detail, indicator.detail
        assert "PLANTED" not in indicator.detail, "a refusal quoted the planted bytes"

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(["--root", str(root), "--caller", "soc-test"])
    assert code == 1, out.getvalue()
    assert "DEGRADED" in out.getvalue()


def _report_json(root: Path) -> tuple[int, dict[str, Any]]:
    """``scripts/report_sli.py --json`` as a scheduler runs it: a subprocess with a timeout.

    A subprocess because the case it serves plants a FIFO, and what a FIFO
    ``-journal`` did before ``EventStore.open`` refused it was hang inside
    SQLite's open, where ``SIGALRM`` does not reach (``test_store_sidecars.py``).
    In-process, a regression there would hang the suite rather than fail it.
    """
    try:
        result = subprocess.run(  # noqa: S603 - fixed interpreter, literal argv, test paths
            [
                sys.executable,
                "scripts/report_sli.py",
                "--root",
                str(root),
                "--caller",
                "soc-test",
                "--json",
            ],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=_CLI_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("report_sli.py blocked on the store instead of reporting it")
    assert result.stdout.strip(), result.stderr[-600:]
    return result.returncode, json.loads(result.stdout)


@pytest.mark.security
def test_a_fifo_journal_reads_unknown_not_damaged_and_still_exits_1(tmp_path: Path) -> None:
    """The case that surfaced this: since #257 a FIFO ``-journal`` is refused, not hung on.

    The refusal was right and the reporter mislabelled it — "the store's
    database is damaged: ... has a -journal beside it that is not a regular file
    (a FIFO)". The detail named the real cause while the label pointed at the
    restore branch, over a database nothing had touched. Asserted through the
    CLI's JSON because that is what a scheduler records, and with the exit code
    because ``UNKNOWN`` must still page someone.
    """
    root = _stored(tmp_path)
    database = root / _STORE
    journal = database.with_name(database.name + "-journal")
    os.mkfifo(journal, 0o600)
    before = database.read_bytes()

    code, report = _report_json(root)

    assert code == 1, report
    assert report["healthy"] is False
    by_id = {item["id"]: item for item in report["indicators"]}
    for objective in ("store-intact", "store-readable"):
        item = by_id[objective]
        assert item["status"] == Status.UNKNOWN.value, item
        assert item["value"] is None, item
        detail = item["detail"]
        assert detail.startswith(_REFUSED), detail
        assert "StoreSidecarError: " in detail, detail
        assert "-journal" in detail and "(a FIFO)" in detail, detail
        assert _DAMAGED not in detail, detail
    # Read-only in both directions: the FIFO was not consumed, the database not touched.
    assert journal.is_fifo()
    assert database.read_bytes() == before


def _damage_first_met_at(root: Path) -> str | None:
    """Where a store measurement first meets damage, asked of the store directly.

    The calls the two store measurers make, in this order: ``open``, then the
    readability sample's two queries, then ``verify_integrity``. So
    ``"quick-check"`` means the sample read cleanly and only the quick check
    refused.
    """
    try:
        store = EventStore.open(root)
    except StoreCorruptionError:
        return "open"
    with store:
        try:
            store.query(Query(limit=READABILITY_SAMPLE))
            store.query(Query(limit=READABILITY_SAMPLE, newest_first=False))
        except StoreCorruptionError:
            return "query"
        try:
            store.verify_integrity()
        except StoreCorruptionError:
            return "quick-check"
    return None


@pytest.mark.security
@pytest.mark.parametrize("stage", ["open", "query", "quick-check"])
def test_real_damage_still_reads_damaged_wherever_it_is_met(tmp_path: Path, stage: str) -> None:
    """The other direction: classifying the open must not launder damage into "unknown".

    A zeroed page can be met in three places and a 12-event store has all
    three. Measured: the first two pages after the header fail inside
    ``open``, some fail the readability sample's query, and the rest fail only
    ``quick_check``. Each is asserted where it is met, because the grading is
    per stage and a change that broke one would pass a test of the other two.
    The page is found by measurement rather than by number, so a schema or
    page-size change moves it instead of voiding the test.
    """
    from scripts.report_sli import main

    root = _stored(tmp_path)
    database = root / _STORE
    folding = sqlite3.connect(database)
    try:
        folding.execute("PRAGMA journal_mode=DELETE")
        page_size = int(folding.execute("PRAGMA page_size").fetchone()[0])
    finally:
        folding.close()
    pristine = database.read_bytes()

    def damage(pageno: int) -> None:
        # Every open, the classifying one included, may switch the file to WAL and
        # leave sidecars, so each measurement starts from the same damaged image.
        for suffix in SIDECAR_SUFFIXES:
            database.with_name(database.name + suffix).unlink(missing_ok=True)
        offset = (pageno - 1) * page_size
        database.write_bytes(pristine[:offset] + bytes(page_size) + pristine[offset + page_size :])

    found = None
    for pageno in range(2, len(pristine) // page_size + 1):
        damage(pageno)
        if _damage_first_met_at(root) == stage:
            found = pageno
            break
    assert found is not None, f"no page's loss is first met at {stage!r}; nothing was exercised"

    damage(found)
    by_id = _store_objectives(root)

    intact = by_id["store-intact"]
    assert intact.status is Status.BREACHED, intact.summary()
    assert intact.value == 0.0
    assert intact.detail.startswith(f"the store's {_DAMAGED}"), intact.detail
    readable = by_id["store-readable"]
    if stage == "quick-check":
        # The reason the two objectives are separate (tests/unit/test_sli.py owns
        # that argument): the sample read cleanly and only store-intact saw it.
        assert readable.status is Status.MET, readable.summary()
    else:
        assert readable.status is Status.BREACHED, readable.summary()
        assert readable.value == 0.0
        assert readable.detail.startswith("the store cannot be read: StoreCorruptionError"), (
            readable.detail
        )
    assert not intact.detail.startswith(_REFUSED)
    assert not readable.detail.startswith(_REFUSED)

    damage(found)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(["--root", str(root), "--caller", "soc-test"])
    assert code == 1, out.getvalue()
    assert "store-intact: breached" in out.getvalue(), out.getvalue()


@pytest.mark.security
@pytest.mark.parametrize(
    "identifier",
    ["PLANTED-" + "q" * 50_000, "\x1b[2J"],
    ids=["unbounded_text", "terminal_escape"],
)
def test_a_forged_event_id_reaches_the_report_described(tmp_path: Path, identifier: str) -> None:
    """The route a forged ``event_id`` took to the operator's terminal, end to end.

    ``store-readable`` copies the store's refusal into its detail, and
    ``report_sli.py`` prints details as they are. Measured before the store
    stopped echoing the id: a 50,152-character detail, and a raw ESC on
    stdout. Planted at the stored mark, so the mark checks cannot be what
    refuses, and inside the readability sample, so the query reaches it. The
    grade is pinned too, because describing the id must not soften it.
    """
    from scripts.report_sli import main

    root = _stored(tmp_path)
    with EventStore.open(root) as store:
        mark = store.high_water_mark()
        projection = canonical_json(normalize(_RECORD % 99).to_dict())
        with store._conn:
            store._conn.execute(
                "INSERT INTO events (event_id, ingested_at, occurred_at, source_type, "
                "vendor, parse_status, user_name, hostname, src_ip, dst_ip, projection) "
                "VALUES (?, ?, NULL, 'unknown', 'planted', 'text', NULL, NULL, NULL, NULL, ?)",
                (identifier, mark, projection),
            )

    readable = _store_objectives(root)["store-readable"]
    assert readable.status is Status.BREACHED, readable.summary()
    assert readable.value == 0.0
    assert readable.detail.startswith(
        "the store cannot be read: StoreIntegrityError: a stored event_id is"
    ), readable.detail[:200]
    assert len(readable.detail) < 400, f"{len(readable.detail)} chars of detail"
    assert readable.detail.isprintable(), "a control character reached the detail"

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(["--root", str(root), "--caller", "soc-test"])
    assert code == 1, out.getvalue()[:2000]
    assert "store-readable: breached" in out.getvalue()
    assert "\x1b" not in out.getvalue(), "a raw ESC reached the operator's terminal"
    assert identifier[:20] not in out.getvalue(), "the report echoed the stored id"
