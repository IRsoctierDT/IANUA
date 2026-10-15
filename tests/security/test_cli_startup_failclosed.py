# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Scheduled entry points must fail closed at startup, and leave nothing behind.

The four CLIs a scheduler runs unattended — collector, pipeline, retention,
backup — share one startup contract. It is asserted here for all four at once,
in one table, because **the grouping is the control**: every defect this file
pins took the shape "three copies fixed, one missed", and a per-CLI test file
is how that shape survives review.

The properties:

* **An unnamed root is refused.** ``Path("") == Path(".")`` and
  ``Path(".").is_dir()`` is ``True``, so the documented scheduler line
  ``--root "$IANUA_ROOT"`` with the variable unset passed an ``is_dir()``
  check and built a complete shadow ``data/`` tree in whatever the working
  directory happened to be — the collector storing events into it, every
  signal green. Measured on all four. That is the failure
  ``docs/PRODUCTION_SOC_PLAN.md`` names as the catastrophic one, reached by
  the likeliest misconfiguration there is.
* **A refused startup creates nothing** — not a shadow tree in the working
  directory, not the root it was told to use, not even its own lock file.
  Startup validates, and only then opens; the lock is the last thing the
  startup block touches, so nothing that can fail happens after a descriptor
  is open.
* **A startup failure is a translated exit code, never a traceback.** A lock
  path that is a *directory* used to escape as ``IsADirectoryError`` with exit
  1, where the documented contract says 2: ``_prepare_lock`` had moved
  ``mkdir``/``touch``/``chmod`` inside the caller's ``try`` and left the
  ``open`` behind in the context manager, outside every ``try`` — in three
  CLIs, while the fourth had no ``_prepare_lock`` at all.
* **The table is complete.** A fifth scheduled CLI cannot be added without
  appearing here: the coverage guard reads ``scripts/`` and fails if anything
  defines ``_single_instance`` without a row in this file.

:func:`store.paths.validated_root` is the shared implementation of the first
two, so its own refusals are asserted directly as well.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest
from scripts import run_backup, run_collector, run_pipeline, run_retention
from store.paths import validated_root

#: Roots that resolve to the working directory, or to somewhere else the
#: operator did not name. The first four are all ``Path(".")`` once argparse is
#: done, which is why the check cannot be an ``is_dir()``: the working
#: directory is a perfectly good directory.
#:
#: The last four are the second lesson, and it cost a P1 on the pull request
#: that introduced the guard. ``Path.resolve()`` with ``strict=False`` collapses
#: ``..`` lexically against components that **do not exist**, so a guard that
#: resolved first and checked afterwards accepted ``missing/..`` as the working
#: directory — and ``run_pipeline`` exited 0 with "idle: no new events" after
#: writing ``data/events/events.sqlite3`` into it. The guard it replaced had
#: stated ``args.root.is_dir()`` on the *unresolved* path, where the kernel
#: refuses to walk ``..`` out of a component that is not there, so the first
#: version was a **regression** for this spelling while fixing the one above.
RELATIVE_ROOTS = (
    "",
    ".",
    "./",
    "././.",
    "missing/..",
    "./missing/..",
    "also/missing/../..",
    "real/../real",
)

#: What argparse hands over for an unset shell variable: the empty spelling.
#: Taken from the table rather than written inline, because ruff flags an empty
#: ``Path`` literal as a redundant way of writing the current directory — and
#: that equivalence *is* the defect, so the spelling has to survive the lint.
UNSET_ROOT = Path(RELATIVE_ROOTS[0])


class _Bespoke(Exception):
    """A caller's own error type, to prove the helper raises what it is given."""


@dataclass(frozen=True)
class Cli:
    """One scheduled entry point: how to invoke it, and where it locks."""

    name: str
    main: Callable[[list[str]], int]
    #: The lock file, relative to ``--root``.
    lock: Path
    #: The collector is the only one that needs a declared source to get as
    #: far as the lock.
    needs_source: bool = False


CLIS: tuple[Cli, ...] = (
    Cli(
        "run_collector",
        run_collector.main,
        Path("data") / "collect" / "collect.lock",
        needs_source=True,
    ),
    Cli("run_pipeline", run_pipeline.main, Path("data") / "pipeline" / "cycle.lock"),
    Cli("run_retention", run_retention.main, Path("data") / "events" / "retention.lock"),
    Cli("run_backup", run_backup.main, Path("data") / "backups" / "backup.lock"),
)
_IDS = [cli.name for cli in CLIS]


def _argv(cli: Cli, root: Path | str, tmp_path: Path, *extra: str) -> list[str]:
    """Build an argv for ``cli`` with ``root`` passed through verbatim.

    ``root`` is taken as given (a bare ``""`` stays ``""``) because the defect
    lives in how the *argument* is spelled, not in how a ``Path`` renders it.
    """
    argv = ["--root", str(root), "--caller", "soc-test", *extra]
    if cli.needs_source:
        source = tmp_path / "source.log"
        source.write_text("one line\n", encoding="utf-8")
        argv += ["--source", str(source)]
    return argv


def _tree(directory: Path) -> set[Path]:
    """Every path under ``directory``, relative — an artifact snapshot."""
    return {path.relative_to(directory) for path in directory.rglob("*")}


# ------------------------------------------------------------------ the CLIs
@pytest.mark.security
@pytest.mark.parametrize("cli", CLIS, ids=_IDS)
@pytest.mark.parametrize("relative", RELATIVE_ROOTS)
def test_a_relative_root_is_refused_and_builds_no_shadow_tree(
    cli: Cli,
    relative: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The working directory must not become the lab-data root by default."""
    work = tmp_path / "scheduler-cwd"
    work.mkdir()
    # The ``chdir`` is the point, not scaffolding: an implementation that
    # resolved the argument before testing it would find a real, writable
    # directory here and accept every spelling in the table.
    monkeypatch.chdir(work)
    (work / "real").mkdir()  # makes "real/../real" resolvable, so it must be
    #                          refused for being relative rather than for
    #                          naming nothing.

    assert cli.main(_argv(cli, relative, tmp_path)) == 2
    assert _tree(work) == {Path("real")}, "a refused startup built a tree in the cwd"
    assert "must be an absolute path" in capsys.readouterr().err


@pytest.mark.security
@pytest.mark.parametrize("cli", CLIS, ids=_IDS)
def test_a_root_that_does_not_exist_is_refused_not_created(
    cli: Cli, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``data/`` is created beneath the root, never the root itself."""
    missing = tmp_path / "unmounted-volume"

    assert cli.main(_argv(cli, missing, tmp_path)) == 2
    assert not missing.exists(), "a refused startup created the root it was handed"
    assert "not an existing directory" in capsys.readouterr().err


@pytest.mark.security
@pytest.mark.parametrize("cli", CLIS, ids=_IDS)
def test_a_lock_path_that_is_a_directory_is_translated_not_raised(
    cli: Cli, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An unusable lock path exits 2, not a traceback with exit 1.

    Returning at all is half the assertion: an escaping ``IsADirectoryError``
    would fail this test by propagating out of ``main``.
    """
    root = tmp_path / "root"
    (root / cli.lock).mkdir(parents=True)

    assert cli.main(_argv(cli, root, tmp_path)) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: "), err
    # Named specifically, because exit 2 is also what a bad root yields: this
    # pins that the *lock* failure is the one being translated.
    assert "Is a directory" in err


@pytest.mark.security
@pytest.mark.parametrize("cli", CLIS, ids=_IDS)
def test_a_startup_refused_after_the_root_leaves_no_lock_behind(
    cli: Cli, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A valid root, an unreadable policy bundle: still nothing created.

    This pins the ordering inside the startup block — the lock is opened last,
    after everything that can fail. Open it first and this test sees the lock
    file and its two parent directories left behind by a run that refused.
    """
    root = tmp_path / "root"
    root.mkdir()

    code = cli.main(_argv(cli, root, tmp_path, "--policy", str(tmp_path / "absent.json")))

    assert code == 2
    assert "policy bundle" in capsys.readouterr().err
    assert _tree(root) == set(), "a refused startup left state under the root"


@pytest.mark.security
def test_every_single_instance_cli_has_a_row_here() -> None:
    """A fifth scheduled CLI cannot quietly skip this contract.

    The defects above were each "fixed in three of the four". Keying the
    coverage on ``_single_instance`` rather than on a hand-kept list is what
    makes the fourth impossible to forget.
    """
    scripts = Path(__file__).resolve().parents[2] / "scripts"
    locked = {
        path.stem
        for path in scripts.glob("*.py")
        if "def _single_instance(" in path.read_text(encoding="utf-8")
    }
    assert locked == {cli.name for cli in CLIS}


# --------------------------------------------------------- validated_root
@pytest.mark.security
@pytest.mark.parametrize("relative", RELATIVE_ROOTS)
def test_validated_root_refuses_every_relative_spelling(
    relative: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A relative root is the scheduler's working directory, whatever that is.

    The ``chdir`` is the test, not scaffolding: with a real directory as the
    cwd, an implementation that resolved before testing would accept every
    spelling in the table. ``real/`` exists so that ``real/../real`` is a
    perfectly resolvable relative path and is refused for being *relative*,
    not for naming nothing.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "real").mkdir()
    with pytest.raises(_Bespoke, match="must be an absolute path"):
        validated_root(Path(relative), error=_Bespoke)


@pytest.mark.security
def test_validated_root_tests_the_path_as_supplied_not_as_resolved(
    tmp_path: Path,
) -> None:
    """``resolve()`` does not normalize an absolute root, it invents one.

    ``/…/absent/..`` collapses lexically to an existing ``/…`` with
    ``strict=False``, so a guard that resolved first and tested afterwards
    accepted it. The kernel will not walk ``..`` out of a component that is not
    there, so stating the supplied path is what refuses it — and this is the
    absolute twin of the P1 the reviewer found at ``missing/..``.
    """
    invented = tmp_path / "absent" / ".."
    assert invented.resolve() == tmp_path.resolve(), "fixture must exercise the collapse"
    assert invented.resolve().is_dir(), "the resolved form is a real directory"

    with pytest.raises(_Bespoke, match="not an existing directory"):
        validated_root(invented, error=_Bespoke)


@pytest.mark.security
def test_validated_root_accepts_a_dotdot_whose_every_component_exists(
    tmp_path: Path,
) -> None:
    """Which is why ``..`` is not refused as a spelling, only as an invention.

    With both rules in force, a surviving ``..`` means the operator named a
    real directory the long way round. Asserted so that over-tightening this
    into a blanket ``..`` ban shows up as a failing test rather than as a
    refused deployment.
    """
    inner = tmp_path / "inner"
    inner.mkdir()

    assert validated_root(inner / "..", error=_Bespoke) == tmp_path.resolve()


@pytest.mark.security
def test_validated_root_quotes_an_empty_root_so_it_is_visible(tmp_path: Path) -> None:
    """``--root ""`` is invisible in a cron line; the message has to show it."""
    with pytest.raises(_Bespoke, match=r"got '\.'"):
        validated_root(UNSET_ROOT, error=_Bespoke, what="--root")


@pytest.mark.security
def test_validated_root_refuses_a_root_that_does_not_exist(tmp_path: Path) -> None:
    with pytest.raises(_Bespoke, match="not an existing directory"):
        validated_root(tmp_path / "absent", error=_Bespoke)


@pytest.mark.security
def test_validated_root_refuses_a_file(tmp_path: Path) -> None:
    """A root is a directory; a regular file at that path is a typo."""
    occupied = tmp_path / "root"
    occupied.write_text("not a directory\n", encoding="utf-8")
    with pytest.raises(_Bespoke, match="not an existing directory"):
        validated_root(occupied, error=_Bespoke)


#: Absolute spellings that all resolve to the filesystem root. The first is
#: what an unset shell variable produces when the scheduler line carries an
#: ordinary trailing slash — measured: ``--root "$IANUA_ROOT"`` is ``""`` and
#: refused as relative, but ``--root "$IANUA_ROOT/"`` is exactly ``"/"``, which
#: is absolute and *is* a directory. One character from the hole the guard was
#: written to close, and the same catastrophic class: the event store lands at
#: ``/data`` with every signal reading healthy.
FILESYSTEM_ROOTS = ("/", "//", "/.", "/..", "/../../..")


@pytest.mark.security
@pytest.mark.parametrize("spelling", FILESYSTEM_ROOTS)
def test_validated_root_refuses_the_filesystem_root(spelling: str) -> None:
    """The one absolute path a misconfigured scheduler writes by accident.

    Asserted against the helper rather than through a CLI, deliberately: a
    CLI-level test for this case would create ``/data`` on the host the moment
    it regressed, and a test must not leave behind the artifact whose absence
    it asserts.
    """
    with pytest.raises(_Bespoke, match="must not be the filesystem root"):
        validated_root(Path(spelling), error=_Bespoke)


@pytest.mark.security
@pytest.mark.skipif(not Path("/proc/self/root").exists(), reason="Linux /proc only")
def test_validated_root_refuses_a_synthetic_path_to_the_filesystem_root() -> None:
    """``/proc/self/root`` resolves to ``/``, so the test is on the resolved path."""
    with pytest.raises(_Bespoke, match="must not be the filesystem root"):
        validated_root(Path("/proc/self/root"), error=_Bespoke)


@pytest.mark.security
def test_validated_root_accepts_a_top_level_directory(tmp_path: Path) -> None:
    """``/srv`` is a legitimate root; only ``/`` itself is refused.

    Guards the refusal above against being widened into "anything shallow",
    which would refuse the root the runbooks actually document. The directory
    is *derived* from ``tmp_path`` rather than written as a literal, so this
    stays honest on any platform and does not hard-code a world-writable path.
    """
    resolved = tmp_path.resolve()
    top_level = resolved.parents[-2]  # [-1] is the filesystem root itself
    assert top_level.parent == Path(resolved.anchor), "fixture must be one level down"

    assert validated_root(top_level, error=_Bespoke) == top_level


@pytest.mark.security
@pytest.mark.parametrize(
    "unstatable",
    [
        pytest.param(("a" * 256,), id="component-over-NAME_MAX"),
        pytest.param(("b" * 100,) * 45, id="path-over-PATH_MAX"),
    ],
)
def test_validated_root_raises_the_callers_error_for_an_unstatable_path(
    unstatable: tuple[str, ...], tmp_path: Path
) -> None:
    """``Path.is_dir()`` does not swallow every ``OSError``.

    It returns False for ENOENT, ENOTDIR, EBADF and ELOOP, but lets
    ENAMETOOLONG through: a 256-byte component raised ``[Errno 36] File name
    too long`` straight past the documented ``error`` contract. The four CLIs
    catch ``OSError`` too, so the exit code was right by accident — which is
    not the same as the contract holding, and a library caller with its own
    taxonomy got a bare ``OSError``.
    """
    with pytest.raises(_Bespoke, match="cannot be stated"):
        validated_root(tmp_path.joinpath(*unstatable), error=_Bespoke)


@pytest.mark.security
def test_validated_root_returns_a_resolved_root(tmp_path: Path) -> None:
    """An accepted root comes back resolved, so later joins are unambiguous."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    assert validated_root(link, error=_Bespoke) == real.resolve()


@pytest.mark.security
def test_validated_root_raises_the_callers_error_type(tmp_path: Path) -> None:
    """Each entry point keeps its own exception taxonomy and exit code."""
    with pytest.raises(_Bespoke):
        validated_root(UNSET_ROOT, error=_Bespoke)
    with pytest.raises(ValueError):
        validated_root(UNSET_ROOT, error=ValueError)


@pytest.mark.security
def test_validated_root_names_what_it_refused(tmp_path: Path) -> None:
    """``what`` is how an operator learns *which* argument was wrong."""
    with pytest.raises(_Bespoke, match="--root must be an absolute path"):
        validated_root(UNSET_ROOT, error=_Bespoke, what="--root")
