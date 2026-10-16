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

import errno
import os
import socket
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from scripts import run_backup, run_collector, run_pipeline, run_retention
from scripts._locking import (
    _DESCRIBED_TYPES,
    DIR_MODE,
    FILE_MODE,
    _describe,
    prepare_lock,
    single_instance,
)
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
@pytest.mark.parametrize("cli", CLIS, ids=_IDS)
def test_an_existing_lock_directory_is_narrowed_not_left_as_found(cli: Cli, tmp_path: Path) -> None:
    """A lock directory that already exists must end owner-only, for all four.

    ``Path.mkdir``'s ``mode`` is masked by the umask on creation and does
    **nothing at all** to a directory that is already there, so the mode a
    lock directory was created with is the mode it keeps. Only ``run_backup``
    followed its ``mkdir`` with an explicit ``chmod``; calling the other three
    copies of ``_prepare_lock`` in isolation left an existing ``0o755``
    directory at ``0o755``. The lock *file* was ``0o600`` in all four — it was
    the directory that was left alone.

    **Deployed, the exposure was two CLIs, and two separate measurements say
    so.** Run against the four pre-extraction copies — ``main``'s
    ``scripts/run_*.py`` with this test file — it fails for exactly
    ``run_collector`` and ``run_pipeline``:

        2 failed, 2 passed

    ``run_backup`` passes on its own ``directory.chmod``. ``run_retention``
    passes for a *different* reason, which is the one worth recording: its
    lock directory is ``data/events/``, and ``EventStore.open`` narrows that
    itself (``store/events.py``'s ``_narrow(path.parent, _DIR_MODE)``,
    measured ``0o755 → 0o700``). So retention was covered incidentally, by
    another component, and only on a pass that got as far as opening the
    store — a pass that *declines* the lock exits before that, so the
    directory stayed wide on every declined pass. Incidental and conditional
    is not a control, which is the reason to make it unconditional here rather
    than to call retention already fine.

    The second measurement is this assertion's **non-vacuity**, and it is a
    different experiment that must not be confused with the first: removing
    ``directory.chmod(DIR_MODE)`` from the extracted ``scripts/_locking.py``
    fails it for ``run_collector``, ``run_pipeline`` **and** ``run_backup``
    (retention still passing, for the reason above). Backup fails there
    because the *shared helper* would lack the chmod its own copy had — not
    because its copy ever lacked it. Conflating the two is how an earlier
    version of this docstring came to claim three pre-extraction failures;
    review caught it.

    What was genuinely exposed is ``data/collect/`` and ``data/pipeline/``
    under the gitignored lab-data root, which AGENTS.md §5 treats as sensitive
    by default. ``data/collect/`` is the serious one: it holds copies of
    collected log files, which are stored evidence. ``store/events.py``
    already records this exact asymmetry running the wrong way — "bookkeeping
    protected, evidence readable by every local account".

    Reached without an adversary: ``docs/PRODUCTION_SOC_PLAN.md`` has an
    operator run a manual pass as themselves after the documented root cron
    entry has already created the directory as root — the same scenario
    ``run_collector``'s own docstring records for a different defect in this
    same function.
    """
    root = tmp_path / "root"
    root.mkdir()
    directory = root / cli.lock.parent
    directory.mkdir(mode=0o755, parents=True)
    directory.chmod(0o755)  # defeat the umask, so the precondition is real
    assert stat.S_IMODE(directory.stat().st_mode) == 0o755, "precondition not set up"

    cli.main(_argv(cli, root, tmp_path))

    assert stat.S_IMODE(directory.stat().st_mode) == 0o700, (
        f"{cli.name} left its lock directory at {oct(stat.S_IMODE(directory.stat().st_mode))}"
    )
    assert stat.S_IMODE((root / cli.lock).stat().st_mode) == 0o600, (
        f"{cli.name} left its lock file group- or world-readable"
    )


#: How a scheduled CLI declares that it takes the single-instance lock.
#: Keyed on the import rather than on a ``def``, because the two functions
#: now live in one module instead of four copies.
# --------------------------------------------------------------------------
# A hostile object at the lock path (#58)
# --------------------------------------------------------------------------
#
# Measured on the code these replace, across all four CLIs: a FIFO with no
# reader blocked FOREVER — exit 124 under `timeout`, zero bytes on either
# stream, still blocked at 30 s with `wchan = wait_for_partner`. A FIFO WITH a
# reader was worse: `flock` succeeded on the pipe and the pass ran its full
# work, the collector committing an event and retention running a pass, both at
# exit 0. And because `touch`, `chmod` and `open` all follow a symlink while
# none of them asks what is there, a symlinked lock path chmodded its target —
# including `/dev/null` (0o666 -> 0o600) and a directory outside the root
# (0o755 -> drw-------) — while a DANGLING symlink created a new file outside
# the lab-data root entirely.


def _hold_reader(fifo: Path) -> int:
    """Open a FIFO for reading so a writer's open returns instead of blocking."""
    return os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)


def _bind_socket(target: Path) -> socket.socket:
    """Bind an AF_UNIX socket at ``target``, relatively.

    ``sockaddr_un.sun_path`` is ~108 bytes and a pytest ``tmp_path`` plus the
    lock's own subdirectory can exceed it, so the bind is done from inside the
    directory. A harness detail, not a property of the control.
    """
    sock = socket.socket(socket.AF_UNIX)
    here = Path.cwd()
    try:
        os.chdir(target.parent)
        sock.bind(target.name)
    finally:
        os.chdir(here)
    return sock


#: ``(label, make the object, the word the message must contain)``. Each one
#: opens happily, or blocks, without a type guard on the descriptor.
#:
#: **Only the two types an unprivileged process can create.** The first version
#: of this table included a character device built with
#: ``os.mknod(..., S_IFCHR, makedev(1, 3))``, which needs ``CAP_MKNOD``. It
#: passed locally as root and failed all four CLIs on the CI runner with
#: ``PermissionError: [Errno 1] Operation not permitted`` — measured, and the
#: reason this comment exists. Gating it on ``geteuid() == 0`` was the wrong
#: repair: a security assertion that skips in the environment that matters
#: proves nothing there, which is the objection this repository already records
#: against a ``dbstat``-conditional test in ``test_store_hardening.py``. The
#: device branches are pinned instead by
#: :func:`test_describe_names_every_non_regular_type_it_claims_to`, which
#: *reads* an existing device node rather than creating one.
_NOT_REGULAR = (
    ("fifo-no-reader", lambda p: os.mkfifo(p, 0o600), "a FIFO"),
    ("socket", _bind_socket, "a socket"),
)


#: Device nodes present on any Linux or macOS host, read rather than created.
_CHARACTER_DEVICE = Path("/dev/null")

#: ``_DESCRIBED_TYPES`` entries no assertion below exercises, each with the
#: reason. Kept as an explicit accounting rather than left implicit so that
#: adding a sixth type to the table fails this file instead of shipping unpinned.
_UNEXERCISED_DESCRIPTIONS = frozenset(
    {
        # A block device cannot be created without CAP_MKNOD either, and unlike
        # a character device there is no path guaranteed to exist on both CI
        # runners and a developer's machine (/dev/loop0 and /dev/sda are both
        # absent in containers). The predicate is the same ``stat.S_IS*``
        # dispatch as the four that are exercised; faking an ``lstat`` to reach
        # it would be mocking the function under test.
        "a block device",
    }
)


@pytest.mark.security
@pytest.mark.parametrize("cli", CLIS, ids=_IDS)
@pytest.mark.parametrize(
    ("label", "make", "expected"), _NOT_REGULAR, ids=[c[0] for c in _NOT_REGULAR]
)
def test_a_lock_path_that_is_not_a_regular_file_is_refused_by_type(
    cli: Cli,
    label: str,
    make: object,
    expected: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Exit 2 with a message naming what is there, for every non-regular type.

    The type is checked on the **descriptor** ``os.open`` returned, not on the
    path, so the thing inspected and the thing locked are the same inode by
    construction. A ``path.is_fifo()`` guard before the open would not be: a
    ``rename`` between the check and the open yields a descriptor on a
    different inode with nothing raised, leaving the hang in place behind a
    check that visibly ran and passed.

    The message names the object rather than inferring it from the errno. The
    first version of this fix did infer it, and was wrong — ``os.open`` returns
    ``ENXIO`` for a socket as well as for a reader-less FIFO, so a socket
    reported itself as a FIFO.
    """
    root = tmp_path / "root"
    (root / cli.lock).parent.mkdir(parents=True)
    held = make(root / cli.lock)  # type: ignore[operator]
    try:
        assert cli.main(_argv(cli, root, tmp_path)) == 2
        err = capsys.readouterr().err
        assert err.startswith("error: "), err
        assert expected in err, f"{label}: message does not name the object: {err}"
    finally:
        if isinstance(held, socket.socket):
            held.close()


#: ``(label, the mode the lock file already carries, is it recoverable)``.
#:
#: The open is ``O_RDONLY``, which is what makes ``0o400`` recoverable and what
#: makes ``0o200`` refuse. Both rows are pinned deliberately: the second is the
#: *price* of the first, and a silent change in either direction is a behaviour
#: change four scheduled CLIs depend on. ``prepare_lock``'s docstring carries
#: the measured table.
_PREEXISTING_MODES = (
    ("owner-read-only", 0o400, True),
    ("owner-write-only", 0o200, False),
    ("no-permissions", 0o000, False),
    ("group-and-world-readable", 0o644, True),
)


@pytest.mark.security
@pytest.mark.skipif(
    os.geteuid() == 0,
    reason="root bypasses the DAC checks this asserts, so the result would be vacuous",
)
@pytest.mark.parametrize(
    ("label", "mode", "recoverable"), _PREEXISTING_MODES, ids=[c[0] for c in _PREEXISTING_MODES]
)
def test_a_pre_existing_lock_file_is_recovered_or_refused_by_its_mode(
    label: str, mode: int, recoverable: bool, tmp_path: Path
) -> None:
    """A lock file an operator left read-only must not stop every scheduled pass.

    Reported in review against the first version of this change, which opened
    ``O_WRONLY``: a pre-existing ``0o400`` lock made ``os.open`` fail ``EACCES``
    *before* the ``os.fchmod`` that would have widened it, so all four CLIs
    refused to start until a human intervened — where the ``touch``/``chmod``/
    ``open`` sequence this replaced had recovered the same file, because
    ``chmod`` needs ownership rather than write permission.

    ``0o400`` is not an exotic mode here: ``agents/tools/containment.py`` chmods
    a quarantined payload to it for forensic preservation, and it is what any
    "harden the data directory" script produces. Nothing in this repository puts
    one at a *lock* path, so the trigger is an operator or an external script —
    weaker than a code path, which is why this is pinned rather than argued.

    **Why skipping as root is legitimate here and was not for the device node.**
    The `mknod` case was gated out of *CI*, which is the one environment where a
    security assertion has to hold. This skips the inverse way round: CI runs
    unprivileged, so this assertion runs exactly where it matters, and it steps
    aside only for a developer running as root — where the kernel ignores the
    mode bits and the assertion would pass without testing anything.
    """
    directory = tmp_path / "data" / "pipeline"
    directory.mkdir(parents=True)
    lock_path = directory / "cycle.lock"
    lock_path.touch()
    lock_path.chmod(mode)
    assert stat.S_IMODE(lock_path.stat().st_mode) == mode, "precondition not set up"

    if not recoverable:
        with pytest.raises(OSError) as caught:
            prepare_lock(directory, "cycle.lock")
        assert caught.value.errno == errno.EACCES, (
            f"{label}: expected EACCES, got errno {caught.value.errno}"
        )
        # And the refusal left the operator's mode alone rather than half-fixing it.
        assert stat.S_IMODE(lock_path.stat().st_mode) == mode
        return

    handle = prepare_lock(directory, "cycle.lock")
    # Recovered to the owner-only mode the rest of the lab root uses...
    assert stat.S_IMODE(lock_path.stat().st_mode) == FILE_MODE, (
        f"{label}: lock left at {oct(stat.S_IMODE(lock_path.stat().st_mode))}"
    )
    # ...and the handle is a working lock, not merely an open file. This is the
    # assertion that would catch O_RDONLY having broken exclusion: flock keys on
    # the open file description, not on access mode, but that is a measured fact
    # rather than an obvious one.
    with single_instance(handle) as acquired:
        assert acquired is True
        second = prepare_lock(directory, "cycle.lock")
        with single_instance(second) as overlapping:
            assert overlapping is False, f"{label}: a read-only open stopped excluding"


@pytest.mark.security
def test_describe_names_every_non_regular_type_it_claims_to(tmp_path: Path) -> None:
    """``_describe`` is what puts the object's name in the refusal message.

    Pinned directly, and at this level deliberately: the end-to-end matrix
    above can only plant the two types an unprivileged process can create, so
    without this the character-device branch would be exercised nowhere that
    CI runs. The device node is **read**, never created — see
    ``_NOT_REGULAR``'s comment for the measured reason.

    The last assertion is the one that matters for the future: it fails if a
    type is added to ``_DESCRIBED_TYPES`` without a pin here, rather than
    letting a new branch ship unexercised.
    """
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "absent")
    sock = _bind_socket(tmp_path / "sock")
    try:
        seen = {
            "a FIFO": _describe(fifo),
            "a symlink": _describe(link),
            "a socket": _describe(tmp_path / "sock"),
        }
    finally:
        sock.close()
    assert seen["a FIFO"] == "a FIFO"
    assert seen["a socket"] == "a socket"
    # The symlink's description carries its own clause, so match the prefix.
    assert (seen["a symlink"] or "").startswith("a symlink"), seen["a symlink"]

    assert _CHARACTER_DEVICE.is_char_device(), (
        f"{_CHARACTER_DEVICE} is not a character device on this host; the "
        "character-device branch would go unexercised"
    )
    assert _describe(_CHARACTER_DEVICE) == "a character device"

    # A regular file and a directory are not "worth naming" — _describe returns
    # None so the caller keeps the kernel's own errno text (EISDIR's "Is a
    # directory" is already exact, and a test asserts it elsewhere).
    regular = tmp_path / "regular"
    regular.write_text("", encoding="utf-8")
    assert _describe(regular) is None
    assert _describe(tmp_path) is None
    assert _describe(tmp_path / "does-not-exist") is None

    described = {description for _, description in _DESCRIBED_TYPES}
    exercised = {"a FIFO", "a socket", "a character device"} | {
        d for d in described if d.startswith("a symlink")
    }
    unaccounted = described - exercised - _UNEXERCISED_DESCRIPTIONS
    assert not unaccounted, (
        f"_DESCRIBED_TYPES gained {sorted(unaccounted)} with no assertion here — "
        "pin it, or add it to _UNEXERCISED_DESCRIPTIONS with the reason"
    )


@pytest.mark.security
@pytest.mark.parametrize("cli", CLIS, ids=_IDS)
def test_a_fifo_with_a_reader_is_refused_rather_than_locked(
    cli: Cli, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The case that was worse than the hang, pinned separately.

    With a reader attached the open returns immediately, so ``O_NONBLOCK``
    cannot help and only the descriptor type check can: measured on the old
    code, ``flock`` succeeded **on the pipe** and the pass ran its full work at
    exit 0 — the collector committing an event, retention running a pass —
    with nothing anywhere saying the single-instance lock was a pipe.
    """
    root = tmp_path / "root"
    (root / cli.lock).parent.mkdir(parents=True)
    os.mkfifo(root / cli.lock, 0o600)
    reader = _hold_reader(root / cli.lock)
    try:
        assert cli.main(_argv(cli, root, tmp_path)) == 2
        assert "a FIFO" in capsys.readouterr().err
    finally:
        os.close(reader)


@pytest.mark.security
@pytest.mark.parametrize("cli", CLIS, ids=_IDS)
def test_a_symlinked_lock_path_is_refused_and_its_target_untouched(
    cli: Cli, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A symlink at the lock file is refused, and nothing reaches the target.

    ``O_NOFOLLOW`` applies to the final component only — an ancestor symlink
    still opens, which is AGENTS.md §5's posture for ``collect/`` ("No symlink
    at the log file ... Ancestor components are not walked, deliberately") and
    stricter, because the check and the open are one syscall.

    The target's mode is the assertion that matters, not just the exit code:
    measured on the old code, ``touch`` and ``chmod`` followed the link and
    changed a file outside the root from ``0o644`` to ``0o600``.

    ``run_retention`` refuses earlier and with its own wording, because it
    alone passes the lock filename through ``store.paths.confine``, which
    rejects a symlinked component before ``prepare_lock`` is reached. Both
    refusals are exit 2 and both leave the target alone, which is what is
    asserted here.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "target.txt"
    target.write_text("sentinel")
    target.chmod(0o644)
    before = (target.stat().st_mode & 0o777, target.read_text())

    root = tmp_path / "root"
    (root / cli.lock).parent.mkdir(parents=True)
    (root / cli.lock).symlink_to(target)

    assert cli.main(_argv(cli, root, tmp_path)) == 2
    assert capsys.readouterr().err.startswith("error: ")
    assert (target.stat().st_mode & 0o777, target.read_text()) == before, (
        "the symlink target outside the root was modified"
    )


@pytest.mark.security
@pytest.mark.parametrize("cli", CLIS, ids=_IDS)
def test_a_dangling_symlinked_lock_path_creates_nothing_outside_the_root(
    cli: Cli, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Measured on the old code: this CREATED a file outside the lab-data root.

    ``O_CREAT`` on a dangling symlink creates the file wherever the link
    points; with ``O_NOFOLLOW`` it is ``ELOOP`` instead. AGENTS.md §5 confines
    everything this platform writes to the gitignored lab-data root, and a lock
    path is the one place that confinement was escapable by a symlink nobody
    checked.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    absent = outside / "absent.txt"

    root = tmp_path / "root"
    (root / cli.lock).parent.mkdir(parents=True)
    (root / cli.lock).symlink_to(absent)

    assert cli.main(_argv(cli, root, tmp_path)) == 2
    assert capsys.readouterr().err.startswith("error: ")
    assert not absent.exists(), "a refused startup created a file outside the root"


@pytest.mark.security
@pytest.mark.parametrize("cli", CLIS, ids=_IDS)
def test_a_refused_lock_path_leaves_its_directory_traversable(
    cli: Cli, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A second defect, which nobody had filed, found while measuring the first.

    With a **directory** at the lock path the old ``touch(exist_ok=True)``
    *succeeded* — it merely ``utime``d it — so the following ``chmod`` left the
    lock *directory* at ``0o600``, measured ``0o700 -> 0o600``. A refused
    startup left the directory non-traversable, so the next pass could not
    reach its own lock even after the operator removed the offending object.
    One ``os.open`` never gets that far.
    """
    root = tmp_path / "root"
    lock_directory = (root / cli.lock).parent
    (root / cli.lock).mkdir(parents=True)

    assert cli.main(_argv(cli, root, tmp_path)) == 2
    assert "Is a directory" in capsys.readouterr().err
    assert stat.S_IMODE(lock_directory.stat().st_mode) == DIR_MODE, (
        "a refused startup left the lock directory non-traversable"
    )


@pytest.mark.security
@pytest.mark.parametrize("cli", CLIS, ids=_IDS)
def test_a_pre_existing_lock_file_is_narrowed_to_owner_only(cli: Cli, tmp_path: Path) -> None:
    """The narrowing of an **existing** lock file was pinned by nothing.

    The only other assertion on the lock file's mode is in
    :func:`test_an_existing_lock_directory_is_narrowed_not_left_as_found`,
    where the file is freshly created — so a change that narrowed only on
    creation would have passed every test while leaving a world-writable lock
    file in place. Measured on the old code: all four narrowed it silently, and
    the ``os.fchmod`` here keeps that.

    It matters because ``os.fchmod`` is what replaced ``path.chmod``, and the
    declined alternative — ``O_CREAT | O_EXCL`` first, so a file we did not
    create is never chmodded — would have dropped this silently. That
    alternative is recorded in ``scripts/_locking.py`` against the hard-link
    residual it would close; this test is why it was not taken blind.
    """
    root = tmp_path / "root"
    lock_path = root / cli.lock
    lock_path.parent.mkdir(parents=True)
    lock_path.write_text("")
    lock_path.chmod(0o666)

    assert cli.main(_argv(cli, root, tmp_path)) in (0, 1)
    assert stat.S_IMODE(lock_path.stat().st_mode) == FILE_MODE, (
        "a pre-existing lock file was left wider than owner-only"
    )


_LOCKING_IMPORT = "from scripts._locking import"


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
        if _LOCKING_IMPORT in path.read_text(encoding="utf-8")
    }
    assert locked == {cli.name for cli in CLIS}
    # Non-vacuity, spelled out because the predicate changed once already:
    # it used to scan for ``def _single_instance(``, and when that function
    # moved into ``scripts/_locking.py`` the set went empty. The equality
    # above caught it — ``set() == {four names}`` fails — which is why the
    # discovery is keyed on an equality and not a subset. This keeps the
    # floor explicit anyway, so a future predicate that matches nothing says
    # so in its own words.
    assert len(locked) == 4, f"expected four locked CLIs, discovered {sorted(locked)}"


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
def test_a_root_symlink_swapped_between_the_check_and_the_return_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The path validated and the path returned are not the same path.

    ``root.is_dir()`` states the supplied path and ``root.resolve()`` returns
    the target, so an atomic deployment symlink swap — ``/srv/ianua`` repointed
    from one release to the next between those two calls — hands back a target
    nothing checked, including one that does not exist, which the callers'
    ``mkdir(parents=True)`` would then create.

    The swap is performed deterministically in the window rather than raced, so
    this pins the guard rather than hoping for an interleaving. It does not
    claim to close an adversary racing the two calls on purpose: that is two
    syscalls apart like any other check, and §5 of the charter already records
    why that race is unwinnable.
    """
    target = tmp_path / "release-1"
    target.mkdir()
    link = tmp_path / "current"
    link.symlink_to(target, target_is_directory=True)
    never_created = tmp_path / "release-2"

    real_resolve = Path.resolve

    def swapping_resolve(self: Path, *args: object, **kwargs: object) -> Path:
        if self == link:
            link.unlink()
            link.symlink_to(never_created, target_is_directory=True)
        return real_resolve(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "resolve", swapping_resolve)

    with pytest.raises(_Bespoke, match="resolved to"):
        validated_root(link, error=_Bespoke)


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
