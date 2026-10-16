# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""A broken lock must not report the benign skip a held lock reports.

``single_instance`` caught bare ``OSError`` and yielded ``False`` for all of
it, so a ``flock`` failing for any reason other than contention became
"skipped: another pass holds the lock; this invocation did nothing." at exit 0
— the documented, correct outcome for a *held* lock. Measured through all four
real CLIs on the code this replaces, with ``ENOLCK`` at the flock:

    run_retention  exit 0   skipped: another retention pass holds the lock…
    run_collector  exit 0   skipped: another pass holds the lock…
    run_pipeline   exit 0   skipped: another cycle holds the lock…
    run_backup     exit 0   skipped: another backup pass holds the lock…

On a lab-data root whose filesystem does not implement ``flock``, or whose
kernel lock table is exhausted, that is **every** pass, forever, with no
contention anywhere and no work ever done. Worse than a hang, which at least
shows up as a timeout: this reports success on the documented contract, so a
scheduler, a log shipper and the SLI layer all read healthy.

**Why the failure is injected at the ``flock`` call rather than produced by the
kernel.** The first harness closed the handle's descriptor to get a genuine
``EBADF``. It measured the wrong thing: closing the descriptor also breaks
``with handle:``'s own ``close()``, whose ``EBADF`` is raised *during
unwinding* and **replaces** the error under test — so the assertion saw a bare
``OSError`` and would have reported the fix broken when it was not. The errnos
below are therefore real values the kernel was measured to produce
(``EAGAIN`` for contention, ``EBADF`` for a bad descriptor), injected at the
one call whose dispatch is under test, with ``LOCK_UN`` left working so the
release path stays honest.
"""

from __future__ import annotations

import errno
import fcntl
import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from scripts import run_backup, run_collector, run_pipeline, run_retention
from scripts._locking import LockUnavailableError, prepare_lock, single_instance

_REAL_FLOCK: Callable[..., Any] = fcntl.flock


def _fail_acquire_with(code: int) -> Callable[[int, int], Any]:
    """Fail only the acquire; let ``LOCK_UN`` through so ``close()`` is unaffected."""

    def flock(descriptor: int, operation: int) -> Any:
        if operation & fcntl.LOCK_UN:
            return _REAL_FLOCK(descriptor, operation)
        raise OSError(code, errno.errorcode[code])

    return flock


#: Errnos ``flock`` can fail with that are **not** contention, each with why it
#: happens. None of them means "another pass holds the lock", so none may yield
#: the benign skip.
_NOT_CONTENTION = (
    ("EBADF", errno.EBADF, "the descriptor is not open — measured from the kernel"),
    ("ENOLCK", errno.ENOLCK, "the kernel's lock table is exhausted"),
    ("EOPNOTSUPP", errno.EOPNOTSUPP, "the filesystem does not implement flock"),
    ("EACCES", errno.EACCES, "permission denied on the lock"),
    ("EINTR", errno.EINTR, "a signal interrupted the call"),
    ("EDEADLK", errno.EDEADLK, "the kernel detected a deadlock"),
)


@pytest.mark.security
@pytest.mark.parametrize(
    ("name", "code", "why"), _NOT_CONTENTION, ids=[c[0] for c in _NOT_CONTENTION]
)
def test_a_non_contention_errno_is_refused_not_skipped(
    name: str, code: int, why: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each one raises, carrying its errno, instead of yielding ``False``."""
    handle = prepare_lock(tmp_path / "data" / "pipeline", "cycle.lock")
    monkeypatch.setattr(fcntl, "flock", _fail_acquire_with(code))
    with pytest.raises(LockUnavailableError) as caught, single_instance(handle) as acquired:
        raise AssertionError(
            f"{name} ({why}) yielded {acquired!r} — a broken lock reported as a "
            "benign skip, which is the defect this file exists for"
        )
    assert caught.value.errno == code, f"{name}: errno {caught.value.errno} not preserved"


@pytest.mark.security
def test_real_contention_still_yields_the_benign_skip(tmp_path: Path) -> None:
    """The control, and it is not optional.

    Narrowing the catch would be worthless — or worse than the defect — if it
    also stopped a genuinely held lock from reporting a skip: every overlapping
    scheduled pass would then page an operator. The contention here is **real**,
    two handles on one inode, with nothing injected.
    """
    directory = tmp_path / "data" / "pipeline"
    first = prepare_lock(directory, "cycle.lock")
    with single_instance(first) as held:
        assert held is True
        second = prepare_lock(directory, "cycle.lock")
        with single_instance(second) as overlapping:
            assert overlapping is False, "a genuinely held lock stopped reporting a skip"


@pytest.mark.security
def test_the_kernel_really_reports_contention_as_blockingioerror(tmp_path: Path) -> None:
    """The measurement the class-based catch rests on, asserted rather than trusted.

    ``except BlockingIOError`` is only the right allow-list if that is what the
    kernel's contention actually arrives as. Measured: ``EAGAIN`` (11), which
    Python surfaces as ``BlockingIOError`` — and *not* ``EACCES``, a caveat that
    belongs to ``fcntl``-style ``F_SETLK`` locks rather than to ``flock``.

    If a future platform reported contention as something else, this goes red
    here rather than silently turning every overlap into an exit-2 page.
    """
    path = tmp_path / "lock"
    first = os.open(path, os.O_RDONLY | os.O_CREAT, 0o600)
    fcntl.flock(first, fcntl.LOCK_EX)
    second = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(BlockingIOError) as caught:
            fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert caught.value.errno == errno.EWOULDBLOCK
        assert errno.EWOULDBLOCK == errno.EAGAIN, "this platform separates them; revisit"
    finally:
        os.close(second)
        fcntl.flock(first, fcntl.LOCK_UN)
        os.close(first)


@pytest.mark.security
def test_the_error_is_an_oserror_so_errno_and_broad_handlers_survive() -> None:
    """A dedicated type, but not a foreign one."""
    assert issubclass(LockUnavailableError, OSError)
    error = LockUnavailableError(errno.ENOLCK, "probe")
    assert error.errno == errno.ENOLCK
    assert isinstance(error, OSError)


def _clis(tmp_path: Path) -> Iterator[tuple[str, Any, list[str]]]:
    """Every scheduled entry point, with an argv that reaches its lock."""
    root = tmp_path / "lab"
    root.mkdir(exist_ok=True)
    source = tmp_path / "source.log"
    source.write_text("one line\n", encoding="utf-8")
    base = ["--root", str(root), "--caller", "test"]
    yield "run_retention", run_retention, [*base]
    yield "run_collector", run_collector, [*base, "--source", str(source)]
    yield "run_pipeline", run_pipeline, [*base]
    yield "run_backup", run_backup, [*base, "--name", "snapshot"]


@pytest.mark.security
def test_every_cli_exits_2_with_a_message_not_0_with_a_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The end-to-end property, for all four, against the measured pre-fix behaviour.

    Exit 2 specifically, because that is the contract an unusable lock *path*
    already has — ``prepare_lock``'s refusals land there — so an operator reads
    one code for "the lock is not usable" however it failed. A traceback would
    also have been honest and would also have been a regression: this module's
    own history records a raw traceback at exit 1 where the contract says 2 as
    a defect worth fixing.
    """
    for name, module, argv in _clis(tmp_path):
        monkeypatch.setattr(fcntl, "flock", _fail_acquire_with(errno.ENOLCK))
        code = module.main(argv)
        monkeypatch.undo()
        captured = capsys.readouterr()
        assert code == 2, f"{name}: exit {code}, not 2 (pre-fix this was 0)"
        assert "skipped" not in captured.out.lower(), (
            f"{name}: still claims a skip — {captured.out.strip()!r}"
        )
        assert "lock could not be taken" in captured.err, (
            f"{name}: the message does not say the lock failed — {captured.err.strip()!r}"
        )


@pytest.mark.security
def test_a_genuinely_held_lock_still_exits_0_through_the_real_clis(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """And the overlap case end to end, with a real lock held by this process.

    Paired with the test above deliberately: together they say the exit code
    distinguishes the two situations, which is the whole property. Either alone
    is satisfiable by a CLI that always returns the same thing.
    """
    for name, module, argv in _clis(tmp_path):
        root = Path(argv[argv.index("--root") + 1])
        # Hold each CLI's own lock before invoking it. Taken through the
        # shipped helper, so the test cannot hold a different lock than the
        # CLI looks for.
        locks = {
            "run_retention": ("data/events", "retention.lock"),
            "run_collector": ("data/collect", "collect.lock"),
            "run_pipeline": ("data/pipeline", "cycle.lock"),
            "run_backup": ("data/backups", "backup.lock"),
        }
        directory, filename = locks[name]
        holder = prepare_lock(root / directory, filename)
        with single_instance(holder) as held:
            assert held is True, f"{name}: could not hold its lock to set the test up"
            code = module.main(argv)
        assert code == 0, f"{name}: a held lock gave exit {code}, not the benign 0"
        assert "skipped" in capsys.readouterr().out.lower(), f"{name}: no skip reported"
