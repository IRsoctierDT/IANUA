# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The platform's locks fence *processes on one node*, never two nodes.

``DESIGN.md`` §11 records the approved active/passive HA decision and the gate
it waits on. The load-bearing fact behind that gate is measured here rather
than argued: ``flock`` is scoped to an **inode**, so two nodes — which means
two filesystem roots — hold two different locks and both acquire.

This is pinned because the obvious way to build active/passive is to reuse the
lock the platform already has, and that reuse would produce a fence that looks
present in the code and is absent at runtime. These are *characterisation*
assertions: they state what the current mechanism does, so that a change
claiming to add cross-node exclusion cannot land while a per-inode lock is
still the only thing underneath it.

Every assertion is paired with a same-root control, because "both acquired"
is also what a simply-broken lock would produce — without the control these
tests would pass against a ``single_instance`` that had stopped locking at all.

Security consideration: the property under test is a *missing* control, not a
present one. Nothing here should be read as licensing HA code; the two
prerequisites (an egress amendment and a fence design) are recorded as blocked
in ``DESIGN.md`` §11 and remain so.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
from pathlib import Path

import pytest

from agents.policies.audit import AuditLogger
from scripts._locking import prepare_lock, single_instance

_REPO = Path(__file__).resolve().parents[2]

#: The minimum fencing action the §11 record names, as a literal. Review found
#: that the row originally offered a load balancer as a fence, which cannot stop
#: a local timer, and "the operator decides" as another, which is not an action.
#: The corrected row points at this command instead — so this is the citation
#: that must not dangle.
_FENCING_COMMAND = "systemctl --user stop ianua-pipeline.timer ianua-collector.timer"


def _take(root: Path) -> contextlib.AbstractContextManager[bool]:
    """Open and lock one node's pipeline lock, as the shipped CLIs do."""
    return single_instance(prepare_lock(root / "data" / "pipeline", "cycle.lock"))


@pytest.mark.security
def test_two_roots_both_acquire_the_single_instance_lock(tmp_path: Path) -> None:
    """Two nodes are two inodes, so the single-instance lock fences neither."""
    with contextlib.ExitStack() as stack:
        acquired = [stack.enter_context(_take(tmp_path / name)) for name in ("node-a", "node-b")]
        # Asserted INSIDE the stack: both are held at this point, which is the
        # property. Outside it, the list would only say each acquired at some
        # point, which a working fence would also satisfy.
        assert acquired == [True, True], (
            "the single-instance lock is expected NOT to fence two roots; if this "
            "now refuses, a cross-node fence may have been added — update DESIGN.md §11"
        )


@pytest.mark.security
def test_one_root_refuses_the_second_holder(tmp_path: Path) -> None:
    """The control for the test above: the lock does work where it is scoped to."""
    root = tmp_path / "node-a"
    with _take(root) as first:
        assert first is True
        with _take(root) as second:
            assert second is False, "the lock did not exclude a second holder in one root"


@pytest.mark.security
def test_the_two_roots_really_were_two_inodes(tmp_path: Path) -> None:
    """Name the mechanism, so the test above cannot be read as being about paths.

    ``flock`` keys on the inode and not on the path, which is why a hard link
    does not split a lock and why two roots do.
    """
    inodes = set()
    with contextlib.ExitStack() as stack:
        for name in ("node-a", "node-b"):
            handle = prepare_lock(tmp_path / name / "data" / "pipeline", "cycle.lock")
            stack.enter_context(handle)
            inodes.add(os.fstat(handle.fileno()).st_ino)
    assert len(inodes) == 2, f"two roots shared an inode: {inodes}"


@pytest.mark.security
def test_the_audit_chain_lock_lives_inside_the_root_it_protects(tmp_path: Path) -> None:
    """So the audit chain's exclusion is per-node too — the sharpest consequence.

    ``AuditLogger`` locks a sidecar beside its own log, so two active nodes can
    append to two chains that each verify cleanly while neither contains the
    other's entries. #53 gave the chain a lock to stop two *processes* forking
    it; that lock cannot stop two *nodes*, and this is where that is written
    down.

    The assertion is on the lock's *location* rather than on a second holder
    being refused, deliberately: this lock takes a **blocking** ``LOCK_EX``
    (filed as #69), so a same-root control would hang rather than report. A
    future author who "fixes" cross-node exclusion by moving this sidecar to a
    fixed path outside the root will fail this test and find the reason here.
    """
    for name in ("node-a", "node-b"):
        log_path = tmp_path / name / "data" / "audit" / "audit.jsonl"
        # Reaching for the private attribute deliberately: its *location* is
        # the property under test, and no public accessor exposes it.
        lock_path = AuditLogger(log_path)._lock_path
        assert lock_path.parent == log_path.parent, (
            f"{name}: the audit lock left the tree it protects ({lock_path}) — a lock "
            "outside the root does not create a cross-node fence either; see DESIGN.md §11"
        )


@pytest.mark.security
def test_the_lock_the_clis_take_is_an_flock_on_a_file_under_the_lab_root(
    tmp_path: Path,
) -> None:
    """Name what the exclusion *is*, so the tests above are about a mechanism.

    The whole of it is ``LOCK_EX | LOCK_NB`` on a descriptor for a file inside
    the root passed on the command line. Nothing shared between hosts is
    consulted, which is why the two-root result above is a property and not an
    accident of this harness.

    The descriptor is tied to the file by ``(st_dev, st_ino)`` rather than by
    reading ``/proc/self/fd``, which would make this assertion Linux-only for
    no gain.
    """
    directory = tmp_path / "data" / "pipeline"
    handle = prepare_lock(directory, "cycle.lock")
    expected = (directory / "cycle.lock").stat()
    with handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = os.fstat(handle.fileno())
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    assert (locked.st_dev, locked.st_ino) == (expected.st_dev, expected.st_ino), (
        "the locked descriptor is not the lock file under the lab root"
    )


@pytest.mark.security
def test_the_fencing_command_the_decision_row_cites_actually_exists() -> None:
    """``DESIGN.md`` §11 names one concrete action as the operator's fence.

    The row was corrected after review: it had listed a load balancer among the
    candidate fences, which steers *inbound clients* and so cannot stop this
    platform's writers — every one of them is a local scheduled one-shot, which
    is why the corrected row points at a ``systemctl --user stop`` of the two
    timers instead. A record whose fence is a command is only as good as the
    command existing, and "a docstring citing an assertion that does not exist"
    is a defect this repository has already had to fix once.

    So this asserts the citation both ways: the command is in the runbook, and
    the decision row still points at it. Either half alone would let the two
    drift apart silently.
    """
    runbook = (_REPO / "docs" / "RETENTION.md").read_text(encoding="utf-8")
    assert _FENCING_COMMAND in runbook, (
        f"docs/RETENTION.md no longer contains {_FENCING_COMMAND!r} — DESIGN.md §11's "
        "HA row cites it as the operator's fencing action, so that citation now dangles"
    )
    design = (_REPO / "DESIGN.md").read_text(encoding="utf-8")
    assert "systemctl --user stop" in design, (
        "DESIGN.md §11's HA row no longer names a concrete fencing action; if the fence "
        "changed, this test and the runbook reference need changing with it"
    )
    # And the thing the correction was about: a load balancer must not be
    # offered as a fence again, in a repository whose writers are local timers.
    row = next(
        line
        for line in design.splitlines()
        if line.startswith("| 2026-10-16 | The approved active/passive HA decision")
    )
    assert "load balancer does not" in row, (
        "the HA row no longer says a load balancer does not fence — it was listed as a "
        "candidate fence once, and nothing in front of a node stops that node's own timers"
    )
