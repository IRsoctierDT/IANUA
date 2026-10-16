# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""A busy store and a broken store must not report the same exit code.

``1`` used to mean both, and ``docs/RETENTION.md`` carried a paragraph warning
an operator about the conflation instead of the code resolving it. These tests
are what let that paragraph be deleted.

**The contention is real in every case here.** A held ``BEGIN IMMEDIATE`` on
the store's own database file is a genuine second writer, which is how this
arises on a node where the collector and a prune overlap. Only the *busy
timeout* is shortened, by patching ``sqlite3.connect`` to pass ``timeout``:
without it each case waits out Python's 5.0 s default, and a suite that takes
20 s to assert four exit codes would get skipped rather than run. The
exception the code sees is the same ``SQLITE_BUSY`` either way — measured, a
0.60 s real expiry reports the identical primary.

What is deliberately *not* asserted here: ``run_pipeline`` and ``run_backup``
reaching ``4``. Measured with a real held write transaction, neither does —
the pipeline's store access is a read, and a WAL reader does not block on a
writer, while ``Connection.backup`` **succeeded** under the held writer and
exited 0. Their branches are defence in depth against a write path that is not
reachable today, so claiming a measured behaviour for them would be the kind
of unsupported claim this suite exists to catch.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from ingest import normalize
from pipeline import Cursor, cursor_path, save_cursor
from scripts import run_collector, run_retention
from scripts._exit_codes import EXIT_RETRYABLE
from store import EventStore, Query

#: One real auditd record, as the retention suite seeds with. Real rather than
#: synthetic so the store exercises its actual projection and content hash.
_RECORD = 'type=USER_AUTH msg=audit(1760000000.1:1): acct="svc-deploy" addr=203.0.113.9 res=failed'

#: Captured before the fixture patches the name, so the holder connection and
#: the restore both use the genuine one.
_REAL_CONNECT: Callable[..., sqlite3.Connection] = sqlite3.connect


@contextmanager
def _busy_store(root: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Hold the store's write lock, as a concurrent pass on a busy node does."""
    database = root / "data" / "events" / "events.sqlite3"
    assert database.is_file(), "no store to contend for — the fixture did not seed one"
    holder = _REAL_CONNECT(database)
    try:
        holder.execute("BEGIN IMMEDIATE")
        # A statement that takes the write lock without changing anything, so
        # the contention is the only thing this fixture contributes.
        holder.execute("DELETE FROM meta WHERE key = '__no_such_key__'")

        def _impatient(*args: Any, **kwargs: Any) -> sqlite3.Connection:
            kwargs.setdefault("timeout", 0.2)
            return _REAL_CONNECT(*args, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", _impatient)
        yield
    finally:
        monkeypatch.undo()
        holder.rollback()
        holder.close()


def _seed(root: Path, *, old: int = 5, recent: int = 3) -> None:
    """Events old enough to prune, and a cursor saying the cycle has seen them.

    Both halves are load-bearing: retention clamps its threshold to the
    pipeline cursor, so a root without one prunes nothing and would exit 0
    before ever touching the write lock — measuring the clamp instead of the
    contention. Written against the same API the retention unit suite uses
    (``store.next_stamp`` and ``save_cursor``) rather than a hand-rolled
    equivalent, so this fixture cannot drift from the real write path.
    """
    now = time.time()
    with EventStore.open(root) as store:
        for index in range(old):
            store.append(
                normalize(_RECORD.replace("svc-deploy", f"old{index}")),
                ingested_at=store.next_stamp(now - 200 * 86_400 + index),
            )
        for index in range(recent):
            store.append(
                normalize(_RECORD.replace("svc-deploy", f"new{index}")),
                ingested_at=store.next_stamp(now - 3_600 + index),
            )
        held = store.count()
        assert held == old + recent, f"seeded {held}, wanted {old + recent}"
        # The cursor goes on the NEWEST event: a caught-up cycle, so the clamp
        # permits the whole window and the prune genuinely attempts a write.
        reached = store.query(Query(limit=held, newest_first=False))[-1]
    save_cursor(
        cursor_path(root),
        Cursor(ingested_at=reached.ingested_at, event_id=reached.event_id),
    )


def _granted(tmp_path: Path, *labels: str) -> Path:
    """The committed policy bundle with exactly ``labels`` granted."""
    repo = Path(__file__).resolve().parents[2]
    bundle = json.loads((repo / "agents" / "policies" / "policy.json").read_text(encoding="utf-8"))
    bundle["allow"] = list(labels)
    path = tmp_path / "granted.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return path


def _held(root: Path) -> int:
    with EventStore.open(root) as store:
        return store.count()


@pytest.mark.security
def test_a_busy_store_stops_retention_at_4_with_every_event_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The headline case: a prune that could not get the lock deleted nothing.

    The count assertion is the half that matters. ``4`` means "retry, nothing
    is broken", and that is only honest if the pass genuinely left the store
    alone — an exit code promising safety over a partial delete would be worse
    than the conflation it replaces.
    """
    root = tmp_path / "root"
    root.mkdir()
    _seed(root)
    before = _held(root)
    argv = [
        "--root",
        str(root),
        "--caller",
        "test",
        "--apply",
        "--policy",
        str(_granted(tmp_path, "retain_events:apply")),
    ]

    with _busy_store(root, monkeypatch):
        code = run_retention.main(argv)

    assert code == EXIT_RETRYABLE, f"a busy store reported {code}, not {EXIT_RETRYABLE}"
    assert _held(root) == before, "a 'retry, nothing is broken' exit deleted events"
    assert "busy" in capsys.readouterr().err.lower(), "the message does not say what happened"


@pytest.mark.security
def test_a_busy_store_stops_the_collector_at_4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The collector reaches ``4`` by its partial-progress path, not its outer one.

    Its per-source handler records the failure and carries on, so the decision
    is made after the audit, the report and the offset save. That is the path
    exercised here, and the one where "retry" is most clearly right: a retry
    re-reads only the source that was busy.
    """
    root = tmp_path / "root"
    root.mkdir()
    _seed(root)
    source = tmp_path / "source.log"
    source.write_text("one line\n", encoding="utf-8")
    argv = ["--root", str(root), "--caller", "test", "--source", str(source)]

    with _busy_store(root, monkeypatch):
        code = run_collector.main(argv)

    assert code == EXIT_RETRYABLE, f"a busy store reported {code}, not {EXIT_RETRYABLE}"
    assert "locked" in capsys.readouterr().err.lower()


@pytest.mark.security
def test_a_damaged_store_is_still_1_and_never_4(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The fail-open direction, asserted rather than assumed.

    Reporting damage as retryable would have a scheduler retry a corrupt store
    forever while nothing ever pages — strictly worse than the conflation this
    change removes. So the damaged case is pinned alongside the busy one.
    """
    root = tmp_path / "root"
    root.mkdir()
    _seed(root)
    database = root / "data" / "events" / "events.sqlite3"
    database.write_bytes(b"not a database at all" * 64)

    code = run_retention.main(["--root", str(root), "--caller", "test"])

    assert code == 1, f"a damaged store reported {code}; only contention may report 4"
    assert code != EXIT_RETRYABLE
    assert capsys.readouterr().err.startswith("error: ")
