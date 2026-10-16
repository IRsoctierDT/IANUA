# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""``is_retryable_contention`` must tell "busy" from "broken", and nothing else.

The exceptions here are **provoked, not constructed**. A hand-built
``sqlite3.OperationalError("database is locked")`` carries no
``sqlite_errorcode`` at all, so a suite built from those would pass against a
predicate that always returned ``True`` — and would never notice that the
production path reports a plain primary rather than an extended one. Every
decisive case below comes from a real contended or real damaged database.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from scripts._exit_codes import EXIT_RETRYABLE, is_retryable_contention
from scripts._locking import LOCK_UNAVAILABLE_MESSAGE


def _busy_error(tmp_path: Path) -> sqlite3.Error:
    """Provoke a genuine ``SQLITE_BUSY`` by contending for the write lock."""
    database = tmp_path / "busy.sqlite3"
    holder = sqlite3.connect(database)
    holder.execute("PRAGMA journal_mode=WAL")
    holder.execute("CREATE TABLE t (x INTEGER)")
    holder.commit()
    holder.execute("BEGIN IMMEDIATE")
    holder.execute("INSERT INTO t VALUES (1)")
    # ``timeout=0`` only makes the wait instant; the contention is real either
    # way, and a 0.6 s real expiry was measured to report the same primary.
    second = sqlite3.connect(database, timeout=0)
    try:
        second.execute("BEGIN IMMEDIATE")
        second.execute("INSERT INTO t VALUES (2)")
    except sqlite3.Error as exc:
        return exc
    finally:
        second.close()
        holder.rollback()
        holder.close()
    raise AssertionError("the second writer was not refused — no contention to test")


def _corruption_error(tmp_path: Path) -> sqlite3.Error:
    """Provoke a genuine ``SQLITE_NOTADB``, the case that must NOT be retried."""
    database = tmp_path / "garbage.sqlite3"
    database.write_bytes(b"this is definitely not a database file" * 8)
    try:
        sqlite3.connect(database).execute("SELECT count(*) FROM sqlite_master")
    except sqlite3.Error as exc:
        return exc
    raise AssertionError("the garbage file opened cleanly — no damage to test")


@pytest.mark.unit
def test_a_real_busy_error_is_contention(tmp_path: Path) -> None:
    """The case the whole change exists for, from a real second writer."""
    exc = _busy_error(tmp_path)
    assert exc.sqlite_errorcode & 0xFF == sqlite3.SQLITE_BUSY
    assert is_retryable_contention(exc) is True


@pytest.mark.unit
def test_a_real_corruption_error_is_not_contention(tmp_path: Path) -> None:
    """The fail-open direction, which matters more than the fix itself.

    Reporting damage as retryable would have a scheduler retry a corrupt store
    forever while nothing pages. This is the assertion that forbids it.
    """
    exc = _corruption_error(tmp_path)
    assert exc.sqlite_errorcode & 0xFF == sqlite3.SQLITE_NOTADB
    assert is_retryable_contention(exc) is False


#: Every extended name sqlite3 exposes for the two contention primaries, with
#: the primary each one masks to. Measured on this build; the point of the
#: table is that a *name*-based predicate would need all seven and would miss
#: an eighth, while masking the low byte is the rule the names follow.
_CONTENTION_CODES = (
    ("SQLITE_BUSY", sqlite3.SQLITE_BUSY, 5),
    ("SQLITE_BUSY_RECOVERY", sqlite3.SQLITE_BUSY_RECOVERY, 5),
    ("SQLITE_BUSY_SNAPSHOT", sqlite3.SQLITE_BUSY_SNAPSHOT, 5),
    ("SQLITE_BUSY_TIMEOUT", sqlite3.SQLITE_BUSY_TIMEOUT, 5),
    ("SQLITE_LOCKED", sqlite3.SQLITE_LOCKED, 6),
    ("SQLITE_LOCKED_SHAREDCACHE", sqlite3.SQLITE_LOCKED_SHAREDCACHE, 6),
    ("SQLITE_LOCKED_VTAB", sqlite3.SQLITE_LOCKED_VTAB, 6),
)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("name", "code", "primary"), _CONTENTION_CODES, ids=[c[0] for c in _CONTENTION_CODES]
)
def test_every_extended_contention_code_is_admitted(name: str, code: int, primary: int) -> None:
    """An extended code refines a primary; it does not change what it means."""
    assert code & 0xFF == primary, f"{name} does not mask to {primary}"
    exc = sqlite3.OperationalError("provoked")
    exc.sqlite_errorcode = code
    exc.sqlite_errorname = name
    assert is_retryable_contention(exc) is True, f"{name} was not admitted"


#: Primaries that must be refused. ``SQLITE_CORRUPT``/``SQLITE_NOTADB`` are
#: damage; the rest are a caller or schema problem, which retrying cannot fix.
_REFUSED_CODES = (
    ("SQLITE_CORRUPT", sqlite3.SQLITE_CORRUPT),
    ("SQLITE_NOTADB", sqlite3.SQLITE_NOTADB),
    ("SQLITE_READONLY", sqlite3.SQLITE_READONLY),
    ("SQLITE_CONSTRAINT", sqlite3.SQLITE_CONSTRAINT),
    ("SQLITE_ERROR", sqlite3.SQLITE_ERROR),
    ("SQLITE_FULL", sqlite3.SQLITE_FULL),
)


@pytest.mark.unit
@pytest.mark.parametrize(("name", "code"), _REFUSED_CODES, ids=[c[0] for c in _REFUSED_CODES])
def test_everything_else_keeps_its_own_meaning(name: str, code: int) -> None:
    """Including ``SQLITE_FULL``: a full disk is not fixed by trying again."""
    exc = sqlite3.OperationalError("provoked")
    exc.sqlite_errorcode = code
    exc.sqlite_errorname = name
    assert is_retryable_contention(exc) is False, f"{name} was wrongly admitted"


@pytest.mark.unit
def test_an_error_without_a_code_is_refused() -> None:
    """Absent means "cannot show this is contention", which fails to the safe side.

    ``sqlite_errorcode`` is set by the engine, so an exception raised by
    anything else — a test double, a wrapper, a future library — has none. The
    predicate must not treat that as permission to retry.
    """
    assert is_retryable_contention(sqlite3.Error("no code at all")) is False
    assert is_retryable_contention(sqlite3.OperationalError("database is locked")) is False, (
        "the MESSAGE must not be what decides it — a hand-built error carries "
        "no errorcode, and matching on text would admit this"
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "exc",
    [OSError("disk"), ValueError("bad"), KeyError("k"), RuntimeError("x")],
    ids=["OSError", "ValueError", "KeyError", "RuntimeError"],
)
def test_a_non_sqlite_exception_is_refused(exc: BaseException) -> None:
    """The clauses this serves catch four or five types at once."""
    assert is_retryable_contention(exc) is False


@pytest.mark.unit
def test_the_exit_code_collides_with_nothing_already_in_use() -> None:
    """``4`` because ``3`` was taken, which the first version of this plan missed.

    Asserted against the shipped CLIs rather than a remembered list: the codes
    in use are read out of the sources, so a future ``return 4`` elsewhere for
    a different meaning fails here.
    """
    assert EXIT_RETRYABLE == 4
    scripts = Path(__file__).resolve().parents[2] / "scripts"
    offenders = {
        path.name
        for path in scripts.glob("*.py")
        if path.name != "_exit_codes.py"
        and "return 4" in path.read_text(encoding="utf-8")
        and "EXIT_RETRYABLE" not in path.read_text(encoding="utf-8")
    }
    assert not offenders, f"{sorted(offenders)} return 4 for something other than contention"


#: Phrases by which an operator-facing document enumerates the policy-blocking
#: exit code. Whichever one a document uses, ``4`` has to be enumerated beside
#: it — the set is the contract, and half the contract is worse than none.
_POLICY_BLOCK_PHRASES = ("blocked by policy", "policy blocks", "if policy")


@pytest.mark.unit
def test_no_document_enumerates_the_exit_set_without_4() -> None:
    """Wherever a document lists the scheduled CLIs' exit codes, ``4`` is in the list.

    Keyed on the *content* a document must contain, not on the phrasing it
    happens to use, and that distinction is the whole reason this exists. The
    sweep done by hand for this change searched for the phrase "exit codes" and
    found three documents; it **missed** ``docs/RESTORE.md``, which spells the
    same contract as prose — "Exit ``0`` on success, ``1`` on failure, ``2`` on
    bad arguments, ``3`` if policy blocks it" — and review caught it. The same
    class of miss had already happened once on the HA decision record, where one
    of two rows in a single file was corrected and the other left contradicting
    it.

    So the rule is anchored on the one thing every such enumeration contains: a
    policy-blocking exit. If a document names one, ``4`` must appear near it.
    """
    repo = Path(__file__).resolve().parents[2]
    documents = sorted([*(repo / "docs").glob("*.md"), repo / "README.md"])
    assert documents, "no documents found to check"

    missing: list[str] = []
    for path in documents:
        # Whitespace-flattened before searching, and that is a repair rather
        # than a flourish. Measured: rewrapping one of
        # ``docs/PRODUCTION_SOC_PLAN.md``'s two enumerations so that "blocked
        # by" ended a line dropped it out of this gate entirely — the phrase
        # count went 2 → 1 and the test stayed green, because a contract split
        # across a newline matches no anchor. An ordinary reflow could have
        # done it, which makes it an evasion nobody has to intend.
        text = " ".join(path.read_text(encoding="utf-8").split())
        lowered = text.lower()
        for phrase in _POLICY_BLOCK_PHRASES:
            start = 0
            while (found := lowered.find(phrase, start)) != -1:
                start = found + len(phrase)
                # A window rather than the whole file: a document may mention a
                # policy block in one place and exit codes in another without
                # the two being one contract, and a whole-file check would pass
                # on that coincidence.
                window = text[max(0, found - 500) : found + 500]
                if "`4`" not in window:
                    line = text[:found].count("\n") + 1
                    missing.append(f"{path.relative_to(repo)}:{line} ({phrase!r})")

    assert not missing, (
        "these documents enumerate a policy-blocking exit code without `4` beside it, "
        "so an operator reading them cannot tell retryable contention from damage: "
        f"{missing}"
    )


#: Every place that states the scheduled CLIs' exit-code contract to an
#: operator. Committed by hand rather than discovered, because a discovered set
#: is only as good as its detector and this one is checked for completeness
#: separately below — which is the half that keeps the list from going stale.
#:
#: ``DESIGN.md`` is deliberately absent. Its decision rows record *why* the
#: contract is what it is, as of the day it was decided; they are a historical
#: log and are not rewritten when a contract gains a clause.
_EXIT_CONTRACTS = (
    "docs/PRODUCTION_SOC_PLAN.md",
    "docs/RESTORE.md",
    "docs/RETENTION.md",
    "scripts/_exit_codes.py",
    "scripts/run_backup.py",
    "scripts/run_collector.py",
    "scripts/run_pipeline.py",
    "scripts/run_retention.py",
)


@pytest.mark.unit
@pytest.mark.parametrize("relative", _EXIT_CONTRACTS, ids=_EXIT_CONTRACTS)
def test_every_exit_contract_names_the_lock_that_could_not_be_taken(relative: str) -> None:
    """A condition reachable at ``2`` must appear in what ``2`` is documented to mean.

    The defect this pins was found by challenging a decision rather than by a
    gate. ``single_instance`` now returns exit ``2`` when ``flock`` fails for
    any reason other than contention — and **none of these eight files
    mentioned a lock at all**. All four CLI docstrings, this module's own
    table, ``docs/RETENTION.md``, ``docs/RESTORE.md`` and
    ``docs/PRODUCTION_SOC_PLAN.md`` twice said "bad arguments", so an operator
    who got a ``2`` from a broken lock would have read the documented meaning
    and gone looking at their argv.

    Asserted against the **literal the code emits**, imported rather than
    retyped, so the message an operator reads and the contract they look it up
    in cannot drift apart by paraphrase. Whole-file rather than windowed on
    purpose: the list is committed, so the coincidence a window guards against
    cannot arise.

    Whitespace-flattened, for the reason the sweep below now is — and the first
    version of this test was *written* with the defect it had just repaired
    there. It went red on four of the eight files, every one of them because
    the phrase had been wrapped across a line by the same edit that added it.
    A contract does not stop naming a condition because the sentence broke.
    """
    path = Path(__file__).resolve().parents[2] / relative
    flattened = " ".join(path.read_text(encoding="utf-8").split())
    assert LOCK_UNAVAILABLE_MESSAGE in flattened, (
        f"{relative} states the exit-code contract without naming the lock failure "
        f"that reaches exit 2 — an operator reading it is told to check their arguments"
    )


@pytest.mark.unit
def test_the_committed_list_of_exit_contracts_is_complete() -> None:
    """A ninth place that states the contract fails here rather than going stale.

    The other half of the test above: that one is exact because its list is
    committed, and a committed list is worthless if nothing notices a new
    member. Anchored on the one clause every such enumeration contains — a
    policy-blocking exit — over the same scope the document sweep walks plus
    ``scripts/``.
    """
    repo = Path(__file__).resolve().parents[2]
    scope = sorted(
        [*(repo / "docs").glob("*.md"), repo / "README.md", *(repo / "scripts").glob("*.py")]
    )
    found = {
        str(path.relative_to(repo))
        for path in scope
        if any(
            phrase in " ".join(path.read_text(encoding="utf-8").split()).lower()
            for phrase in _POLICY_BLOCK_PHRASES
        )
    }
    assert found == set(_EXIT_CONTRACTS), (
        "the set of files stating the exit-code contract has changed; add or remove it in "
        f"_EXIT_CONTRACTS so the assertion above covers it. Added: {sorted(found - set(_EXIT_CONTRACTS))}. "
        f"Gone: {sorted(set(_EXIT_CONTRACTS) - found)}"
    )
