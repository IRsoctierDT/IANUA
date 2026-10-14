# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The pipeline runs unattended — hold its boundaries closed.

Every other package in this repository is invoked by a human who is watching.
This one is invoked by cron at 03:00 with nobody reading the output, which
changes which failures matter. Three properties therefore get assertions
rather than prose:

* **Containment.** The cursor is the only thing the pipeline writes, and it
  cannot leave the gitignored lab-data root — not via a filename, not via a
  symlink planted where the directory should be. A pipeline that can be
  induced to write outside ``data/`` is a file-write primitive that runs as
  root on a timer.
* **Attribution.** The run is gated and audited before it reads, the audit
  record precedes the cursor advancing, and the identity in that record is
  supplied explicitly — never inherited from whichever account owns the
  scheduler. The repository already contains the environment-reading idiom
  four times in ``agents/tools/llm.py``, so this is asserted over the AST, not
  assumed.
* **Reach.** The ``pipeline`` package imports nothing that could open a socket,
  spawn a process, or read a clock. ``scripts/run_pipeline.py`` is the single
  place any of that is allowed, which is what makes the layers below it
  reproducible.

The AST tests key on the **root module name**, so ``from pipeline.cursor
import Cursor`` stays legal while ``import socket`` can never return.
"""

from __future__ import annotations

import ast
import json
import stat
import sys
from pathlib import Path
from unittest import mock

import pytest
from agents.policies import AUDIT_FIELD_DELIMITER
from pipeline import (
    Cursor,
    CursorError,
    CursorPathError,
    cursor_path,
    load_cursor,
    reference,
    run_cycle,
    save_cursor,
)
from store import EventStore

from ingest import normalize

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PIPELINE_ROOT = _REPO_ROOT / "pipeline"
_CLI = _REPO_ROOT / "scripts" / "run_pipeline.py"

#: The pipeline needs json, hashlib, re, dataclasses and pathlib. Anything that
#: could reach out, spawn, or load code at runtime is permanently out of scope
#: for a package that runs unattended.
_BANNED_IMPORTS = {
    "socket",
    "subprocess",
    "requests",
    "urllib",
    "http",
    "ftplib",
    "telnetlib",
    "smtplib",
    "importlib",
    "ctypes",
    "pickle",
    "shutil",
    "os",
    "time",
    "datetime",
}
_BANNED_CALLS = {"eval", "exec", "compile", "__import__", "system", "popen"}
#: Checked on attribute calls only. ``compile`` is omitted deliberately:
#: ``re.compile`` is both legitimate and present, and banning the bare name is
#: what catches the dangerous builtin.
_BANNED_ATTR_CALLS = _BANNED_CALLS - {"compile"}

_CLOUD = {
    "eventVersion": "1.08",
    "eventSource": "sts.amazonaws.com",
    "eventName": "AssumeRole",
    "eventTime": "2026-10-14T01:00:00Z",
    "awsRegion": "us-east-1",
    "recipientAccountId": "1",
    "userIdentity": {"type": "IAMUser", "userName": "svc-deploy"},
    "sourceIPAddress": "198.51.100.7",
    "eventID": "e1",
}
_ENDPOINT = {"type": "SYSCALL", "node": "web-01", "auid": "svc-deploy", "comm": "bash"}


def _pipeline_modules() -> list[Path]:
    """Every module in the package, recursively.

    ``glob("*.py")`` would leave a subpackage entirely unchecked, so
    ``pipeline/sinks/http.py`` could import ``socket`` and call ``eval`` while
    every invariant below still passed. The ban is on the package, not on its
    top level.
    """
    modules = sorted(_PIPELINE_ROOT.rglob("*.py"))
    assert modules, "no pipeline modules found; the invariant tests would pass vacuously"
    return modules


# --------------------------------------------------------------------------
# Containment: the cursor cannot escape
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize(
    "filename",
    [
        "../cursor.json",
        "../../etc/cron.d/cursor.json",
        "/etc/cron.d/cursor.json",
        "sub/cursor.json",
        "cursor.json/..",
        "",
        ".",
        "..",
        "cursor\x00.json",
        "cursor\n.json",
        "." * 300,
    ],
)
def test_a_cursor_filename_cannot_escape_the_pipeline_directory(
    tmp_path: Path, filename: str
) -> None:
    """The pipeline runs on a timer; a path primitive here is a scheduled one."""
    with pytest.raises(CursorPathError):
        cursor_path(tmp_path, filename=filename)


@pytest.mark.security
def test_a_symlinked_pipeline_directory_cannot_relocate_the_cursor(tmp_path: Path) -> None:
    """Resolve the root then append — not resolve the whole candidate path.

    If the pipeline directory is resolved *before* the comparison, a symlink
    planted there resolves to its own target and the check passes while the
    write lands wherever the link points. That ordering bug is the one this
    test exists for.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "pipeline").symlink_to(outside, target_is_directory=True)
    with pytest.raises(CursorPathError):
        cursor_path(tmp_path)


@pytest.mark.security
def test_a_symlinked_cursor_file_cannot_redirect_the_write(tmp_path: Path) -> None:
    """A link at the cursor's own path is the narrower version of the same attack."""
    target = tmp_path / "elsewhere.json"
    target.write_text("{}", encoding="utf-8")
    directory = tmp_path / "data" / "pipeline"
    directory.mkdir(parents=True)
    (directory / "cursor.json").symlink_to(target)
    with pytest.raises(CursorPathError):
        cursor_path(tmp_path)


@pytest.mark.security
def test_a_symlinked_ancestor_cannot_relocate_the_cursor(tmp_path: Path) -> None:
    """The gap the leaf-only check left open, found by review and reproduced.

    ``CURSOR_SUBDIR`` is two deep (``data/pipeline``). The original check
    examined only the leaf directory and the file, so a link planted at
    ``<root>/data`` was never looked at — and ``mkdir(parents=True)`` then
    created ``pipeline/`` *through* it, putting the cursor outside the lab root
    while every name still looked valid.

    The existence gating made it worse: the check was ``path.exists() and
    path.resolve() != path``, and a link whose target does not yet contain the
    child reports ``exists() is False``, so the one case mkdir goes on to
    create was precisely the case that was skipped.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    (root / "data").symlink_to(outside, target_is_directory=True)
    with pytest.raises(CursorPathError):
        cursor_path(root)
    assert not (outside / "pipeline").exists(), "the cursor directory was created outside the root"


@pytest.mark.security
def test_a_dangling_symlink_at_the_cursor_path_is_refused(tmp_path: Path) -> None:
    """``exists()`` is False for a dangling link, so the old check skipped it."""
    directory = tmp_path / "data" / "pipeline"
    directory.mkdir(parents=True)
    (directory / "cursor.json").symlink_to(tmp_path / "nonexistent.json")
    with pytest.raises(CursorPathError):
        cursor_path(tmp_path)


@pytest.mark.security
def test_the_store_refuses_the_same_symlinked_ancestor(tmp_path: Path) -> None:
    """The pipeline inherited this bug from the store, so both are pinned here.

    ``store/events.py`` had the identical leaf-only, existence-gated check, and
    a link at ``<root>/data`` relocated the whole **evidence database** outside
    the lab root. Asserted alongside the cursor so the two cannot drift: they
    solve one problem and must keep solving it the same way.
    """
    from store import StorePathError

    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    (root / "data").symlink_to(outside, target_is_directory=True)
    with pytest.raises(StorePathError):
        EventStore.open(root)
    assert not (outside / "events").exists(), "the event store was created outside the root"


@pytest.mark.security
def test_two_cycles_cannot_run_at_once(tmp_path: Path) -> None:
    """Concurrency corrupts the audit chain permanently, so it is prevented.

    ``AuditLogger`` derives each record's ``seq`` and ``prev_hash`` by reading
    the last line and appending — a read-modify-write with no locking. Before
    the lock, six concurrent invocations produced a duplicate ``seq``, a forked
    chain, and ``verify()`` returning ``False`` for every future reader, while
    every process exited 0. That is worse than losing records: it puts a false
    positive into a tamper detector.

    Deterministic by construction: the lock is held in-process and a second
    attempt must decline, rather than racing real processes and hoping the
    interleaving shows up.
    """
    from scripts.run_pipeline import _single_instance

    directory = cursor_path(tmp_path).parent
    with _single_instance(directory) as first:
        assert first is True, "the first caller must get the lock"
        with _single_instance(directory) as second:
            assert second is False, "a second cycle acquired the lock concurrently"
    # Released on exit, so the next scheduled run is not locked out forever.
    with _single_instance(directory) as third:
        assert third is True, "the lock was not released"


@pytest.mark.security
def test_a_declined_lock_does_not_exit_nonzero_or_touch_state(tmp_path: Path) -> None:
    """The timer outrunning the cycle is expected, not a failure.

    Exiting non-zero would mail the operator every five minutes on a tight
    schedule, which trains them to ignore it. It must still be visible, and it
    must leave no audit record and no cursor — nothing happened.
    """
    from scripts.run_pipeline import _single_instance, main

    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_CLOUD), normalize(_ENDPOINT)), ingested_at=1000.0)
    directory = cursor_path(tmp_path).parent
    with _single_instance(directory) as held:
        assert held is True
        assert main(["--root", str(tmp_path)]) == 0
    assert not cursor_path(tmp_path).exists(), "a skipped invocation advanced the cursor"
    log = directory / "audit.log"
    assert not log.exists() or log.read_text(encoding="utf-8") == "", (
        "a skipped invocation wrote an audit record for work it did not do"
    )


@pytest.mark.security
def test_an_incident_reference_is_unkeyed_and_therefore_not_evidence(tmp_path: Path) -> None:
    """Asserted functionally, not against a docstring substring.

    The previous version checked that the docstring contained certain words,
    which would have passed on a docstring claiming the opposite. The property
    that matters is that the digest is reproducible by anyone holding the event
    ids — no key, no salt, nothing an attacker who can write the store lacks.
    That is exactly why it deduplicates and exactly why it proves nothing about
    origin; attribution belongs to the hash-chained audit log.
    """
    import hashlib

    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_CLOUD), normalize(_ENDPOINT)), ingested_at=1000.0)
        incident = run_cycle(store).incidents[0]
    recomputed = hashlib.sha256()
    for event_id in sorted(incident.event_ids):
        recomputed.update(event_id.encode("utf-8"))
        recomputed.update(b"\x00")
    assert reference(incident) == recomputed.hexdigest()[:16], (
        "if this needs a secret to recompute it is a MAC, and the docstring is wrong; "
        "if it does not, it is a correlation id and cannot be evidence"
    )


@pytest.mark.security
def test_a_vanished_temp_file_with_no_cursor_written_is_an_error(tmp_path: Path) -> None:
    """The third outcome of the race, and the one that must fail loudest.

    If the temporary file is gone and the destination holds *nothing*, no
    writer put anything there — the file was removed rather than renamed. The
    caller's cursor was not saved, so reporting success would advance a
    pipeline over a window whose progress was never recorded.

    This is the branch that makes the race handling fail-closed rather than a
    swallowed error, so it is tested directly rather than left to inference.
    """
    path = cursor_path(tmp_path)

    def vanish_without_renaming(self: Path, target: object) -> Path:
        if self.name.endswith(".tmp"):
            self.unlink()
            raise FileNotFoundError(2, "No such file or directory", str(self))
        raise AssertionError("unexpected replace target")

    with (
        mock.patch.object(Path, "replace", vanish_without_renaming),
        pytest.raises(CursorError, match="no cursor was written"),
    ):
        save_cursor(path, Cursor(ingested_at=1.0, event_id="abc"))
    assert not path.exists()


@pytest.mark.security
def test_the_cursor_is_written_owner_only(tmp_path: Path) -> None:
    """It names stored evidence; it inherits the audit logger's file posture."""
    path = cursor_path(tmp_path)
    save_cursor(path, Cursor(ingested_at=1.0, event_id="abc"))
    mode = stat.S_IMODE(path.stat().st_mode)
    assert not mode & stat.S_IRGRP and not mode & stat.S_IROTH, f"mode {mode:o} is readable"
    assert not mode & stat.S_IWGRP and not mode & stat.S_IWOTH, f"mode {mode:o} is writable"


@pytest.mark.security
def test_an_interrupted_save_leaves_the_previous_cursor_intact(tmp_path: Path) -> None:
    """Actually interrupt it, rather than asserting a clean save is clean.

    The previous version of this test saved a cursor and checked no temporary
    files remained — which the atomic rename could be deleted entirely and it
    would still pass. It interrupted nothing.

    This crashes the save *between* the temporary write and the rename, which
    is the window the whole temp-file-and-rename dance exists for, and asserts
    the property that matters: a reader sees the OLD cursor, never a partial
    one. A half-written cursor would be refused on the next load, which is
    correct but means the pipeline stops and needs an operator.
    """
    path = cursor_path(tmp_path)
    save_cursor(path, Cursor(ingested_at=1.0, event_id="first"))

    real_replace = Path.replace

    def crash_before_rename(self: Path, target: object) -> Path:
        if self.name.endswith(".tmp"):
            raise OSError("simulated crash between write and rename")
        return real_replace(self, target)  # type: ignore[arg-type]

    with mock.patch.object(Path, "replace", crash_before_rename), pytest.raises(OSError):
        save_cursor(path, Cursor(ingested_at=2.0, event_id="second"))

    survived = load_cursor(path)
    assert survived == Cursor(ingested_at=1.0, event_id="first"), (
        f"an interrupted save left {survived} — the rename was not atomic"
    )
    leftovers = [p.name for p in path.parent.iterdir() if p != path]
    assert leftovers == [], f"the interrupted save left temporary files: {leftovers}"


@pytest.mark.security
def test_a_save_that_loses_an_identical_content_race_does_not_report_failure(
    tmp_path: Path,
) -> None:
    """The temp name is content-keyed, so only an identical writer can take it.

    Finding its temporary file already renamed into place means another writer
    put *the same bytes* there — the outcome this call wanted. Raising would be
    a lie, and the CLI would exit 1 reporting "cursor was not advanced" for a
    cycle that advanced correctly.

    The destination is verified rather than assumed, so a genuine failure still
    fails; the companion test below covers that direction.
    """
    path = cursor_path(tmp_path)
    cursor = Cursor(ingested_at=1000.0, event_id="abc123")
    real_chmod = Path.chmod
    raced = {"done": False}

    def complete_a_rival_save(self: Path, mode: int) -> None:
        if not raced["done"] and self.name.endswith(".tmp"):
            raced["done"] = True
            save_cursor(path, cursor)  # the rival finishes, renaming our temp away
        real_chmod(self, mode)

    with mock.patch.object(Path, "chmod", complete_a_rival_save):
        save_cursor(path, cursor)  # must not raise

    assert load_cursor(path) == cursor
    assert raced["done"], "the race never happened; this test proved nothing"


@pytest.mark.security
def test_a_save_whose_destination_holds_something_else_still_fails(
    tmp_path: Path,
) -> None:
    """Fail-closed: the race is only benign when the bytes actually match."""
    path = cursor_path(tmp_path)
    cursor = Cursor(ingested_at=1000.0, event_id="abc123")
    real_chmod = Path.chmod
    raced = {"done": False}

    def rival_writes_something_else(self: Path, mode: int) -> None:
        if not raced["done"] and self.name.endswith(".tmp"):
            raced["done"] = True
            save_cursor(path, cursor)
            path.write_text(
                json.dumps({"version": 1, "ingested_at": 9.0, "event_id": "other"}),
                encoding="utf-8",
            )
        real_chmod(self, mode)

    with (
        mock.patch.object(Path, "chmod", rival_writes_something_else),
        pytest.raises(CursorError),
    ):
        save_cursor(path, cursor)


# --------------------------------------------------------------------------
# Attribution: gated, audited, explicitly identified
# --------------------------------------------------------------------------


@pytest.mark.security
def test_a_denied_policy_reads_nothing_and_advances_nothing(tmp_path: Path) -> None:
    """The gate must precede the read it authorizes — asserted by behaviour.

    This replaced a pair of ``source.index("enforce(") < source.index(...)``
    checks, which were brittle against a reformat and vacuous against a real
    reordering: moving the gate after the cycle leaves the source order intact
    if the call text shifts. What matters is observable instead — under a deny
    policy, the gate decision is recorded and *nothing else happens*: no
    outcome record, no cursor.
    """
    from scripts.run_pipeline import main

    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_CLOUD), normalize(_ENDPOINT)), ingested_at=1000.0)
    bundle = tmp_path / "deny.json"
    bundle.write_text(json.dumps({"version": 1, "policy": {"read_only": "deny"}}), encoding="utf-8")

    assert main(["--root", str(tmp_path), "--policy", str(bundle)]) == 3

    log = cursor_path(tmp_path).parent / "audit.log"
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert [r["decision"] for r in records] == ["deny"], (
        "a denied cycle must record exactly the gate decision and nothing after it"
    )
    assert not any(r["action"].startswith("pipeline_cycle:") for r in records), (
        "an outcome record means the cycle ran despite the deny"
    )
    assert not cursor_path(tmp_path).exists(), "a denied cycle wrote a cursor"


@pytest.mark.security
def test_the_audit_record_precedes_the_cursor_on_disk(tmp_path: Path) -> None:
    """A consumed window is never unrecorded.

    Also behavioural rather than structural: after a successful cycle the
    outcome record exists and names the cursor it was about to write, and the
    cursor on disk matches it. The ordering is what makes the failure mode
    recoverable — a crash between the two re-reads a window the record already
    described.
    """
    from scripts.run_pipeline import main

    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_CLOUD), normalize(_ENDPOINT)), ingested_at=1000.0)
    assert main(["--root", str(tmp_path)]) == 0

    log = cursor_path(tmp_path).parent / "audit.log"
    outcome = [
        json.loads(line)
        for line in log.read_text(encoding="utf-8").splitlines()
        if json.loads(line)["action"].startswith("pipeline_cycle:")
    ][-1]
    saved = load_cursor(cursor_path(tmp_path))
    assert saved is not None
    assert saved.event_id[:16] in outcome["reason"], (
        "the record must name the cursor it was about to write"
    )


@pytest.mark.security
def test_the_cli_reaches_the_environment_only_for_the_signing_key() -> None:
    """``--caller`` is explicit or absent; identity is never inherited.

    Asserted over the AST because the idiom this forbids already exists in this
    repository — ``field(default_factory=lambda: os.environ.get(...))`` appears
    four times in ``agents/tools/llm.py`` — so a ``$USER`` fallback would read
    as idiomatic while putting an unauthenticated name into a hash-chained,
    signed record.

    The ban is on **reaching the environment at all**, not on a list of
    variable names. An earlier version of this test checked a set of
    well-known names (``USER``, ``SUDO_USER``, …) and so passed happily on
    ``os.environ.get("IANUA_OPERATOR")`` — the same defect under a name nobody
    had thought to enumerate. A guard that only catches the examples its author
    imagined is not a guard.

    ``signing_key_from_env`` is the one sanctioned exception, and it is named
    rather than pattern-matched: a *key* must come from the environment
    (AGENTS.md §5 forbids it in source), while an *identity* must not.
    """
    tree = ast.parse(_CLI.read_text(encoding="utf-8"), filename=str(_CLI))
    for node in ast.walk(tree):
        # os.environ / os.getenv / os.environb, in any call or subscript form.
        if isinstance(node, ast.Attribute):
            assert node.attr not in {"environ", "environb", "getenv"}, (
                f"the CLI reaches the process environment via .{node.attr}; only "
                "signing_key_from_env may, and an identity never may"
            )
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] != "os", (
                    "the CLI imports os; the environment is reachable from it"
                )
        if isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            if root == "os":
                raise AssertionError("the CLI imports from os")
            # `from agents.policies.audit import signing_key_from_env` is the
            # sanctioned path and is allowed; any other *_from_env is not.
            for alias in node.names:
                assert alias.name in {"signing_key_from_env"} or not alias.name.endswith(
                    "_from_env"
                ), f"{alias.name} is an environment-sourced value other than the signing key"


@pytest.mark.security
def test_an_audited_identity_cannot_carry_the_hash_delimiter() -> None:
    """The forgery primitive this platform already fixed, re-asserted here.

    The audit preimage is an unescaped ``|`` join, so a principal containing
    one lets a writer forge a different field split. The CLI builds its
    principal from ``--caller``, which is operator-supplied, so the guard has
    to hold at this boundary and not only inside ``audit.record``.
    """
    from agents.policies import Principal, PrincipalError

    with pytest.raises(PrincipalError):
        Principal("pipeline", f"ivan{AUDIT_FIELD_DELIMITER}root")


# --------------------------------------------------------------------------
# Reach: no socket, no subprocess, no clock
# --------------------------------------------------------------------------


@pytest.mark.security
def test_the_pipeline_imports_nothing_that_could_reach_out_or_execute() -> None:
    """Keyed on the root module name, so intra-package imports stay legal."""
    for path in _pipeline_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert root not in _BANNED_IMPORTS, f"{path.name}: imports {alias.name}"
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                assert root not in _BANNED_IMPORTS, f"{path.name}: imports from {node.module}"


@pytest.mark.security
def test_the_pipeline_calls_no_executor() -> None:
    for path in _pipeline_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in _BANNED_CALLS, f"{path.name}: calls {node.func.id}()"
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in _BANNED_ATTR_CALLS, (
                    f"{path.name}: calls .{node.func.attr}()"
                )


@pytest.mark.security
def test_the_pipeline_reads_no_clock() -> None:
    """The window is the cursor, never "the last five minutes".

    A time-ranged window is what lets a slow run silently widen its window or
    a clock skew silently narrow it. Keeping the clock out of the package
    makes that class of bug unrepresentable, and keeps every cycle
    reproducible in a test.
    """
    forbidden = {"now", "utcnow", "today", "time", "monotonic", "time_ns", "perf_counter"}
    for path in _pipeline_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in forbidden, (
                    f"{path.name}: reads the clock via .{node.func.attr}()"
                )


@pytest.mark.security
def test_the_pipeline_adds_no_runtime_dependency() -> None:
    """``dependencies = []`` stays load-bearing; the pipeline is stdlib-only."""
    import tomllib

    config = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["project"]["dependencies"] == []


# --------------------------------------------------------------------------
# Fail-closed behaviour of the cycle itself
# --------------------------------------------------------------------------


@pytest.mark.security
def test_a_cycle_persists_nothing_so_reprocessing_is_safe(tmp_path: Path) -> None:
    """At-least-once is only safe because the cycle writes no state.

    If ``run_cycle`` appended incidents anywhere, a replayed window would
    duplicate them on disk and the at-least-once trade would stop being free.
    Asserted by running the same window twice and comparing the whole tree.
    """
    with EventStore.open(tmp_path) as store:
        store.append_many(
            tuple(normalize(record) for record in (_CLOUD, _ENDPOINT)), ingested_at=1000.0
        )

        def snapshot() -> dict[str, int]:
            return {
                str(p.relative_to(tmp_path)): p.stat().st_size
                for p in sorted(tmp_path.rglob("*"))
                if p.is_file()
            }

        before = snapshot()
        first = run_cycle(store)
        after = snapshot()
    assert first.events_read == 2
    assert before == after, f"the cycle wrote state: {set(after) ^ set(before)}"


@pytest.mark.security
def test_a_window_is_bounded_even_when_the_caller_asks_for_everything(
    tmp_path: Path,
) -> None:
    """An unbounded read is how a scheduled job becomes an outage."""
    from store import MAX_QUERY_LIMIT

    records = tuple(
        {"type": "SYSCALL", "node": f"web-{index:02d}", "auid": "svc-deploy", "comm": "bash"}
        for index in range(5)
    )
    with EventStore.open(tmp_path) as store:
        store.append_many(tuple(normalize(r) for r in records), ingested_at=1000.0)
        # Seeded with more than one event on purpose: with a single event every
        # clamp can be deleted at both layers and the assertion still holds.
        result = run_cycle(store, batch=MAX_QUERY_LIMIT * 1000)
        clamped = run_cycle(store, batch=2)
    assert result.events_read == 5
    assert clamped.events_read == 2, "the batch bound was not applied"


@pytest.mark.security
def test_importing_the_cli_runs_no_cycle() -> None:
    """Importing the module must do nothing, observed in a fresh interpreter.

    Two earlier versions of this test were weak and the second was wrong in an
    instructive way. The first opened with ``assert
    os.environ.get("IANUA_PIPELINE_RAN") is None`` — a variable nothing ever
    sets, so it could never fail. The second imported the module and asserted a
    ``tmp_path`` was untouched, which misses the real case entirely: an
    import-time ``main([])`` runs against the **default** root, so it would
    scribble in the repository while the assertion watched an empty temp
    directory and passed.

    So this imports in a subprocess and asserts the import produced **no
    output**. A cycle always prints — either ``idle:`` or ``read N event(s)`` —
    so silence is the observable form of "did nothing", wherever it would have
    run. ``scripts/`` modules are importable, and a tool doing work at import
    time would do it from any test, linter or doc build that touched it.
    """
    import subprocess

    result = subprocess.run(
        [sys.executable, "-c", "import scripts.run_pipeline; print('IMPORT-OK')"],
        capture_output=True,
        text=True,
        cwd=_REPO_ROOT,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, f"importing the CLI failed: {result.stderr[-400:]}"
    assert result.stdout.strip() == "IMPORT-OK", (
        "importing the CLI produced output, so it did work at import time: "
        f"{result.stdout.strip()!r}"
    )
    # The entry point exists but was not called.
    assert (
        "main"
        in subprocess.run(
            [
                sys.executable,
                "-c",
                "import scripts.run_pipeline as m; print('main' if callable(m.main) else '')",
            ],
            capture_output=True,
            text=True,
            cwd=_REPO_ROOT,
            timeout=120,
            check=False,
        ).stdout
    )
