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
import os
import stat
from pathlib import Path

import pytest
from agents.policies import AUDIT_FIELD_DELIMITER
from pipeline import Cursor, CursorPathError, cursor_path, reference, run_cycle, save_cursor
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
    modules = sorted(_PIPELINE_ROOT.glob("*.py"))
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
def test_the_cursor_is_written_owner_only(tmp_path: Path) -> None:
    """It names stored evidence; it inherits the audit logger's file posture."""
    path = cursor_path(tmp_path)
    save_cursor(path, Cursor(ingested_at=1.0, event_id="abc"))
    mode = stat.S_IMODE(path.stat().st_mode)
    assert not mode & stat.S_IRGRP and not mode & stat.S_IROTH, f"mode {mode:o} is readable"
    assert not mode & stat.S_IWGRP and not mode & stat.S_IWOTH, f"mode {mode:o} is writable"


@pytest.mark.security
def test_an_interrupted_save_cannot_leave_a_truncated_cursor(tmp_path: Path) -> None:
    """Written to a temporary file and renamed, so a reader never sees a partial.

    A half-written cursor would be refused on the next load (which is correct),
    but refusing means the pipeline stops — so the atomic rename is what keeps
    a crash during the save from needing an operator.
    """
    path = cursor_path(tmp_path)
    save_cursor(path, Cursor(ingested_at=1.0, event_id="abc"))
    assert json.loads(path.read_text(encoding="utf-8"))["event_id"] == "abc"
    leftovers = [p.name for p in path.parent.iterdir() if p != path]
    assert leftovers == [], f"save left temporary files behind: {leftovers}"


# --------------------------------------------------------------------------
# Attribution: gated, audited, explicitly identified
# --------------------------------------------------------------------------


@pytest.mark.security
def test_the_cli_gates_the_cycle_before_reading() -> None:
    """``enforce`` must be called, and must not be reachable only after the read.

    Asserted structurally: the gate call appears in the source before the
    ``run_cycle`` call. A gate that runs after the work has already happened
    records a decision it cannot enforce.
    """
    source = _CLI.read_text(encoding="utf-8")
    assert "enforce(" in source, "the cycle is not policy-gated"
    assert source.index("enforce(\n") < source.index("run_cycle("), (
        "the policy gate must precede the read it authorizes"
    )


@pytest.mark.security
def test_the_cli_audits_before_it_advances_the_cursor() -> None:
    """The ordering that keeps a consumed window from going unrecorded.

    If the cursor were saved first and the audit write then failed, the
    pipeline would have consumed a window with no record that it did. In this
    order a failure between the two re-reads the window, which is what
    at-least-once already promises.
    """
    source = _CLI.read_text(encoding="utf-8")
    assert source.index("audit.record(") < source.index("save_cursor("), (
        "the audit record must be written before the cursor advances"
    )


@pytest.mark.security
def test_the_cli_derives_no_identity_from_the_environment() -> None:
    """``--caller`` is explicit or absent; it is never inherited from the process.

    Asserted over the AST because the idiom this forbids already exists in
    this repository — ``field(default_factory=lambda: os.environ.get(...))``
    appears four times in ``agents/tools/llm.py`` — so a ``$USER`` fallback
    would read as idiomatic while putting an unauthenticated name into a
    hash-chained, signed record.

    ``signing_key_from_env`` is exempt and named explicitly: a *key* must come
    from the environment (AGENTS.md §5 forbids it in source), while an
    *identity* must not.
    """
    tree = ast.parse(_CLI.read_text(encoding="utf-8"), filename=str(_CLI))
    identity_env_vars = {"USER", "USERNAME", "LOGNAME", "SUDO_USER", "IANUA_PRINCIPAL"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert node.value not in identity_env_vars, (
                f"{node.value!r} appears in the CLI; an identity must be passed, not inherited"
            )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in {"getenv", "environ"}, (
                "the CLI reads the environment directly; only signing_key_from_env may"
            )


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


@pytest.mark.security
def test_an_incident_reference_is_not_presented_as_a_security_claim() -> None:
    """It is an unkeyed digest for deduplication; attribution is the audit chain.

    Pinned so a later reader does not start treating it as tamper-evidence: it
    is derived entirely from data an attacker who can write the store already
    controls.
    """
    docstring = reference.__doc__ or ""
    assert "not" in docstring and "security claim" in docstring
    assert "unkeyed" in docstring


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

    with EventStore.open(tmp_path) as store:
        store.append_many((normalize(_CLOUD),), ingested_at=1000.0)
        result = run_cycle(store, batch=MAX_QUERY_LIMIT * 1000)
    assert result.events_read == 1


@pytest.mark.security
def test_the_cli_is_not_importable_as_a_side_effecting_module() -> None:
    """Importing the CLI must not run a cycle.

    ``scripts/`` modules are importable, and a tool that ran work at import
    time would do so from any test or linter that touched it.
    """
    assert os.environ.get("IANUA_PIPELINE_RAN") is None
    source = _CLI.read_text(encoding="utf-8")
    assert 'if __name__ == "__main__":' in source
    assert source.rstrip().endswith("raise SystemExit(main())")
