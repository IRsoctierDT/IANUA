# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Collection reaches outside the project — hold that reach closed.

This is the package the owner approved a §5 boundary crossing for, and it is
the only one in the platform that reads files the project does not own. Four
properties therefore get assertions rather than prose:

* **Only declared sources, only log-shaped ones.** No glob, no walk, no
  heuristic. A relative path, a symlinked log, a non-regular file and anything
  matching the credential deny-list are refused — a collector faithfully turns
  what it reads into stored events, so pointing it at a private key would copy
  that key into ``data/``.
* **Read-only, outward.** Nothing here opens a source for writing. A collector
  that could modify the logs it reads could destroy the evidence it exists to
  preserve.
* **Containment, inward.** The offsets file cannot leave the gitignored
  lab-data root, including via a symlink planted at any ancestor — the same
  property ``store/`` and ``pipeline/`` hold, now through one shared
  implementation, and asserted here for all three together so they cannot
  drift apart again.
* **Reach.** The package imports nothing that could open a socket, spawn a
  process, read a clock or load code. That is why ``journald`` is out of
  scope: reading it means running ``journalctl``.

The AST tests key on the **root module name** and walk the package
recursively, so ``from collect.offsets import Position`` stays legal while a
subpackage cannot smuggle ``import socket`` past them.
"""

from __future__ import annotations

import ast
import json
import stat
from pathlib import Path
from unittest import mock

import pytest
from collect import (
    CollectPathError,
    Position,
    SourceError,
    declare,
    offsets_path,
    save_offsets,
)
from store import EventStore, StorePathError
from store.paths import confine

_REPO_ROOT = Path(__file__).resolve().parents[2]
_COLLECT_ROOT = _REPO_ROOT / "collect"
_CLI = _REPO_ROOT / "scripts" / "run_collector.py"

#: ``collect/`` needs json, hashlib, re, dataclasses and pathlib. Anything that
#: could reach out, spawn, or load code at runtime is permanently out of scope
#: for a package that runs unattended against operator-supplied paths.
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
#: ``re.compile`` is legitimate and present; banning the bare builtin is what
#: catches the dangerous one.
_BANNED_ATTR_CALLS = _BANNED_CALLS - {"compile"}


def _collect_modules() -> list[Path]:
    """Every module in the package, recursively.

    ``glob("*.py")`` would leave a subpackage unchecked, so
    ``collect/sinks/http.py`` could import ``socket`` while every invariant
    below still passed. The ban is on the package, not on its top level.
    """
    modules = sorted(_COLLECT_ROOT.rglob("*.py"))
    assert modules, "no collect modules found; the invariant tests would pass vacuously"
    return modules


def _log(tmp_path: Path, name: str, body: str = "x\n") -> Path:
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    path = logs / name
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Only declared, log-shaped sources
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize(
    "name",
    [
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/root/.ssh/id_rsa",
        "/home/ivan/.ssh/authorized_keys",
        "/home/ivan/.aws/credentials",
        "/home/ivan/.gnupg/secring.gpg",
        "/srv/app/server.pem",
        "/srv/app/tls.key",
        "/srv/app/keystore.jks",
        "/srv/app/.env",
        "/home/ivan/.netrc",
        "/home/ivan/.pgpass",
        "/opt/x/id_ed25519",
    ],
)
def test_the_deny_list_pattern_covers_known_credential_paths(name: str) -> None:
    """A collector copies what it reads into the event store.

    Pointing it at a secret would put that secret in ``data/``, which AGENTS.md
    §5 treats as sensitive by default. Refused rather than warned about: "the
    operator asked for it" is not a reason to help, and the deny-list is
    checked before the file is opened so a refusal leaks nothing.

    This checks the *pattern*, by path shape, so it holds on a machine where
    none of these exist. It deliberately does **not** prove the pattern is
    wired in — see the test below, which does. Keeping both is the lesson from
    planting the defect: deleting the ``if _DENIED.search(...)`` branch left
    this test passing, because a regex nobody consults still matches.
    """
    from collect.sources import _DENIED

    assert _DENIED.search(name), f"{name} is not caught by the credential deny-list"


@pytest.mark.security
@pytest.mark.parametrize(
    "relative",
    ["server.pem", "tls.key", "store.p12", ".env", ".netrc", ".pgpass", "id_ed25519"],
)
def test_declare_actually_refuses_a_credential_file(tmp_path: Path, relative: str) -> None:
    """Through ``declare``, against a real file — so the branch is proven wired.

    The pattern test above passes even with the deny-list check deleted from
    ``declare``, which is how a control becomes decorative. This one creates a
    readable file whose *name* matches the deny-list and asserts the refusal,
    so removing the branch fails here.
    """
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    secret = logs / relative
    secret.write_text("not actually a secret, but shaped like one\n", encoding="utf-8")
    with pytest.raises(SourceError, match="credential store"):
        declare(secret)


@pytest.mark.security
def test_declare_refuses_an_ssh_directory_path(tmp_path: Path) -> None:
    """The ``/.ssh/`` pattern is positional rather than an extension."""
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    key = ssh / "authorized_keys"
    key.write_text("ssh-ed25519 AAAA...\n", encoding="utf-8")
    with pytest.raises(SourceError, match="credential store"):
        declare(key)


@pytest.mark.security
def test_the_deny_list_does_not_refuse_ordinary_logs() -> None:
    """A deny-list that refuses real logs gets switched off, which protects nothing."""
    from collect.sources import _DENIED

    for ordinary in (
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/audit/audit.log",
        "/var/log/suricata/eve.json",
        "/var/log/zeek/conn.log",
        "/srv/app/logs/application.jsonl",
        "/var/log/nginx/access.log",
        "/var/log/keyring-service.log",
    ):
        assert not _DENIED.search(ordinary), f"{ordinary} is wrongly refused"


@pytest.mark.security
def test_a_symlinked_log_is_refused(tmp_path: Path) -> None:
    """A link at the log file redirects this reader without write access to the log.

    What it reads becomes stored evidence, so following one lets an attacker
    who can only create a symlink fabricate telemetry.
    """
    real = _log(tmp_path, "real.log")
    link = tmp_path / "logs" / "link.log"
    link.symlink_to(real)
    with pytest.raises(SourceError, match="is a symlink"):
        declare(link)


@pytest.mark.security
def test_a_fifo_is_refused(tmp_path: Path) -> None:
    """A FIFO has no position to resume from and would block the read.

    An unattended collector blocking forever on a named pipe is a silent
    outage: no events, no error, no exit.
    """
    import os

    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(SourceError, match="not a regular file"):
        declare(fifo)


@pytest.mark.security
def test_the_package_exposes_no_way_to_discover_sources() -> None:
    """Declared, never discovered — asserted structurally, not just documented.

    A collector that searched for sources would eventually find one nobody
    meant it to read, and the blast radius of that is fabricated evidence.
    """
    for path in _collect_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in {"glob", "rglob", "walk", "iterdir", "scandir"}, (
                    f"{path.name} enumerates the filesystem via .{node.func.attr}()"
                )


# --------------------------------------------------------------------------
# Read-only, outward
# --------------------------------------------------------------------------


@pytest.mark.security
def test_a_source_is_only_ever_opened_for_reading() -> None:
    """A collector that could write to a log could destroy the evidence it reads.

    Asserted over the AST: every ``.open(...)`` on a source path passes
    ``"rb"``. The offsets file is written, and that is a different path under
    the lab-data root, so the two are distinguished by which object is opened
    rather than by counting calls.
    """
    tail = _COLLECT_ROOT / "tail.py"
    tree = ast.parse(tail.read_text(encoding="utf-8"), filename=str(tail))
    opens = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "open"
    ]
    assert opens, "tail.py opens nothing; this test would pass vacuously"
    for call in opens:
        modes = [arg.value for arg in call.args if isinstance(arg, ast.Constant)]
        assert modes == ["rb"], f"a source is opened with {modes!r}, not read-only"


@pytest.mark.security
def test_collecting_does_not_modify_the_source(tmp_path: Path) -> None:
    """Observed, not inferred: the file's bytes and mtime survive a pass."""
    from collect import read_new

    path = _log(tmp_path, "audit.log", body="type=SYSCALL node=web-01 auid=x comm=bash\n")
    before = (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
    read_new(declare(path), None)
    after = (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
    assert before == after, "collecting changed the source file"


# --------------------------------------------------------------------------
# Containment, inward — and parity across all three callers
# --------------------------------------------------------------------------


@pytest.mark.security
def test_a_symlinked_ancestor_cannot_relocate_the_offsets(tmp_path: Path) -> None:
    """``data/collect`` is two deep, so a link at ``data`` must be caught."""
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    (root / "data").symlink_to(outside, target_is_directory=True)
    with pytest.raises(CollectPathError):
        offsets_path(root)
    assert not (outside / "collect").exists()


@pytest.mark.security
def test_all_three_lab_data_writers_refuse_the_same_escape(tmp_path: Path) -> None:
    """One implementation, so the three cannot drift apart again.

    ``store/``, ``pipeline/`` and ``collect/`` each grew their own copy of this
    check, and two of them were wrong in the *same two ways*: leaf-only, and
    gated on ``exists()`` so a dangling link was skipped. They now share
    ``store.paths.confine``; this asserts all three still refuse, so a future
    change cannot fix one and leave the others.
    """
    from pipeline import CursorPathError, cursor_path

    for index, (call, expected) in enumerate(
        (
            (lambda root: EventStore.open(root), StorePathError),
            (lambda root: cursor_path(root), CursorPathError),
            (lambda root: offsets_path(root), CollectPathError),
        )
    ):
        outside = tmp_path / f"outside{index}"
        outside.mkdir()
        root = tmp_path / f"root{index}"
        root.mkdir()
        (root / "data").symlink_to(outside, target_is_directory=True)
        with pytest.raises(expected):
            call(root)


@pytest.mark.security
@pytest.mark.parametrize(
    "filename", ["../escape.json", "a/b.json", "", ".", "..", "x\x00.json", "." * 300]
)
def test_an_offsets_filename_cannot_escape(tmp_path: Path, filename: str) -> None:
    with pytest.raises(CollectPathError):
        offsets_path(tmp_path, filename=filename)


@pytest.mark.security
def test_the_shared_helper_raises_the_caller_s_own_error_type(tmp_path: Path) -> None:
    """So a caller catching its own taxonomy need not know this helper exists."""

    class Bespoke(Exception):
        pass

    with pytest.raises(Bespoke):
        confine(tmp_path, Path("data"), "../escape", error=Bespoke, what="thing")


@pytest.mark.security
def test_the_offsets_are_written_owner_only(tmp_path: Path) -> None:
    """They name paths on this host, which is operational detail worth not publishing."""
    root = tmp_path / "root"
    root.mkdir()
    path = offsets_path(root)
    save_offsets(path, {"a": Position(offset=1, inode=1, device=1, size=1)})
    mode = stat.S_IMODE(path.stat().st_mode)
    assert not mode & (stat.S_IRGRP | stat.S_IROTH), f"mode {mode:o} is readable"
    assert not mode & (stat.S_IWGRP | stat.S_IWOTH), f"mode {mode:o} is writable"
    assert [p.name for p in path.parent.iterdir() if p != path] == []


# --------------------------------------------------------------------------
# Reach: no socket, no subprocess, no clock
# --------------------------------------------------------------------------


@pytest.mark.security
def test_collect_imports_nothing_that_could_reach_out_or_execute() -> None:
    """Keyed on the root module name, so intra-package imports stay legal.

    ``os`` and ``time`` are on the list, which is why ``journald`` is out of
    scope for this stage: reading it means running ``journalctl``, and a
    collector that can spawn a process is a much larger thing to review.
    """
    for path in _collect_modules():
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
def test_collect_calls_no_executor() -> None:
    for path in _collect_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in _BANNED_CALLS, f"{path.name}: calls {node.func.id}()"
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in _BANNED_ATTR_CALLS, (
                    f"{path.name}: calls .{node.func.attr}()"
                )


@pytest.mark.security
def test_collect_reads_no_clock() -> None:
    """Positions are byte offsets and file identities, never times.

    Nothing here depends on the host's clock being sane, which matters because
    the one thing the CLI does with a clock is clamp it to the store's
    high-water mark.
    """
    forbidden = {"now", "utcnow", "today", "time", "monotonic", "time_ns", "perf_counter"}
    for path in _collect_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in forbidden, (
                    f"{path.name}: reads the clock via .{node.func.attr}()"
                )


@pytest.mark.security
def test_collect_adds_no_runtime_dependency() -> None:
    """``dependencies = []`` stays load-bearing; collection is stdlib-only."""
    import tomllib

    config = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["project"]["dependencies"] == []


# --------------------------------------------------------------------------
# The CLI's own boundary
# --------------------------------------------------------------------------


@pytest.mark.security
def test_the_cli_reaches_the_environment_only_for_the_signing_key() -> None:
    """``--caller`` is explicit or absent; identity is never inherited.

    The ban is on reaching the environment at all, not on a list of variable
    names: a previous version of this test elsewhere in the suite checked
    well-known names and so passed on ``os.environ.get("IANUA_OPERATOR")``.
    """
    tree = ast.parse(_CLI.read_text(encoding="utf-8"), filename=str(_CLI))
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            assert node.attr not in {"environ", "environb", "getenv"}, (
                f"the CLI reaches the environment via .{node.attr}; only "
                "signing_key_from_env may, and an identity never may"
            )
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] != "os", "the CLI imports os"
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] == "os":
                raise AssertionError("the CLI imports from os")
            for alias in node.names:
                assert alias.name in {"signing_key_from_env"} or not alias.name.endswith(
                    "_from_env"
                ), f"{alias.name} is an environment-sourced value other than the signing key"


@pytest.mark.security
def test_two_passes_cannot_run_at_once(tmp_path: Path) -> None:
    """Concurrency forks the audit chain permanently, so it is prevented.

    ``AuditLogger`` derives each record's ``seq`` and ``prev_hash`` by reading
    the last line and appending, with no lock. Two appenders produce a
    duplicate ``seq`` and ``verify()`` returns ``False`` for every future
    reader — a false positive in a tamper detector, which is worse than losing
    the records. Deterministic by construction rather than by racing processes.
    """
    from scripts.run_collector import _single_instance

    root = tmp_path / "root"
    root.mkdir()
    directory = offsets_path(root).parent
    with _single_instance(directory) as first:
        assert first is True
        with _single_instance(directory) as second:
            assert second is False, "a second pass acquired the lock concurrently"
    with _single_instance(directory) as third:
        assert third is True, "the lock was not released"


@pytest.mark.security
def test_a_declined_lock_exits_zero_and_touches_nothing(tmp_path: Path) -> None:
    """A minutely schedule is expected to overlap; failing would train neglect."""
    from scripts.run_collector import _single_instance, main

    root = tmp_path / "root"
    root.mkdir()
    log = _log(tmp_path, "audit.log", body="type=SYSCALL node=web-01 auid=x comm=bash\n")
    directory = offsets_path(root).parent
    with _single_instance(directory) as held:
        assert held is True
        assert main(["--root", str(root), "--source", str(log)]) == 0
    assert not offsets_path(root).exists(), "a skipped pass advanced the offsets"


@pytest.mark.security
def test_collection_is_its_own_policy_class() -> None:
    """So an operator can stop collection without stopping detection.

    The pipeline is gated ``read_only``. Collection is the one action that
    reaches outside the project, and sharing a switch with detection would mean
    turning off the thing that reads host files also turns off the thing that
    correlates what was already read.
    """
    from typing import get_args

    from agents.policies import ActionClass

    assert "collection" in get_args(ActionClass)
    bundle = json.loads(
        (_REPO_ROOT / "agents" / "policies" / "policy.json").read_text(encoding="utf-8")
    )
    assert bundle["policy"]["collection"] == "allow"
    assert bundle["policy"]["read_only"] == "allow"
    source = _CLI.read_text(encoding="utf-8")
    assert 'ACTION_CLASS: ActionClass = "collection"' in source


@pytest.mark.security
def test_a_save_that_loses_an_identical_content_race_does_not_report_failure(
    tmp_path: Path,
) -> None:
    """The temp name is content-keyed, so only an identical writer can take it.

    Finding the temporary file already renamed into place means another writer
    put *the same bytes* there — the outcome this call wanted. Raising would be
    a lie, and the CLI would exit 1 reporting that offsets were not advanced
    when they were. Same mechanics and same reasoning as the pipeline cursor.
    """
    root = tmp_path / "root"
    root.mkdir()
    path = offsets_path(root)
    positions = {"a": Position(offset=1, inode=1, device=1, size=1)}
    real_chmod = Path.chmod
    raced = {"done": False}

    def complete_a_rival_save(self: Path, mode: int) -> None:
        if not raced["done"] and self.name.endswith(".tmp"):
            raced["done"] = True
            save_offsets(path, positions)
        real_chmod(self, mode)

    with mock.patch.object(Path, "chmod", complete_a_rival_save):
        save_offsets(path, positions)  # must not raise

    assert raced["done"], "the race never happened; this test proved nothing"
    from collect import load_offsets

    assert load_offsets(path) == positions


@pytest.mark.security
def test_a_save_whose_destination_holds_something_else_still_fails(
    tmp_path: Path,
) -> None:
    """Fail-closed: the race is benign only when the bytes actually match."""
    from collect import OffsetError

    root = tmp_path / "root"
    root.mkdir()
    path = offsets_path(root)
    positions = {"a": Position(offset=1, inode=1, device=1, size=1)}
    real_chmod = Path.chmod
    raced = {"done": False}

    def rival_writes_something_else(self: Path, mode: int) -> None:
        if not raced["done"] and self.name.endswith(".tmp"):
            raced["done"] = True
            save_offsets(path, positions)
            path.write_text(json.dumps({"version": 1, "sources": {"other": {}}}), encoding="utf-8")
        real_chmod(self, mode)

    with (
        mock.patch.object(Path, "chmod", rival_writes_something_else),
        pytest.raises(OffsetError),
    ):
        save_offsets(path, positions)


@pytest.mark.security
def test_a_vanished_temp_file_with_no_offsets_written_is_an_error(tmp_path: Path) -> None:
    """Temp gone and destination empty means nothing was written at all.

    Reporting success would advance a collector over lines whose progress was
    never recorded, which is the silent loss this whole package refuses.
    """
    from collect import OffsetError

    root = tmp_path / "root"
    root.mkdir()
    path = offsets_path(root)

    def vanish_without_renaming(self: Path, target: object) -> Path:
        if self.name.endswith(".tmp"):
            self.unlink()
            raise FileNotFoundError(2, "No such file or directory", str(self))
        raise AssertionError("unexpected replace target")

    with (
        mock.patch.object(Path, "replace", vanish_without_renaming),
        pytest.raises(OffsetError, match="no offsets were written"),
    ):
        save_offsets(path, {"a": Position(offset=1, inode=1, device=1, size=1)})
    assert not path.exists()
