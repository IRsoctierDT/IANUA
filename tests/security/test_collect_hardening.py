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
from collections.abc import Callable
from pathlib import Path
from unittest import mock

import pytest

from collect import (
    MAX_BYTES_PER_RUN,
    MAX_LINE_BYTES,
    CollectPathError,
    OffsetError,
    Position,
    SourceError,
    declare,
    load_offsets,
    offsets_path,
    read_new,
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
def test_nothing_in_the_collection_path_can_discover_sources() -> None:
    """Declared, never discovered — over the CLI as well as the package.

    Two gaps found by review: the check looked only at attribute calls, so a
    plain ``from glob import glob`` would have passed all three AST
    invariants; and it never covered ``scripts/run_collector.py``, which is
    where operator paths actually enter. A collector that searched for sources
    would eventually find one nobody meant it to read, and the blast radius of
    that is fabricated evidence.
    """
    enumerators = {"glob", "rglob", "walk", "iterdir", "scandir", "listdir"}
    for path in [*_collect_modules(), _CLI]:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in enumerators, (
                    f"{path.name} enumerates the filesystem via .{node.func.attr}()"
                )
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in enumerators, (
                    f"{path.name} calls {node.func.id}() directly"
                )
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in {"glob", "fnmatch"}, (
                        f"{path.name} imports {alias.name}"
                    )
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in {"glob", "fnmatch"}, (
                    f"{path.name} imports from {node.module}"
                )
                for alias in node.names:
                    assert alias.name not in enumerators, (
                        f"{path.name} imports {alias.name} by name"
                    )


# --------------------------------------------------------------------------
# Read-only, outward
# --------------------------------------------------------------------------


@pytest.mark.security
def test_no_collect_module_opens_a_source_for_writing() -> None:
    """Every module, not just tail.py, and every mode, not just the first arg.

    The earlier version parsed one hard-coded file, so a sibling module could
    open a log for writing and pass every gate. Found by review.
    """
    for path in _collect_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "open"
            ):
                continue
            modes: list[str] = [
                arg.value
                for arg in node.args
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
            ]
            modes += [
                kw.value.value
                for kw in node.keywords
                if kw.arg == "mode"
                and isinstance(kw.value, ast.Constant)
                and isinstance(kw.value.value, str)
            ]
            for mode in modes:
                assert set(mode) <= {"r", "b"}, (
                    f"{path.name} opens something with mode {mode!r}; a collector that "
                    "can write to a log can destroy the evidence it reads"
                )


@pytest.mark.security
def test_no_collect_module_can_destroy_a_source() -> None:
    """Read-only means more than the open mode.

    ``unlink``, ``rename``, ``truncate``, ``chmod`` or ``write_text`` on a
    source would destroy evidence just as thoroughly as a write mode, and the
    mode check alone would not see any of them. ``offsets.py`` legitimately
    writes — under the lab-data root, never to a source — so it is exempted by
    name rather than by pattern, which keeps the exemption visible.
    """
    destructive = {"unlink", "rename", "replace", "truncate", "rmdir", "write_bytes"}
    for path in _collect_modules():
        if path.name == "offsets.py":
            continue  # writes the offsets file, by design; covered by its own tests
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in destructive, (
                    f"{path.name} calls .{node.func.attr}(), which could destroy a source"
                )


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

    writers: tuple[tuple[str, Callable[[Path], object], type[Exception]], ...] = (
        ("store", lambda root: EventStore.open(root), StorePathError),
        ("pipeline", lambda root: cursor_path(root), CursorPathError),
        ("collect", lambda root: offsets_path(root), CollectPathError),
    )
    # Both link shapes, because the second was the actual defect and every
    # fixture here used to be the first: a link to an existing directory is
    # caught by any check at all, whereas a link whose target does not exist
    # yet reads as absent to ``exists()`` and is precisely what
    # ``mkdir(parents=True)`` then materializes. The docstring claimed this
    # case; planting it back showed nothing asserted it.
    for shape in ("existing", "dangling"):
        for name, call, expected in writers:
            root = tmp_path / f"root-{shape}-{name}"
            root.mkdir()
            outside = tmp_path / f"outside-{shape}-{name}"
            if shape == "existing":
                outside.mkdir()
            (root / "data").symlink_to(outside, target_is_directory=True)
            assert outside.exists() is (shape == "existing")
            with pytest.raises(expected):
                call(root)
            assert not (outside / "collect").exists()
            assert not (outside / "pipeline").exists()
            if shape == "dangling":
                assert not outside.exists(), (
                    f"{name} created the link's target instead of refusing to follow "
                    "it; a dangling link reads as absent to exists() and mkdir() "
                    "walks straight through it"
                )


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
                "signer_from_env may (the signing key), and an identity never may"
            )
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] != "os", "the CLI imports os"
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] == "os":
                raise AssertionError("the CLI imports from os")
            for alias in node.names:
                assert alias.name in {"signer_from_env"} or not alias.name.endswith("_from_env"), (
                    f"{alias.name} is an environment-sourced value other than the signing key"
                )


@pytest.mark.security
def test_two_passes_cannot_run_at_once(tmp_path: Path) -> None:
    """Concurrency forks the audit chain permanently, so it is prevented.

    ``AuditLogger`` derives each record's ``seq`` and ``prev_hash`` by reading
    the last line and appending, with no lock. Two appenders produce a
    duplicate ``seq`` and ``verify()`` returns ``False`` for every future
    reader — a false positive in a tamper detector, which is worse than losing
    the records. Deterministic by construction rather than by racing processes.
    """
    from scripts._locking import prepare_lock, single_instance
    from scripts.run_collector import LOCK_FILE

    root = tmp_path / "root"
    root.mkdir()
    # One ``prepare_lock`` per attempt rather than one handle reused:
    # ``flock`` is held by the open file *description*, so re-locking a
    # single handle succeeds and would make this test vacuous.
    with single_instance(prepare_lock(offsets_path(root).parent, LOCK_FILE)) as first:
        assert first is True
        with single_instance(prepare_lock(offsets_path(root).parent, LOCK_FILE)) as second:
            assert second is False, "a second pass acquired the lock concurrently"
    with single_instance(prepare_lock(offsets_path(root).parent, LOCK_FILE)) as third:
        assert third is True, "the lock was not released"


@pytest.mark.security
def test_a_declined_lock_exits_zero_and_touches_nothing(tmp_path: Path) -> None:
    """A minutely schedule is expected to overlap; failing would train neglect."""
    from scripts._locking import prepare_lock, single_instance
    from scripts.run_collector import LOCK_FILE, main

    root = tmp_path / "root"
    root.mkdir()
    log = _log(tmp_path, "audit.log", body="type=SYSCALL node=web-01 auid=x comm=bash\n")
    with single_instance(prepare_lock(offsets_path(root).parent, LOCK_FILE)) as held:
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


@pytest.mark.security
@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        ("[]", "a JSON array is not an offsets object"),
        ('{"version": 2}', "no 'sources' object at all"),
        ('{"version": 2, "sources": []}', "'sources' is not an object"),
        ('{"version": 1, "sources": {}}', "an older format must not be read as this one"),
        ('{"version": 2, "sources": {"/x": 7}}', "a position that is not an object"),
    ],
)
def test_an_offsets_file_that_is_not_this_format_is_refused(
    tmp_path: Path, payload: str, reason: str
) -> None:
    """Migration is explicit, never implicit.

    Reading a version this build does not speak — or a shape it does not
    recognize — and carrying on would resume from a position whose meaning has
    changed. ``version`` went 1 → 2 in this stage precisely because the
    continuity fingerprint changed what a stored position means, so an offset
    written by the previous build must be refused rather than reused.
    """
    path = offsets_path(tmp_path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(OffsetError):
        load_offsets(path)


@pytest.mark.security
@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("offset", "12"),
        ("offset", True),
        ("offset", -1),
        ("inode", 1.5),
        ("device", None),
        ("size", -4),
        ("fingerprint", 7),
    ],
)
def test_a_malformed_stored_position_is_refused_field_by_field(
    tmp_path: Path, field: str, bad: object
) -> None:
    """The offsets file decides where the next read starts, so it is parsed fail-closed.

    A position accepted with a nonsense field would seek somewhere nobody
    chose — past the end (silently collecting nothing forever) or back to zero
    (re-reading a window as if it were new). ``bool`` is in the table on
    purpose: it is an ``int`` subclass and would otherwise pass as offset 0 or
    1 without a murmur.
    """
    path = offsets_path(tmp_path)
    good: dict[str, object] = {
        "offset": 10,
        "inode": 2,
        "device": 3,
        "size": 10,
        "fingerprint": "ab",
    }
    good[field] = bad
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 2, "sources": {"/var/log/x": good}}), encoding="utf-8")
    with pytest.raises(OffsetError):
        load_offsets(path)


@pytest.mark.security
def test_an_empty_source_yields_no_position_claim_it_cannot_support(tmp_path: Path) -> None:
    """At offset 0 there is no consumed context, so the fingerprint is empty.

    Claiming a digest of nothing would make the continuity check compare an
    arbitrary constant on the next pass and report ``replaced`` for a file that
    had simply not been written to yet.
    """
    log = tmp_path / "logs" / "empty.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_bytes(b"")
    result = read_new(declare(log), None)
    assert result.count == 0
    assert result.position is not None
    assert result.position.offset == 0
    assert result.position.fingerprint == ""
    assert result.reset == "first-run"


@pytest.mark.security
def test_the_shipped_default_caps_are_the_ones_that_hold() -> None:
    """Pinned against fixed literals, not against themselves.

    The caps are a memory-exhaustion bound on attacker-influenced input, and
    every positioning test passes explicit values (``max_bytes=64``,
    ``max_line=100``), so the *shipped* numbers were never exercised by
    anything — a plausible "the backlog never drains" fix raising
    ``MAX_BYTES_PER_RUN`` would let one source pull an unbounded file into one
    ``bytes`` object with the suite green. Found by review. The literals here
    are the contract; scaling an assertion from the constant under test is the
    tautology this file has already been caught writing once.
    """
    assert MAX_LINE_BYTES <= 64 * 1024, "the line cap was raised; justify it here"
    assert MAX_BYTES_PER_RUN <= 8 * 1024 * 1024, "the per-run cap was raised; justify it here"


@pytest.mark.security
def test_the_default_line_cap_truncates_rather_than_passing_the_line_on(tmp_path: Path) -> None:
    """Behaviourally, at the default — ``read_new`` called with no caps at all."""
    body = "A" * (MAX_LINE_BYTES + 500) + "\n" + "type=SYSCALL node=web-01 comm=bash\n"
    source = declare(_log(tmp_path, name="long.log", body=body))
    result = read_new(source, None)
    assert result.truncated == 1, "the default line cap did not fire"
    assert len(result.lines[0]) == MAX_LINE_BYTES
    assert result.count == 2, "the line after the over-long one was lost"


@pytest.mark.security
def test_the_default_per_run_cap_bounds_one_read(tmp_path: Path) -> None:
    """One source cannot pull an unbounded file into memory in a single pass.

    Uses the real default rather than an injected one, because the default is
    what an unattended schedule runs with. The file is deliberately just over
    the cap: enough to prove the bound fires, small enough to stay a unit test.
    """
    # The fixture's size is bounded by a *literal*, not by the constant under
    # test. Sizing it from MAX_BYTES_PER_RUN means raising the cap grows this
    # file to match — a 512 MiB plant made this test allocate 512 MiB instead
    # of failing. Clamped, a raised cap leaves the read uncapped and the
    # assertion below fails, which is the outcome that was wanted.
    line = b"x" * 63 + b"\n"
    body = line * (min(MAX_BYTES_PER_RUN, 8 * 1024 * 1024) // len(line) + 16)
    log = tmp_path / "logs" / "big.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_bytes(body)

    result = read_new(declare(log), None)
    assert result.capped is True, "the default per-run cap did not bound the read"
    assert result.position is not None
    assert result.position.offset <= MAX_BYTES_PER_RUN


@pytest.mark.security
def test_a_credential_reached_through_a_symlinked_ancestor_is_refused(
    tmp_path: Path,
) -> None:
    """The positional deny-list rules were bypassed without any symlink at the file.

    ``/.ssh/`` and ``/.gnupg/`` describe *where* a secret lives, and a
    symlinked ancestor resolves them away — ``~/.ssh`` pointing into an
    encrypted volume is an ordinary dotfile-manager layout. Checking only the
    resolved path let every positional rule through. Found by review; both
    spellings are now checked.

    The resolved path is asserted *not* to match first. Without that, a
    fixture whose real location also matches (``volume/ivan/.ssh/id_rsa``)
    passes with the declared-spelling check deleted, which is how this test
    was first written and how it stayed green while the defect was planted
    back in.
    """
    from collect.sources import _DENIED

    vault = tmp_path / "vault" / "keys"
    vault.mkdir(parents=True)
    key = vault / "authorized_keys"
    key.write_text("ssh-ed25519 AAAA... not a real key\n", encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    (home / ".ssh").symlink_to(vault, target_is_directory=True)

    declared = home / ".ssh" / "authorized_keys"
    assert not _DENIED.search(str(declared.resolve())), (
        "the fixture's real location matches the deny-list too, so this test "
        "would pass on the resolved spelling alone and prove nothing"
    )
    assert _DENIED.search(str(declared)), "the fixture no longer exercises a positional rule"
    with pytest.raises(SourceError, match="credential store"):
        declare(declared)


@pytest.mark.security
def test_a_symlinked_ancestor_pointing_into_a_credential_store_is_refused(
    tmp_path: Path,
) -> None:
    """The mirror case, and the one an attacker actually arranges.

    Checking only the *declared* spelling is just as broken as checking only
    the resolved one, and in the more dangerous direction: an operator names
    ``/opt/app/logs/current``, which looks like a log, and whoever can create
    a symlink at ``logs`` points it at a key directory. No symlink sits at the
    file, so the final-component check does not fire, and the declared path
    carries nothing to deny. Only the resolved spelling shows where the read
    would land.

    Found by planting the deny-list the other way round: with ``resolved``
    dropped the suite stayed green, because every other credential fixture
    has both spellings matching at once and so proves neither.
    """
    from collect.sources import _DENIED

    secrets = tmp_path / "root" / ".ssh"
    secrets.mkdir(parents=True)
    (secrets / "current").write_text("ssh-ed25519 AAAA... not a real key\n", encoding="utf-8")
    app = tmp_path / "opt" / "app"
    app.mkdir(parents=True)
    (app / "logs").symlink_to(secrets, target_is_directory=True)

    declared = app / "logs" / "current"
    assert not _DENIED.search(str(declared)), (
        "the declared spelling matches the deny-list, so this test would pass on "
        "it alone and prove nothing about where the read lands"
    )
    assert _DENIED.search(str(declared.resolve())), "the fixture no longer resolves into /.ssh/"
    with pytest.raises(SourceError, match="credential store"):
        declare(declared)


@pytest.mark.security
def test_each_source_commits_at_its_own_stamp(tmp_path: Path) -> None:
    """One stamp across a multi-source pass stranded the later sources forever.

    ``append_many`` is one transaction per call, so a stamp hoisted out of the
    per-source loop gave every source's *separate* commit the same
    ``ingested_at``. The pipeline holds a different lock from the collector, so
    a cycle can fire between two of those commits and save a cursor **inside**
    that tie group — and the keyset is strictly after ``(ingested_at,
    event_id)``, so every later-source event whose content hash sorts below the
    cursor's id is behind a cursor that has already passed it. Never read, by
    any cycle.

    Reproduced before the fix at 30 of 60 collected events permanently
    invisible, with the pipeline reporting ``events_read: 0`` while the store
    held all 60 rows. This is exactly the loss ``next_stamp`` exists to
    prevent, reintroduced one layer up. Found by review.
    """
    import sqlite3 as _sqlite3

    root = tmp_path / "root"
    root.mkdir(exist_ok=True)
    first = _log(tmp_path, name="one.log", body="type=SYSCALL node=web-01 auid=a comm=bash\n")
    second = _log(tmp_path, name="two.log", body="type=SYSCALL node=web-02 auid=b comm=sh\n")

    from scripts.run_collector import main

    assert main(["--root", str(root), "--source", str(first), "--source", str(second)]) == 0

    database = next((root / "data" / "events").glob("*.sqlite3"))
    stamps = [
        row[0]
        for row in _sqlite3.connect(database).execute(
            "SELECT DISTINCT ingested_at FROM events ORDER BY 1"
        )
    ]
    assert len(stamps) == 2, (
        f"two sources committed at {len(stamps)} distinct stamp(s): {stamps}. One stamp "
        "for separate commits lets a cursor land inside a tie group."
    )
    assert stamps[1] > stamps[0], "the second commit did not advance the mark"


@pytest.mark.security
def test_a_cycle_between_two_sources_commits_strands_nothing(tmp_path: Path) -> None:
    """The interleaving itself, driven through the real CLI.

    The collector and the pipeline hold separate locks by design — each exists
    to stop *its own* concurrent invocations forking the audit chain — so
    nothing prevents a cycle landing mid-pass.

    The cycle is fired from inside ``append_many`` so that it lands exactly
    between two of the pass's commits, which is the only place the defect is
    reachable. An earlier version of this test drove the store API directly and
    therefore passed with the defect planted back: it was asserting its own
    arithmetic rather than the CLI's. Found by planting.
    """
    from unittest import mock

    from pipeline import cursor_path, load_cursor, run_cycle, save_cursor
    from scripts.run_collector import main
    from store import EventStore

    root = tmp_path / "root"
    root.mkdir(exist_ok=True)
    one = _log(
        tmp_path,
        name="a.log",
        body="".join(f"type=SYSCALL node=web-01 auid=svc comm=sh{i}\n" for i in range(8)),
    )
    two = _log(
        tmp_path,
        name="b.log",
        body="".join(f"type=SYSCALL node=web-02 auid=svc comm=ls{i}\n" for i in range(8)),
    )

    read: list[int] = []

    def cycle() -> None:
        with EventStore.open(root) as store:
            result = run_cycle(store, cursor=load_cursor(cursor_path(root)))
        if result.cursor is not None:
            save_cursor(cursor_path(root), result.cursor)
        read.append(result.events_read)

    real_append = EventStore.append_many

    def append_then_cycle(self: EventStore, events: object, **kwargs: object) -> int:
        count = real_append(self, events, **kwargs)  # type: ignore[arg-type]
        cycle()  # a timer firing between this commit and the next
        return count

    with mock.patch.object(EventStore, "append_many", append_then_cycle):
        assert main(["--root", str(root), "--source", str(one), "--source", str(two)]) == 0

    for _ in range(4):
        cycle()
        if read[-1] == 0:
            break

    with EventStore.open(root) as store:
        total = store.count()
    assert total == 16
    assert sum(read) == total, (
        f"{total - sum(read)} of {total} stored events were never read by any cycle; a "
        "cursor landed inside a tie group and passed them"
    )


@pytest.mark.security
def test_the_collection_gate_record_does_not_call_the_crossing_benign() -> None:
    """It is the platform's only §5 boundary crossing, in a tamper-evident log.

    The default allow reason reads "Read-only/benign action.", which would
    misdescribe the one action an auditor most needs to find.
    """
    from agents.policies import PolicyEngine

    decision = PolicyEngine().decide(action_class="collection", label="collect_logs")
    assert decision.decision == "allow"
    assert "benign" not in decision.reason.lower()
    assert "collection" in decision.reason.lower()
    assert "read-only" in decision.reason.lower(), (
        "the reason should still say the crossing is read-only"
    )
