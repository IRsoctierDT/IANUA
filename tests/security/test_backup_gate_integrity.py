# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The backup gates hold against the cases an independent review measured past them.

Each test names the finding it pins. They share one shape: a backup or a live root
an attacker with write access to it could have prepared, a gate that used to exit 0,
hang, or write into a backup on it, and the refusal it gives now. The cases whose
failure was a hang or a large allocation run in a child with a timeout and an
address-space limit. Keys are generated at run time and never written anywhere.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

import scripts.run_backup as run_backup
from agents.policies.audit import AuditLogger, signing_key_from_env
from ingest import normalize
from scripts._exit_codes import EXIT_RETRYABLE
from scripts._locking import prepare_lock, single_instance
from scripts.run_backup import main as backup_main
from store import EventStore

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RECORD = 'type=USER_AUTH msg=audit(1760000000.1:1): acct="svc-%d" addr=203.0.113.9 res=failed'
_CHAIN = "data/events/audit.log"
_COLLECT_CHAIN = "data/collect/audit.log"
_REPORT = "data/reports/r.md"
_ADDRESS_SPACE = 4 << 30


def _seed(root: Path) -> None:
    now = time.time()
    with EventStore.open(root) as store:
        for index in range(12):
            store.append(normalize(_RECORD % index), ingested_at=store.next_stamp(now + index))
    (root / _REPORT).parent.mkdir(parents=True, exist_ok=True)
    (root / _REPORT).write_text("# incident\n", encoding="utf-8")


def _take(root: Path, name: str) -> Path:
    assert backup_main(["--root", str(root), "--name", name, "--caller", "test"]) == 0
    return root / "data" / "backups" / name


def _source(tmp_path: Path, *names: str) -> tuple[Path, list[Path]]:
    root = tmp_path / "source"
    root.mkdir()
    _seed(root)
    return root, [_take(root, name) for name in names or ("probe",)]


def _restore(backup: Path, live: Path) -> None:
    """``docs/RESTORE.md`` step 4: a plain copy into a fresh root."""
    (live / "data").mkdir(parents=True)
    shutil.copytree(backup / "data", live / "data", dirs_exist_ok=True)


def _link_tree(source: Path, target: Path) -> None:
    """``cp -al``: the same directories, every file a hard link."""
    for directory, _subdirs, files in os.walk(source):
        here = target / Path(directory).relative_to(source)
        here.mkdir(parents=True, exist_ok=True)
        for name in files:
            os.link(Path(directory) / name, here / name)


def _fingerprint(path: Path) -> tuple[int, str]:
    return path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest(backup: Path) -> dict[str, object]:
    loaded: dict[str, object] = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    return loaded


def _write_manifest(backup: Path, manifest: dict[str, object]) -> None:
    (backup / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _redeclare(backup: Path, relative: str) -> None:
    """Rewrite one manifest entry to match the file as it now is, as a forger would."""
    manifest = _manifest(backup)
    target = backup / relative
    for entry in manifest["files"]:  # type: ignore[attr-defined]
        if entry["path"] == relative:
            entry["size"] = target.stat().st_size
            entry["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
    _write_manifest(backup, manifest)


def _declare(backup: Path, relative: str) -> None:
    """Add a manifest entry for a file, as a backup taken by an older revision has."""
    manifest = _manifest(backup)
    data = (backup / relative).read_bytes()
    manifest["files"].append(  # type: ignore[attr-defined]
        {"path": relative, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    )
    _write_manifest(backup, manifest)


def _sparse(path: Path, size: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    try:
        os.truncate(path, size)
    except OSError as exc:
        path.unlink()
        pytest.skip(f"this filesystem cannot hold a sparse file of {size} bytes ({exc})")
    if path.stat().st_blocks * 512 > 1 << 30:
        path.unlink()
        pytest.skip("this filesystem allocated the sparse file")


def _child(argv: list[str], *, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
    """The CLI in a child with a timeout and an address-space limit."""
    code = (
        "import resource, sys\n"
        f"resource.setrlimit(resource.RLIMIT_AS, ({_ADDRESS_SPACE}, {_ADDRESS_SPACE}))\n"
        f"sys.path.insert(0, {str(_REPO_ROOT)!r})\n"
        f"from scripts.run_backup import main\nsys.exit(main({argv!r}))\n"
    )
    try:
        return subprocess.run(  # noqa: S603 - fixed interpreter, literal code, test paths
            [sys.executable, "-c", code],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"the CLI ran for {timeout}s instead of refusing: {argv}")


@pytest.fixture
def key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDIT_HMAC_KEY", secrets.token_hex(32))


# -- a lock inside a backup is never waited on --------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize("mode", ["--verify", "--verify-restore"])
def test_a_backup_lock_linked_to_the_pass_own_lock_is_a_finding_not_a_hang(
    tmp_path: Path, key: None, mode: str
) -> None:
    """Found by review, high: a backup's ``audit.log.lock`` replaced by a hard link to the
    lock this pass holds (both empty, so the manifest still matched) made the pass wait
    for ever on itself, and every take skipped at exit 0 meanwhile."""
    root, (backup,) = _source(tmp_path)
    held = (
        root
        / "data"
        / "backups"
        / (run_backup.VERIFY_LOCK_FILE if mode == "--verify" else run_backup.LOCK_FILE)
    )
    held.touch()
    lock = backup / (_CHAIN + ".lock")
    # A take no longer copies a lock; a backup taken before that declares one.
    assert not lock.exists(), "the premise: this revision's take copied no lock"
    os.link(held, lock)
    _declare(backup, _CHAIN + ".lock")
    live = tmp_path / "live"
    if mode == "--verify-restore":
        _restore(backup, live)
        # The live root's own backups directory holds the lock this mode takes.
        (live / "data" / "backups").mkdir(exist_ok=True)
        os.link(held, live / "data" / "backups" / run_backup.LOCK_FILE)
    target = root if mode == "--verify" else live

    result = _child(["--root", str(target), "--caller", "test", mode, str(backup)], timeout=60)

    assert result.returncode == 1, result.stdout[-600:] + result.stderr[-600:]
    assert f"{_CHAIN}: not verified: its lock in the backup is held" in result.stdout
    # Said once, not as "chain no longer verifies: <chain>: not verified: ..."
    assert f"no longer verifies: {_CHAIN}: not verified" not in result.stdout


# -- the manifest's chain records are checked against the backup --------------------------


@pytest.mark.security
@pytest.mark.parametrize("tamper", ["called-absent", "family-deleted", "both"])
def test_a_manifest_that_hides_the_events_chain_does_not_pass_the_gate(
    tmp_path: Path, key: None, tamper: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review, high: ``_backed_up_chain_problems`` skipped any chain the manifest
    called absent, so a forged chain passed at exit 0 once the manifest said so; and with
    the family deleted and ``entries`` set to 0, every backed-up record was gone at exit
    0. A take always records its gate decision in this chain before it copies."""
    _root, (backup,) = _source(tmp_path)
    manifest = _manifest(backup)
    record = manifest["chains"][_CHAIN]  # type: ignore[index]
    if tamper in {"called-absent", "both"}:
        record.clear()
        record["present"] = False
    if tamper in {"family-deleted", "both"}:
        for found in (backup / "data" / "events").iterdir():
            if found.name.startswith("audit.log"):
                found.unlink()
        manifest["files"] = [
            entry
            for entry in manifest["files"]  # type: ignore[attr-defined]
            if not entry["path"].startswith(_CHAIN)
        ]
        if tamper == "family-deleted":
            record["entries"] = 0
    _write_manifest(backup, manifest)
    live = tmp_path / "live"
    _restore(backup, live)
    capsys.readouterr()

    argv = ["--root", str(live), "--caller", "test", "--verify-restore", str(backup)]
    assert backup_main(argv) == 1
    out = capsys.readouterr().out
    assert _CHAIN in out, out
    clean = tmp_path / "clean"
    clean.mkdir()
    assert backup_main(["--root", str(clean), "--caller", "test", "--verify", str(backup)]) == 1


# -- no gate record is appended through a shared file ---------------------------------------


@pytest.mark.security
@pytest.mark.parametrize("mode", ["take", "--verify", "--verify-restore"])
def test_a_live_chain_with_a_second_name_is_refused_before_the_gate_record(
    tmp_path: Path, mode: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review, high and medium: a restore hard-linked from a second copy of the
    backup passed 4b at exit 0, because identity was compared only with the argued
    backup; and a take or a ``--verify`` with ``--root`` at a hard-linked root appended
    its gate record into the backup. Every mode now refuses before it writes."""
    _root, (backup,) = _source(tmp_path)
    staged = tmp_path / "staging" / "probe"
    shutil.copytree(backup, staged)
    live = tmp_path / "live"
    _link_tree(staged / "data", live / "data")
    before = _fingerprint(staged / _CHAIN)
    capsys.readouterr()

    argv = ["--root", str(live), "--caller", "test"]
    if mode == "take":
        argv += ["--name", "next"]
    else:
        argv += [mode, str(backup)]
    assert backup_main(argv) == 1
    err = capsys.readouterr().err
    assert f"the live {_CHAIN} shares its file with 1 other name(s)" in err, err
    assert _fingerprint(staged / _CHAIN) == before, "the gate record went into the copy"


@pytest.mark.security
def test_a_live_file_linked_to_another_backup_is_a_finding(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``rsync --link-dest`` pointed at the previous backup links whatever is unchanged,
    the report here, to that older backup: found by review, 4b passed and step 5 then
    wrote into it."""
    _root, (older, newer) = _source(tmp_path, "older", "newer")
    live = tmp_path / "live"
    _restore(newer, live)
    (live / _REPORT).unlink()
    os.link(older / _REPORT, live / _REPORT)
    capsys.readouterr()

    argv = ["--root", str(live), "--caller", "test", "--verify-restore", str(newer)]
    assert backup_main(argv) == 1
    out = capsys.readouterr().out
    assert f"LINKED: {_REPORT} in the live root shares its file with 1 other name(s)" in out


@pytest.mark.security
def test_an_argument_too_deep_to_resolve_writes_no_gate_record(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: the identity check fell open on a link chain too deep to follow,
    and the gate record was appended before the argument was refused. It is resolved
    first now, so nothing is written."""
    _root, (backup,) = _source(tmp_path)
    live = tmp_path / "live"
    _restore(backup, live)
    links = tmp_path / "links"
    links.mkdir()
    target = backup
    for index in range(1100):
        link = links / f"l{index}"
        link.symlink_to(target)
        target = link
    try:
        os.path.realpath(target)
    except RecursionError:
        pass
    else:  # pragma: no cover - interpreter-dependent
        pytest.skip("this interpreter's realpath follows the chain without recursing")
    before = _fingerprint(live / _CHAIN)
    capsys.readouterr()

    argv = ["--root", str(live), "--caller", "test", "--verify-restore", str(target)]
    assert backup_main(argv) == 1
    assert "more symbolic links than can be followed" in capsys.readouterr().err
    assert _fingerprint(live / _CHAIN) == before, "a gate record was written"


# -- reads stay bounded on the live side and through a symlinked chain directory ------------


@pytest.mark.security
@pytest.mark.parametrize("planted", ["audit.log", "audit.log.99"])
def test_the_gate_does_not_append_to_a_live_chain_larger_than_the_backup(
    tmp_path: Path, planted: str
) -> None:
    """Found by review, medium: appending the gate record reads the head segment whole,
    so a 1 TiB live ``audit.log``, or a 1 TiB archive the manifest never listed, was a
    ``MemoryError`` traceback before any check ran. Sparse; the child is limited."""
    _root, (backup,) = _source(tmp_path)
    live = tmp_path / "live"
    _restore(backup, live)
    _sparse(live / "data" / "events" / planted, 1 << 40)

    result = _child(["--root", str(live), "--caller", "test", "--verify-restore", str(backup)])

    assert result.returncode == 1, result.stdout[-600:] + result.stderr[-600:]
    assert "Traceback" not in result.stderr, result.stderr[-800:]
    assert f"the live data/events/{planted}" in result.stderr, result.stderr[-800:]


@pytest.mark.security
def test_a_symlinked_chain_directory_in_a_backup_is_not_read_through(tmp_path: Path) -> None:
    """Found by review, medium: ``_unbounded_chain`` returned "safe" for a symlinked
    chain directory, and ``--verify`` read a 2 GiB file outside the backup whole. What is
    pinned is the refusal by name, which is what keeps the read from happening; the child
    is limited so a regression is a failure, not a long read."""
    root, (backup,) = _source(tmp_path)
    outside = tmp_path / "outside"
    _sparse(outside / "audit.log", 2 << 30)
    shutil.rmtree(backup / "data" / "compliance", ignore_errors=True)
    (backup / "data" / "compliance").symlink_to(outside)

    result = _child(["--root", str(root), "--caller", "test", "--verify", str(backup)])

    assert result.returncode == 1, result.stdout[-600:] + result.stderr[-600:]
    assert "data/compliance/audit.log: not verified: chain directory" in result.stdout


@pytest.mark.security
def test_a_symlinked_live_chain_directory_is_not_verified_through(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: ``data/compliance`` pointed outside the restored root passed 4b at
    exit 0, "every chain still verifies"."""
    _root, (backup,) = _source(tmp_path)
    live = tmp_path / "live"
    _restore(backup, live)
    outside = tmp_path / "outside"
    outside.mkdir()
    shutil.copy2(live / _CHAIN, outside / "audit.log")
    shutil.rmtree(live / "data" / "compliance", ignore_errors=True)
    (live / "data" / "compliance").symlink_to(outside)
    capsys.readouterr()

    argv = ["--root", str(live), "--caller", "test", "--verify-restore", str(backup)]
    assert backup_main(argv) == 1
    out = capsys.readouterr().out
    assert "data/compliance/audit.log: not verified: live chain directory" in out, out


@pytest.mark.security
def test_a_chain_line_nested_too_deeply_is_a_finding_not_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review, medium: json's own RecursionError on a deeply nested line escaped
    as a traceback; only MemoryError was caught. The manifest is redeclared to match, as
    a forger would, so the read is reached."""
    root, (backup,) = _source(tmp_path)
    with (backup / _CHAIN).open("a", encoding="utf-8") as handle:
        handle.write("[" * 200_000 + "]" * 200_000 + "\n")
    _redeclare(backup, _CHAIN)
    capsys.readouterr()

    assert backup_main(["--root", str(root), "--caller", "test", "--verify", str(backup)]) == 1
    captured = capsys.readouterr()
    assert "nested too deeply to read" in captured.out, captured.out
    assert "Traceback" not in captured.err


@pytest.mark.security
def test_a_memory_error_while_verifying_a_chain_is_a_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: the MemoryError handlers were untested, and removing one put a
    traceback where the report should be."""
    root, (backup,) = _source(tmp_path)

    def exhausted(self: AuditLogger) -> object:
        raise MemoryError

    monkeypatch.setattr(AuditLogger, "verify_report", exhausted)
    capsys.readouterr()
    assert backup_main(["--root", str(root), "--caller", "test", "--verify", str(backup)]) == 1
    assert "too large to verify in memory" in capsys.readouterr().out


# -- a take is consistent under a concurrent writer -----------------------------------------


@pytest.mark.security
def test_a_verify_landing_mid_take_does_not_tear_the_signed_backup(
    tmp_path: Path, key: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review, medium: once ``--verify`` stopped sharing the take's lock, a
    verify's record landing between the take's copy of ``audit.log`` and of its
    signature left a backup whose head signature was stale, which never verified again;
    8 of 40 takes under a continuous verify. The take now copies each chain under the
    chain's shared lock, so the overlapping verify waits instead. Deterministic: the
    verify is started right after ``audit.log`` is copied and given time to finish."""
    assert signing_key_from_env() is not None, "the premise: the chain is signed"
    root, (first,) = _source(tmp_path, "first")
    real_copy = shutil.copy2
    children: list[subprocess.Popen[str]] = []
    code = (
        f"import sys\nsys.path.insert(0, {str(_REPO_ROOT)!r})\n"
        "from scripts.run_backup import main\n"
        f"sys.exit(main(['--root', {str(root)!r}, '--caller', 'test', '--verify', "
        f"{str(first)!r}]))\n"
    )

    def interleaved(src: str, dst: str) -> object:
        copied = real_copy(src, dst)
        if str(src).endswith(_CHAIN) and not children:
            children.append(
                subprocess.Popen(  # noqa: S603 - fixed interpreter, literal code, test paths
                    [sys.executable, "-c", code],
                    cwd=_REPO_ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            )
            deadline = time.monotonic() + 6
            while children[0].poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
        return copied

    monkeypatch.setattr(run_backup.shutil, "copy2", interleaved)
    second = _take(root, "second")
    monkeypatch.setattr(run_backup.shutil, "copy2", real_copy)
    assert children, "the premise: the take copied the events chain"
    out, err = children[0].communicate(timeout=60)
    assert children[0].returncode == 0, out + err
    capsys.readouterr()

    assert backup_main(["--root", str(root), "--caller", "test", "--verify", str(second)]) == 0, (
        capsys.readouterr().out
    )


@pytest.mark.security
def test_a_take_whose_copy_of_a_chain_does_not_verify_names_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: such a take printed only "wrote", its verdict was in the manifest
    alone, and ``--verify`` then said the chain "no longer verifies". It is named now,
    and still exits 0: a second review measured exit 1 paging on states that are not
    damage (the first take after a key is configured, whose chains are not yet signed)."""
    root, _backups = _source(tmp_path)
    chain = root / _CHAIN
    text = chain.read_text(encoding="utf-8")
    chain.write_text(text.replace("test", "tset", 1), encoding="utf-8")
    capsys.readouterr()

    assert backup_main(["--root", str(root), "--name", "torn", "--caller", "test", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert any(entry.startswith(f"{_CHAIN}: ") for entry in payload["chains_broken"]), payload
    backup = root / "data" / "backups" / "torn"
    assert (backup / "manifest.json").is_file(), "the backup is still written"

    clean = tmp_path / "clean"
    clean.mkdir()
    assert backup_main(["--root", str(clean), "--caller", "test", "--verify", str(backup)]) == 1
    assert "did not when the backup was taken either" in capsys.readouterr().out

    assert backup_main(["--root", str(root), "--name", "torn-text", "--caller", "test"]) == 0
    assert "warning: chains that did NOT verify in this backup as it was taken:" in (
        capsys.readouterr().out
    )


# -- a skipped gate is not a pass ------------------------------------------------------------


@pytest.mark.security
def test_a_skipped_verify_under_json_says_so_in_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: a skip printed plain text under ``--json``, at exit 0."""
    root, (backup,) = _source(tmp_path)
    locks = root / "data" / "backups"
    with (
        prepare_lock(locks, run_backup.VERIFY_LOCK_FILE) as handle,
        single_instance(handle) as held,
    ):
        assert held
        capsys.readouterr()
        argv = ["--root", str(root), "--caller", "test", "--verify", str(backup), "--json"]
        assert backup_main(argv) == EXIT_RETRYABLE
        payload = json.loads(capsys.readouterr().out)
    assert payload["skipped"] is True and payload["verified"] is False, payload


# -- tests review found missing --------------------------------------------------------------


@pytest.mark.security
def test_a_backed_up_chain_file_that_differs_from_its_manifest_is_named(
    tmp_path: Path, key: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: the family-digest check in ``_backed_up_chain_problems`` had no
    test, and removing it passed every backup test."""
    _root, (backup,) = _source(tmp_path)
    live = tmp_path / "live"
    _restore(backup, live)
    chain = backup / _CHAIN
    data = bytearray(chain.read_bytes())
    data[-2] = ord("x") if data[-2] != ord("x") else ord("y")
    chain.write_bytes(bytes(data))
    capsys.readouterr()

    argv = ["--root", str(live), "--caller", "test", "--verify-restore", str(backup)]
    assert backup_main(argv) == 1
    assert f"{_CHAIN}: the backup's copy is not what its manifest recorded" in (
        capsys.readouterr().out
    )


@pytest.mark.security
def test_a_take_writes_its_manifest_only_under_a_staging_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Found by review: the atomic-manifest test passed with the pre-fix direct write.
    This one fails if the manifest is ever written in place."""
    root, _backups = _source(tmp_path)
    written: list[str] = []
    real_write = Path.write_bytes
    real_text = Path.write_text

    def write_bytes(self: Path, data: bytes) -> int:
        written.append(self.name)
        return real_write(self, data)

    def write_text(self: Path, data: str, *args: object, **kwargs: object) -> int:
        written.append(self.name)
        return real_text(self, data, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "write_bytes", write_bytes)
    monkeypatch.setattr(Path, "write_text", write_text)
    _take(root, "staged")

    assert "manifest.json" not in written, written
    assert ".manifest.json.tmp" in written, written


# -- third review: links inside a backup, and what a restore carries over --------------------


def _cp_a(backup: Path, live: Path, *extra: str) -> None:
    """``docs/RESTORE.md`` step 4 with the real ``cp``, which keeps hard links between the
    files it copies unless told not to."""
    (live / "data").mkdir(parents=True, exist_ok=True)
    subprocess.run(  # noqa: S603 - fixed program, test paths
        ["cp", "-a", *extra, f"{backup / 'data'}/.", f"{live / 'data'}/"],  # noqa: S607
        check=True,
        timeout=60,
    )


@pytest.mark.security
def test_a_backup_holding_a_link_to_a_lock_is_refused_and_its_restore_does_not_hang(
    tmp_path: Path,
) -> None:
    """Found by review, high: a chain lock in a backup hard-linked to a planted
    ``data/backups/backup.lock`` passed step 2; ``cp -a`` restored the link, and 4b and
    every take on the restored root then waited for ever on the lock they held."""
    if shutil.which("cp") is None:  # pragma: no cover - coreutils is on every runner
        pytest.skip("no cp")
    root, (backup,) = _source(tmp_path)
    lock = backup / (_CHAIN + ".lock")
    lock.touch()
    _declare(backup, _CHAIN + ".lock")
    (backup / "data" / "backups").mkdir()
    os.link(lock, backup / "data" / "backups" / run_backup.LOCK_FILE)

    step2 = _child(["--root", str(root), "--caller", "test", "--verify", str(backup)])
    assert step2.returncode == 1, step2.stdout[-600:]
    # The planted directory itself is named, and not descended into.
    assert "UNDECLARED: data/backups is a directory in the backup" in step2.stdout

    live = tmp_path / "live"
    _cp_a(backup, live)
    assert (live / (_CHAIN + ".lock")).stat().st_nlink == 2, "the premise: cp -a kept the link"
    for argv in (
        ["--root", str(live), "--caller", "test", "--verify-restore", str(backup)],
        ["--root", str(live), "--caller", "test", "--name", "next"],
    ):
        result = _child(argv, timeout=60)
        assert result.returncode == 1, result.stdout[-600:] + result.stderr[-600:]
        assert f"the live {_CHAIN}.lock shares its file with 1 other name(s)" in result.stderr

    # The runbook's step 4 does not carry the link over.
    clean = tmp_path / "clean-restore"
    _cp_a(backup, clean, "--no-preserve=links")
    assert (clean / (_CHAIN + ".lock")).stat().st_nlink == 1


@pytest.mark.security
def test_a_take_does_not_wait_on_a_chain_lock_that_is_its_own(tmp_path: Path) -> None:
    """Found by review, high (a regression in 46f9f84): a take holds every chain's shared
    lock while it copies, and waited for ever when one of them was the same file as the
    ``backup.lock`` it already held. It is refused before the gate now."""
    root, _backups = _source(tmp_path)
    collect = root / "data" / "collect"
    collect.mkdir(parents=True, exist_ok=True)
    os.link(root / "data" / "backups" / run_backup.LOCK_FILE, collect / "audit.log.lock")

    result = _child(["--root", str(root), "--caller", "test", "--name", "next"], timeout=60)

    assert result.returncode == 1, result.stdout[-600:] + result.stderr[-600:]
    assert "the live data/collect/audit.log.lock shares its file" in result.stderr


@pytest.mark.security
def test_a_take_does_not_lock_through_a_symlinked_chain_directory(tmp_path: Path) -> None:
    """Found by review: the take flocked a file outside the root through a symlinked
    chain directory it refused to copy, and waited as long as anything held that file.
    Held here by the test, so a regression is a timeout."""
    import fcntl

    root, _backups = _source(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "audit.log").write_text("", encoding="utf-8")
    (outside / "audit.log.lock").touch()
    shutil.rmtree(root / "data" / "collect", ignore_errors=True)
    (root / "data" / "collect").symlink_to(outside)
    with (outside / "audit.log.lock").open("rb") as holder:
        fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
        result = _child(["--root", str(root), "--caller", "test", "--name", "next"], timeout=30)

    assert result.returncode == 0, result.stdout[-600:] + result.stderr[-600:]
    assert "data/collect" in result.stdout, "the refused source is named"


@pytest.mark.security
@pytest.mark.parametrize("mode", ["take", "--verify", "--verify-restore"])
@pytest.mark.parametrize("where", ["the-backup", "inside-it"])
def test_a_root_that_is_a_backup_is_refused_before_anything_is_written(
    tmp_path: Path, mode: str, where: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review, high: ``--verify`` with the backup as its own ``--root`` appended
    its records to the backup's chain and created a lock inside it; a take with a backup
    as its root wrote those records and a whole nested backup into it, at exit 0; and
    neither backup verified again. Refused before the lock, as a bad argument (exit 2).
    ``inside-it`` pins the containment half: a mutant comparing only equality passed."""
    _root, (backup, other) = _source(tmp_path, "probe", "other")
    target = backup if where == "the-backup" else backup / "data"
    before = sorted(str(p.relative_to(backup)) for p in backup.rglob("*"))
    chain = _fingerprint(backup / _CHAIN)
    capsys.readouterr()

    argv = ["--root", str(target), "--caller", "test"]
    # The argued backup is a different one, so only the "is a backup" check can fire.
    argv += ["--name", "inner"] if mode == "take" else [mode, str(other)]
    assert backup_main(argv) == 2
    resolved = Path(os.path.realpath(backup))
    err = capsys.readouterr().err
    if where == "the-backup":
        assert f"holds a backup manifest ({resolved / 'manifest.json'})" in err, err
    else:
        assert f"lies inside the backup {resolved}" in err, err
    assert sorted(str(p.relative_to(backup)) for p in backup.rglob("*")) == before
    assert _fingerprint(backup / _CHAIN) == chain


@pytest.mark.security
def test_a_root_inside_the_argued_backup_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _root, (backup,) = _source(tmp_path)
    capsys.readouterr()
    argv = ["--root", str(backup / "data"), "--caller", "test", "--verify", str(backup)]
    assert backup_main(argv) == 2
    assert "is the backup being verified, or inside it" in capsys.readouterr().err


@pytest.mark.security
def test_two_files_of_one_backup_that_are_the_same_file_are_named(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A link *inside* a backup, which a take never makes and ``cp -a`` would carry over;
    links *between* backups, which a snapshot farm makes, are not looked at."""
    root, (backup,) = _source(tmp_path)
    report = backup / _REPORT
    twin = backup / "data" / "reports" / "twin.md"
    os.link(report, twin)
    _declare(backup, "data/reports/twin.md")
    capsys.readouterr()

    assert backup_main(["--root", str(root), "--caller", "test", "--verify", str(backup)]) == 1
    out = capsys.readouterr().out
    assert "are the same file (a hard link inside the backup)" in out, out


@pytest.mark.security
def test_an_events_chain_emptied_and_redeclared_is_refused(
    tmp_path: Path, key: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: the ``entries >= 1`` rule had no test of its own; with the chain
    emptied, redeclared and its record set to 0 entries, removing it passed both gates."""
    _root, (backup,) = _source(tmp_path)
    (backup / _CHAIN).write_bytes(b"")
    _redeclare(backup, _CHAIN)
    manifest = _manifest(backup)
    manifest["chains"][_CHAIN]["entries"] = 0  # type: ignore[index]
    _write_manifest(backup, manifest)
    clean = tmp_path / "clean"
    clean.mkdir()
    capsys.readouterr()

    assert backup_main(["--root", str(clean), "--caller", "test", "--verify", str(backup)]) == 1
    assert f"{_CHAIN}: the manifest records it present with 0 entries" in (capsys.readouterr().out)


@pytest.mark.security
def test_a_chain_the_manifest_calls_absent_but_the_backup_holds_is_named(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: the present comparison was exercised only on the events chain,
    where another check also fires."""
    _root, (backup,) = _source(tmp_path)
    planted = AuditLogger(backup / _COLLECT_CHAIN)
    for index in range(3):
        planted.record(
            actor="test",
            action=f"probe:{index}",
            action_class="read_only",
            decision="allow",
            reason="planted",
        )
    for found in sorted((backup / "data" / "collect").iterdir()):
        if not found.name.endswith(".lock"):
            _declare(backup, str(found.relative_to(backup)))
    (backup / (_COLLECT_CHAIN + ".lock")).unlink()
    live = tmp_path / "live"
    _restore(backup, live)
    capsys.readouterr()

    argv = ["--root", str(live), "--caller", "test", "--verify-restore", str(backup)]
    assert backup_main(argv) == 1
    assert (
        f"{_COLLECT_CHAIN}: the manifest records present=False and the backup holds it"
        in capsys.readouterr().out
    )


# -- the live events chain is bounded by size, never refused by name -------------------------


@pytest.mark.security
def test_the_live_chain_bound_admits_what_a_same_node_restore_leaves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Found by review, high (a regression in 46f9f84): a same-node restore merges into
    the old tree, so a newer active log or archive the backup never held is legitimate,
    and refusing it by name failed a correct restore that repeating step 4 could not
    clear. Bounded by size instead; small files, so this runs without sparse files."""
    _root, (backup,) = _source(tmp_path)
    live = tmp_path / "live"
    _restore(backup, live)
    (live / _CHAIN).unlink()
    (live / _CHAIN).write_bytes(b"x" * 64)  # an active log the backup's manifest lists
    (live / (_CHAIN + ".7")).write_bytes(b"x" * 64)  # an archive it does not
    assert run_backup._live_chain_bound(live, backup) is None

    monkeypatch.setattr(run_backup, "LIVE_SEGMENT_CAP", 32)
    refusal = run_backup._live_chain_bound(live, backup)
    assert refusal is not None and f"the live {_CHAIN}.7 is 64 bytes" in refusal

    monkeypatch.setattr(run_backup, "LIVE_SEGMENT_CAP", 1 << 20)
    recorded = _manifest(backup)
    size = next(e["size"] for e in recorded["files"] if e["path"] == _CHAIN)  # type: ignore[attr-defined]
    monkeypatch.setattr(run_backup, "LIVE_CHAIN_GROWTH", 0)
    (live / _CHAIN).write_bytes(b"x" * (size + 1))
    refusal = run_backup._live_chain_bound(live, backup)
    assert refusal is not None and f"the backup holds {size}" in refusal


@pytest.mark.security
def test_the_live_chain_bound_never_raises_on_an_unreadable_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Found by review: an account that cannot read the backup got a PermissionError
    traceback from this pre-gate check; the pass reports it by name instead."""

    def denied(directory: Path) -> object:
        raise PermissionError(13, "Permission denied", str(directory))

    monkeypatch.setattr(run_backup, "_load_manifest", denied)
    assert run_backup._live_chain_bound(tmp_path, tmp_path / "backup") is None


# -- messages review found unasserted ---------------------------------------------------------


@pytest.mark.security
def test_a_file_that_changes_while_it_is_read_is_named_as_such(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "f"
    path.write_bytes(b"0123456789")
    real_fstat = os.fstat

    def shorter(fd: int) -> os.stat_result:
        found = real_fstat(fd)
        fields = list(found)
        fields[6] = 5  # st_size: the file "grew" after this was taken
        return os.stat_result(fields)

    monkeypatch.setattr(run_backup.os, "fstat", shorter)
    size, digest = run_backup._digest_exact(path, 5)
    assert digest is None and size == run_backup.CHANGED_WHILE_READ
    assert "changed size while it was read" in run_backup._size_finding("f", size, 5)


@pytest.mark.security
def test_a_symlinked_manifest_is_named(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root, (backup,) = _source(tmp_path)
    # Not in an ancestor of the root: a backup manifest there makes the root a backup's.
    real = tmp_path / "elsewhere" / "manifest.json"
    real.parent.mkdir()
    (backup / "manifest.json").rename(real)
    (backup / "manifest.json").symlink_to(real)
    capsys.readouterr()
    assert backup_main(["--root", str(root), "--caller", "test", "--verify", str(backup)]) == 1
    assert "is a symlink, which a take never writes" in capsys.readouterr().err


@pytest.mark.security
def test_a_manifest_too_large_to_decode_is_refused_not_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root, (backup,) = _source(tmp_path)
    real_loads = json.loads

    def exhausted(text: str | bytes, *args: object, **kwargs: object) -> object:
        if isinstance(text, str) and '"format"' in text:
            raise MemoryError
        return real_loads(text, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(run_backup.json, "loads", exhausted)
    capsys.readouterr()
    assert backup_main(["--root", str(root), "--caller", "test", "--verify", str(backup)]) == 1
    assert "cannot be decoded as JSON (MemoryError)" in capsys.readouterr().err


@pytest.mark.security
def test_a_lock_in_a_backup_that_cannot_be_opened_is_not_taken_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root, (backup,) = _source(tmp_path)
    (backup / (_CHAIN + ".lock")).touch()
    _declare(backup, _CHAIN + ".lock")
    real_open = run_backup._open_regular
    opened: list[str] = []

    def refusing(path: Path) -> object:
        # The second open of the lock is the probe; the first is its manifest digest.
        if str(path).endswith(".lock"):
            opened.append(str(path))
            if len(opened) > 1:
                raise PermissionError(13, "Permission denied", str(path))
        return real_open(path)

    monkeypatch.setattr(run_backup, "_open_regular", refusing)
    capsys.readouterr()
    assert backup_main(["--root", str(root), "--caller", "test", "--verify", str(backup)]) == 1
    assert f"{_CHAIN}: not verified: its lock cannot be checked (PermissionError)" in (
        capsys.readouterr().out
    )


@pytest.mark.security
def test_a_gate_record_that_runs_out_of_memory_is_an_error_not_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root, (backup,) = _source(tmp_path)

    def exhausted(self: AuditLogger, **kwargs: object) -> object:
        raise MemoryError

    monkeypatch.setattr(AuditLogger, "record", exhausted)
    capsys.readouterr()
    assert backup_main(["--root", str(root), "--caller", "test", "--verify", str(backup)]) == 1
    assert "could not record the gate decision: MemoryError" in capsys.readouterr().err


@pytest.mark.security
def test_a_skipped_take_under_json_says_so_in_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, _backups = _source(tmp_path)
    locks = root / "data" / "backups"
    with prepare_lock(locks, run_backup.LOCK_FILE) as handle, single_instance(handle) as held:
        assert held
        capsys.readouterr()
        argv = ["--root", str(root), "--caller", "test", "--name", "next", "--json"]
        assert backup_main(argv) == 0
        assert json.loads(capsys.readouterr().out)["skipped"] is True


# -- fifth review: same-node restores, directories, unsigned chains, merge gaps --------------


def _same_node_restore(root: Path, backup: Path) -> None:
    """``docs/RESTORE.md`` steps 3 and 4 over the root the backup was taken from, after the
    store was lost: the positions and the store go, the old tree's chains stay."""
    for leftover in (root / "data" / "events").glob("events.sqlite3*"):
        leftover.unlink()
    for position in run_backup.EXCLUDED:
        (root / position).unlink(missing_ok=True)
    _cp_a(backup, root, "--no-preserve=links")


@pytest.mark.security
def test_a_same_node_restore_after_a_rotation_names_the_leftover_segment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review, high: after any rotation since the take, a same-node restore
    failed 4b with an unexplained "chain break … found seq 0", repeating step 4 could not
    clear it, and the PR claimed the case fixed. 4b now names the leftover archive, the
    named remedy (move it out and keep it) clears it, and moving the chains aside before
    step 4, as the runbook now says, avoids it."""
    if shutil.which("cp") is None:  # pragma: no cover - coreutils is on every runner
        pytest.skip("no cp")
    root, (backup,) = _source(tmp_path)
    for _ in range(2):
        assert backup_main(["--root", str(root), "--caller", "test", "--verify", str(backup)]) == 0
    rotated = AuditLogger(root / _CHAIN, max_bytes=1).apply_retention()
    assert rotated["rotated"], rotated
    archive = root / (_CHAIN + ".1")
    assert archive.is_file(), "the premise: the rotation left an archive the backup lacks"
    _same_node_restore(root, backup)
    capsys.readouterr()

    argv = ["--root", str(root), "--caller", "test", "--verify-restore", str(backup)]
    assert backup_main(argv) == 1
    out = capsys.readouterr().out
    assert f"UNDECLARED: {_CHAIN}.1 is beside the restored {_CHAIN} but not in the backup" in out
    assert "chain break" not in out, out

    kept = tmp_path / "kept"
    kept.mkdir()
    archive.rename(kept / archive.name)
    assert backup_main(argv) == 0, capsys.readouterr().out
    assert (kept / archive.name).stat().st_size > 0, "the post-backup records were kept"


@pytest.mark.security
def test_moving_the_chains_aside_before_step_4_keeps_every_record_and_passes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: step 4's cp -a replaces the live events log with the backup's, so
    every audit record written since the take was silently discarded and 4b still passed.
    The runbook now moves each chain's family aside first; nothing is lost and 4b passes."""
    if shutil.which("cp") is None:  # pragma: no cover
        pytest.skip("no cp")
    root, (backup,) = _source(tmp_path)
    assert backup_main(["--root", str(root), "--caller", "test", "--verify", str(backup)]) == 0
    AuditLogger(root / _CHAIN, max_bytes=1).apply_retention()
    before = {p.name: p.read_bytes() for p in (root / "data" / "events").glob("audit.log*")}
    kept = tmp_path / "kept"
    for chain in run_backup.CHAIN_FILES:
        for segment in (root / chain.parent).glob(chain.name + "*"):
            if not segment.name.endswith(".lock"):
                (kept / chain.parent).mkdir(parents=True, exist_ok=True)
                segment.rename(kept / chain.parent / segment.name)
    _same_node_restore(root, backup)
    capsys.readouterr()

    argv = ["--root", str(root), "--caller", "test", "--verify-restore", str(backup)]
    assert backup_main(argv) == 0, capsys.readouterr().out
    kept_events = {p.name: p.read_bytes() for p in (kept / "data" / "events").iterdir()}
    assert {n: b for n, b in before.items() if not n.endswith(".lock")} == kept_events


@pytest.mark.security
@pytest.mark.parametrize(
    "path",
    [
        "data/collect/audit.log.lock",
        "data/pipeline/audit.log.lock",
        "data/compliance/audit.log.lock",
        "data/pipeline/audit.log",
    ],
)
def test_a_directory_at_a_chain_or_lock_path_is_not_called_a_second_name(
    tmp_path: Path, path: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: a directory's link count was read as a second name, so a take
    that main completes was refused with "shares its file with 1 other name(s)" and a
    remedy that could not work."""
    root, _backups = _source(tmp_path)
    (root / path).mkdir(parents=True)
    capsys.readouterr()

    assert backup_main(["--root", str(root), "--name", "next", "--caller", "test"]) == 0
    captured = capsys.readouterr()
    assert "shares its file" not in captured.out + captured.err


@pytest.mark.security
def test_a_chain_lock_linked_to_another_lock_names_the_lock_to_remove(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: the remedy said to remove the names "that are not this root's own",
    and both names were the root's own."""
    root, _backups = _source(tmp_path)
    compliance = root / "data" / "compliance"
    compliance.mkdir(parents=True, exist_ok=True)
    os.link(root / "data" / "backups" / run_backup.LOCK_FILE, compliance / "audit.log.lock")
    capsys.readouterr()

    assert backup_main(["--root", str(root), "--name", "next", "--caller", "test"]) == 1
    assert "remove this chain lock's name (data/compliance/audit.log.lock)" in (
        capsys.readouterr().err
    )
    (compliance / "audit.log.lock").unlink()
    assert backup_main(["--root", str(root), "--name", "next", "--caller", "test"]) == 0


@pytest.mark.security
@pytest.mark.parametrize("planted", ["data/collect/offsets.json", "data/backups/backup.lock"])
def test_an_undeclared_directory_in_a_backup_is_named_and_not_restored_silently(
    tmp_path: Path, planted: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: empty directories planted at a position or lock path passed step 2,
    and once restored every CLI exited 2 and step 3's rm -f could not remove them."""
    root, (backup,) = _source(tmp_path)
    (backup / planted).mkdir(parents=True)
    capsys.readouterr()

    assert backup_main(["--root", str(root), "--caller", "test", "--verify", str(backup)]) == 1
    out = capsys.readouterr().out
    assert "is a directory in the backup that no file its manifest lists lies in" in out, out


@pytest.mark.security
def test_a_position_that_is_a_directory_is_named_with_a_remedy_that_works(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _root, (backup,) = _source(tmp_path)
    live = tmp_path / "live"
    _restore(backup, live)
    (live / "data" / "collect" / "offsets.json").mkdir(parents=True)
    capsys.readouterr()

    argv = ["--root", str(live), "--caller", "test", "--verify-restore", str(backup)]
    assert backup_main(argv) == 1
    assert (
        "POSITION PRESENT: data/collect/offsets.json in the live root is a directory"
        in capsys.readouterr().out
    )


@pytest.mark.security
def test_a_chain_unsigned_when_the_backup_was_taken_is_named_as_such_at_4b(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: the first take after a key is configured records an older chain
    unsigned, and 4b under the key called it a chain that "does not authenticate", whose
    row says it was edited and not to promote."""
    root = tmp_path / "source"
    root.mkdir()
    _seed(root)
    unsigned = AuditLogger(root / _COLLECT_CHAIN)
    unsigned.record(
        actor="test", action="probe", action_class="read_only", decision="allow", reason="pre-key"
    )
    monkeypatch.setenv("AUDIT_HMAC_KEY", secrets.token_hex(32))
    backup = _take(root, "first-keyed")
    taken = _manifest(backup)["chains"][_COLLECT_CHAIN]  # type: ignore[index]
    assert taken["signature"] == "missing", taken
    live = tmp_path / "live"
    _restore(backup, live)
    capsys.readouterr()

    argv = ["--root", str(live), "--caller", "test", "--verify-restore", str(backup)]
    assert backup_main(argv) == 1
    out = capsys.readouterr().out
    assert (
        f"{_COLLECT_CHAIN}: the backed-up chain carries no head signature, and its manifest "
        "records it unsigned when the backup was taken (signature 'missing')"
    ) in out, out
    assert f"{_COLLECT_CHAIN}: the backed-up chain does not authenticate" not in out


@pytest.mark.security
@pytest.mark.parametrize("where", ["manifest", "directory"])
def test_a_manifest_this_account_cannot_read_is_not_called_damaged(
    tmp_path: Path, where: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: an unreadable manifest was reported as "damaged or edited", and an
    unsearchable backup directory replaced the report with a bare errno. Simulated, because
    this suite may run as root, which no mode stops."""
    root, (backup,) = _source(tmp_path)
    if where == "manifest":
        real_open = run_backup._open_regular

        def denied(path: Path) -> object:
            if path.name == "manifest.json":
                raise PermissionError(13, "Permission denied", str(path))
            return real_open(path)

        monkeypatch.setattr(run_backup, "_open_regular", denied)
    else:
        real_is_file = Path.is_file

        def unsearchable(self: Path) -> bool:
            if self.name == "manifest.json":
                raise PermissionError(13, "Permission denied", str(self))
            return real_is_file(self)

        monkeypatch.setattr(Path, "is_file", unsearchable)
    capsys.readouterr()

    assert backup_main(["--root", str(root), "--caller", "test", "--verify", str(backup)]) == 1
    err = capsys.readouterr().err
    assert "cannot be read by this account (PermissionError)" in err, err
    assert "damaged or edited" not in err


@pytest.mark.security
def test_an_events_chain_left_only_as_a_checkpoint_is_a_takes(tmp_path: Path) -> None:
    """A rotation that pruned every segment inside the take's copy window leaves only the
    checkpoint, and that is still a take's chain; a checkpoint of another chain is not."""
    record = {"present": True, "entries": 0, "intact": True}
    files = [{"path": _CHAIN + ".checkpoint", "size": 1, "sha256": "0" * 64}]
    chains = {str(chain): {"present": False} for chain in run_backup.CHAIN_FILES}
    assert (
        run_backup._events_chain_problems({"chains": {**chains, _CHAIN: record}, "files": files})
        == []
    )
    other = [{"path": _COLLECT_CHAIN + ".checkpoint", "size": 1, "sha256": "0" * 64}]
    assert run_backup._events_chain_problems({"chains": {**chains, _CHAIN: record}, "files": other})


@pytest.mark.security
@pytest.mark.parametrize("planted", ["file", "fifo", "sidecar"])
def test_the_backup_inventory_runs_under_verify_restore_too(
    tmp_path: Path, planted: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """The inventory under --verify-restore, its naming of a non-regular file, and its
    allowance for the store's own transient sidecars, which --verify writes and removes."""
    _root, (backup,) = _source(tmp_path)
    live = tmp_path / "live"
    _restore(backup, live)
    extra = backup / "data" / "reports" / "planted.md"
    if planted == "file":
        extra.write_text("x", encoding="utf-8")
    elif planted == "fifo":
        os.mkfifo(extra)
    else:
        (backup / (run_backup.EVENTS_SUBDIR / "events.sqlite3-shm")).write_bytes(b"")
    capsys.readouterr()

    argv = ["--root", str(live), "--caller", "test", "--verify-restore", str(backup)]
    code = backup_main(argv)
    out = capsys.readouterr().out
    if planted == "sidecar":
        assert "UNDECLARED" not in out, out
    else:
        assert code == 1
        kind = "a file" if planted == "file" else "a FIFO"
        assert f"UNDECLARED: data/reports/planted.md is {kind} in the backup" in out, out


@pytest.mark.security
def test_verify_restore_reports_a_live_store_linked_elsewhere_rather_than_raising(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Ported from a test the merge dropped: the finding is in the report on stdout, and
    the store's refusal does not replace the report with an error on stderr."""
    _root, (backup,) = _source(tmp_path)
    live = tmp_path / "live"
    _restore(backup, live)
    os.link(live / "data" / "events" / "events.sqlite3", tmp_path / "elsewhere.sqlite3")
    capsys.readouterr()

    argv = ["--root", str(live), "--caller", "test", "--verify-restore", str(backup)]
    assert backup_main(argv) == 1
    captured = capsys.readouterr()
    assert "has 2 hard links" in captured.out, captured.out
    assert captured.err == "", captured.err


@pytest.mark.security
def test_a_store_path_the_slis_cannot_check_is_not_read_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ported from a test the merge dropped: the SLI guard's non-absence error branch."""
    import sli.indicators
    from sli import measure

    root = tmp_path / "source"
    root.mkdir()
    _seed(root)
    db = root / "data" / "events" / "events.sqlite3"
    real_lstat = os.lstat

    def refusing(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if os.fspath(path) == str(db):  # type: ignore[call-overload]
            raise PermissionError(13, "Permission denied", os.fspath(path))  # type: ignore[call-overload]
        return real_lstat(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(sli.indicators.os, "lstat", refusing)
    report = {item.objective.id: item for item in measure(root, now=time.time()).indicators}
    for objective in ("ingest-freshness", "detection-lag", "detection-backlog"):
        assert report[objective].value is None, report[objective].detail
        assert "cannot be checked (PermissionError)" in report[objective].detail


# -- sixth review: step 4a as printed, moved backups, chains the backup never held ----------


def _runbook_step_4a(live_root: Path, kept_base: Path) -> str:
    """``docs/RESTORE.md`` step 4a exactly as printed, with only its two paths replaced."""
    text = (_REPO_ROOT / "docs" / "RESTORE.md").read_text(encoding="utf-8")
    start = text.index("# 4a. SAME-NODE RESTORE ONLY")
    end = text.index("# 4. Put the state back.", start)
    body = "\n".join(line for line in text[start:end].splitlines() if not line.startswith("#"))
    assert "mkdir -m 700" in body and "mv -n" in body, "the premise: this is the step"
    return body.replace("/srv/ianua-kept", str(kept_base)).replace("/srv/ianua", str(live_root))


def _run_bash(script: str) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if bash is None:  # pragma: no cover - bash is on every runner
        pytest.skip("no bash")
    return subprocess.run(  # noqa: S603 - fixed program, a script built from the runbook
        [bash, "-c", script], capture_output=True, text=True, timeout=60, check=False
    )


@pytest.mark.security
def test_the_runbooks_step_4a_keeps_every_record_and_never_overwrites_what_it_kept(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review, high: step 4a's fixed destination and plain mv overwrote what an
    earlier run kept, so repeating it, or a later incident on the node, lost every
    post-backup record; and it skipped data/compliance/evidence.jsonl, which step 4 then
    replaced. Run here exactly as printed, twice, with the restore between."""
    if shutil.which("cp") is None:  # pragma: no cover
        pytest.skip("no cp")
    root, _backups = _source(tmp_path)
    evidence = root / "data" / "compliance" / "evidence.jsonl"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text('{"line": "pre"}\n', encoding="utf-8")
    backup = _take(root, "with-evidence")
    with evidence.open("a", encoding="utf-8") as handle:
        handle.write('{"line": "post"}\n')
    assert backup_main(["--root", str(root), "--caller", "test", "--verify", str(backup)]) == 0
    events_before = (root / _CHAIN).read_bytes()
    kept_base = tmp_path / "kept"

    first = _run_bash(_runbook_step_4a(root, kept_base))
    assert first.returncode == 0, first.stdout + first.stderr
    kept_first = Path(first.stdout.strip().removeprefix("kept in "))
    assert stat.S_IMODE(kept_first.stat().st_mode) == 0o700
    assert (kept_first / "events" / "audit.log").read_bytes() == events_before
    assert '"post"' in (kept_first / "compliance" / "evidence.jsonl").read_text(encoding="utf-8")

    _same_node_restore(root, backup)
    capsys.readouterr()
    argv = ["--root", str(root), "--caller", "test", "--verify-restore", str(backup)]
    assert backup_main(argv) == 0, capsys.readouterr().out

    time.sleep(1.1)  # the directory is named to the second, and mkdir refuses a reuse
    second = _run_bash(_runbook_step_4a(root, kept_base))
    assert second.returncode == 0, second.stdout + second.stderr
    assert Path(second.stdout.strip().removeprefix("kept in ")) != kept_first
    assert (kept_first / "events" / "audit.log").read_bytes() == events_before
    assert '"post"' in (kept_first / "compliance" / "evidence.jsonl").read_text(encoding="utf-8")


@pytest.mark.security
@pytest.mark.parametrize("mode", ["take", "--verify", "--verify-restore"])
def test_a_root_inside_a_moved_backup_is_refused(
    tmp_path: Path, mode: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: a backup copied out of data/backups was not recognised, and a pass
    with --root at its data/ wrote records, locks and directories into it."""
    _root, (backup,) = _source(tmp_path)
    moved = tmp_path / "offsite" / "b1"
    shutil.copytree(backup, moved)
    before = sorted(str(p.relative_to(moved)) for p in moved.rglob("*"))
    capsys.readouterr()

    argv = ["--root", str(moved / "data"), "--caller", "test"]
    argv += ["--name", "x"] if mode == "take" else [mode, str(backup)]
    assert backup_main(argv) == 2
    assert f"lies inside the backup {Path(os.path.realpath(moved))}" in capsys.readouterr().err
    assert sorted(str(p.relative_to(moved)) for p in moved.rglob("*")) == before


@pytest.mark.security
def test_an_unrelated_manifest_above_a_lab_root_is_not_a_backup(tmp_path: Path) -> None:
    """Found by review: a lab root under a directory holding some other manifest.json was
    refused in every mode."""
    parent = tmp_path / "data" / "backups" / "project"
    parent.mkdir(parents=True)
    (parent / "manifest.json").write_text('{"name": "some-package"}\n', encoding="utf-8")
    root = parent / "lab"
    root.mkdir()
    _seed(root)
    assert backup_main(["--root", str(root), "--name", "first", "--caller", "test"]) == 0


@pytest.mark.security
def test_a_lab_root_holding_a_backup_manifest_names_the_file_to_move(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A lab root restored by copying a whole backup directory holds that backup's
    manifest; the refusal names it, and moving it out is the whole remedy."""
    _root, (backup,) = _source(tmp_path)
    live = tmp_path / "live"
    shutil.copytree(backup, live)
    capsys.readouterr()

    argv = ["--root", str(live), "--name", "next", "--caller", "test"]
    assert backup_main(argv) == 2
    err = capsys.readouterr().err
    assert f"holds a backup manifest ({Path(os.path.realpath(live)) / 'manifest.json'})" in err
    assert "move that manifest.json out of it" in err
    (live / "manifest.json").rename(tmp_path / "kept-manifest.json")
    assert backup_main(argv) == 0


@pytest.mark.security
def test_a_chain_the_backup_never_held_is_named_whole_and_clears(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: for a chain created after the take, 4b named only its archive, and
    once that was moved 4b still failed on the chain's own live log."""
    if shutil.which("cp") is None:  # pragma: no cover
        pytest.skip("no cp")
    root, (backup,) = _source(tmp_path)
    pipeline = AuditLogger(root / "data" / "pipeline" / "audit.log")
    for index in range(3):
        pipeline.record(
            actor="t", action=f"a{index}", action_class="read_only", decision="allow", reason="r"
        )
    AuditLogger(root / "data" / "pipeline" / "audit.log", max_bytes=1).apply_retention()
    pipeline.record(
        actor="t", action="late", action_class="read_only", decision="allow", reason="r"
    )
    _same_node_restore(root, backup)
    capsys.readouterr()

    argv = ["--root", str(root), "--caller", "test", "--verify-restore", str(backup)]
    assert backup_main(argv) == 1
    out = capsys.readouterr().out
    assert "UNDECLARED: data/pipeline/audit.log is the live log of a chain the backup" in out
    assert "UNDECLARED: data/pipeline/audit.log.1 is beside the restored" in out
    assert "chain break" not in out, out
    kept = tmp_path / "kept"
    kept.mkdir()
    for name in ("audit.log", "audit.log.1"):
        (root / "data" / "pipeline" / name).rename(kept / name)
    assert backup_main(argv) == 0, capsys.readouterr().out


@pytest.mark.security
def test_a_backup_taken_before_the_key_is_named_unsigned_at_4b(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: a backup taken with no key records its chains 'unsigned', and 4b
    under the key called them edited."""
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    root = tmp_path / "source"
    root.mkdir()
    _seed(root)
    AuditLogger(root / _COLLECT_CHAIN).record(
        actor="t", action="pre-key", action_class="read_only", decision="allow", reason="r"
    )
    backup = _take(root, "pre-key")
    live = tmp_path / "live"
    _restore(backup, live)
    monkeypatch.setenv("AUDIT_HMAC_KEY", secrets.token_hex(32))
    capsys.readouterr()

    argv = ["--root", str(live), "--caller", "test", "--verify-restore", str(backup)]
    assert backup_main(argv) == 1
    out = capsys.readouterr().out
    assert "records it unsigned when the backup was taken (signature 'unsigned')" in out, out
    assert "UNDECLARED: data/events/audit.log.sig" not in out, "the gate's signature is skipped"


@pytest.mark.security
def test_a_signature_stripped_after_the_take_is_not_called_unsigned_at_take(
    tmp_path: Path, key: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """The unsigned-at-take wording applies only where the manifest recorded it so; a
    chain the take recorded signed and whose signature is gone is the generic finding."""
    root = tmp_path / "source"
    root.mkdir()
    _seed(root)
    AuditLogger(root / _COLLECT_CHAIN, signing_key=signing_key_from_env()).record(
        actor="t", action="keyed", action_class="read_only", decision="allow", reason="r"
    )
    backup = _take(root, "signed")
    assert _manifest(backup)["chains"][_COLLECT_CHAIN]["signature"] == "valid"  # type: ignore[index]
    signature = _COLLECT_CHAIN + ".sig"
    (backup / signature).unlink()
    manifest = _manifest(backup)
    manifest["files"] = [e for e in manifest["files"] if e["path"] != signature]  # type: ignore[attr-defined]
    _write_manifest(backup, manifest)
    live = tmp_path / "live"
    _restore(backup, live)
    capsys.readouterr()

    argv = ["--root", str(live), "--caller", "test", "--verify-restore", str(backup)]
    assert backup_main(argv) == 1
    out = capsys.readouterr().out
    assert f"{_COLLECT_CHAIN}: the backed-up chain does not authenticate (signature missing)" in out
    assert "records it unsigned when the backup was taken" not in out


@pytest.mark.security
@pytest.mark.parametrize("shape", ["fifo", "dangling-symlink", "directory"])
def test_a_position_that_is_not_a_regular_file_gets_a_remedy_that_works(
    tmp_path: Path, shape: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: POSITION PRESENT said step 3's rm -f cannot remove a FIFO or a
    symlink, which it does; only a directory needs moving. The remedy is run here."""
    _root, (backup,) = _source(tmp_path)
    live = tmp_path / "live"
    _restore(backup, live)
    position = live / "data" / "collect" / "offsets.json"
    position.parent.mkdir(parents=True, exist_ok=True)
    if shape == "fifo":
        os.mkfifo(position)
    elif shape == "dangling-symlink":
        position.symlink_to(tmp_path / "nowhere")
    else:
        position.mkdir()
    capsys.readouterr()

    argv = ["--root", str(live), "--caller", "test", "--verify-restore", str(backup)]
    assert backup_main(argv) == 1
    out = capsys.readouterr().out
    if shape == "directory":
        assert "is a directory, which no pass writes and step 3's rm -f does not remove" in out
        position.rename(tmp_path / "kept-position")
    else:
        kind = "a FIFO" if shape == "fifo" else "a symlink"
        assert (
            f"POSITION PRESENT: data/collect/offsets.json exists in the live root (as {kind})"
            in out
        )
        assert "does not remove" not in out
        subprocess.run(["rm", "-f", str(position)], check=True, timeout=30)  # noqa: S603,S607
    assert backup_main(argv) == 0, capsys.readouterr().out


@pytest.mark.security
def test_a_position_that_cannot_be_checked_is_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _root, (backup,) = _source(tmp_path)
    live = tmp_path / "live"
    _restore(backup, live)
    real_lstat = os.lstat

    def refusing(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if os.fspath(path).endswith("cursor.json"):  # type: ignore[call-overload]
            raise PermissionError(13, "Permission denied", os.fspath(path))  # type: ignore[call-overload]
        return real_lstat(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(run_backup.os, "lstat", refusing)
    capsys.readouterr()
    argv = ["--root", str(live), "--caller", "test", "--verify-restore", str(backup)]
    assert backup_main(argv) == 1
    assert "POSITION PRESENT: data/pipeline/cursor.json cannot be checked (PermissionError)" in (
        capsys.readouterr().out
    )


@pytest.mark.security
def test_a_planted_directorys_contents_are_not_reported_one_by_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, (backup,) = _source(tmp_path)
    planted = backup / "data" / "planted"
    (planted / "inner").mkdir(parents=True)
    (planted / "inner" / "file").write_text("x", encoding="utf-8")
    capsys.readouterr()

    assert backup_main(["--root", str(root), "--caller", "test", "--verify", str(backup)]) == 1
    out = capsys.readouterr().out
    assert "UNDECLARED: data/planted is a directory in the backup" in out
    assert "data/planted/inner" not in out, out


@pytest.mark.security
def test_a_non_file_at_a_chain_family_name_is_named_by_kind(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _root, (backup,) = _source(tmp_path)
    live = tmp_path / "live"
    _restore(backup, live)
    os.mkfifo(live / (_CHAIN + ".7"))
    capsys.readouterr()

    argv = ["--root", str(live), "--caller", "test", "--verify-restore", str(backup)]
    assert backup_main(argv) == 1
    assert f"UNDECLARED: {_CHAIN}.7 is a FIFO at a name of {_CHAIN}'s family" in (
        capsys.readouterr().out
    )
