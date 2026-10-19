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
    assert lock.stat().st_size == 0, "the premise: a chain lock is empty"
    lock.unlink()
    os.link(held, lock)
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
    chain directory, and ``--verify`` read a 2 GiB file outside the backup whole."""
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
def test_a_take_whose_copy_of_a_chain_does_not_verify_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by review: such a take printed only "wrote" at exit 0, its verdict was in
    the manifest alone, and ``--verify`` then said the chain "no longer verifies"."""
    root, _backups = _source(tmp_path)
    chain = root / _CHAIN
    text = chain.read_text(encoding="utf-8")
    chain.write_text(text.replace("test", "tset", 1), encoding="utf-8")
    capsys.readouterr()

    assert backup_main(["--root", str(root), "--name", "torn", "--caller", "test", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert any(entry.startswith(f"{_CHAIN}: ") for entry in payload["chains_broken"]), payload
    backup = root / "data" / "backups" / "torn"
    assert (backup / "manifest.json").is_file(), "the backup is still written"

    clean = tmp_path / "clean"
    clean.mkdir()
    assert backup_main(["--root", str(clean), "--caller", "test", "--verify", str(backup)]) == 1
    assert "was already broken when the backup was taken" in capsys.readouterr().out


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
