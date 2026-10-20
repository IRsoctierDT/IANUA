# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""``--verify`` reads what the manifest bounds, and holds no lock a take needs.

A backup is an artifact under inspection, so its files are data an attacker
with write access to ``data/backups`` chose. Measured on main (found by
independent review): a ``files[]`` entry or the store, planted as a 1 TiB sparse
file, was digested in full at about 200 MiB/s after its size was already known
to be wrong; a 1 TiB manifest, or a 1 TiB archive planted beside a backed-up
chain, ended the verifier in a ``MemoryError`` traceback; and because ``--verify``
held ``backup.lock`` throughout, every scheduled take printed "skipped" at exit 0
for the hour and a half the read took.

The 1 TiB files are sparse, so they cost no disk, and every run whose failure is
a hang or an allocation goes to a child process with a timeout and an address
space limit: the pre-fix code fails these by timing out or raising, never by
filling the machine.
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

from ingest import normalize
from scripts._exit_codes import EXIT_RETRYABLE
from scripts._locking import FILE_MODE, prepare_lock, single_instance
from scripts.run_backup import LOCK_FILE, MANIFEST_CAP, VERIFY_LOCK_FILE
from store import EventStore
from tests._backup_cli import backup_main, with_audit_anchor

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RECORD = 'type=USER_AUTH msg=audit(1760000000.1:1): acct="svc-%d" addr=203.0.113.9 res=failed'
_STORE = "data/events/events.sqlite3"
_CHAIN = "data/events/audit.log"
_REPORT = "data/reports/r.md"
_HUGE = 1 << 40
#: Enough for the interpreter and a verify; far short of reading a 1 TiB file.
_ADDRESS_SPACE = 4 << 30


def _seed(root: Path) -> Path:
    """A root with a store, a report, a chain and one backup of them, ``probe``."""
    now = time.time()
    with EventStore.open(root) as store:
        for index in range(12):
            store.append(normalize(_RECORD % index), ingested_at=store.next_stamp(now + index))
    (root / _REPORT).parent.mkdir(parents=True)
    (root / _REPORT).write_text("# incident\n", encoding="utf-8")
    assert backup_main(["--root", str(root), "--name", "probe", "--caller", "test"]) == 0
    return root / "data" / "backups" / "probe"


def _sparse(path: Path, size: int = _HUGE) -> None:
    """Extend ``path`` to ``size`` without allocating it, or skip where that fails."""
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


def _run_bounded(argv: list[str], *, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
    """Run the CLI in a child with a timeout and an address-space limit.

    The shape of ``test_backup_manifest_shape.py``'s ``_run_isolated``, plus
    ``RLIMIT_AS``: the pre-fix verifier asked for a 1 TiB buffer, and the limit
    makes that a prompt ``MemoryError`` here rather than a question for the
    container's overcommit policy.
    """
    argv = with_audit_anchor(argv)
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
        pytest.fail(f"the verifier read for {timeout}s instead of refusing: {argv}")


def _verify(root: Path, backup: Path) -> subprocess.CompletedProcess[str]:
    return _run_bounded(["--root", str(root), "--caller", "test", "--verify", str(backup)])


def _manifest(backup: Path) -> dict[str, object]:
    loaded: dict[str, object] = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    return loaded


def _write_manifest(backup: Path, manifest: dict[str, object]) -> None:
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    (backup / "manifest.json").write_text(text, encoding="utf-8")


def _recorded_size(backup: Path, relative: str) -> int:
    manifest = _manifest(backup)
    if relative == _STORE:
        return int(manifest["store"]["size"])  # type: ignore[index]
    for entry in manifest["files"]:  # type: ignore[attr-defined]
        if entry["path"] == relative:
            return int(entry["size"])
    raise AssertionError(f"{relative} is not in the manifest")


@pytest.mark.security
@pytest.mark.parametrize("planted", [_REPORT, _CHAIN, _STORE])
def test_an_oversized_backed_up_file_is_refused_by_its_size_without_being_read(
    tmp_path: Path, planted: str
) -> None:
    """Measured on main: each of these was read to the end, about an hour and a half
    for 1 TiB, after the size alone had already said it was not the file backed up."""
    root = tmp_path / "root"
    root.mkdir()
    backup = _seed(root)
    recorded = _recorded_size(backup, planted)
    _sparse(backup / planted)

    started = time.monotonic()
    result = _verify(root, backup)

    assert result.returncode == 1, result.stdout[-600:] + result.stderr[-600:]
    assert result.stderr == "", result.stderr[-600:]
    assert f"{planted}: size {_HUGE} != " in result.stdout, result.stdout[-600:]
    assert str(recorded) in result.stdout
    assert time.monotonic() - started < 30, "refused, but only after reading"


@pytest.mark.security
def test_an_oversized_store_is_not_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The size already says this is not the store that was backed up, so it is not
    opened at all. In-process with a spy, because opening leaves nothing behind once it
    closes, and found by review: the version of this test that compared the directory
    listing passed with the guard removed."""
    import scripts.run_backup as run_backup

    root = tmp_path / "root"
    root.mkdir()
    backup = _seed(root)
    _sparse(backup / _STORE)
    opened: list[Path] = []
    real_open = run_backup.EventStore.open

    def spy(directory: Path, **kwargs: object) -> object:
        opened.append(Path(directory))
        return real_open(directory, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(run_backup.EventStore, "open", spy)
    clean = tmp_path / "clean"
    clean.mkdir()

    assert backup_main(["--root", str(clean), "--caller", "test", "--verify", str(backup)]) == 1
    assert "is not the backed-up store and was not read further" in capsys.readouterr().out
    assert Path(os.path.realpath(backup)) not in opened, opened


@pytest.mark.security
def test_a_manifest_over_the_cap_is_refused_before_it_is_parsed(tmp_path: Path) -> None:
    """Measured on main: a 1 TiB manifest was a ``MemoryError`` traceback in both
    verifiers, and one of 2 GiB took 55 s and 4.2 GB before failing to decode."""
    root = tmp_path / "root"
    root.mkdir()
    backup = _seed(root)
    _sparse(backup / "manifest.json")

    result = _verify(root, backup)

    assert result.returncode == 1, result.stdout[-600:] + result.stderr[-600:]
    assert "Traceback" not in result.stderr, result.stderr[-600:]
    assert f"is larger than {MANIFEST_CAP} bytes" in result.stderr, result.stderr[-600:]


@pytest.mark.security
def test_a_manifest_one_byte_over_the_cap_is_refused_and_one_at_it_is_parsed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The boundary, both sides: padding is JSON whitespace, so at the cap the
    manifest still parses and verifies, and one byte more is refused."""
    root = tmp_path / "root"
    root.mkdir()
    backup = _seed(root)
    path = backup / "manifest.json"
    original = path.read_bytes()
    clean = tmp_path / "clean"
    clean.mkdir()
    argv = ["--root", str(clean), "--caller", "test", "--verify", str(backup)]

    path.write_bytes(original + b" " * (MANIFEST_CAP - len(original)))
    capsys.readouterr()
    assert backup_main(argv) == 0, capsys.readouterr().out[-600:]

    path.write_bytes(original + b" " * (MANIFEST_CAP + 1 - len(original)))
    capsys.readouterr()
    assert backup_main(argv) == 1
    assert f"is larger than {MANIFEST_CAP} bytes" in capsys.readouterr().err


@pytest.mark.security
@pytest.mark.parametrize("size", [_HUGE, 0])
def test_a_file_planted_beside_a_backed_up_chain_is_not_read(tmp_path: Path, size: int) -> None:
    """The chain verifier finds archives by listing the directory and reads each
    whole, so the manifest check above never bounded it: measured on main, a 1 TiB
    ``audit.log.99`` with the manifest untouched was a ``MemoryError`` traceback.
    An empty one is the same rule at no cost: a take declares every file of a
    chain's family, so one the manifest does not name was not put there by a take."""
    root = tmp_path / "root"
    root.mkdir()
    backup = _seed(root)
    planted = backup / f"{_CHAIN}.99"
    if size:
        _sparse(planted, size)
    else:
        planted.touch()

    result = _verify(root, backup)

    assert result.returncode == 1, result.stdout[-600:] + result.stderr[-600:]
    assert result.stderr == "", result.stderr[-600:]
    expected = f"{_CHAIN}: not verified: {_CHAIN}.99 is beside it but not in the manifest"
    assert expected in result.stdout, result.stdout[-600:]


@pytest.mark.security
def test_a_file_planted_beside_a_signed_backed_up_chain_is_not_read_on_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--verify-restore`` authenticates the backup's chain under a key
    (``test_signed_restore.py``), which reads the same family, so the same bound
    applies there. The key is generated here and never written anywhere."""
    monkeypatch.setenv("AUDIT_HMAC_KEY", secrets.token_hex(32))
    root, live = tmp_path / "root", tmp_path / "live"
    root.mkdir()
    backup = _seed(root)
    (live / "data").mkdir(parents=True)
    shutil.copytree(backup / "data", live / "data", dirs_exist_ok=True)
    _sparse(backup / f"{_CHAIN}.99")

    result = _run_bounded(
        ["--root", str(live), "--caller", "test", "--verify-restore", str(backup)]
    )

    assert result.returncode == 1, result.stdout[-600:] + result.stderr[-600:]
    assert result.stderr == "", result.stderr[-600:]
    assert f"{_CHAIN}: not verified: {_CHAIN}.99 is beside it" in result.stdout


@pytest.mark.security
def test_a_backed_up_chain_file_whose_size_differs_is_not_read(tmp_path: Path) -> None:
    """Declared, but not at the size declared: the file's own entry is a size
    finding, and the chain is not read either, since its size bounds the read."""
    root = tmp_path / "root"
    root.mkdir()
    backup = _seed(root)
    recorded = _recorded_size(backup, _CHAIN)
    with (backup / _CHAIN).open("ab") as handle:
        handle.write(b"\n")

    result = _verify(root, backup)

    assert result.returncode == 1
    assert f"{_CHAIN}: size {recorded + 1} != {recorded}" in result.stdout
    assert (
        f"{_CHAIN}: not verified: {_CHAIN} is {recorded + 1} bytes and the manifest records "
        f"{recorded}"
    ) in result.stdout, result.stdout[-600:]


@pytest.mark.security
@pytest.mark.parametrize("value", ["absent", "12", -1, True, None])
def test_a_manifest_without_a_usable_store_size_is_refused(
    tmp_path: Path, value: object, capsys: pytest.CaptureFixture[str]
) -> None:
    """The store's size is what bounds its digest, so it is required. Measured on
    main, a manifest with it removed verified at exit 0: nothing read it."""
    root = tmp_path / "root"
    root.mkdir()
    backup = _seed(root)
    manifest = _manifest(backup)
    store = manifest["store"]
    assert isinstance(store, dict)
    if value == "absent":
        del store["size"]
    else:
        store["size"] = value
    _write_manifest(backup, manifest)
    capsys.readouterr()

    assert backup_main(["--root", str(root), "--caller", "test", "--verify", str(backup)]) == 1
    assert "store size must be a non-negative integer" in capsys.readouterr().err


@pytest.mark.security
def test_verify_does_not_wait_for_a_take_and_a_take_does_not_wait_for_verify(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Measured on main: with ``backup.lock`` held, ``--verify`` printed "skipped"
    and did nothing, which is why one slow verify starved every scheduled take."""
    root = tmp_path / "root"
    root.mkdir()
    backup = _seed(root)
    locks = root / "data" / "backups"
    verify = ["--root", str(root), "--caller", "test", "--verify", str(backup)]

    with prepare_lock(locks, LOCK_FILE) as handle, single_instance(handle) as held:
        assert held, "the premise: this test holds the take's lock"
        capsys.readouterr()
        assert backup_main(verify) == 0
        out = capsys.readouterr().out
        assert out.startswith("verified "), out

    with prepare_lock(locks, VERIFY_LOCK_FILE) as handle, single_instance(handle) as held:
        assert held, "the premise: this test holds the verifier's lock"
        capsys.readouterr()
        assert backup_main(["--root", str(root), "--name", "second", "--caller", "test"]) == 0
        assert "skipped" not in capsys.readouterr().out
        # Skipped, and not a pass: nothing was verified (found by review).
        assert backup_main(verify) == EXIT_RETRYABLE
        assert "skipped: another verify pass holds the lock" in capsys.readouterr().out


@pytest.mark.security
def test_verify_restore_still_serialises_with_a_take(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Only ``--verify`` moved: ``--verify-restore`` reads and writes the live root a
    take reads, so it keeps the take's lock. A skipped gate exits 4, never 0: it
    verified nothing, and docs/RESTORE.md step 4b must not read it as a pass."""
    root = tmp_path / "root"
    root.mkdir()
    backup = _seed(root)
    locks = root / "data" / "backups"

    with prepare_lock(locks, LOCK_FILE) as handle, single_instance(handle) as held:
        assert held
        capsys.readouterr()
        argv = ["--root", str(root), "--caller", "test", "--verify-restore", str(backup)]
        assert backup_main(argv) == EXIT_RETRYABLE
        assert "skipped: another backup pass holds the lock" in capsys.readouterr().out


@pytest.mark.security
def test_a_take_writes_its_manifest_whole_and_records_the_bytes_it_wrote(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A verify no longer waits for a take, so the manifest is renamed into place
    once complete, and the sha256 the take reports is of the file that is there."""
    root = tmp_path / "root"
    root.mkdir()
    _seed(root)
    capsys.readouterr()

    assert backup_main(["--root", str(root), "--name", "second", "--caller", "test", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    backup = root / "data" / "backups" / "second"

    assert sorted(path.name for path in backup.iterdir() if path.name.startswith(".")) == []
    manifest = backup / "manifest.json"
    assert payload["manifest_sha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert manifest.stat().st_mode & 0o777 == FILE_MODE
