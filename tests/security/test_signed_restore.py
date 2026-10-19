# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""A signed restore verifies, and a signed restore that was tampered with does not.

With ``AUDIT_HMAC_KEY`` set, ``--verify-restore`` used to fail **every** correct
restore with ``REWRITTEN: data/events/audit.log.sig``. The head signature is not
appended to: every keyed record replaces it, and this CLI's own gate record does
so before the comparison runs, so comparing its bytes against the backup could
never succeed. Measured on main, and the obvious repair — skip the signature —
is wrong on its own: measured, deleting the backup's signature and its manifest
entry gave exit 0 under a key, because nothing then checked the backed-up history
against the key at all.

So the signature is checked where it still means something, in the backup, and
the live chain is tied to that history through the manifest. The control
direction is asserted both ways, as ``test_promotion_verify.py`` does: a check
that refused every signed restore would satisfy every tamper case below.

Keys are generated at run time and never written anywhere (AGENTS.md §5).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import shutil
import time
from pathlib import Path

import pytest

from ingest import normalize
from scripts.run_backup import main as backup_main
from store import EventStore

_RECORD = 'type=USER_AUTH msg=audit(1760000000.1:1): acct="svc-%d" addr=203.0.113.9 res=failed'
_CHAIN = "data/events/audit.log"
_SIG = "data/events/audit.log.sig"


def _seed(root: Path) -> None:
    now = time.time()
    with EventStore.open(root) as store:
        for index in range(12):
            store.append(normalize(_RECORD % index), ingested_at=store.next_stamp(now + index))


def _take(root: Path, name: str) -> Path:
    assert backup_main(["--root", str(root), "--name", name, "--caller", "test"]) == 0
    return root / "data" / "backups" / name


def _restore(backup: Path, into: Path) -> None:
    """``docs/RESTORE.md`` step 4: a plain copy into a fresh root."""
    (into / "data").mkdir(parents=True)
    shutil.copytree(backup / "data", into / "data", dirs_exist_ok=True)


def _verify_restore(live: Path, backup: Path) -> int:
    return backup_main(["--root", str(live), "--caller", "test", "--verify-restore", str(backup)])


def _redeclare(backup: Path, relative: str) -> None:
    """Rewrite one manifest entry to match the file as it now is, as a forger would."""
    path = backup / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    target = backup / relative
    for entry in manifest["files"]:
        if entry["path"] == relative:
            entry["size"] = target.stat().st_size
            entry["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _forget(backup: Path, relative: str) -> None:
    """Remove one file and its manifest entry, as a forger would."""
    (backup / relative).unlink()
    path = backup / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["files"] = [entry for entry in manifest["files"] if entry["path"] != relative]
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


@pytest.fixture
def key(monkeypatch: pytest.MonkeyPatch) -> str:
    value = secrets.token_hex(32)
    monkeypatch.setenv("AUDIT_HMAC_KEY", value)
    return value


@pytest.mark.security
def test_a_correct_signed_restore_verifies(
    tmp_path: Path, key: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Measured on main: exit 1, ``REWRITTEN: data/events/audit.log.sig``, every time."""
    source, live = tmp_path / "source", tmp_path / "live"
    source.mkdir()
    _seed(source)
    backup = _take(source, "probe")
    assert (backup / _SIG).is_file(), "the premise: a keyed take writes a head signature"
    _restore(backup, live)
    capsys.readouterr()

    assert _verify_restore(live, backup) == 0, capsys.readouterr().out
    assert "restore verified" in capsys.readouterr().out


@pytest.mark.security
@pytest.mark.parametrize("tamper", ["forged-signature", "stripped-signature", "truncated-chain"])
def test_a_tampered_signed_backup_does_not_verify_after_restore(
    tmp_path: Path, key: str, tamper: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Each tamper also rewrites the manifest to match, so only the key can catch it.

    ``stripped-signature`` is the case main passed at exit 0: with the signature and
    its entry gone, nothing compared the backed-up history against the key.
    ``truncated-chain`` drops the last record of a two-take chain, leaving a genuine
    signature over a head the chain no longer has.
    """
    source, live = tmp_path / "source", tmp_path / "live"
    source.mkdir()
    _seed(source)
    _take(source, "first")
    backup = _take(source, "second")
    if tamper == "forged-signature":
        sig = json.loads((backup / _SIG).read_text(encoding="utf-8"))
        flipped = "0" if sig["signature"][0] != "0" else "1"
        sig["signature"] = flipped + sig["signature"][1:]
        (backup / _SIG).write_text(json.dumps(sig), encoding="utf-8")
        _redeclare(backup, _SIG)
    elif tamper == "stripped-signature":
        _forget(backup, _SIG)
    else:
        lines = (backup / _CHAIN).read_text(encoding="utf-8").splitlines(keepends=True)
        assert len(lines) >= 2, "the premise: the second backup's chain holds earlier records"
        (backup / _CHAIN).write_text("".join(lines[:-1]), encoding="utf-8")
        _redeclare(backup, _CHAIN)
    _restore(backup, live)
    capsys.readouterr()

    assert _verify_restore(live, backup) == 1
    out = capsys.readouterr().out
    expected = (
        # Named for what it is: a take under a key always signs this chain.
        "the backup carries no head signature for it and a key is set"
        if tamper == "stripped-signature"
        else "the backed-up chain does not authenticate"
    )
    assert expected in out, out


@pytest.mark.security
def test_a_wrong_key_does_not_authenticate(
    tmp_path: Path, key: str, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    source, live = tmp_path / "source", tmp_path / "live"
    source.mkdir()
    _seed(source)
    backup = _take(source, "probe")
    _restore(backup, live)
    monkeypatch.setenv("AUDIT_HMAC_KEY", secrets.token_hex(32))
    capsys.readouterr()

    assert _verify_restore(live, backup) == 1
    assert "(signature invalid)" in capsys.readouterr().out


@pytest.mark.security
def test_an_unsigned_backup_verified_without_a_key_still_passes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other side of the previous test: no key anywhere is the unsigned posture, and
    it keeps verifying on the chain alone."""
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    source, live = tmp_path / "source", tmp_path / "live"
    source.mkdir()
    _seed(source)
    backup = _take(source, "probe")
    assert not (backup / _SIG).exists()
    _restore(backup, live)
    capsys.readouterr()

    assert _verify_restore(live, backup) == 0, capsys.readouterr().out


@pytest.mark.security
def test_a_live_chain_rewritten_after_the_restore_is_still_caught(
    tmp_path: Path, key: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Skipping the signature's bytes must not skip the chain's: the live prefix is
    still compared against the manifest."""
    source, live = tmp_path / "source", tmp_path / "live"
    source.mkdir()
    _seed(source)
    backup = _take(source, "probe")
    _restore(backup, live)
    chain = live / _CHAIN
    text = chain.read_text(encoding="utf-8")
    chain.write_text(text.replace("test", "tset", 1), encoding="utf-8")
    capsys.readouterr()

    assert _verify_restore(live, backup) == 1
    assert f"REWRITTEN: {_CHAIN}" in capsys.readouterr().out
