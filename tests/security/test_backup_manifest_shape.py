# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""A backup manifest is untrusted input; a verifier must not write the artifact it reads.

Measured before the fix: a ``store.path`` naming another existing file in the backup
sent ``--verify`` on to ``EventStore.open``, which **created** the store inside the
backup under inspection; four malformed shapes reached a traceback under both
verifiers. Refusal is paired with acceptance: the untampered backup verifies first.
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import pytest

from ingest import normalize
from scripts.run_backup import main as backup_main
from store import EventStore

_RECORD = 'type=USER_AUTH msg=audit(1760000000.1:1): acct="svc-%d" addr=203.0.113.9 res=failed'
_FORMAT = "ianua.backup.v1"


def _backup(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "lab"
    root.mkdir()
    now = time.time()
    with EventStore.open(root) as store:
        for index in range(12):
            store.append(normalize(_RECORD % index), ingested_at=store.next_stamp(now + index))
    assert backup_main(["--root", str(root), "--name", "probe", "--caller", "test"]) == 0
    return root, root / "data" / "backups" / "probe"


def _tree(path: Path) -> set[str]:
    return {str(child.relative_to(path)) for child in path.rglob("*")}


def _verify(root: Path, backup: Path, mode: str) -> int:
    return backup_main(["--root", str(root), "--caller", "test", mode, str(backup)])


@pytest.mark.security
def test_verify_does_not_create_a_store_inside_the_backup(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, backup = _backup(tmp_path)
    assert _verify(root, backup, "--verify") == 0, "the untampered backup must verify"

    shutil.rmtree(backup / "data" / "events")
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["store"]["path"] = "manifest.json"  # another regular file inside the backup
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    before = _tree(backup)
    capsys.readouterr()

    assert _verify(root, backup, "--verify") == 1
    assert _tree(backup) == before, "a read-only verification wrote into the backup"
    assert "only path a backup writes" in capsys.readouterr().err


def _store(events: object) -> dict[str, object]:
    digest = "0" * 64
    return {
        "path": "data/events/events.sqlite3",
        "sha256": digest,
        "attestation": {"events": events, "digest": digest},
    }


_MALFORMED: dict[str, object] = {
    "array": [],
    "store-is-string": {"format": _FORMAT, "store": "x", "files": [], "chains": {}},
    "attestation-events-null": {
        "format": _FORMAT,
        "store": _store(None),
        "files": [],
        "chains": {},
    },
    "files-entry-string": {"format": _FORMAT, "store": _store(1), "files": ["x"], "chains": {}},
    "chains-is-list": {"format": _FORMAT, "store": _store(1), "files": [], "chains": []},
}


@pytest.mark.security
@pytest.mark.parametrize("mode", ["--verify", "--verify-restore"])
@pytest.mark.parametrize("shape", sorted(_MALFORMED))
def test_a_malformed_manifest_is_a_message_and_exit_1_not_a_traceback(
    tmp_path: Path, shape: str, mode: str, capsys: pytest.CaptureFixture[str]
) -> None:
    root, _real = _backup(tmp_path)
    hostile = tmp_path / shape
    (hostile / "data" / "events").mkdir(parents=True)
    (hostile / "manifest.json").write_text(json.dumps(_MALFORMED[shape]), encoding="utf-8")
    capsys.readouterr()

    # An exception propagating out of main() fails this line on its own.
    assert _verify(root, hostile, mode) == 1
    err = capsys.readouterr().err
    assert "manifest.json" in err and "refusing to verify" in err, err
