# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import pytest

from store import StoreFileError
from store.lab_vulnerabilities import LabInputError, lab_database


def test_workspace_refuses_symlinked_data_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "data").symlink_to(outside, target_is_directory=True)
    with pytest.raises(LabInputError, match="Unsafe workspace path"), lab_database(tmp_path):
        pytest.fail("opened a symlinked workspace")
    assert not list(outside.iterdir())


def test_workspace_refuses_hard_linked_sqlite_sidecar(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_bytes(b"test")
    data = tmp_path / "data" / "command-center"
    data.mkdir(parents=True)
    (data / "lab.sqlite3-journal").hardlink_to(outside)
    with pytest.raises(StoreFileError), lab_database(tmp_path):
        pytest.fail("opened a hard-linked sidecar")
    assert outside.read_bytes() == b"test"
