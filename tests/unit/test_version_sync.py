from __future__ import annotations

import pytest
from scripts import check_version_sync


@pytest.mark.unit
def test_release_version_surfaces_are_in_sync() -> None:
    assert check_version_sync.check() == "2.1.0"


@pytest.mark.unit
def test_release_tag_must_be_canonical() -> None:
    assert check_version_sync.check("v2.1.0") == "2.1.0"
    with pytest.raises(check_version_sync.VersionSyncError):
        check_version_sync.check("IANUA_v2.1.0")
