# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The embedded Qdrant store is anchored at the source tree, never the CWD.

Measured before the fix: ``QDRANT_PATH=`` fell back to ``"./data/qdrant"``,
so it built a shadow store in any working directory (from ``scripts/`` one the
root-anchored ``/data/`` ignore rule does not cover), and ``"$UNSET/"`` gave
``"/"``. Every case runs from a foreign CWD so a CWD-relative answer shows.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rag.qdrant import QdrantPathError, embedded_path


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = (tmp_path / "repo").resolve()
    (root / "data").mkdir(parents=True)
    (root / "scripts").mkdir()
    (tmp_path / "cwd").mkdir()
    monkeypatch.chdir(tmp_path / "cwd")
    return root


@pytest.mark.parametrize("value", [None, "", "data/qdrant", "./data/qdrant", "data/x/../qdrant"])
def test_unset_empty_and_relative_values_anchor_at_the_tree(repo: Path, value: str | None) -> None:
    assert embedded_path(value, repo_root=repo) == repo / "data" / "qdrant"


_REFUSED_RELATIVE = (" ", "\t", ".", "./", "data", "data/..", "scripts/data/qdrant", "../outside")
_REFUSED_ABSOLUTE = ("{repo}", "{repo}/scripts/data/qdrant", "{repo}/data/../scripts")
_FILESYSTEM_ROOT = ("/", "//", "/.", "/..")


@pytest.mark.parametrize("value", [*_REFUSED_RELATIVE, *_REFUSED_ABSOLUTE, *_FILESYSTEM_ROOT])
def test_values_outside_the_lab_data_root_are_refused(repo: Path, value: str) -> None:
    with pytest.raises(QdrantPathError, match="QDRANT_PATH="):
        embedded_path(value.format(repo=repo), repo_root=repo)
    assert list(Path.cwd().iterdir()) == []


def test_a_link_leading_out_of_data_is_refused_not_followed(repo: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (repo / "data").rmdir()
    (repo / "data").symlink_to(outside)
    for value in ("", f"{repo}/data/qdrant"):
        with pytest.raises(QdrantPathError):
            embedded_path(value, repo_root=repo)
    (repo / "data").unlink()
    (repo / "data").mkdir()
    (repo / "data" / "qdrant").symlink_to(tmp_path / "dangling")
    with pytest.raises(QdrantPathError):
        embedded_path("", repo_root=repo)


def test_an_absolute_path_outside_the_tree_is_the_operators_choice(
    repo: Path, tmp_path: Path
) -> None:
    chosen = tmp_path / "elsewhere" / "store"
    assert embedded_path(str(chosen), repo_root=repo) == chosen.resolve()
