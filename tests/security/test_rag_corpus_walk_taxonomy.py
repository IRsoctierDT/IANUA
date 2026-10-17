# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Every corpus walk or read failure reaches callers as ``ValidationError``.

``KnowledgeBaseAgent`` and ``scripts/rag_cli.py`` fail soft on that type only.
Measured before ``discover_documents`` mapped its own errors: an unsearchable
subdirectory, a file removed between ``is_file()`` and ``stat()`` (2094 of
20000 racing ``ingest()`` calls) and a path past ``PATH_MAX`` each escaped all
of them as a raw ``OSError`` carrying the absolute path; a symlink-loop root
escaped as ``RuntimeError``. Deterministic hooks stand in for DAC (the suite
may run as root) and for the race window, so every case runs everywhere.
"""

from __future__ import annotations

import errno
import os
from collections.abc import Callable
from pathlib import Path

import pytest

import rag.ingest
from agents.knowledge_base_agent import KnowledgeBaseAgent
from agents.tools.validation import ValidationError
from rag.ingest import ingest, read_documents
from scripts.rag_cli import main


def _past_path_max(corpus: Path, mp: pytest.MonkeyPatch) -> None:
    fd = os.open(corpus, os.O_RDONLY)  # dir_fd keeps every single call short
    for i in range(25):
        os.mkdir(f"d{i:02d}" + "x" * 196, dir_fd=fd)
        nxt = os.open(f"d{i:02d}" + "x" * 196, os.O_RDONLY, dir_fd=fd)
        os.close(fd)
        fd = nxt
    os.close(fd)


def _vanishes_after_is_file(corpus: Path, mp: pytest.MonkeyPatch) -> None:
    real = rag.ingest.resolve_within

    def unlink_in_the_window(base: Path, candidate: str) -> Path:
        target = real(base, candidate)
        target.unlink()  # between is_file() and stat(), as the race does
        return target

    mp.setattr("rag.ingest.resolve_within", unlink_in_the_window)


def _deny(method: str, under: Path) -> Callable[[Path, pytest.MonkeyPatch], None]:
    def hook(corpus: Path, mp: pytest.MonkeyPatch) -> None:
        (corpus / "sub").mkdir()
        (corpus / "sub" / "doc.md").write_text("brute force", encoding="utf-8")
        real = getattr(Path, method)

        def denied(self: Path, *args: object, **kwargs: object) -> object:
            if self.is_relative_to(corpus / under) and self != corpus / under:
                raise PermissionError(errno.EACCES, "Permission denied", str(self))
            return real(self, *args, **kwargs)

        mp.setattr(Path, method, denied)

    return hook


_BREAKERS = [_past_path_max, _vanishes_after_is_file, _deny("is_symlink", Path("sub"))]


@pytest.mark.parametrize(
    "breaker",
    [*_BREAKERS, _deny("read_text", Path("sub"))],
    ids=["path-max", "vanished", "unsearchable-dir", "unreadable-file"],
)
def test_corpus_failures_stay_in_the_taxonomy_without_the_absolute_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, breaker: Callable[..., None]
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    breaker(corpus, monkeypatch)
    agent = KnowledgeBaseAgent(kb_root=corpus)
    soft: list[tuple[Callable[[], object], object]] = [
        (lambda: agent.retrieve("brute force"), []),
        (lambda: agent.cite("brute force"), []),
        (lambda: agent.verify_citations([]), False),
        (lambda: main(["--corpus", str(corpus), "--query", "brute", "--offline"]), 2),
    ]

    for reader in (ingest, read_documents):
        (corpus / "ok.md").write_text("brute force", encoding="utf-8")  # "vanished" eats it
        with pytest.raises(ValidationError) as info:
            reader(corpus)
        assert str(tmp_path) not in str(info.value)
    for call, degraded in soft:
        (corpus / "ok.md").write_text("brute force", encoding="utf-8")
        assert call() == degraded


def test_a_symlink_loop_root_is_a_validation_error(tmp_path: Path) -> None:
    loop = tmp_path / "loop"
    loop.symlink_to(loop)
    with pytest.raises(ValidationError, match="cannot be resolved"):
        ingest(loop)
    assert KnowledgeBaseAgent(kb_root=loop).cite("x") == []
