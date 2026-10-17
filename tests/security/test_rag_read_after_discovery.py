# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""A document changed between discovery and read is refused, not followed.

``discover_documents`` checks symlinks and size; the read is a later call.
Measured through ``scripts/ingest_cyber_kb_chunked.py`` before
``read_document`` held one descriptor: a swap to a symlink upserted an outside
file's content and a file grown past the bound was read whole. Each case
here swaps after the real discovery returns, so no race is needed.
"""

from __future__ import annotations

import os
import signal
from collections.abc import Callable
from pathlib import Path

import pytest

import rag.ingest
from agents.tools.validation import ValidationError
from rag.ingest import ingest, read_document


def _to_link(doc: Path) -> None:
    doc.unlink()
    doc.symlink_to(doc.parent.parent / "outside.md")


def _to_fifo(doc: Path) -> None:
    doc.unlink()
    os.mkfifo(doc)


def _grow(doc: Path) -> None:
    with doc.open("a", encoding="utf-8") as handle:
        handle.write("G" * 200)  # MAX_FILE_BYTES is patched to 100 below


def _blocked(signum: int, frame: object) -> None:
    # Not TimeoutError: that is an OSError, which the reader maps to ValidationError.
    pytest.fail("read_document blocked on a FIFO")


@pytest.mark.parametrize("swap", [_to_link, _to_fifo, _grow], ids=["symlink", "fifo", "grown"])
def test_a_document_swapped_after_discovery_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap: Callable[[Path], None]
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (tmp_path / "outside.md").write_text("OUTSIDE-THE-CORPUS", encoding="utf-8")
    (corpus / "z.md").write_text("lab note", encoding="utf-8")
    monkeypatch.setattr("rag.ingest.MAX_FILE_BYTES", 100)
    real = rag.ingest.discover_documents

    def discover_then_swap(root: Path) -> list[Path]:
        found = real(root)
        swap(corpus / "z.md")
        return found

    monkeypatch.setattr("rag.ingest.discover_documents", discover_then_swap)
    previous = signal.signal(signal.SIGALRM, _blocked)
    signal.alarm(10)  # a blocking open on the FIFO fails the test instead of hanging it
    try:
        with pytest.raises(ValidationError, match=r"'z\.md'"):
            ingest(corpus)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def test_newlines_and_bom_read_as_read_text_did(tmp_path: Path) -> None:
    doc = tmp_path / "crlf.md"
    doc.write_bytes(b"\xef\xbb\xbfa\r\nb\rc\n\r\n")
    assert read_document(doc) == doc.read_text(encoding="utf-8") == "﻿a\nb\nc\n\n"
