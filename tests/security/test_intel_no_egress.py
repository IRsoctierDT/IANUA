"""intel/ is structurally offline and clock-free."""

from __future__ import annotations

import ast
import socket
from datetime import date
from pathlib import Path

import pytest

_INTEL_DIR = Path(__file__).resolve().parents[2] / "intel"

_BANNED = {"urllib", "socket", "http", "ssl", "ftplib", "smtplib", "asyncio", "subprocess"}


@pytest.mark.security
def test_no_network_imports_or_clock_reads() -> None:
    for path in sorted(_INTEL_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in _BANNED, (
                        f"{path.name} imports {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in _BANNED, (
                    f"{path.name} imports from {node.module}"
                )
            elif isinstance(node, ast.Attribute) and node.attr in ("now", "today", "utcnow"):
                raise AssertionError(f"{path.name} reads a clock ({node.attr})")


@pytest.mark.security
def test_full_load_and_query_opens_no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []

    class _Boom(OSError):
        pass

    def _deny(*args: object, **kwargs: object) -> None:
        calls.append(args)
        raise _Boom("socket use is banned in intel/")

    monkeypatch.setattr(socket, "socket", _deny)
    from attack import load_corpus
    from intel import load_store, lookup_indicator, match_behaviors

    store = load_store()
    corpus = load_corpus()
    lookup_indicator(store, "203.0.113.66", as_of=date(2026, 8, 21))
    match_behaviors(store, "authentication failure", corpus, as_of=date(2026, 8, 21))
    assert calls == []
