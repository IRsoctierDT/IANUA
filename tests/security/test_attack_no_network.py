"""attack/ is structurally offline, clock-free, and dependency-free.

The vocabulary layer must be safe to import from every other layer: no
network module, no subprocess, no dynamic-import escape hatch, no wall-clock
reads, and zero first-party imports (the layering is structural). An AST walk
catches literal imports; a sys.modules diff around a fresh import catches the
transitive case the AST cannot see.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

_ATTACK_DIR = Path(__file__).resolve().parents[2] / "attack"

_BANNED_MODULES = {
    "urllib",
    "urllib.request",
    "socket",
    "http",
    "http.client",
    "ssl",
    "ftplib",
    "smtplib",
    "asyncio",
    "subprocess",
    "importlib",
}
_BANNED_CALLS = {"__import__", "eval", "exec", "compile"}
_FIRST_PARTY = {"agents", "compliance", "dashboard", "mcp", "rag", "scripts", "tests"}


def _modules() -> list[Path]:
    files = sorted(_ATTACK_DIR.glob("*.py"))
    assert files, "attack/ has no modules?"
    return files


@pytest.mark.security
def test_no_banned_or_first_party_imports() -> None:
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert alias.name not in _BANNED_MODULES and root not in _BANNED_MODULES, (
                        f"{path.name} imports banned module {alias.name}"
                    )
                    assert root not in _FIRST_PARTY, (
                        f"{path.name} imports first-party {alias.name} — layering violation"
                    )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                root = module.split(".")[0]
                assert module not in _BANNED_MODULES and root not in _BANNED_MODULES, (
                    f"{path.name} imports from banned module {module}"
                )
                assert root not in _FIRST_PARTY, (
                    f"{path.name} imports first-party {module} — layering violation"
                )
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in _BANNED_CALLS, (
                    f"{path.name} calls {node.func.id} — dynamic-import escape hatch"
                )


@pytest.mark.security
def test_no_clock_reads() -> None:
    # freshness() takes an injected `today`; nothing in attack/ may read one.
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in ("now", "today", "utcnow"):
                raise AssertionError(f"{path.name} reads a clock ({node.attr})")


@pytest.mark.security
def test_transitive_import_surface_is_clean() -> None:
    # Fresh interpreter: importing attack must not pull in any network module.
    code = (
        "import sys; before = set(sys.modules); import attack; "
        "attack.load_corpus(); new = set(sys.modules) - before; "
        "banned = {'socket', 'ssl', 'http', 'urllib.request', 'subprocess'}; "
        "hit = sorted(banned & new); print(','.join(hit) if hit else 'CLEAN')"
    )
    result = subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
        cwd=_ATTACK_DIR.parent,
    )
    assert result.stdout.strip() == "CLEAN", f"attack import pulled in: {result.stdout}"
