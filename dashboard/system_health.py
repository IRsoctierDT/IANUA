"""Read-only system-health probes for the dashboard sidebar.

Each probe fails soft — it returns a human-readable status string rather than
raising — so the dashboard renders even when Ollama/Qdrant/git are unavailable.
"""

from __future__ import annotations

import subprocess
import sys

from qdrant_client import QdrantClient


def get_python_info() -> str:
    """Return the running Python version string."""
    return sys.version


def get_git_tag() -> str:
    """Return the latest git tag, or 'unknown' if none/unavailable."""
    try:
        return subprocess.check_output(
            ["git", "describe", "--tags", "--abbrev=0"],  # noqa: S607 - git is a known system tool
            text=True,
        ).strip()
    except Exception:
        return "unknown"


def get_ollama_models() -> str:
    """Return `ollama list` output, or an 'unavailable' message."""
    try:
        return subprocess.check_output(["ollama", "list"], text=True)  # noqa: S607 - hardcoded trusted command
    except Exception as exc:
        return f"Ollama unavailable: {exc}"


def get_qdrant_collections() -> list[str]:
    """Return Qdrant collection names, or a single 'unavailable' entry."""
    try:
        client = QdrantClient(url="http://localhost:6333", check_compatibility=False)
        return [collection.name for collection in client.get_collections().collections]
    except Exception as exc:
        return [f"Qdrant unavailable: {exc}"]
