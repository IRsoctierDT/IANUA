"""Agent package — shared platform version (single source of truth).

Every agent reports the **platform** version in its display name (e.g.
``"SOC Analyst Agent v1.9.0"``), derived at import time from one authority
instead of per-agent hard-coded strings, so agent versions can never drift
from the release again (the incident this module fixes: the SOC Analyst Agent
still announced ``v0.2`` while the platform was at ``v1.9.0``).

Resolution order for :data:`__version__`:

1. ``pyproject.toml`` ``[project].version`` at the repository root — the
   release source of truth (matches ``scripts/build_status_page.py``); present
   in dev checkouts and editable installs.
2. Installed distribution metadata (``importlib.metadata``) — covers
   non-editable installs where ``pyproject.toml`` is not on disk.
3. ``"0.0.0"`` — a deliberately conspicuous sentinel rather than a crash:
   failing to resolve a display version must not take the agents down, but it
   should be unmissable in output (AGENTS.md §3: secure defaults, visible
   failure).

Security considerations: reads only the local, committed ``pyproject.toml``
(trusted repository file, stdlib ``tomllib``) or local package metadata — no
network access, no untrusted input.
"""

from __future__ import annotations

import tomllib
from importlib import metadata
from pathlib import Path

_DIST_NAME = "ai-operator-cyber-command-center"
_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _resolve_version() -> str:
    """Resolve the platform version (pyproject → installed metadata → sentinel)."""
    try:
        data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
        version = data.get("project", {}).get("version")
        if isinstance(version, str) and version:
            return version
    except (OSError, tomllib.TOMLDecodeError):
        pass
    try:
        return metadata.version(_DIST_NAME)
    except metadata.PackageNotFoundError:
        return "0.0.0"


__version__: str = _resolve_version()


def versioned_agent_name(base: str) -> str:
    """Return ``"<base> v<platform version>"`` for an agent display name.

    Args:
        base: The agent's human-readable base name, e.g. ``"SOC Analyst Agent"``.

    Returns:
        The base name suffixed with the current platform version, so every
        agent's reported identity tracks each release automatically.
    """
    return f"{base} v{__version__}"
