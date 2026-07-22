"""Shared Qdrant client factory: embedded-by-default, server by opt-in.

Security consideration — attack-surface reduction: when ``QDRANT_URL`` is not
set, the client runs **embedded** (in-process, vectors stored under
``QDRANT_PATH``, default ``./data/qdrant`` — inside the gitignored ``data/``
tree). Embedded mode opens **zero listening ports** and needs no service,
container, or daemon; it is the secure default for laptops, Codespaces, and
CI. Setting ``QDRANT_URL`` (documented in ``.env.example``) opts in to a
running Qdrant server, e.g. the compose lab stack.

Embedded-mode caveat: the storage path is locked by one process at a time —
run either the dashboard or an ingest script against it, not both at once
(the server mode has no such restriction).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # heavy optional dep: imported lazily at call time
    from qdrant_client import QdrantClient

DEFAULT_EMBEDDED_PATH = "./data/qdrant"


def make_client() -> QdrantClient:
    """Build the Qdrant client from the environment (embedded unless opted in).

    ``QDRANT_URL`` set → remote/server client (explicit opt-in to a network
    service). Otherwise → embedded local client at ``QDRANT_PATH`` (default
    ``./data/qdrant``), which listens on nothing.

    Raises ``RuntimeError`` with an actionable message when the optional
    ``qdrant-client`` dependency is absent (minimal installs), instead of a
    bare ``ModuleNotFoundError`` traceback.
    """
    try:
        from qdrant_client import QdrantClient
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised via stub tests
        raise RuntimeError(
            "qdrant-client is not installed - semantic vector search needs the "
            "dashboard extra: pip install -e '.[dashboard]'"
        ) from exc

    url = os.environ.get("QDRANT_URL")
    if url:
        return QdrantClient(url=url, check_compatibility=False)

    path = Path(os.environ.get("QDRANT_PATH", DEFAULT_EMBEDDED_PATH))
    path.mkdir(parents=True, exist_ok=True)
    return QdrantClient(path=str(path))
