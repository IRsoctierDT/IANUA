# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Shared Qdrant client factory: embedded-by-default, server by opt-in.

Security consideration — attack-surface reduction: when ``QDRANT_URL`` is not
set, the client runs **embedded** (in-process, vectors stored under
``QDRANT_PATH``, default ``data/qdrant`` at the source tree — in the gitignored ``data/``
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

#: The source tree this module was loaded from (``agents/incident_report_agent.py``'s
#: anchor): the checkout for an editable install, as ``.devcontainer`` runs. A
#: non-editable install anchors at the installed package; set QDRANT_PATH absolute.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_LAB_DIR = "data"
_DEFAULT_RELATIVE = Path(_LAB_DIR, "qdrant")

#: Where the embedded store goes when ``QDRANT_PATH`` is unset or empty.
DEFAULT_EMBEDDED_PATH = _REPO_ROOT / _DEFAULT_RELATIVE


class QdrantPathError(ValueError):
    """``QDRANT_PATH`` names a place the embedded store must not be created."""


def embedded_path(value: str | None, *, repo_root: Path | None = None) -> Path:
    """Return the resolved directory the embedded store uses for ``value``.

    ``value`` is ``QDRANT_PATH`` as found in the environment. Nothing is
    created here; :func:`make_client` creates exactly the path returned.

    * Unset or empty selects ``data/qdrant`` beneath ``repo_root`` (default
      :data:`_REPO_ROOT`). The previous fallback, the string ``"./data/qdrant"``,
      was relative to the *working directory*: measured, an empty variable built
      a shadow ``data/qdrant`` in an unrelated CWD, and from ``scripts/`` one the
      root-anchored ``/data/`` ignore rule does not cover.
    * A relative value is joined to ``repo_root``, never to the CWD, so the
      ``.env.example`` value ``./data/qdrant`` names one directory from anywhere.
    * A value whose lexical or resolved path is inside ``repo_root`` must resolve
      **strictly beneath** ``repo_root/data``. That refuses ``" "``, ``"."``,
      ``"scripts/data/qdrant"``, ``"../x"``, an absolute path into the tracked
      tree, and a symlink at ``data`` or ``data/qdrant`` leading out of it.
    * A path resolving to the filesystem root is refused: ``"$UNSET/"`` is
      exactly ``"/"``, the case ``store/paths.py::validated_root`` refuses.

    **Not refused, deliberately:** any other absolute path outside ``repo_root``,
    including ``/proc/self/cwd`` from a CWD outside the tree and a symlink the
    operator chose. Whoever writes one has named that directory; nothing here
    can tell that from intent. A link swapped in after this check is not caught.

    Raises:
        QdrantPathError: on any refusal above, naming the value and the rule.
    """
    root = (_REPO_ROOT if repo_root is None else repo_root).resolve()
    lab_root = root / _LAB_DIR
    raw = Path(value) if value else _DEFAULT_RELATIVE
    candidate = raw if raw.is_absolute() else root / raw
    resolved = candidate.resolve()
    if resolved.parent == resolved:
        raise QdrantPathError(
            f"QDRANT_PATH={value!r} resolves to the filesystem root; an unset variable "
            'with a trailing slash ("$QDRANT_DIR/") is exactly "/"'
        )
    in_tree = candidate.is_relative_to(root) or resolved.is_relative_to(root)
    if in_tree and lab_root not in resolved.parents:
        raise QdrantPathError(
            f"QDRANT_PATH={value!r} resolves to {resolved}, inside {root} but not beneath "
            f"its gitignored {lab_root}; a relative value is anchored at {root}, never at "
            "the working directory. Name a path under data/, or an absolute one outside "
            "the tree."
        )
    return resolved


def make_client() -> QdrantClient:
    """Build the Qdrant client from the environment (embedded unless opted in).

    ``QDRANT_URL`` set → remote/server client (explicit opt-in to a network
    service). Otherwise → embedded local client at :func:`embedded_path` of
    ``QDRANT_PATH`` (default ``data/qdrant`` beneath the source tree), which
    listens on nothing.

    Raises ``RuntimeError`` with an actionable message when the optional
    ``qdrant-client`` dependency is absent (minimal installs), instead of a
    bare ``ModuleNotFoundError`` traceback, and :class:`QdrantPathError`
    before creating anything when ``QDRANT_PATH`` is refused.
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

    # Set-but-empty is unset: ``Path("") == Path(".")`` once reached
    # ``QdrantClient(path=".")``. ``embedded_path`` owns every rule.
    path = embedded_path(os.environ.get("QDRANT_PATH"))
    path.mkdir(parents=True, exist_ok=True)
    return QdrantClient(path=str(path))
