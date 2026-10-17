# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Ollama availability probe for the dashboard sidebar.

Security consideration: this is the one dashboard module that starts a
process. ``ensure_ollama_running`` runs on every Streamlit rerun — every
widget interaction — and the first version spawned ``ollama serve`` on each
one while the daemon was not answering: measured, three reruns against a
non-responding Ollama spawned three daemons and blocked the UI for 30 s. The
spawn is now attempted **once per process**; later reruns report the earlier
attempt instead of repeating it. The argv is a literal, the probe URL is a
loopback constant, and nothing from the page reaches either.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from urllib.error import URLError
from urllib.request import urlopen

OLLAMA_URL = "http://localhost:11434/api/tags"

_start_attempted = False


def is_ollama_installed() -> bool:
    """Return whether an ``ollama`` executable is on ``PATH``."""
    return shutil.which("ollama") is not None


def is_ollama_running() -> bool:
    """Return whether the loopback Ollama API answers (any failure is ``False``)."""
    try:
        with urlopen(OLLAMA_URL, timeout=2) as response:
            return bool(response.status == 200)
    except URLError:
        return False
    except Exception:
        return False


def ensure_ollama_running(timeout_seconds: int = 10) -> str:
    """Return Ollama's status, starting it at most once per dashboard process.

    A detached ``ollama serve`` is spawned only when Ollama is installed, not
    answering, and no earlier call in this process already tried; the result
    is a status label the sidebar shows verbatim.
    """
    global _start_attempted
    if not is_ollama_installed():
        return "Ollama not installed"

    if is_ollama_running():
        return "Ollama running"

    if _start_attempted:
        return "Ollama start attempted earlier but not responding (not retried)"
    _start_attempted = True

    subprocess.Popen(
        ["ollama", "serve"],  # noqa: S607 - ollama is a known, user-installed system tool
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    deadline = time.time() + timeout_seconds

    while time.time() < deadline:
        if is_ollama_running():
            return "Ollama started"
        time.sleep(0.5)

    return "Ollama start attempted but not responding"
