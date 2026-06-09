import shutil
import subprocess
import time
from urllib.request import urlopen
from urllib.error import URLError


OLLAMA_URL = "http://localhost:11434/api/tags"


def is_ollama_installed() -> bool:
    return shutil.which("ollama") is not None


def is_ollama_running() -> bool:
    try:
        with urlopen(OLLAMA_URL, timeout=2) as response:
            return response.status == 200
    except URLError:
        return False
    except Exception:
        return False


def ensure_ollama_running(timeout_seconds: int = 10) -> str:
    if not is_ollama_installed():
        return "Ollama not installed"

    if is_ollama_running():
        return "Ollama running"

    subprocess.Popen(
        ["ollama", "serve"],
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
