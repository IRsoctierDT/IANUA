import subprocess
import sys
from qdrant_client import QdrantClient


def get_python_info():
    return sys.version


def get_git_tag():
    try:
        return subprocess.check_output(
            ["git", "describe", "--tags", "--abbrev=0"],
            text=True
        ).strip()
    except Exception:
        return "unknown"


def get_ollama_models():
    try:
        return subprocess.check_output(["ollama", "list"], text=True)
    except Exception as exc:
        return f"Ollama unavailable: {exc}"


def get_qdrant_collections():
    try:
        client = QdrantClient(url="http://localhost:6333", check_compatibility=False)
        return [collection.name for collection in client.get_collections().collections]
    except Exception as exc:
        return [f"Qdrant unavailable: {exc}"]
