"""Integration test: the rag_cli pipeline end-to-end in --offline mode."""

from pathlib import Path

import pytest
from scripts.rag_cli import main

# Repo root is two levels up from tests/integration/.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_KNOWLEDGE_BASE = _REPO_ROOT / "knowledge-base"


@pytest.mark.integration
def test_cli_offline_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "zt.md").write_text("zero trust network segmentation with vlans", encoding="utf-8")
    (corpus / "ids.md").write_text("suricata ids ips tuning for the lab", encoding="utf-8")

    code = main(
        ["--corpus", str(corpus), "--query", "zero trust segmentation", "--k", "1", "--offline"]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "zt.md" in out  # most similar document surfaced first


@pytest.mark.integration
def test_cli_empty_corpus_returns_1(tmp_path: Path) -> None:
    corpus = tmp_path / "empty"
    corpus.mkdir()
    code = main(["--corpus", str(corpus), "--query", "anything", "--offline"])
    assert code == 1


@pytest.mark.security
def test_cli_missing_corpus_fails_cleanly(tmp_path: Path) -> None:
    code = main(["--corpus", str(tmp_path / "nope"), "--query", "x", "--offline"])
    assert code == 2  # ValidationError -> exit 2, no traceback


@pytest.mark.integration
@pytest.mark.skipif(
    not _KNOWLEDGE_BASE.is_dir(), reason="shipped knowledge-base/ corpus not present"
)
def test_shipped_knowledge_base_is_retrievable(capsys: pytest.CaptureFixture[str]) -> None:
    """The shipped cybersecurity knowledge base ingests and returns results.

    Guards against accidental deletion/corruption of the curated corpus. Uses the
    offline embedder, so this asserts the pipeline works end-to-end over real
    content without asserting semantic ranking (the offline embedder is not
    semantic by design).
    """
    code = main(
        [
            "--corpus",
            str(_KNOWLEDGE_BASE),
            "--query",
            "security operations",
            "--k",
            "3",
            "--offline",
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert out.strip(), "expected at least one retrieved chunk from the knowledge base"
    assert ".md#" in out  # results reference markdown sources with chunk indices
