# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""release.yml never writes to an immutable release, and refuses to guess whether one is.

Release immutability was enabled on this repository on 2026-10-23. GitHub fixes
a release's immutability when it is published, so v2.3.0 and every earlier
release stay mutable and every later one locks its tag and assets at publish.
The step "Create release with assets or repair existing release" therefore
meets both kinds: a mutable release it may still repair with
``gh release upload --clobber``, and an immutable one that refuses every upload.

Before this change the step uploaded to any published release. Against an
immutable release that is a refused upload and a failed job with no explanation,
and the case that reaches it is the one a human is most likely to cause:
publishing from the web page, which locks the release before this workflow can
attach anything.

These tests run the step's own ``run:`` script, read from the workflow, under
``bash -e`` (GitHub's default for a ``run:`` step that names no shell) against a
stand-in ``gh``. The stand-in is not GitHub: it models only the calls the step
makes, it refuses an upload to an immutable release with a stand-in message
rather than GitHub's own, and it fails on ``isImmutable`` when told to, as a
``gh`` older than the field would. ``jq``, ``grep`` and ``basename`` are the real
ones. The step's hard-coded ``/tmp/`` paths are redirected into the test's own
directory, so a run neither reads nor leaves files in the real ``/tmp``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 — fixed argv, shell=False, a stand-in gh on PATH
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

_WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/release.yml"
_STEP = "Create release with assets or repair existing release"
_TAG = "v9.9.9"
# The step's own scratch prefix, matched so the test can redirect it.
_STEP_TMP = "/tmp/"  # noqa: S108 - read from the workflow, never written to
_ASSETS = (
    "SHA256SUMS",
    "ianua-9.9.9-py3-none-any.whl",
    "ianua-9.9.9.tar.gz",
    "provenance-attestation.intoto.jsonl",
    "sbom-attestation.intoto.jsonl",
    "sbom.cdx.json",
)

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("jq") is None,
    reason="the step's script needs bash and jq, as the GitHub runner provides",
)

# The stand-in gh. State is a JSON file named by FAKE_GH_STATE; every call is
# appended to FAKE_GH_LOG so a test can assert what was never attempted.
_FAKE_GH = r"""
import json
import os
import sys
from pathlib import Path

state_path = Path(os.environ["FAKE_GH_STATE"])
state = json.loads(state_path.read_text(encoding="utf-8"))
argv = sys.argv[1:]
with open(os.environ["FAKE_GH_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(argv) + "\n")


def flag(name):
    return argv[argv.index(name) + 1] if name in argv else None


def save():
    state_path.write_text(json.dumps(state), encoding="utf-8")


if argv[:1] != ["release"] or len(argv) < 3:
    sys.exit("stand-in gh: unsupported call")
command = argv[1]
if command == "view":
    if not state["exists"]:
        sys.exit("release not found")
    fields = flag("--json").split(",")
    for field in fields:
        if field in state.get("unknown_fields", []):
            sys.exit(f'Unknown JSON field: "{field}"')
    record = {
        "isDraft": state["isDraft"],
        "isImmutable": state["isImmutable"],
        "assets": [{"name": name} for name in state["assets"]],
    }
    query = flag("--jq")
    if query is None:
        print(json.dumps({field: record[field] for field in fields}))
    elif query == ".isImmutable":
        print(json.dumps(record["isImmutable"]))
    elif query == ".assets[].name":
        print("\n".join(state["assets"]))
    else:
        sys.exit(f"stand-in gh: unmodelled --jq {query}")
elif command == "upload":
    if state["isImmutable"] is True:
        sys.exit("HTTP 422: stand-in refusal of an upload to an immutable release")
    names = [Path(p).name for p in argv[3:] if not p.startswith("--")]
    state["assets"] = sorted(set(state["assets"]) | set(names))
    save()
elif command == "create":
    if state["exists"]:
        sys.exit("a release with the same tag name already exists")
    paths = []
    for arg in argv[3:]:
        if arg.startswith("--"):
            break
        paths.append(arg)
    state.update(exists=True, isDraft=False, assets=sorted(Path(p).name for p in paths))
    save()
else:
    sys.exit(f"stand-in gh: unmodelled command {command}")
"""


def _step_script() -> str:
    """Return the step's ``run:`` script exactly as the workflow holds it."""
    workflow = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["publish-assets"]["steps"]
    script = next(step["run"] for step in steps if step.get("name") == _STEP)
    assert isinstance(script, str)
    return script


def _run(
    tmp_path: Path, state: dict[str, Any]
) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
    """Run the step against *state*; return the process and every gh call it made."""
    work = tmp_path / "work"
    (work / "release-assets").mkdir(parents=True)
    for name in _ASSETS:
        (work / "release-assets" / name).write_bytes(b"built")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    script = _step_script()
    assert f"{_STEP_TMP}release-state.json" in script  # the redirection below is not vacuous
    script_path = tmp_path / "step.sh"
    script_path.write_text(script.replace(_STEP_TMP, f"{scratch}/"), encoding="utf-8")

    bindir = tmp_path / "bin"
    bindir.mkdir()
    (tmp_path / "fake_gh.py").write_text(_FAKE_GH, encoding="utf-8")
    shims = {
        "gh": f'#!/bin/sh\nexec "{sys.executable}" "{tmp_path / "fake_gh.py"}" "$@"\n',
        # The create path passes `--target "$(git rev-parse HEAD)"`.
        "git": "#!/bin/sh\necho 0123456789abcdef0123456789abcdef01234567\n",
    }
    for name, body in shims.items():
        shim = bindir / name
        shim.write_text(body, encoding="utf-8")
        shim.chmod(0o755)

    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({"assets": [], **state}), encoding="utf-8")
    log_path = tmp_path / "calls.jsonl"
    log_path.touch()
    env = {
        "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}",
        "HOME": str(tmp_path),
        "TAG": _TAG,
        "GH_REPO": "example/ianua",
        "FAKE_GH_STATE": str(state_path),
        "FAKE_GH_LOG": str(log_path),
    }
    bash = shutil.which("bash")
    assert bash is not None
    result = subprocess.run(  # noqa: S603 - fixed argv, a stand-in gh on PATH
        [bash, "-e", str(script_path)],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    calls = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    return result, calls


def _writes(calls: list[list[str]]) -> list[list[str]]:
    return [call for call in calls if call[1] in {"upload", "create"}]


def _published(*, immutable: object, assets: tuple[str, ...] = ()) -> dict[str, Any]:
    return {"exists": True, "isDraft": False, "isImmutable": immutable, "assets": list(assets)}


def test_a_first_publication_creates_the_release_with_every_asset(tmp_path: Path) -> None:
    """Control: with no release yet, the step creates one carrying the whole set."""
    result, calls = _run(tmp_path, {"exists": False, "isDraft": False, "isImmutable": None})
    assert result.returncode == 0, result.stdout + result.stderr
    writes = _writes(calls)
    assert [call[1] for call in writes] == ["create"]
    assert sorted(
        Path(arg).name for arg in writes[0] if arg.startswith("release-assets/")
    ) == sorted(_ASSETS)


def test_a_mutable_release_is_still_repaired_in_place(tmp_path: Path) -> None:
    """v2.3.0 and earlier were published before the setting and stay repairable."""
    result, calls = _run(tmp_path, _published(immutable=False))
    assert result.returncode == 0, result.stdout + result.stderr
    writes = _writes(calls)
    assert [call[1] for call in writes] == ["upload"]
    assert "--clobber" in writes[0]


def test_a_complete_immutable_release_is_left_alone(tmp_path: Path) -> None:
    """A re-dispatch for a locked, complete release succeeds without writing to it."""
    result, calls = _run(tmp_path, _published(immutable=True, assets=_ASSETS))
    assert result.returncode == 0, result.stdout + result.stderr
    assert _writes(calls) == []
    assert f"::notice::{_TAG} is an immutable release" in result.stdout


@pytest.mark.parametrize(
    "attached",
    [
        pytest.param((), id="published-from-the-web-page"),
        pytest.param(tuple(a for a in _ASSETS if a != "SHA256SUMS"), id="one-asset-missing"),
    ],
)
def test_an_incomplete_immutable_release_fails_and_names_what_is_missing(
    tmp_path: Path, attached: tuple[str, ...]
) -> None:
    """Nothing can be attached, so the job fails, says which asset, and never tries."""
    result, calls = _run(tmp_path, _published(immutable=True, assets=attached))
    assert result.returncode != 0
    assert _writes(calls) == []
    missing = sorted(set(_ASSETS) - set(attached))[0]
    assert f"::error::{_TAG} has no release asset named {missing}" in result.stdout


def test_an_unreadable_immutability_is_refused_not_guessed(tmp_path: Path) -> None:
    """``null`` is neither answer: treating it as mutable would upload into a refusal."""
    result, calls = _run(tmp_path, _published(immutable=None))
    assert result.returncode != 0
    assert _writes(calls) == []
    assert f"::error::cannot tell whether {_TAG} is an immutable release" in result.stdout


def test_a_gh_without_the_field_fails_instead_of_creating_a_duplicate(tmp_path: Path) -> None:
    """An older gh rejects ``isImmutable``; that must not read as "no release exists"."""
    state = _published(immutable=True, assets=_ASSETS)
    state["unknown_fields"] = ["isImmutable"]
    result, calls = _run(tmp_path, state)
    assert result.returncode != 0
    assert _writes(calls) == []
    assert 'Unknown JSON field: "isImmutable"' in result.stderr


def test_a_draft_is_still_refused_before_anything_is_written(tmp_path: Path) -> None:
    """Unchanged behaviour: an existing draft is never published or repaired from here."""
    result, calls = _run(tmp_path, {"exists": True, "isDraft": True, "isImmutable": False})
    assert result.returncode != 0
    assert _writes(calls) == []
