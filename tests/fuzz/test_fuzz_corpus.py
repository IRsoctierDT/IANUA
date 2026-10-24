# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The fuzz harness, held in place on every platform, Atheris installed or not.

Atheris runs only on Linux x86_64 with Python >= 3.12, so on macOS, on 3.11 and
in every other CI job the fuzz targets would otherwise go unexercised and could
rot unseen. This file runs them the cheap way: every seed through its target,
plus one planted violation per target to show its invariants can fail at all —
a target whose checks never fire would pass these and fuzz nothing. It also
pins the parts that silently disable fuzzing when they go wrong: the runner's
instrumentation, the CI matrix and path filters, the workflow's assumption that
the targets need nothing but the standard library, and the marker that keeps
the dependency off platforms with no wheel.
"""

from __future__ import annotations

import ast
import dataclasses
import ipaddress
import json
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml
from packaging.markers import default_environment
from packaging.requirements import Requirement

from ingest.normalize import normalize
from ingest.schema import MAX_FIELD_LEN, NormalizedEvent
from tests.fuzz import seeds as seeds_module
from tests.fuzz import targets
from tests.fuzz.seeds import seeds
from tests.fuzz.targets import TARGETS

_REPO = Path(__file__).resolve().parents[2]
_RUNNER = _REPO / "tests" / "fuzz" / "__main__.py"
_WORKFLOW = _REPO / ".github" / "workflows" / "fuzz.yml"

_CASES = [(name, index) for name in sorted(TARGETS) for index in range(len(seeds(name)))]


@pytest.mark.security
@pytest.mark.parametrize(("name", "index"), _CASES, ids=[f"{n}-{i:03d}" for n, i in _CASES])
def test_every_seed_keeps_its_targets_invariants(name: str, index: int) -> None:
    TARGETS[name](seeds(name)[index])


@pytest.mark.unit
@pytest.mark.parametrize("name", sorted(TARGETS))
def test_every_target_has_seeds(name: str) -> None:
    assert seeds(name), f"{name} has no seeds, so the fuzzer would start from nothing"


@pytest.mark.unit
def test_the_seeds_cli_writes_one_file_per_seed(tmp_path: Path) -> None:
    assert seeds_module.main(["seeds", "egress", str(tmp_path)]) == 0
    assert len(list(tmp_path.iterdir())) == len(seeds("egress"))
    assert seeds_module.main(["seeds", "no-such-target", str(tmp_path)]) == 2


# --- each target's invariants can fail -------------------------------------


def _event() -> NormalizedEvent:
    return normalize(seeds("normalize")[0])


@pytest.mark.security
def test_the_normalize_target_refuses_an_unbounded_event(monkeypatch: pytest.MonkeyPatch) -> None:
    oversized = dataclasses.replace(_event(), message="x" * (MAX_FIELD_LEN + 1))
    monkeypatch.setattr(targets, "normalize", lambda _data: oversized)
    with pytest.raises(AssertionError, match="message is"):
        targets.one_input_normalize(b"anything")


@pytest.mark.security
def test_the_normalize_target_refuses_an_observable_from_outside_the_excerpt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    leaked = dataclasses.replace(
        _event(), vendor="unrecognized", raw_excerpt="{}", observables=("outside.example",)
    )
    monkeypatch.setattr(targets, "normalize", lambda _data: leaked)
    with pytest.raises(AssertionError, match="not inside the retained excerpt"):
        targets.one_input_normalize(b"anything")


@pytest.mark.security
def test_the_keyvalue_target_refuses_a_value_the_line_does_not_contain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(targets, "decode", lambda _line: {"user": "invented", "src": "x"})
    with pytest.raises(AssertionError, match="does not occur in the line"):
        targets.one_input_keyvalue(b"user=alice src=x")


@pytest.mark.security
def test_the_egress_target_refuses_an_accepted_link_local_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        targets, "parse_address", lambda _value: ipaddress.ip_address("169.254.169.254")
    )
    with pytest.raises(AssertionError, match="link-local"):
        targets.one_input_egress((80).to_bytes(2, "big") + b"169.254.169.254")


@pytest.mark.security
def test_the_projection_target_refuses_an_unbounded_rebuild(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oversized = dataclasses.replace(_event(), message="x" * (MAX_FIELD_LEN + 1))
    monkeypatch.setattr(NormalizedEvent, "from_dict", classmethod(lambda _cls, _payload: oversized))
    with pytest.raises(AssertionError, match="message is"):
        targets.one_input_projection(seeds("projection")[0])


# --- the parts that silently disable fuzzing --------------------------------


def _is_atheris_call(node: ast.AST, name: str) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == name
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "atheris"
    )


@pytest.mark.unit
def test_the_runner_instruments_the_code_under_test_before_fuzzing() -> None:
    body = ast.parse(_RUNNER.read_text(encoding="utf-8")).body
    instrumented = [
        index
        for index, node in enumerate(body)
        if isinstance(node, ast.With)
        and any(_is_atheris_call(item.context_expr, "instrument_imports") for item in node.items)
        and any(
            isinstance(inner, ast.ImportFrom) and inner.module == "tests.fuzz.targets"
            for inner in node.body
        )
    ]
    assert instrumented, "the targets must be imported inside atheris.instrument_imports()"
    after = [
        index
        for index, node in enumerate(body)
        if isinstance(node, ast.Expr) and _is_atheris_call(node.value, "instrument_all")
    ]
    assert after and after[0] > instrumented[0], (
        "atheris.instrument_all() must follow the import block: `import atheris` loads "
        "ipaddress itself, so instrument_imports() can never reach it"
    )
    # A relative import has no module name; "." keeps it visible to the check.
    imports = {
        alias.name for node in body if isinstance(node, ast.Import) for alias in node.names
    } | {node.module or "." for node in body if isinstance(node, ast.ImportFrom)}
    allowed = {"__future__", "sys", "atheris"}
    assert imports <= allowed, (
        f"imported outside the instrumented block: {sorted(imports - allowed)}"
    )


def _workflow() -> dict[Any, Any]:
    # ``dict[Any, Any]``: PyYAML reads the key ``on`` as the boolean True.
    workflow = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict), "fuzz.yml must parse to a mapping"
    return workflow


@pytest.mark.unit
def test_the_workflow_fuzzes_every_target() -> None:
    matrices = [
        job.get("strategy", {}).get("matrix", {}).get("target")
        for job in _workflow()["jobs"].values()
    ]
    assert sorted(TARGETS) in matrices, (
        f"fuzz.yml's matrix {matrices} does not run exactly the registered targets {sorted(TARGETS)}"
    )


#: Every repository file the targets and seeds load, printed by a fresh
#: interpreter started the way the workflow starts one: from the checkout root,
#: with nothing installed. ``-S`` leaves site-packages off ``sys.path``, so an
#: import from outside the standard library fails here as it would in CI, and
#: ``-E`` ignores ``PYTHONPATH`` and ``PYTHONSAFEPATH``.
_IMPORT_GRAPH = """\
import json, sys
from pathlib import Path
import tests.fuzz.seeds, tests.fuzz.targets
root = Path.cwd().resolve()
files = {Path(m.__file__).resolve() for m in list(sys.modules.values()) if getattr(m, "__file__", None)}
print(json.dumps(sorted(f.relative_to(root).as_posix() for f in files if f.is_relative_to(root))))
"""


def _covered(path: str, patterns: list[str]) -> bool:
    return any(
        path.startswith(pattern.removesuffix("**")) if pattern.endswith("/**") else path == pattern
        for pattern in patterns
    )


@pytest.mark.unit
def test_the_workflow_runs_on_every_file_the_targets_read() -> None:
    result = subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, "-E", "-S", "-c", _IMPORT_GRAPH],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=_REPO,
        check=False,
    )
    assert result.returncode == 0, (
        "the targets must import with the standard library alone, because fuzz.yml installs "
        f"Atheris and nothing else:\n{result.stderr}"
    )
    read = set(json.loads(result.stdout)) | {
        path.relative_to(_REPO).as_posix()
        for path in (
            seeds_module._FIXTURES,
            _RUNNER,
            _WORKFLOW,
            _REPO / "security" / "sbom" / "requirements.lock",
        )
    }
    triggers = _workflow()[True]
    patterns: list[str] = triggers["pull_request"]["paths"]
    assert triggers["push"]["paths"] == patterns, "pull_request and push filter different paths"
    for pattern in patterns:
        assert not set(pattern.removesuffix("/**")) & set("*?[]!+"), (
            f"{pattern!r}: only `directory/**` and exact paths are checked here"
        )
    missed = sorted(path for path in read if not _covered(path, patterns))
    assert not missed, f"fuzz.yml does not run when these change: {missed}"
    unread = [
        pattern for pattern in patterns if not any(_covered(path, [pattern]) for path in read)
    ]
    assert not unread, f"fuzz.yml runs on paths the targets never read: {unread}"


def _fuzz_requirement() -> Requirement:
    project = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    (spec,) = project["optional-dependencies"]["fuzz"]
    return Requirement(spec)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("system", "machine", "python", "installs"),
    [
        ("linux", "x86_64", "3.12", True),
        ("linux", "x86_64", "3.13", True),
        ("linux", "x86_64", "3.11", False),
        ("linux", "aarch64", "3.12", False),
        ("darwin", "arm64", "3.12", False),
        ("win32", "AMD64", "3.12", False),
    ],
)
def test_the_fuzz_extra_installs_only_where_atheris_ships_a_wheel(
    system: str, machine: str, python: str, installs: bool
) -> None:
    requirement = _fuzz_requirement()
    assert requirement.name == "atheris"
    assert requirement.marker is not None, "without a marker, macOS and 3.11 installs fail"
    environment = {
        **{key: str(value) for key, value in default_environment().items()},
        "sys_platform": system,
        "platform_machine": machine,
        "python_version": python,
        "python_full_version": f"{python}.0",
    }
    assert requirement.marker.evaluate(environment) is installs
