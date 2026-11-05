# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""`uv` is pinned to an exact version and an independently sourced checksum.

`uv` resolves and installs this repository's dependency tree, and `uv lock
--check` is a CI gate. So which `uv` runs, and whether the binary that runs is
the one upstream published, are supply-chain questions rather than conveniences.

**What was measured, on the job's own log and the action's own source at the SHA
`ci.yml` pins (2026-11-05).** With no `version` input, `setup-uv` reported
"Could not determine uv version from uv.toml or pyproject.toml. Falling back to
latest" and installed 0.13.7 — a gate's toolchain moving with no commit.

The checksum gap that created is **structural, not incidental**.
`src/download/checksum/checksum.ts` validates a download against, in priority
order, a user-supplied checksum, the action's own bundled table, then the
manifest's — and with none of the three it "returns without validating".
`src/download/checksum/known-checksums.json` at that SHA holds 5630 entries
topping out at uv **0.13.6**, so the 0.13.7 that `latest` resolved was one
release *past* the bundled set. A bundle that necessarily lags new uv releases
means `latest` lands outside it every time. What remained was the manifest
checksum, served by `releases.astral.sh` — the same host that serves the
artifact. Verification against a hash from the artifact's own origin is not
independent verification.

**So both inputs are required here, and the asymmetry is the point.** The
version is fixed, and the expected hash is taken from `github.com` while the
artifact is served by `releases.astral.sh`, so CI compares across origins on
every run. The hash covers the *archive*: measured in
`src/download/download-version.ts`, `validateChecksum` receives `downloadPath`
and runs before `tc.extractTar`.

This module fails if either input is dropped, if the version stops being exact
(a range cannot have one checksum), or if the checksum stops being a 64-hex
sha256. It does **not** verify the hash against upstream — that would need
network access a test must not take, and CI performs that comparison itself.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]
_WORKFLOWS = _REPO / ".github" / "workflows"

#: Both spellings GitHub accepts, matching `test_workflow_permissions.py`.
_SUFFIXES = (".yml", ".yaml")

#: An exact version, never a range or an alias. `latest` and `latest-known` are
#: what this pin exists to stop, and a range cannot carry a single checksum.
_EXACT_VERSION = re.compile(r"^\d+\.\d+\.\d+$")

#: sha256, lowercase hex, as `checksum.ts` compares it.
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def setup_uv_steps(workflow: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Every step in ``workflow`` that invokes ``astral-sh/setup-uv``."""
    return [
        (job_name, step)
        for job_name, job in (workflow.get("jobs") or {}).items()
        for step in (job.get("steps") or [])
        if str(step.get("uses", "")).startswith("astral-sh/setup-uv@")
    ]


def pin_violations(where: str, step: dict[str, Any]) -> list[str]:
    """Ways a ``setup-uv`` step could stop pinning its toolchain.

    A callable rather than an inline loop, so the rules can be driven against
    planted steps as well as the shipped ones — the shipped corpus is one step
    today, and a guard that only ever sees a passing case proves little.
    """
    problems: list[str] = []
    inputs = step.get("with") or {}

    version = str(inputs.get("version", "")).strip()
    if not version:
        problems.append(
            f"{where}: setup-uv declares no `version`, so it resolves `latest` — measured,"
            " that installed a uv one release past the action's bundled checksum table,"
            " leaving only a manifest hash served by the same host as the artifact"
        )
    elif not _EXACT_VERSION.match(version):
        problems.append(
            f"{where}: `version: {version!r}` is not an exact X.Y.Z. A range or alias cannot"
            " have one pinned checksum, so the two inputs would disagree by construction"
        )

    checksum = str(inputs.get("checksum", "")).strip()
    if not checksum:
        problems.append(
            f"{where}: setup-uv declares no `checksum`. Without it the expected hash comes"
            " from the artifact's own origin, or — with no manifest hash either — the action"
            " returns without validating at all"
        )
    elif not _SHA256_HEX.match(checksum):
        problems.append(f"{where}: `checksum: {checksum!r}` is not a lowercase 64-hex sha256")
    return problems


def _workflows() -> list[tuple[Path, dict[str, Any]]]:
    out: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(_WORKFLOWS.iterdir()):
        if path.is_file() and path.suffix.lower() in _SUFFIXES:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                out.append((path, loaded))
    return out


# --------------------------------------------------------------------------- #
# The live assertions
# --------------------------------------------------------------------------- #


@pytest.mark.security
def test_there_is_a_setup_uv_step_to_check() -> None:
    """A guard over zero steps is vacuous, so assert the corpus is non-empty."""
    found = [(p.name, job) for p, w in _workflows() for job, _ in setup_uv_steps(w)]
    assert found, "no astral-sh/setup-uv step found; this module would prove nothing"


@pytest.mark.security
def test_every_setup_uv_step_pins_an_exact_version_and_a_checksum() -> None:
    problems: list[str] = []
    for path, workflow in _workflows():
        for job_name, step in setup_uv_steps(workflow):
            problems += pin_violations(f"{path.name}:{job_name}", step)
    assert not problems, "uv toolchain is not pinned:\n" + "\n".join(problems)


# --------------------------------------------------------------------------- #
# The rules, driven against planted steps
# --------------------------------------------------------------------------- #


_GOOD = {"version": "0.13.7", "checksum": "c" * 64}


@pytest.mark.security
def test_a_fully_pinned_step_passes() -> None:
    assert (
        pin_violations("planted", {"uses": "astral-sh/setup-uv@" + "a" * 40, "with": _GOOD}) == []
    )


@pytest.mark.security
@pytest.mark.parametrize(
    ("inputs", "reason"),
    [
        (None, "no `with:` block at all — the state this change fixes"),
        ({}, "an empty `with:` block"),
        ({"checksum": "c" * 64}, "checksum without a version: nothing fixes what it describes"),
        ({"version": "0.13.7"}, "version without a checksum"),
        ({**_GOOD, "version": "latest"}, "`latest` — what the action falls back to"),
        ({**_GOOD, "version": "latest-known"}, "the other alias the action accepts"),
        ({**_GOOD, "version": ">=0.13"}, "a range cannot carry one checksum"),
        ({**_GOOD, "version": "0.13"}, "a two-part version is not exact"),
        ({**_GOOD, "checksum": "C" * 64}, "uppercase hex, which the comparison would miss"),
        ({**_GOOD, "checksum": "c" * 63}, "a truncated digest"),
        (
            {**_GOOD, "checksum": "sha256:" + "c" * 64},
            "a prefixed digest the action will not match",
        ),
    ],
)
def test_each_way_the_pin_could_be_lost_is_caught(inputs: Any, reason: str) -> None:
    step = {"uses": "astral-sh/setup-uv@" + "a" * 40}
    if inputs is not None:
        step["with"] = inputs
    assert pin_violations("planted", step), f"not caught: {reason}"


@pytest.mark.security
def test_a_step_that_is_not_setup_uv_is_not_examined() -> None:
    """The selector must not stray onto other actions, including lookalikes."""
    workflow = {
        "jobs": {
            "j": {
                "steps": [
                    {"uses": "actions/checkout@" + "a" * 40},
                    {"uses": "astral-sh/setup-uv-mirror@" + "b" * 40},  # not the same action
                    {"run": "echo hello"},
                ]
            }
        }
    }
    assert setup_uv_steps(workflow) == []
