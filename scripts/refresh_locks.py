#!/usr/bin/env python3
"""Regenerate the derived pip lockfiles under ``security/sbom/`` from ``uv.lock``.

``uv.lock`` is the dependency source of truth; ``requirements.lock`` (the
Linux/3.12 ``[dev,dashboard]`` closure) and ``requirements-dev.lock`` (the
``[dev]`` export) are derived artifacts consumed by the SBOM/SCA gates. The
previously documented manual procedure ran ``uv pip compile`` *unconstrained*,
which resolves fresh from PyPI and can pick versions newer than ``uv.lock``'s
pins — producing a lock that immediately fails ``scripts/check_locks.py``.

This script closes that gap: it extracts the exact pins from ``uv.lock``
(selecting the correct fork, via PEP 508 marker evaluation, for packages that
``uv``'s universal resolution pins at different versions per platform/Python),
feeds them to ``uv pip compile`` as a constraints file, preserves each lock's
explanatory header comment, and fails closed by running the drift checker over
the result. Re-running it is idempotent.

Security considerations: all inputs are local, trusted repository files;
subprocesses are invoked with fixed argument vectors (never a shell); the only
network access is ``uv``'s sanctioned resolution against PyPI (AGENTS.md §7
supply-chain gate). The script writes only the two derived lockfiles.

Exit codes: ``0`` success · ``1`` regeneration or drift check failed ·
``2`` a required input was missing.
"""

from __future__ import annotations

import argparse
import subprocess  # nosec B404 — fixed argv, shell=False, trusted local tooling (uv)
import sys
import tempfile
import tomllib
from pathlib import Path

from packaging.markers import Marker

REPO_ROOT = Path(__file__).resolve().parent.parent
SBOM_DIR = REPO_ROOT / "security" / "sbom"

#: PEP 508 marker environment for the SBOM/SCA deployment target (Linux/3.12).
#: Mirrors the ``--python-platform x86_64-unknown-linux-gnu --python-version 3.12``
#: flags passed to ``uv pip compile`` below; keep the two in sync.
TARGET_ENVIRONMENT: dict[str, str] = {
    "python_version": "3.12",
    "python_full_version": "3.12.4",
    "sys_platform": "linux",
    "os_name": "posix",
    "platform_system": "Linux",
    "platform_machine": "x86_64",
    "implementation_name": "cpython",
    "platform_python_implementation": "CPython",
}


def lock_header(lock_path: Path) -> str:
    """Return the leading ``#`` comment block of ``lock_path`` (with trailing newline).

    The derived locks carry a human-facing header explaining their provenance;
    ``uv`` is run with ``--no-header`` and the original header is re-attached so
    regeneration never erases the documentation.
    """
    header_lines: list[str] = []
    for line in lock_path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("#"):
            break
        header_lines.append(line)
    return "\n".join(header_lines) + "\n" if header_lines else ""


def _matches_target(resolution_markers: list[str]) -> bool:
    """Return True if any of ``resolution_markers`` is satisfied by the target env.

    ``uv.lock`` attaches ``resolution-markers`` to packages that its universal
    resolution pins at different versions for different environments (e.g.
    ``numpy`` forks on ``python_full_version``). An entry with no markers is
    unconditional and always matches.
    """
    if not resolution_markers:
        return True
    return any(Marker(m).evaluate(environment=TARGET_ENVIRONMENT) for m in resolution_markers)


def target_pins(uv_lock: Path, project_name: str) -> dict[str, str]:
    """Return ``{name: version}`` for every package ``uv.lock`` pins for the target.

    Fails closed with ``ValueError`` if the marker evaluation selects more than
    one version for the same package — that would mean the target environment
    is ambiguous and the constraints would be self-contradictory.
    """
    data = tomllib.loads(uv_lock.read_text(encoding="utf-8"))
    pins: dict[str, str] = {}
    for pkg in data.get("package", []):
        name, version = pkg["name"], pkg["version"]
        if name == project_name:
            continue
        if not _matches_target(pkg.get("resolution-markers", [])):
            continue
        if name in pins and pins[name] != version:
            raise ValueError(
                f"uv.lock pins {name} at both {pins[name]} and {version} "
                f"for the target environment — refusing to build ambiguous constraints"
            )
        pins[name] = version
    return pins


def _run(argv: list[str]) -> None:
    """Run ``argv`` (no shell), raising ``CalledProcessError`` on failure."""
    subprocess.run(argv, check=True)  # noqa: S603  # nosec B603 - fixed argv, shell=False


def refresh(uv_lock: Path, sbom_dir: Path, project_name: str) -> None:
    """Regenerate both derived locks in ``sbom_dir`` from ``uv_lock``."""
    requirements_lock = sbom_dir / "requirements.lock"
    requirements_dev_lock = sbom_dir / "requirements-dev.lock"
    req_header = lock_header(requirements_lock)
    dev_header = lock_header(requirements_dev_lock)

    pins = target_pins(uv_lock, project_name)
    with tempfile.TemporaryDirectory() as tmp:
        constraints = Path(tmp) / "constraints.txt"
        constraints.write_text(
            "".join(f"{name}=={version}\n" for name, version in sorted(pins.items())),
            encoding="utf-8",
        )
        compiled = Path(tmp) / "requirements.lock.body"
        _run(
            [
                "uv",
                "pip",
                "compile",
                str(REPO_ROOT / "pyproject.toml"),
                "--all-extras",
                "--generate-hashes",
                "--python-platform",
                "x86_64-unknown-linux-gnu",
                "--python-version",
                "3.12",
                "--no-header",
                "--no-annotate",
                "-c",
                str(constraints),
                "-o",
                str(compiled),
            ]
        )
        requirements_lock.write_text(
            req_header + compiled.read_text(encoding="utf-8"), encoding="utf-8"
        )

        exported = Path(tmp) / "requirements-dev.lock.body"
        _run(
            [
                "uv",
                "export",
                "--extra",
                "dev",
                "--no-emit-project",
                "--no-annotate",
                "--no-header",
                "-o",
                str(exported),
            ]
        )
        requirements_dev_lock.write_text(
            dev_header + exported.read_text(encoding="utf-8"), encoding="utf-8"
        )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uv-lock", type=Path, default=REPO_ROOT / "uv.lock")
    parser.add_argument("--sbom-dir", type=Path, default=SBOM_DIR)
    parser.add_argument(
        "--project-name",
        default="ianua",
        help="The project's own package name (excluded from constraints).",
    )
    args = parser.parse_args(argv)

    for path in (
        args.uv_lock,
        args.sbom_dir / "requirements.lock",
        args.sbom_dir / "requirements-dev.lock",
    ):
        if not path.is_file():
            print(f"error: not found: {path}", file=sys.stderr)
            return 2

    try:
        refresh(args.uv_lock, args.sbom_dir, args.project_name)
        # Fail closed: the regenerated locks must agree with uv.lock exactly.
        _run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "check_locks.py"),
                "--uv-lock",
                str(args.uv_lock),
                "--lock",
                str(args.sbom_dir / "requirements.lock"),
                "--lock",
                str(args.sbom_dir / "requirements-dev.lock"),
            ]
        )
    except (subprocess.CalledProcessError, ValueError) as exc:
        print(f"error: regeneration failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
