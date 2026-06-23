#!/usr/bin/env python3
"""Assert the exported pip lockfiles stay consistent with ``uv.lock``.

``uv.lock`` is the dependency source of truth (AGENTS.md supply-chain controls).
The pip-format lockfiles under ``security/sbom/`` are *derived* from it
(``requirements.lock`` = the Linux/3.12 export, ``requirements-dev.lock`` = the
``[dev]`` export). When a dependency-update PR (e.g. Dependabot) bumps ``uv.lock``
but the derived locks are not regenerated, the SBOM/SCA inputs silently drift.

This checker fails closed if any pinned ``name==version`` in a derived lock does
not match the version recorded for that package in ``uv.lock``. It performs **no
network access and no resolution** — it only compares the committed files — so it
cannot produce false failures from a newer release appearing on PyPI.

Security consideration: inputs are local, trusted repository files; ``uv.lock`` is
parsed with the standard-library ``tomllib`` (no third-party TOML dependency).

Exit codes: ``0`` consistent · ``1`` drift detected · ``2`` a file was missing.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# A pinned requirement line: ``name==version`` optionally followed by a marker
# (`; ...`) or a line-continuation (`\`). Hash continuation lines are indented
# and never match (no leading name), so they are skipped.
_PIN_RE = re.compile(r"^([A-Za-z0-9._-]+)==([^\s;\\]+)")


def _normalise(name: str) -> str:
    """PEP 503 name normalisation, so ``Foo_Bar`` and ``foo-bar`` compare equal."""
    return re.sub(r"[-_.]+", "-", name).lower()


def uv_lock_versions(uv_lock: Path) -> dict[str, str]:
    """Return ``{normalised-name: version}`` for every package pinned in ``uv.lock``."""
    data = tomllib.loads(uv_lock.read_text(encoding="utf-8"))
    return {_normalise(pkg["name"]): pkg["version"] for pkg in data.get("package", [])}


def drift(lockfile: Path, uv_versions: dict[str, str]) -> list[str]:
    """Return human-readable drift messages for ``lockfile`` vs ``uv.lock``.

    A line drifts when its pinned version differs from ``uv.lock``'s, or when the
    package is absent from ``uv.lock`` entirely. An empty list means consistent.
    """
    problems: list[str] = []
    for line in lockfile.read_text(encoding="utf-8").splitlines():
        match = _PIN_RE.match(line)
        if not match:
            continue
        name, version = _normalise(match.group(1)), match.group(2)
        expected = uv_versions.get(name)
        if expected != version:
            problems.append(
                f"{lockfile.name}: {name}=={version} (uv.lock has {expected or 'MISSING'})"
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uv-lock", type=Path, default=REPO_ROOT / "uv.lock")
    parser.add_argument(
        "--lock",
        type=Path,
        action="append",
        dest="locks",
        help="A derived pip lockfile to check (repeatable).",
    )
    args = parser.parse_args(argv)
    locks: list[Path] = args.locks or [
        REPO_ROOT / "security" / "sbom" / "requirements.lock",
        REPO_ROOT / "security" / "sbom" / "requirements-dev.lock",
    ]

    for path in (args.uv_lock, *locks):
        if not path.is_file():
            print(f"error: not found: {path}", file=sys.stderr)
            return 2

    uv_versions = uv_lock_versions(args.uv_lock)
    problems = [msg for lock in locks for msg in drift(lock, uv_versions)]
    if problems:
        print("Derived pip locks have drifted from uv.lock — regenerate them", file=sys.stderr)
        print("(see security/sbom/README.md):", file=sys.stderr)
        for msg in problems:
            print(f"  {msg}", file=sys.stderr)
        return 1

    print(f"OK: pip locks consistent with uv.lock ({len(uv_versions)} packages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
