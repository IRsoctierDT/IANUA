#!/usr/bin/env python3
"""Fail closed when IANUA release-version surfaces diverge."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class VersionSyncError(ValueError):
    """Raised when a release-version surface disagrees with pyproject.toml."""


def _json(path: str) -> object:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def _project_version() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = data.get("project", {}).get("version")
    if not isinstance(version, str):
        raise VersionSyncError("pyproject.toml: [project].version is missing")
    return version


def _require_equal(label: str, actual: object, expected: str) -> None:
    if actual != expected:
        raise VersionSyncError(f"{label}: expected {expected!r}, got {actual!r}")


def check(tag: str | None = None) -> str:
    """Verify all release-facing version surfaces and return the canonical version."""
    version = _project_version()

    package = _json("package.json")
    if not isinstance(package, dict):
        raise VersionSyncError("package.json: expected object")
    _require_equal("package.json version", package.get("version"), version)

    lock = _json("package-lock.json")
    if not isinstance(lock, dict):
        raise VersionSyncError("package-lock.json: expected object")
    _require_equal("package-lock.json top-level version", lock.get("version"), version)
    packages = lock.get("packages")
    root_package = packages.get("") if isinstance(packages, dict) else None
    if not isinstance(root_package, dict):
        raise VersionSyncError("package-lock.json: packages[''] is missing")
    _require_equal("package-lock.json root package version", root_package.get("version"), version)

    uv_text = (ROOT / "uv.lock").read_text(encoding="utf-8")
    match = re.search(r'(?m)^name = "ianua"\nversion = "([^"]+)"$', uv_text)
    if match is None:
        raise VersionSyncError("uv.lock: IANUA package entry not found")
    _require_equal("uv.lock IANUA version", match.group(1), version)

    status = _json("docs/status.json")
    if not isinstance(status, dict):
        raise VersionSyncError("docs/status.json: expected object")
    _require_equal("docs/status.json version", status.get("version"), version)

    for path in ("security/sbom/npm.cdx.json", "security/sbom/sbom.cdx.json"):
        sbom = _json(path)
        metadata = sbom.get("metadata") if isinstance(sbom, dict) else None
        component = metadata.get("component") if isinstance(metadata, dict) else None
        if not isinstance(component, dict):
            raise VersionSyncError(f"{path}: metadata.component is missing")
        _require_equal(f"{path} root version", component.get("version"), version)

    major_minor = ".".join(version.split(".")[:2])
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    if f"| {major_minor}.x (current" not in security:
        raise VersionSyncError(f"SECURITY.md: {major_minor}.x is not marked current")

    changelog = (ROOT / "docs/Changelog.md").read_text(encoding="utf-8")
    if f"## v{version} " not in changelog:
        raise VersionSyncError(f"docs/Changelog.md: missing v{version} release heading")

    if tag is not None:
        _require_equal("release tag", tag, f"v{version}")

    return version


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", help="Require the canonical release tag v<project-version>.")
    args = parser.parse_args()
    try:
        version = check(args.tag)
    except (OSError, json.JSONDecodeError, VersionSyncError) as exc:
        print(f"version-sync: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"version-sync: OK: v{version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
