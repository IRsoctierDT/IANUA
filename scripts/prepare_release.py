#!/usr/bin/env python3
"""Prepare an IANUA release: bump every version surface in one atomic step.

Cutting a release used to be a hand-edit of a dozen files (v2.1.0 took sixteen
commits in #178). This script performs the same edits deterministically,
regenerates the derived pages, and proves the result with
``check_version_sync`` before it returns. Open the resulting diff as a normal
``release: prepare IANUA vX.Y.Z`` pull request; once it merges and CI is green
on ``main``, ``.github/workflows/release-on-merge.yml`` offers the tag and
GitHub release for human approval.

Surfaces updated (the set ``scripts/check_version_sync.py`` enforces, plus
the human-facing ones a release has always touched):

* ``pyproject.toml`` ``[project].version`` and the ``uv.lock`` IANUA entry
* ``package.json`` / ``package-lock.json`` root versions
* both CycloneDX SBOM root components
* ``docs/status.data.json`` ``as_of``, then the status page (it reads the
  version from ``pyproject.toml``)
* ``docs/Changelog.md`` — the ``## Unreleased`` content becomes
  ``## vX.Y.Z — title — date``
* ``docs/PROJECT_STATUS.md`` current-version line
* ``SECURITY.md`` supported-versions table (minor/major bumps only)
* ``tests/unit/test_version_sync.py`` canonical-version pin
* ``README.md`` generated sections, when ``scripts/build_readme.py`` exists

Security considerations (AGENTS.md §3, §5):
    * **Validate, never repair** — the version must be canonical ``X.Y.Z`` and
      strictly greater than the current one; the title is allowlisted (it lands
      in Markdown headings and table cells); the date must be ISO.
    * **Fail closed and atomic** — every edit is computed in memory first. A
      surface that does not match its expected shape, an empty
      ``## Unreleased`` section, or any regeneration or verification failure
      restores every file to its original bytes.
    * **Local only** — no network, no git operations, no tag. Publishing stays
      behind the human-gated release workflow (AGENTS.md §5.1).

Usage:
    python scripts/prepare_release.py 2.2.0 --title "Live Tool Inspection"
    python scripts/prepare_release.py 2.2.0 --title "..." --date 2026-11-02 --dry-run

Exit codes: ``0`` success · ``2`` invalid input or a surface failed to update.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib
import json
import re
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # allow `python scripts/prepare_release.py` from anywhere
    sys.path.insert(0, str(ROOT))

_VERSION = re.compile(r"^(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})$")
# Lands in a Markdown heading and a table cell: no pipes, asterisks, brackets,
# backticks, angle brackets or newlines. Parentheses are excluded too, because
# SECURITY.md wraps the title in "(current — …)".
_TITLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 &:,.'+/-]{2,79}$")
_UNRELEASED = "## Unreleased\n"
_SUPPORTED = "Supported — security fixes applied"
_LEGACY = "Critical security fixes only, upgrade recommended"

JsonEdit = Callable[[dict[str, object]], None]


class ReleaseError(ValueError):
    """The request or a version surface is invalid (fail closed)."""


def parse_version(text: str) -> tuple[int, int, int]:
    """Parse a canonical ``X.Y.Z`` version; raise ``ReleaseError`` otherwise."""
    match = _VERSION.fullmatch(text)
    if match is None:
        raise ReleaseError(f"version must be canonical X.Y.Z, got {text!r}")
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def current_version() -> str:
    """The version currently in ``pyproject.toml``."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = data.get("project", {}).get("version")
    if not isinstance(version, str):
        raise ReleaseError("pyproject.toml: [project].version is missing")
    return version


def _sub_once(text: str, pattern: str, replacement: str, label: str) -> str:
    """Replace exactly one regex match, or fail closed."""
    new, count = re.subn(pattern, replacement, text, count=2, flags=re.MULTILINE)
    if count != 1:
        raise ReleaseError(f"{label}: expected exactly one match, found {count}")
    return new


def _json_edit(*edits: JsonEdit) -> Callable[[str], str]:
    """Apply dict edits to a JSON file's text (these files round-trip byte-exact)."""

    def transform(text: str) -> str:
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ReleaseError("expected a JSON object")
        for edit in edits:
            edit(data)
        return json.dumps(data, indent=2, ensure_ascii=False) + "\n"

    return transform


def _set_version(old: str, new: str, *keys: str) -> JsonEdit:
    """Set ``version`` at ``keys`` to ``new``, requiring it currently equals ``old``."""

    def edit(data: dict[str, object]) -> None:
        node: object = data
        for key in keys:
            node = node.get(key) if isinstance(node, dict) else None
        if not isinstance(node, dict):
            raise ReleaseError(f"missing object at {'.'.join(keys)!r}")
        if node.get("version") != old:
            label = ".".join((*keys, "version"))
            raise ReleaseError(f"{label}: expected {old!r}, got {node.get('version')!r}")
        node["version"] = new

    return edit


def _set_field(key: str, value: str) -> JsonEdit:
    """Overwrite an existing top-level ``key``; a missing key fails closed."""

    def edit(data: dict[str, object]) -> None:
        if key not in data:
            raise ReleaseError(f"missing key {key!r}")
        data[key] = value

    return edit


def promote_changelog(text: str, version: str, title: str, date: str) -> str:
    """Turn the ``## Unreleased`` content into the ``## vX.Y.Z`` section."""
    start = text.find(_UNRELEASED)
    if start < 0:
        raise ReleaseError("no '## Unreleased' heading")
    body_start = start + len(_UNRELEASED)
    next_heading = text.find("\n## ", body_start)
    body = text[body_start : next_heading if next_heading >= 0 else len(text)]
    if not body.strip():
        raise ReleaseError("'## Unreleased' is empty — nothing to release")
    if f"## v{version} " in text:
        raise ReleaseError(f"v{version} already has a heading")
    return text[:body_start] + f"\n## v{version} — {title} — {date}\n" + text[body_start:]


def update_security(text: str, old: str, new: str, title: str) -> str:
    """On a minor/major bump, mark the new line current and demote the old one."""
    old_mm = ".".join(old.split(".")[:2])
    new_mm = ".".join(new.split(".")[:2])
    if old_mm == new_mm:
        return text
    return _sub_once(
        text,
        rf"^\| {re.escape(old_mm)}\.x \(current — [^)\n]*\) \| {re.escape(_SUPPORTED)} \|$",
        f"| {new_mm}.x (current — {title}) | {_SUPPORTED} |\n| {old_mm}.x | {_LEGACY} |",
        "supported-versions row",
    )


def _replace_pin(old: str, new: str) -> Callable[[str], str]:
    """Move the test's canonical-version pin; fail if the old pin is absent."""

    def transform(text: str) -> str:
        updated = text.replace(f'"{old}"', f'"{new}"').replace(f"v{old}", f"v{new}")
        if updated == text:
            raise ReleaseError(f"pin {old!r} not found")
        return updated

    return transform


def plan(version: str, title: str, date: str) -> dict[Path, tuple[str, str]]:
    """Compute ``{path: (original, updated)}`` for every surface; write nothing."""
    old = current_version()
    if parse_version(version) <= parse_version(old):
        raise ReleaseError(f"version {version} must be greater than the current {old}")
    if _TITLE.fullmatch(title) is None:
        raise ReleaseError(
            "title must be 3-80 chars of letters, digits, spaces and & : , . ' + / -"
        )
    try:
        dt.date.fromisoformat(date)
    except ValueError as exc:
        raise ReleaseError(f"date must be ISO YYYY-MM-DD, got {date!r}") from exc

    old_q = re.escape(old)
    bump = _set_version(old, version)
    transforms: dict[str, Callable[[str], str]] = {
        "pyproject.toml": lambda t: _sub_once(
            t, rf'^version = "{old_q}"$', f'version = "{version}"', "[project].version"
        ),
        "uv.lock": lambda t: _sub_once(
            t,
            rf'^(name = "ianua"\n)version = "{old_q}"$',
            rf'\g<1>version = "{version}"',
            "IANUA package entry",
        ),
        "package.json": _json_edit(bump),
        "package-lock.json": _json_edit(bump, _set_version(old, version, "packages", "")),
        "security/sbom/npm.cdx.json": _json_edit(
            _set_version(old, version, "metadata", "component")
        ),
        "security/sbom/sbom.cdx.json": _json_edit(
            _set_version(old, version, "metadata", "component")
        ),
        "docs/status.data.json": _json_edit(_set_field("as_of", date)),
        "docs/Changelog.md": lambda t: promote_changelog(t, version, title, date),
        "docs/PROJECT_STATUS.md": lambda t: _sub_once(
            t, rf"^v{old_q} — \*\*[^*\n]+\*\* —", f"v{version} — **{title}** —", "version line"
        ),
        "SECURITY.md": lambda t: update_security(t, old, version, title),
        "tests/unit/test_version_sync.py": _replace_pin(old, version),
    }
    changes: dict[Path, tuple[str, str]] = {}
    for rel, transform in transforms.items():
        path = ROOT / rel
        original = path.read_text(encoding="utf-8")
        try:
            updated = transform(original)
        except ReleaseError as exc:
            raise ReleaseError(f"{rel}: {exc}") from exc
        if updated != original:
            changes[path] = (original, updated)
    return changes


def _regenerate() -> dict[Path, str]:
    """Rebuild derived pages in-process; return the originals of the files they own.

    The README generator ships separately (``scripts/build_readme.py``); it runs
    only once present, so this script works on either side of that merge.
    """
    from scripts import build_status_page

    targets: list[tuple[Callable[[list[str]], int], tuple[str, ...]]] = [
        (build_status_page.main, ("docs/status.html", "docs/status.json")),
    ]
    if (ROOT / "scripts" / "build_readme.py").exists():
        build_readme = importlib.import_module("scripts.build_readme")
        targets.append((build_readme.main, ("README.md",)))
    originals: dict[Path, str] = {}
    for generate, owned in targets:
        for rel in owned:
            originals[ROOT / rel] = (ROOT / rel).read_text(encoding="utf-8")
        if generate([]) != 0:
            raise ReleaseError(f"regenerating {', '.join(owned)} failed")
    return originals


def apply(changes: dict[Path, tuple[str, str]], version: str) -> None:
    """Write every change, regenerate, verify; restore all originals on failure."""
    from scripts import check_version_sync

    regenerated: dict[Path, str] = {}
    try:
        for path, (_original, updated) in changes.items():
            path.write_text(updated, encoding="utf-8")
        regenerated = _regenerate()
        if check_version_sync.check(f"v{version}") != version:
            raise ReleaseError("version sync check returned an unexpected version")
    except BaseException:
        for path, original in regenerated.items():
            path.write_text(original, encoding="utf-8")
        for path, (original, _updated) in changes.items():
            path.write_text(original, encoding="utf-8")
        raise


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = argparse.ArgumentParser(description="Prepare an IANUA release.")
    parser.add_argument("version", help="new canonical version, e.g. 2.2.0")
    parser.add_argument("--title", required=True, help="release title (heading and tables)")
    parser.add_argument(
        "--date",
        default=dt.datetime.now(dt.UTC).date().isoformat(),
        help="release date, ISO YYYY-MM-DD (default: today, UTC)",
    )
    parser.add_argument("--dry-run", action="store_true", help="list files; write nothing")
    args = parser.parse_args(argv)
    try:
        changes = plan(args.version, args.title, args.date)
        if args.dry_run:
            for path in sorted(changes):
                print(f"would update {path.relative_to(ROOT)}")
            return 0
        apply(changes, args.version)
    # ReleaseError, VersionSyncError and JSONDecodeError are all ValueErrors.
    except (ValueError, OSError) as exc:
        print(f"prepare-release: FAIL: {exc}", file=sys.stderr)
        return 2
    print(f"prepare-release: OK: v{args.version} — {len(changes)} file(s) updated; review the diff")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
