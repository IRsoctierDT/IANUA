#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Compose a GitHub Release body from the promoted changelog section.

``release.yml`` previously published with ``--generate-notes``, which lists the
pull requests merged since the last tag. That is a useful record, but it is not
the release notes: the curated ``## vX.Y.Z`` section in
:file:`docs/Changelog.md` — written by whoever prepared the release and
reviewed on the release PR — was never read, so the deliberate wording went
nowhere. ``docs/RELEASING.md`` tracked that as a future enhancement; this is
it.

The composed body is the changelog section verbatim, followed by a compare
link to the previous release so the full commit record is still one click away.

Security considerations (AGENTS.md §3, §5):
    * **Validate, never repair** — the tag must be canonical ``vX.Y.Z`` and the
      repository must look like ``owner/name``. Both are interpolated into a
      URL that is published on the release page.
    * **Fail closed** — a missing heading, an empty section, or a duplicated
      heading is an error, not an empty release body. ``check_version_sync``
      already requires the heading to exist before a release is offered, so
      reaching those errors means something upstream broke and publishing
      silently would hide it.
    * **Local only** — reads one file and writes one file. No network, no git.

Usage:
    python scripts/release_notes.py --tag v2.2.0 --repo owner/name
    python scripts/release_notes.py --tag v2.2.0 --repo owner/name --output notes.md
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # allow `python scripts/release_notes.py` from anywhere
    sys.path.insert(0, str(ROOT))

from scripts import prepare_release  # noqa: E402  — needs ROOT on sys.path first

CHANGELOG = "docs/Changelog.md"

#: ``owner/name``. Deliberately narrow: this lands in a published URL.
_REPO = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")

#: A release heading: ``## vX.Y.Z — Title — YYYY-MM-DD``. The em dash is the
#: separator prepare_release.py writes; matching it keeps the two in step.
_RELEASE_HEADING = re.compile(
    r"^## v(?P<version>\d+\.\d+\.\d+) — (?P<title>[^\n]+?) — (?P<date>\d{4}-\d{2}-\d{2})\s*$",
    re.MULTILINE,
)


class ReleaseNotesError(ValueError):
    """The tag, the repository, or the changelog is not in the expected shape."""


def parse_tag(tag: str) -> str:
    """Return the bare version for a canonical tag, or fail closed.

    The version shape is delegated to :func:`prepare_release.parse_version` —
    the script that *writes* these tags — so the reader and the writer cannot
    drift apart on what "canonical" means. A second hand-rolled definition
    beside the real one is exactly how the attestation-expiry gate went inert,
    and a looser one here would accept ``v02.2.0``, find no heading, and blame
    the changelog for a malformed tag.
    """
    if not tag.startswith("v"):
        raise ReleaseNotesError(f"tag must be canonical vX.Y.Z, got {tag!r}")
    version = tag[1:]
    try:
        prepare_release.parse_version(version)
    except prepare_release.ReleaseError as exc:
        raise ReleaseNotesError(f"tag must be canonical vX.Y.Z, got {tag!r}") from exc
    return version


def parse_repo(repo: str) -> str:
    """Return ``owner/name`` unchanged, or fail closed."""
    if _REPO.fullmatch(repo) is None:
        raise ReleaseNotesError(f"repository must look like owner/name, got {repo!r}")
    return repo


def section(text: str, version: str) -> str:
    """Return the body of ``## v<version> — …``, exclusive of the heading.

    The body runs to the next top-level heading, which is the previous
    release. Raises if the heading is absent, duplicated, or the section
    carries no content.
    """
    found = [m for m in _RELEASE_HEADING.finditer(text) if m.group("version") == version]
    if not found:
        raise ReleaseNotesError(f"{CHANGELOG}: no '## v{version} — … — …' release heading")
    if len(found) > 1:
        raise ReleaseNotesError(f"{CHANGELOG}: v{version} has {len(found)} release headings")
    start = found[0].end()
    following = text.find("\n## ", start)
    body = text[start : following if following >= 0 else len(text)]
    if not body.strip():
        raise ReleaseNotesError(
            f"{CHANGELOG}: the v{version} section is empty — refusing to publish blank notes"
        )
    return body.strip()


def previous_version(text: str, version: str) -> str | None:
    """The release documented immediately below ``version``, if any.

    Used only for the compare link; the first release in the file has none, and
    that is not an error.
    """
    versions = [m.group("version") for m in _RELEASE_HEADING.finditer(text)]
    try:
        index = versions.index(version)
    except ValueError:  # pragma: no cover - section() already raised
        return None
    return versions[index + 1] if index + 1 < len(versions) else None


def compose(text: str, tag: str, repo: str) -> str:
    """Build the release body for ``tag`` from the changelog ``text``."""
    version = parse_tag(tag)
    repo = parse_repo(repo)
    body = section(text, version)
    previous = previous_version(text, version)
    if previous is None:
        return body + "\n"
    compare = f"https://github.com/{repo}/compare/v{previous}...v{version}"
    return f"{body}\n\n**Full Changelog**: {compare}\n"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = argparse.ArgumentParser(description="Compose release notes from the changelog.")
    parser.add_argument("--tag", required=True, help="canonical release tag, e.g. v2.2.0")
    parser.add_argument("--repo", required=True, help="owner/name, for the compare link")
    parser.add_argument("--output", help="write here instead of stdout")
    args = parser.parse_args(argv)
    try:
        text = (ROOT / CHANGELOG).read_text(encoding="utf-8")
        notes = compose(text, args.tag, args.repo)
        if args.output is not None:
            Path(args.output).write_text(notes, encoding="utf-8")
    except (ReleaseNotesError, OSError) as exc:
        print(f"release-notes: FAIL: {exc}", file=sys.stderr)
        return 1
    if args.output is None:
        sys.stdout.write(notes)
    else:
        print(f"release-notes: OK: {args.tag} — {len(notes.splitlines())} line(s) -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
