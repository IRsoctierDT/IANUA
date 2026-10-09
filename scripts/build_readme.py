#!/usr/bin/env python3
"""Regenerate the factual sections of README.md from their sources of truth.

README sections wrapped in ``<!-- BEGIN GENERATED: name -->`` /
``<!-- END GENERATED: name -->`` markers are owned by this script; everything
else stays hand-written. Each section is rendered from the file that already
defines it, so the README can never contradict the repository:

* ``release`` — the current version, from ``pyproject.toml`` (the release
  source of truth, same as the status page).
* ``case-studies`` — the case-study count and table, from the index in
  ``docs/case-studies/README.md``.
* ``quality-gates`` — the required-checks block, copied verbatim from
  ``AGENTS.md`` §7, so the README and the charter cannot disagree.

Security considerations (AGENTS.md §5, §6.1):
    * **Fail closed** — a missing, unknown or duplicated marker, an empty
      case-study index or a missing §7 block raises instead of writing a
      partial README.
    * **No network, no untrusted input** — only committed repository files are
      read; output is deterministic, which the ``--check`` drift gate relies on.
    * **Read-only in CI** — the gate never writes or commits; a stale README
      fails the PR and the author regenerates it locally.

Usage:
    python scripts/build_readme.py          # rewrite README.md in place
    python scripts/build_readme.py --check  # CI drift gate; write nothing

Exit codes: ``0`` success / in sync · ``1`` drift detected · ``2`` bad input.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
CASE_STUDY_INDEX = ROOT / "docs" / "case-studies" / "README.md"
AGENTS = ROOT / "AGENTS.md"

_MARKER = re.compile(
    r"(<!-- BEGIN GENERATED: (?P<name>[a-z-]+) -->\n)(?P<body>.*?)"
    r"(<!-- END GENERATED: (?P=name) -->)",
    re.DOTALL,
)
# | 1 | [Title](./file.md) | Layer | What it demonstrates |
_CASE_ROW = re.compile(
    r"^\|\s*\d+\s*\|\s*\[(?P<title>[^\]]+)\]\(\./(?P<file>[A-Za-z0-9._-]+\.md)\)\s*\|"
    r"\s*(?P<layer>[^|]+?)\s*\|\s*(?P<what>[^|]+?)\s*\|\s*$",
    re.MULTILINE,
)
_NUMBER_WORDS = [
    "Zero",
    "One",
    "Two",
    "Three",
    "Four",
    "Five",
    "Six",
    "Seven",
    "Eight",
    "Nine",
    "Ten",
    "Eleven",
    "Twelve",
    "Thirteen",
    "Fourteen",
    "Fifteen",
    "Sixteen",
    "Seventeen",
    "Eighteen",
    "Nineteen",
    "Twenty",
]


class ReadmeError(ValueError):
    """The README or one of its sources is malformed (fail closed)."""


def render_release() -> str:
    """The current release line, from ``[project].version`` in ``pyproject.toml``."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = data["project"]["version"]
    return f"**Current release: v{version}** — see [`docs/Changelog.md`](./docs/Changelog.md).\n"


def render_case_studies() -> str:
    """The case-study count and table, from ``docs/case-studies/README.md``."""
    rows = list(_CASE_ROW.finditer(CASE_STUDY_INDEX.read_text(encoding="utf-8")))
    if not rows:
        raise ReadmeError("no case-study rows found in docs/case-studies/README.md")
    count = len(rows)
    word = _NUMBER_WORDS[count] if count < len(_NUMBER_WORDS) else str(count)
    lines = [
        f"{word} portfolio-grade write-ups — one per component — each following the "
        "[AGENTS.md](./AGENTS.md)",
        "§9 standard with a worked example (real command output) and a "
        "reproduce-it-yourself section.",
        "Full index: [`docs/case-studies/`](./docs/case-studies/README.md).",
        "",
        "| Case study | Layer |",
        "|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| [{row['title']}](./docs/case-studies/{row['file']}) — {row['what']} "
            f"| {row['layer']} |"
        )
    return "\n".join(lines) + "\n"


def render_quality_gates() -> str:
    """The required-checks block, copied verbatim from ``AGENTS.md`` §7."""
    text = AGENTS.read_text(encoding="utf-8")
    start = text.find("## 7. Required Checks")
    end = text.find("### 7.1", start)
    if start < 0 or end < 0:
        raise ReadmeError("AGENTS.md §7 / §7.1 headings not found")
    block = re.search(r"```bash\n.*?\n```\n", text[start:end], re.DOTALL)
    if block is None:
        raise ReadmeError("no ```bash block in AGENTS.md §7")
    return block.group(0)


GENERATORS: dict[str, Callable[[], str]] = {
    "release": render_release,
    "case-studies": render_case_studies,
    "quality-gates": render_quality_gates,
}


def regenerate(text: str) -> tuple[str, list[str]]:
    """Return ``(new README text, names of the sections that changed)``.

    Raises:
        ReadmeError: a generator has no marker, a marker is duplicated or
            unknown, or a source file is malformed.
    """
    found = [m.group("name") for m in _MARKER.finditer(text)]
    unknown = sorted(set(found) - set(GENERATORS))
    missing = sorted(set(GENERATORS) - set(found))
    duplicated = sorted({name for name in found if found.count(name) > 1})
    if unknown or missing or duplicated:
        raise ReadmeError(
            f"README markers invalid: missing={missing} unknown={unknown} duplicated={duplicated}"
        )
    changed: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group("name")
        body = GENERATORS[name]()
        if body != match.group("body"):
            changed.append(name)
        return match.group(1) + body + match.group(4)

    return _MARKER.sub(replace, text), changed


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify README.md generated sections are current; write nothing.",
    )
    args = parser.parse_args(argv)
    try:
        new_text, changed = regenerate(README.read_text(encoding="utf-8"))
    except (ReadmeError, OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.check:
        if changed:
            print(
                "README.md has drifted in generated section(s): " + ", ".join(changed),
                file=sys.stderr,
            )
            print("  fix: python scripts/build_readme.py", file=sys.stderr)
            return 1
        print("OK: README.md generated sections are in sync with their sources")
        return 0
    if changed:
        README.write_text(new_text, encoding="utf-8")
        print("updated README.md section(s): " + ", ".join(changed))
    else:
        print("README.md already up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
