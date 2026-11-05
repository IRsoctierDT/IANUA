#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Assert the append-only logs lose no entry against the merge base.

``DESIGN.md`` §11 and ``docs/Changelog.md`` are the repository's append-only
logs (AGENTS.md §2 step 8 names them as such). Nearly every change adds to
both, so nearly every branch conflicts with its base in them, and the
resolution is mechanical -- which is exactly why nobody reads it. Five times a
merge has resolved one of these conflicts by keeping one side and silently
dropping the other's entries:

* ``697df79`` resolved five conflicts by keeping one side of each;
* ``76b3e96`` took main's side of the SBOM documents;
* ``0b7f4fb`` dropped main's Penthera §11 row (caught in review, #306);
* ``0608b79a`` reverted #301's and #304's log entries on main (PR #313 exists
  to restore them); and
* ``2b3f6b6c`` (#280) **overwrote** the §11 row recording the concurrent-session
  rules with its own row -- one insertion, one deletion, the same date. That
  row is absent from ``DESIGN.md`` and from every tracked markdown file to this
  day. It was found by this gate's own development, not by review.

Nothing in CI detected any of them.

**Why entry identity and not line counts, or lines at all.** A count cannot see
a one-for-one swap: #306's merge dropped one row and added one, so both trees
held 87, and ``2b3f6b6c`` did the same at the same date. Raw line containment
is the opposite failure -- measured over 60 commits on ``main``, 15 of the 38
that touch these two files delete lines (one release promotion deleted 184), so
a no-deleted-lines gate would fire on two commits in five and be switched off
inside a week. This gate keys each entry by its *title* and ignores its body,
so an in-place correction -- which this repository makes constantly -- passes
untouched, while a vanished entry does not. Measured over the same 60 commits:
six entry titles disappeared, four of them the two real incidents above.

**What a key is.** For ``DESIGN.md`` it is the Decision column of a §11 row,
scoped to that section so no other table in the file can contribute. For
``docs/Changelog.md`` it is the bold lead-in of a top-level bullet. Both are
whitespace-normalised.

Keys are compared by **presence, not count**, and that is a measured decision
rather than a convenience. Counting was tried first and produced exactly one
false positive across the 60 commits surveyed: the ``v2.3.0`` release promotion
(``b2436b05``) removed a changelog entry that the tree held *twice*, leaving one
copy -- a de-duplication, and the entry is on ``main`` to this day. Counting
reported that as a loss. Measured on the current tree, neither log has a
duplicate key at all (93 §11 rows, 175 changelog entries, all distinct), so
presence gives up nothing real: the hazard counting would add -- dropping one of
two entries that share a title -- cannot arise while no title is shared, and a
shared title is itself an editorial error to fix rather than to encode here.

**Why the merge base and not the base tip.** A branch that is merely *behind*
its base has not removed anything; comparing against the base tip would report
every entry added to the base since the branch point. Once a branch merges its
base in -- which is when the hazard occurs -- the merge base becomes the base
tip and the two comparisons coincide, so nothing is lost by taking the safer
one. A dropped hunk is a deletion in that diff either way.

**Intentional removals are declared, never inferred.** An entry is sometimes
removed for a good reason: a "Known issues" entry whose issue has been fixed
(#301 and #310 each did this, correctly). Those are listed in
``docs/log_removals.json`` with a reason, so a reviewer sees the removal in a
diff instead of in a 40-line hunk. The file ships empty, so the default answer
is no -- and it is no because nothing has been declared, not because a rule
failed to match. This is ``collect/``'s control with one word changed:
declared, never discovered.

Security considerations: every input is a local, trusted repository file or a
local git object. ``git`` is invoked with a fixed argument vector and
``shell=False``; the base ref is refused unless it matches a conservative
character allow-list, so a ref can never be read as an option or a shell
fragment. The gate reads only -- it writes nothing and reaches no network.

Exit codes: ``0`` no entry lost · ``1`` an undeclared entry was lost ·
``2`` a required input was missing or git could not answer.
"""

from __future__ import annotations

import argparse
import functools
import json
import re
import shutil
import subprocess  # nosec B404 — fixed argv, shell=False, local git only
import sys
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

#: The two append-only logs, by repository-relative path.
DESIGN_MD = "DESIGN.md"
CHANGELOG_MD = "docs/Changelog.md"

#: Declared, reviewable exceptions. Absent or empty means "no removal allowed".
REMOVALS_FILE = "docs/log_removals.json"

#: ``## 11. Decision Log`` opens the table; the next ``## `` heading closes it.
_SECTION_11 = re.compile(r"^##\s+11\.\s", re.M)
_NEXT_H2 = re.compile(r"^##\s", re.M)

#: A §11 row opens with a date or the literal ``_initial_`` in its first cell.
_ROW = re.compile(r"^\|\s*(?:20\d\d-\d\d-\d\d|_initial_)\s*\|")

#: A top-level changelog bullet: ``- **title.**`` possibly spanning lines.
_BULLET = re.compile(r"^- \*\*(.+?)\*\*", re.M | re.S)

#: Conservative ref allow-list: letters, digits and ``._/-^~`` only, and never
#: a leading ``-``, which git would read as an option rather than a revision.
#: ``^`` and ``~`` are ordinary revision syntax (``main^``, ``HEAD~2``) and
#: carry no meaning to ``subprocess`` with ``shell=False``; everything that
#: would matter to a shell stays refused.
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/^~-]{0,200}$")


def _normalise(text: str) -> str:
    """Collapse whitespace so a reflowed cell is still the same key."""
    return re.sub(r"\s+", " ", text).strip()


def decision_keys(text: str) -> list[str]:
    """Return the Decision column of every ``DESIGN.md`` §11 row.

    Scoped to section 11, so a table elsewhere in the file cannot contribute a
    key. Returns an empty list when the section is absent.
    """
    start = _SECTION_11.search(text)
    if start is None:
        return []
    rest = text[start.end() :]
    end = _NEXT_H2.search(rest)
    section = rest[: end.start()] if end else rest
    keys = []
    for line in section.split("\n"):
        if not _ROW.match(line):
            continue
        cells = line.split("|")
        if len(cells) >= 4:
            keys.append(_normalise(cells[2]))
    return [k for k in keys if k]


def changelog_keys(text: str) -> list[str]:
    """Return the bold lead-in of every top-level ``docs/Changelog.md`` bullet."""
    return [k for k in (_normalise(m) for m in _BULLET.findall(text)) if k]


#: Which extractor owns which file.
EXTRACTORS: dict[str, Callable[[str], list[str]]] = {
    DESIGN_MD: decision_keys,
    CHANGELOG_MD: changelog_keys,
}


def lost_keys(base_text: str, head_text: str, extract: Callable[[str], list[str]]) -> list[str]:
    """Keys present in ``base_text`` that ``head_text`` no longer carries.

    Compared by presence, not count (see the module docstring for the measured
    reason). Each lost key is reported once, in the base's own order, so a
    report reads in the same order as the file it describes.
    """
    head = set(extract(head_text))
    out: list[str] = []
    seen: set[str] = set()
    for key in extract(base_text):
        if key not in head and key not in seen:
            seen.add(key)
            out.append(key)
    return out


def load_declared_removals(root: Path) -> dict[str, set[str]]:
    """Read ``docs/log_removals.json`` into ``{path: {key, ...}}``.

    Fails closed on a malformed file: a broken declaration raises rather than
    resolving to "nothing declared", so an operator is told their file is
    broken instead of the gate behaving as though they had declared nothing.
    """
    path = root / REMOVALS_FILE
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{REMOVALS_FILE} could not be read as JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"{REMOVALS_FILE} must hold a JSON object")
    if raw.get("version") != 1:
        raise ValueError(f'{REMOVALS_FILE} must declare "version": 1')
    entries = raw.get("removals")
    if not isinstance(entries, list):
        raise ValueError(f'{REMOVALS_FILE} must hold a "removals" list')
    declared: dict[str, set[str]] = {}
    for index, item in enumerate(entries):
        if not isinstance(item, dict):
            raise ValueError(f"{REMOVALS_FILE}[{index}] is not an object")
        missing = {"file", "key", "reason"} - set(item)
        if missing:
            raise ValueError(
                f"{REMOVALS_FILE}[{index}] is missing {sorted(missing)}"
                " — every removal names its file, its key and why"
            )
        for field in ("file", "key", "reason"):
            if not isinstance(item[field], str) or not item[field].strip():
                raise ValueError(f"{REMOVALS_FILE}[{index}].{field} must be a non-empty string")
        if item["file"] not in EXTRACTORS:
            raise ValueError(
                f"{REMOVALS_FILE}[{index}].file is {item['file']!r};"
                f" this gate covers {sorted(EXTRACTORS)}"
            )
        declared.setdefault(item["file"], set()).add(_normalise(item["key"]))
    return declared


@functools.cache
def _git_executable() -> str:
    """Absolute path to ``git``, resolved once.

    Resolved rather than spelled ``"git"`` because bandit's B607 (CWE-78) is
    right that a bare program name is whatever ``PATH`` resolves it to. Every
    other call site in this repository avoids B607 structurally rather than
    with a ``# nosec``, so this addresses the finding instead of adding a new
    suppression style.
    """
    found = shutil.which("git")
    if found is None:
        raise RuntimeError("git was not found on PATH")
    return found


def _git(root: Path, *args: str) -> str:
    """Run git with a fixed argv and return stdout, or raise ``RuntimeError``."""
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, shell=False, validated ref
        [_git_executable(), *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def resolve_merge_base(root: Path, base_ref: str, head_ref: str) -> str:
    """Return the merge base of ``base_ref`` and ``head_ref``."""
    for ref in (base_ref, head_ref):
        if not _SAFE_REF.match(ref):
            raise ValueError(f"refusing unsafe ref {ref!r}")
    return _git(root, "merge-base", base_ref, head_ref).strip()


def file_at(root: Path, rev: str, path: str) -> str:
    """Return ``path`` as of ``rev``, or ``""`` when it did not exist there."""
    try:
        return _git(root, "show", f"{rev}:{path}")
    except RuntimeError:
        return ""


def main(argv: list[str] | None = None) -> int:
    """Compare both logs at the merge base against the working tree."""
    parser = argparse.ArgumentParser(
        description="Fail if DESIGN.md §11 or docs/Changelog.md lost an entry.",
    )
    parser.add_argument(
        "--base",
        default="origin/main",
        help="base ref to compare against (default: origin/main)",
    )
    parser.add_argument(
        "--head",
        default="HEAD",
        help="head ref whose merge base with --base is used (default: HEAD)",
    )
    parser.add_argument(
        "--root",
        default=str(REPO_ROOT),
        help="repository root (default: this script's repository)",
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()

    try:
        declared = load_declared_removals(root)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        merge_base = resolve_merge_base(root, args.base, args.head)
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    findings: list[str] = []
    for path, extract in EXTRACTORS.items():
        # The default head is the working tree, so a developer sees a bad
        # resolution before committing it. An explicit --head reads that tree
        # instead, which is what replaying a historical merge needs.
        if args.head == "HEAD":
            head_file = root / path
            if not head_file.exists():
                print(f"error: {path} is missing from the working tree", file=sys.stderr)
                return 2
            head_text = head_file.read_text(encoding="utf-8")
        else:
            head_text = file_at(root, args.head, path)
        base_text = file_at(root, merge_base, path)
        if not base_text:
            continue
        allowed = declared.get(path, set())
        for key in lost_keys(base_text, head_text, extract):
            if key not in allowed:
                findings.append(f"  {path}: {key}")

    if findings:
        print(
            f"Entries present at the merge base ({merge_base[:12]}) are gone from this tree.\n"
            "These two files are append-only logs; a merge that resolves their conflict by\n"
            "keeping one side drops the other's entries silently (AGENTS.md §2 step 8).\n"
            "Restore each entry, or -- if the removal is deliberate -- declare it in\n"
            f"{REMOVALS_FILE} with a reason, so a reviewer sees it in the diff.\n",
            file=sys.stderr,
        )
        print("\n".join(findings), file=sys.stderr)
        return 1

    print(f"OK: both append-only logs keep every entry held at {merge_base[:12]}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
