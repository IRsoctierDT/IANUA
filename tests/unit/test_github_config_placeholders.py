# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""GitHub metadata must not ship unsubstituted template placeholders.

`.github/ISSUE_TEMPLATE/config.yml` carried
``https://github.com/OWNER/REPO/security/advisories/new`` — the literal token
from GitHub's own documentation, never substituted. Because
``blank_issues_enabled: false`` and that was the *only* contact link, it was the
sole route the issue chooser offered, and it 404'd. A vulnerability reporter
following the repository's own security-reporting path would have hit a dead
link and, finding no other option in the chooser, plausibly given up or posted
publicly instead.

Two properties make this class worth a gate rather than a fix-and-move-on:

1. **It is invisible until it matters.** Issues are currently disabled
   (``has_issues: false``), so every file under ``.github/ISSUE_TEMPLATE/`` is
   inert — the defect could not be observed by using the repository. It becomes
   reachable at the moment Issues are switched on, which is also the first
   moment a reporter could hit it. Nothing in the repository would have
   announced it in between. (Stage 0, ``docs/PATH_RECONCILIATION_AUDIT.md``.)
2. **It reads as working config.** Unlike a ``TODO``, an unsubstituted
   placeholder is syntactically valid and renders as a real link. Review slides
   over it; eleven ``--check`` drift gates (``AGENTS.md`` §7) compare derived
   artifacts against their sources and none of them look at ``.github/``.

Scope is deliberately ``.github/`` only. ``OWNER/REPO`` legitimately appears in
``docs/PATH_RECONCILIATION_AUDIT.md``, which *documents* this defect; widening
these patterns to the whole tree would flag the audit for describing the thing
it caught, and the obvious response to that would be to loosen the gate.

These tests pin the committed configuration's internal consistency. They do not
reach the network, so a link that is well-formed and names the real repository
still passes here even if the underlying GitHub feature is disabled — enabling
private vulnerability reporting is a repository setting and a maintainer item,
not something this suite can assert.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]

#: The repository's canonical ``owner/name`` slug, and the source of truth for
#: these assertions. Verify with ``git remote get-url origin``. It is declared
#: here rather than derived from the remote on purpose: a fork's remote names
#: the fork, and deriving it would make the gate assert whatever the checkout
#: happens to say — including ``OWNER/REPO`` if someone set that as a remote.
CANONICAL_REPO = "IRsoctierDT/IANUA"

#: Owners whose repositories may be linked from ``.github/`` besides this one.
#: Empty today, and kept as an explicit list so that adding an upstream link
#: (an action's issue tracker, say) is a deliberate edit with a reviewer rather
#: than a reason to delete the assertion below.
ALLOWED_FOREIGN_OWNERS: frozenset[str] = frozenset()

#: Template tokens that are syntactically valid and therefore survive review.
#: Each maps to the message shown when it is found, because "placeholder found"
#: without naming the substitution is a gate that reports a symptom.
PLACEHOLDER_PATTERNS: dict[str, str] = {
    r"\bOWNER/REPO\b": f"substitute the real repository slug ({CANONICAL_REPO})",
    r"\bYOUR[-_](?:ORG|REPO|OWNER|HANDLE|TOKEN|DOMAIN|EMAIL|NAME)\b": "substitute the real value",
    r"(?i)\bCHANGE[-_]?ME\b": "substitute the real value",
    r"(?i)\bREPLACE[-_]ME\b": "substitute the real value",
    r"(?i)<(?:org|owner|repo|handle|username|token|your[a-z-]*)>": (
        "substitute the real value for this angle-bracket placeholder"
    ),
    r"(?i)\bexample\.(?:com|org|net)\b": (
        "reserved example domain — use the real host or remove the reference"
    ),
    r"@(?:owner|your[-_]?(?:org|handle|team))\b": (
        "placeholder GitHub handle — resolves to no account, so the rule enforces nothing"
    ),
}

#: Extension-less GitHub metadata files that are configuration all the same.
#: ``CODEOWNERS`` is here because it held exactly this defect: its rules named
#: ``@owner``, which resolves to no account, so every mandatory-review rule in
#: the file was inert while reading as if it were enforced.
EXTENSIONLESS_CONFIG = {"CODEOWNERS", "FUNDING"}

_CONFIG_SUFFIXES = {".yml", ".yaml", ".md"}


def _tracked_github_files() -> list[Path]:
    """Every tracked config/doc file under ``.github/``.

    Reads the index rather than walking the tree so that untracked local
    scratch files can never fail the build, and so a file that is deleted from
    the index stops being checked without anyone editing this list.
    """
    result = subprocess.run(
        ["git", "ls-files", "-z", ".github"],  # noqa: S607 - git from PATH, test env
        capture_output=True,
        cwd=_REPO,
        timeout=30,
        check=True,
        text=True,
    )
    paths = [Path(entry) for entry in result.stdout.split("\0") if entry]
    assert paths, "git ls-files reported no tracked files under .github/"
    return [
        path
        for path in paths
        if path.suffix in _CONFIG_SUFFIXES or path.name in EXTENSIONLESS_CONFIG
    ]


def _issue_chooser_config() -> dict[str, object]:
    raw = (_REPO / ".github" / "ISSUE_TEMPLATE" / "config.yml").read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    assert isinstance(data, dict), "ISSUE_TEMPLATE/config.yml must parse to a mapping"
    return data


@pytest.mark.unit
def test_no_unsubstituted_placeholders_under_github() -> None:
    """The defect class itself: a template token that reads as real config."""
    findings: list[str] = []
    for path in _tracked_github_files():
        text = (_REPO / path).read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern, remedy in PLACEHOLDER_PATTERNS.items():
                match = re.search(pattern, line)
                if match:
                    findings.append(f"{path}:{lineno}: {match.group(0)!r} — {remedy}")
    assert not findings, "unsubstituted placeholder(s) under .github/:\n" + "\n".join(findings)


@pytest.mark.unit
def test_github_links_name_this_repository() -> None:
    """Catches the stale-slug sibling of the placeholder.

    ``OWNER/REPO`` is one way to point ``.github/`` at a repository that is not
    this one; a pre-rename slug is another, and it fails less visibly because
    GitHub's rename redirect keeps it resolving until someone else claims the
    old name. Both are the same defect — metadata naming the wrong repository —
    so both are asserted by one invariant instead of a growing token list.
    """
    pattern = re.compile(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)")
    wrong: list[str] = []
    for path in _tracked_github_files():
        text = (_REPO / path).read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for slug in pattern.findall(line):
                owner = slug.split("/", 1)[0]
                if slug != CANONICAL_REPO and owner not in ALLOWED_FOREIGN_OWNERS:
                    wrong.append(f"{path}:{lineno}: links to {slug!r}, not {CANONICAL_REPO!r}")
    assert not wrong, (
        "GitHub metadata links to another repository:\n"
        + "\n".join(wrong)
        + f"\n(if intentional, add the owner to ALLOWED_FOREIGN_OWNERS in {Path(__file__).name})"
    )


@pytest.mark.unit
def test_security_contact_link_is_the_private_advisory_form() -> None:
    """The security-reporting route, pinned exactly.

    This is the assertion that would have caught the original defect on its
    own. It is narrower than the sweep above by design: the sweep knows about
    tokens someone has already thought of, while this one states what the link
    has to *be*, so it fails on a URL that is merely wrong as well as on one
    that is obviously a placeholder.
    """
    links = _issue_chooser_config().get("contact_links")
    assert isinstance(links, list) and links, (
        "contact_links must stay populated: with blank_issues_enabled false and no "
        "templates reachable, removing it leaves a reporter no route at all"
    )
    expected = f"https://github.com/{CANONICAL_REPO}/security/advisories/new"
    advisory = [
        link for link in links if str(link.get("url", "")).endswith("/security/advisories/new")
    ]
    assert advisory, f"no private-advisory contact link remains; expected one at {expected}"
    for link in advisory:
        assert link["url"] == expected, (
            f"the private-advisory link points at {link['url']!r}, expected {expected!r} — "
            "this is the only security-reporting route the issue chooser offers"
        )


@pytest.mark.unit
def test_blank_issues_stay_disabled_while_a_contact_link_carries_reporting() -> None:
    """Why the broken link mattered, asserted so the reasoning cannot rot.

    ``blank_issues_enabled: false`` is what made a single dead contact link
    fatal rather than merely untidy: with no blank-issue escape hatch, the
    chooser offered nothing else. That is the right setting for a security
    posture that wants reports triaged, so this does not ask for it to change —
    it pins the pair, so that a future edit which drops the contact links while
    leaving blank issues disabled fails here instead of silently restoring the
    original dead end.
    """
    config = _issue_chooser_config()
    assert config.get("blank_issues_enabled") is False, (
        "blank_issues_enabled changed; re-check test_security_contact_link_* , which "
        "assumes the contact link is the reporter's only route"
    )
