# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Attribution must survive a fork, a rebrand, and a file copied out of context.

Apache-2.0 grants broad rights to copy and modify, and deliberately grants
none to the licensor's marks (§6). What the licence cannot do by itself is make
attribution *travel*: §4 requires notices to be retained in redistributed
source, but nothing carries them into a generated document, a published page,
or a single module lifted into someone else's project.

These tests are the gate for that. They are not security tests — nothing here
protects the running system. They protect the provenance of the work, which is
the one thing the repository's chosen licence reserves.

The valuable assertion is the first one: a new ``.py`` file without an SPDX
notice fails the build, so the 249-file sweep that introduced them cannot
quietly erode one file at a time.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]

#: The machine-readable notice every source file carries. SPDX short-form
#: rather than the full Apache appendix boilerplate: two lines instead of
#: eleven, and license scanners and SBOM tooling detect it automatically —
#: which matters because this project publishes CycloneDX SBOMs.
SPDX_COPYRIGHT = "# SPDX-FileCopyrightText: 2026 Ivan Rozenblad"
SPDX_LICENSE = "# SPDX-License-Identifier: Apache-2.0"

#: The holder named in LICENSE/NOTICE. Asserted against the SPDX line so the
#: two cannot drift into naming different people.
HOLDER = "Ivan Rozenblad"

_PUBLISHED_PAGES = ("docs/index.html", "docs/status.html", "docs/trust.html")


#: Directories holding no first-party source. Walking the tree rather than
#: asking git keeps this free of a subprocess and of any dependency on a git
#: binary being present, so the gate always runs rather than skipping.
_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "build",
        "dist",
        "data",
        "node_modules",
        ".eggs",
    }
)


def _tracked_python_files() -> list[str]:
    """Every first-party ``.py`` file, as repository-relative paths."""
    found = []
    for path in _REPO_ROOT.rglob("*.py"):
        relative = path.relative_to(_REPO_ROOT)
        if _EXCLUDED_DIRS.isdisjoint(relative.parts):
            found.append(relative.as_posix())
    return sorted(found)


@pytest.mark.unit
def test_every_tracked_python_file_carries_an_spdx_notice() -> None:
    """The gate. A new module without a notice fails here, not in review."""
    missing = []
    for relative in _tracked_python_files():
        text = (_REPO_ROOT / relative).read_text(encoding="utf-8")
        if SPDX_COPYRIGHT not in text or SPDX_LICENSE not in text:
            missing.append(relative)
    assert missing == [], (
        f"{len(missing)} file(s) carry no SPDX notice: {missing[:10]}\n"
        "Add these two lines at the top (after any shebang):\n"
        f"{SPDX_COPYRIGHT}\n{SPDX_LICENSE}"
    )


@pytest.mark.unit
def test_the_notice_precedes_the_code_and_follows_any_shebang() -> None:
    """Placement matters, and this is the assertion with real teeth.

    A shebang must stay line 1 to remain executable, and a notice buried below
    the imports is not a notice anyone will see. It also covers a weakness in
    the containment check above: a file that merely *mentions* the notice text
    — this module does, since it defines the constants — satisfies a substring
    search without carrying a header. Position is what cannot be faked, which
    is why both tests exist rather than one.
    """
    misplaced = []
    for relative in _tracked_python_files():
        lines = (_REPO_ROOT / relative).read_text(encoding="utf-8").splitlines()
        expected = 1 if lines and lines[0].startswith("#!") else 0
        if expected >= len(lines) or lines[expected] != SPDX_COPYRIGHT:
            misplaced.append(relative)
    assert misplaced == [], f"notice is not the first line after any shebang: {misplaced[:10]}"


@pytest.mark.unit
def test_the_spdx_holder_matches_license_and_notice() -> None:
    """One copyright holder, named the same everywhere."""
    assert HOLDER in SPDX_COPYRIGHT
    notice = (_REPO_ROOT / "NOTICE").read_text(encoding="utf-8")
    assert HOLDER in notice, "NOTICE names a different holder than the SPDX lines"
    config = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["project"]["license"] == "Apache-2.0", (
        "pyproject declares a licence the SPDX identifier does not match"
    )


@pytest.mark.unit
def test_the_spdx_identifier_matches_the_declared_licence() -> None:
    """A wrong SPDX tag is worse than none — scanners would report the wrong terms."""
    config = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = config["project"]["license"]
    assert SPDX_LICENSE.endswith(declared), (
        f"SPDX says {SPDX_LICENSE!r} but pyproject declares {declared!r}"
    )


@pytest.mark.unit
def test_generated_incident_reports_state_their_origin() -> None:
    """A report reaches a client who will never open the repository.

    Apache-2.0 §4 carries notices through redistributed *source*; nothing
    carries them into a generated document. So the document says where it came
    from — which also makes a rebranded deployment's output visibly
    inconsistent with its branding rather than silently unattributed.
    """
    from agents import __version__
    from agents.incident_report_agent import _PROVENANCE

    source = (_REPO_ROOT / "agents" / "incident_report_agent.py").read_text(encoding="utf-8")
    assert "{_PROVENANCE}" in source, "the report template no longer appends the footer"
    assert "IANUA" in _PROVENANCE
    assert HOLDER in _PROVENANCE
    assert "Apache-2.0" in _PROVENANCE
    assert "github.com/IRsoctierDT/IANUA" in _PROVENANCE
    assert __version__ in _PROVENANCE, "the footer version drifted from the platform version"


@pytest.mark.unit
@pytest.mark.parametrize("page", _PUBLISHED_PAGES)
def test_published_pages_carry_attribution(page: str) -> None:
    """These are the artifacts a rebranded fork would most visibly republish."""
    text = (_REPO_ROOT / page).read_text(encoding="utf-8")
    assert re.search(r"&copy;|©", text), f"{page}: no copyright symbol"
    assert HOLDER in text, f"{page}: does not name the copyright holder"
    assert "Apache-2.0" in text, f"{page}: does not name the licence"
    assert "github.com/IRsoctierDT/IANUA" in text, f"{page}: no link back to the source"


@pytest.mark.unit
def test_the_page_builders_emit_the_attribution_rather_than_it_being_hand_added() -> None:
    """status.html and trust.html are generated, so a hand-edit would be erased.

    Pinned because the obvious way to 'fix' a missing footer is to edit the
    HTML, which the next ``--check`` run would then flag as drift — and the
    regeneration would silently drop the attribution again.
    """
    for builder in ("scripts/build_status_page.py", "scripts/build_trust_page.py"):
        source = (_REPO_ROOT / builder).read_text(encoding="utf-8")
        assert HOLDER in source, f"{builder} does not emit the copyright holder"
        assert "Apache-2.0" in source, f"{builder} does not emit the licence"
