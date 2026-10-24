# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The Pages welcome greets a visitor without learning anything about them.

``docs/index.html`` shows a first-time visitor a welcome card and a returning
one a slim note. Telling the two apart needs per-visitor state, and the card
tells the visitor in so many words where that state lives: *"the flag that
remembers you stays in this browser: no cookies, no analytics, no request."*

That sentence is a promise made on screen, so it is pinned here rather than
left to review. The whole mechanism is one key in the visitor's own browser —
GitHub Pages serves static files and runs none of our code, so there is no
server side that could hold a visitor table, and standing one up elsewhere
would mean storing an identifier (an address, a cookie id) that is personal
data under GDPR/CCPA and would need a notice and a lawful basis. Per-browser
state collects nothing and cannot leak.

What these assertions cover, and what they do not: they read the committed
page, so they catch a greeting that grows an analytics beacon, a cookie, or a
``fetch`` to a counter service. They say nothing about the rest of the page
(the site already loads Google Fonts, which predates this feature), and they
are not a substitute for the browser-level behaviour, which is exercised by
driving the real page in Chromium.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_PAGE = _REPO / "docs" / "index.html"

#: Anything that would turn a greeting into a measurement. ``navigator.`` is
#: here for ``sendBeacon`` and for the fingerprint-shaped properties beside
#: it; ``new Image`` is the oldest tracking pixel there is.
_PHONES_HOME = (
    "fetch(",
    "XMLHttpRequest",
    "sendBeacon",
    "navigator.",
    "document.cookie",
    "new Image",
    "WebSocket",
    "EventSource",
    "import(",
)


def _page() -> str:
    return _PAGE.read_text(encoding="utf-8")


def _welcome_script() -> str:
    """The one inline script that implements the greeting, comments and all."""
    blocks: list[str] = re.findall(r"<script>(.*?)</script>", _page(), re.DOTALL)
    matching = [block for block in blocks if "ianua.visitor" in block]
    assert len(matching) == 1, f"expected exactly one welcome script, found {len(matching)}"
    return matching[0]


def _welcome_code() -> str:
    """The same script with its comments removed.

    The token checks below have to read code rather than prose: this file's
    own explanation of why the record is rendered with ``textContent`` and
    "never ``innerHTML``" would otherwise trip the gate that enforces it.
    Only ``/* */`` blocks and whole comment lines are removed, so an inline
    ``//`` inside a string or a regex is left alone — there are none today,
    and leaving them is the direction that over-reports rather than misses.
    """
    without_blocks = re.sub(r"/\*.*?\*/", "", _welcome_script(), flags=re.DOTALL)
    return "\n".join(
        line for line in without_blocks.splitlines() if not line.lstrip().startswith(("//", "*"))
    )


@pytest.mark.unit
def test_both_greetings_ship_hidden_so_javascript_off_changes_nothing() -> None:
    """A visitor without JavaScript must see the page as it was, not a banner
    they have no way to dismiss."""
    page = _page()
    for element in (
        '<div class="welcome-backdrop" id="welcome"',
        '<div class="welcome-toast" id="welcome-back"',
    ):
        start = page.find(element)
        assert start != -1, f"{element!r} is missing from the page"
        opening_tag = page[start : page.index(">", start)]
        assert " hidden" in opening_tag, f"{element!r} does not ship hidden: {opening_tag!r}"


@pytest.mark.unit
def test_the_dialog_is_announced_as_a_dialog() -> None:
    """Focus is moved into the card and trapped there, so a screen reader has
    to be told what it has been moved into."""
    page = _page()
    start = page.find('<div class="welcome-card"')
    assert start != -1, "the welcome card is missing"
    card = page[start : page.index(">", start)]
    for attribute in ('role="dialog"', 'aria-modal="true"', 'aria-labelledby="welcome-title"'):
        assert attribute in card, f"the welcome card is missing {attribute}"
    assert 'id="welcome-title"' in page, "aria-labelledby points at no element"


@pytest.mark.unit
def test_the_greeting_makes_no_request_and_sets_no_cookie() -> None:
    """The on-screen promise, made mechanical."""
    script = _welcome_code()
    found = [token for token in _PHONES_HOME if token in script]
    assert not found, (
        "the welcome script reaches outside the page, which contradicts what the card tells "
        f"the visitor ('no cookies, no analytics, no request'): {found}"
    )


@pytest.mark.unit
def test_the_card_still_makes_the_promise_the_test_above_enforces() -> None:
    """If the claim is ever dropped from the card, the gate above should be
    reconsidered deliberately rather than left enforcing a sentence nobody
    shows any more."""
    page = _page()
    assert "no cookies, no analytics, no request" in page, (
        "the welcome card no longer states where the visitor flag lives; decide whether "
        "test_the_greeting_makes_no_request_and_sets_no_cookie still describes the feature"
    )


@pytest.mark.unit
def test_stored_visitor_state_never_reaches_the_page_as_markup() -> None:
    """The record is attacker-reachable: every Pages site under one github.io
    account shares an origin, so a sibling site can write this key, and the
    visitor can edit it by hand. It is rendered as text, never as HTML."""
    script = _welcome_code()
    assert "innerHTML" not in script, "the welcome script assigns innerHTML; use textContent"
    assert "textContent" in script, "the welcome script does not render its text with textContent"


@pytest.mark.unit
def test_the_visitor_record_is_validated_rather_than_trusted() -> None:
    """A malformed record must degrade to 'greet them', not to an exception on
    a page load."""
    script = _welcome_code()
    assert "JSON.parse" in script, "the record is not parsed"
    assert script.count("catch") >= 4, (
        "every storage probe, read, parse and write has to be guarded: blocked site data and an "
        "exhausted quota both throw rather than returning null"
    )
    assert "Math.floor(Number(" in script, "the visit count is not coerced to an integer"
    assert re.search(r"/\^\\d\{4\}-\\d\{2\}-\\d\{2\}\$/", script), (
        "the stored date is not matched against a literal pattern before it is displayed"
    )


@pytest.mark.unit
def test_the_storage_key_is_versioned() -> None:
    """A later change to the record's shape must not have to interpret
    whatever an older version of this script wrote."""
    keys = set(re.findall(r"'(ianua\.visitor[^']*)'", _welcome_code()))
    assert keys, "the welcome script names no storage key"
    for key in keys:
        assert re.fullmatch(r"ianua\.visitor\.v\d+(\.probe)?", key), (
            f"unversioned storage key: {key}"
        )


@pytest.mark.unit
def test_the_greeting_adds_no_third_party_script() -> None:
    """The feature is deliberately dependency-free; a greeting is not worth a
    supply-chain edge."""
    assert "<script src=" not in _page(), (
        "docs/index.html now loads an external script; the welcome needs none"
    )
