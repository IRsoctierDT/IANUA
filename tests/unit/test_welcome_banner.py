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
server side that could hold a visitor table; and building one elsewhere would
mean storing an identifier (an address, a cookie id) that is personal data
under GDPR/CCPA and would need a notice and a lawful basis. Per-browser state
collects nothing and cannot leak.

**The page is parsed, not pattern-matched.** An earlier version of this file
found the script with ``re.findall(r"<script>(.*?)</script>")`` and asserted
``"<script src=" not in page``, which CodeQL flagged (``py/bad-tag-filter``,
high) on PR #304. It was right, and the weakness was worse in the gate than
in the extractor: measured, ``<SCRIPT SRC=…>``, a ``src`` on a continuation
line, and the entirely ordinary ``<script defer src=…>`` all bypassed the
third-party-script gate — three of four spellings — while the extractor's
misses merely failed the assertion loudly. A gate that reads green over a
loaded CDN script is worse than no gate, so both now go through
:class:`html.parser.HTMLParser`, which lowercases tag and attribute names and
does not care about whitespace or attribute order.
:func:`test_the_third_party_script_gate_reads_tags_not_text` pins that with
the spellings that used to get through.

What these assertions cover, and what they do not: they read the committed
page, so they catch a greeting that grows an analytics beacon, a cookie, or a
``fetch`` to a counter service. They say nothing about the rest of the page
(the site already loads Google Fonts, which predates this feature), and they
are not a substitute for the browser-level behaviour, which is exercised by
driving the real page in Chromium.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
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

_Attrs = dict[str, str | None]


class _Elements(HTMLParser):
    """Every start tag with its attributes, and every script's text.

    ``HTMLParser`` lowercases tag and attribute names and handles attribute
    order, whitespace and quoting itself, which is the whole reason for
    preferring it to a pattern here. It also switches to CDATA mode inside
    ``<script>``, so the element's text arrives verbatim.
    """

    def __init__(self) -> None:
        # Script text has to be the bytes the browser would run, so entity
        # references are left exactly as written.
        super().__init__(convert_charrefs=False)
        self.elements: list[tuple[str, _Attrs]] = []
        self.scripts: list[tuple[_Attrs, str]] = []
        self._open_script: _Attrs | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        mapping = dict(attrs)
        self.elements.append((tag, mapping))
        if tag == "script":
            self._open_script = mapping
            self._text = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._open_script is not None:
            self.scripts.append((self._open_script, "".join(self._text)))
            self._open_script = None

    def handle_data(self, data: str) -> None:
        if self._open_script is not None:
            self._text.append(data)


def _parse(markup: str) -> _Elements:
    parser = _Elements()
    parser.feed(markup)
    parser.close()
    return parser


def _page() -> str:
    return _PAGE.read_text(encoding="utf-8")


def _parsed() -> _Elements:
    return _parse(_page())


def _element(element_id: str) -> _Attrs:
    """One element's attributes, found by ``id``."""
    found = [attrs for _tag, attrs in _parsed().elements if attrs.get("id") == element_id]
    assert len(found) == 1, f"expected exactly one element with id={element_id!r}, got {len(found)}"
    return found[0]


def _welcome_script() -> str:
    """The one inline script that implements the greeting, comments and all."""
    matching = [text for _attrs, text in _parsed().scripts if "ianua.visitor" in text]
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
    for element_id in ("welcome", "welcome-back"):
        assert "hidden" in _element(element_id), f"#{element_id} does not ship hidden"


@pytest.mark.unit
def test_the_dialog_is_announced_as_a_dialog() -> None:
    """Focus is moved into the card and trapped there, so a screen reader has
    to be told what it has been moved into."""
    cards = [attrs for _tag, attrs in _parsed().elements if attrs.get("class") == "welcome-card"]
    assert len(cards) == 1, f"expected exactly one welcome card, found {len(cards)}"
    card = cards[0]
    assert card.get("role") == "dialog", "the welcome card is not a dialog"
    assert card.get("aria-modal") == "true", "the welcome card is not modal"
    assert card.get("aria-labelledby") == "welcome-title", "the welcome card is unlabelled"
    assert _element("welcome-title"), "aria-labelledby points at no element"


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
    assert "no cookies, no analytics, no request" in _page(), (
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
    loaded = [attrs["src"] for attrs, _text in _parsed().scripts if "src" in attrs]
    assert not loaded, (
        f"docs/index.html now loads external scripts; the welcome needs none: {loaded}"
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "markup",
    [
        '<script src="https://cdn.invalid/x.js"></script>',
        '<SCRIPT SRC="https://cdn.invalid/x.js"></SCRIPT>',
        '<script\n  src="https://cdn.invalid/x.js"></script>',
        '<script defer src="https://cdn.invalid/x.js"></script>',
        "<script src='https://cdn.invalid/x.js'></script>",
    ],
)
def test_the_third_party_script_gate_reads_tags_not_text(markup: str) -> None:
    """The regression behind CodeQL's ``py/bad-tag-filter`` on PR #304.

    Measured against the gate as it was written then (``"<script src=" not in
    page``): only the first spelling was caught. The other four — uppercase,
    a continuation line, an attribute before ``src``, single quotes — each
    bypassed a gate whose whole purpose is to keep an external script out,
    and each reported green.
    """
    scripts = _parse(markup).scripts
    assert [attrs for attrs, _text in scripts if "src" in attrs], (
        f"the third-party-script gate does not see {markup!r}"
    )
