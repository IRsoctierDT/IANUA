"""Security tests for the status page generator.

The source data is trusted and committed, but the renderer escapes every dynamic
field as defense in depth (AGENTS.md §5, §6.1): a component name or detail must
never be able to inject markup into the published page, and unknown status tokens
must fail closed rather than silently producing a broken page.
"""

import pytest
from scripts.build_status_page import (
    StatusDataError,
    parse_report,
    render_html,
)

_XSS = "<script>alert('xss')</script>"
_ATTR = '"><img src=x onerror=alert(1)>'


def _data_with(name: str = "ok", detail: str = "ok", section: str = "ok") -> dict[str, object]:
    return {
        "title": "T",
        "tagline": "g",
        "as_of": "2026-07-10",
        "sections": [
            {
                "title": section,
                "components": [{"name": name, "status": "operational", "detail": detail}],
            }
        ],
    }


@pytest.mark.security
def test_component_name_is_escaped() -> None:
    report = parse_report(_data_with(name=_XSS), version="1.0.0")
    page = render_html(report)
    assert _XSS not in page
    assert "&lt;script&gt;" in page


@pytest.mark.security
def test_component_detail_is_escaped() -> None:
    report = parse_report(_data_with(detail=_XSS), version="1.0.0")
    page = render_html(report)
    assert "<script>" not in page.lower()


@pytest.mark.security
def test_section_title_is_escaped() -> None:
    report = parse_report(_data_with(section=_XSS), version="1.0.0")
    page = render_html(report)
    assert _XSS not in page


@pytest.mark.security
def test_attribute_breakout_is_escaped() -> None:
    # The tagline lands inside an HTML attribute; a naive render would break out.
    data = _data_with()
    data["tagline"] = _ATTR
    report = parse_report(data, version="1.0.0")
    page = render_html(report)
    # The attribute cannot be broken out of: the closing quote and angle
    # brackets are escaped, so no live <img> element is ever emitted. The
    # payload survives only as inert, escaped text.
    assert '"><img' not in page
    assert "<img" not in page.lower()
    assert "&quot;&gt;&lt;img" in page


@pytest.mark.security
def test_version_is_escaped() -> None:
    report = parse_report(_data_with(), version=_XSS)
    page = render_html(report)
    assert "<script>" not in page.lower()


@pytest.mark.security
def test_unknown_status_fails_closed() -> None:
    with pytest.raises(StatusDataError):
        parse_report(_data_with_status("weaponized"), version="1.0.0")


def _data_with_status(status: str) -> dict[str, object]:
    data = _data_with()
    sections = data["sections"]
    assert isinstance(sections, list)
    sections[0]["components"][0]["status"] = status
    return data
