"""Security tests for the trust page generator (AGENTS.md §5, §6.1).

The snapshot is trusted and committed, but the renderer escapes every dynamic
field as defense in depth: a control title or category must never inject markup
into the published page, and unknown status tokens fail closed.
"""

import pytest
from scripts.build_trust_page import TrustDataError, parse_report, render_html

_XSS = "<script>alert('xss')</script>"


def _data_with(
    title: str = "ok", category: str = "ok", as_of: str = "2026-07-24"
) -> dict[str, object]:
    return {
        "as_of": as_of,
        "score": 100,
        "controls": [{"id": "C-01", "title": title, "category": category, "status": "pass"}],
        "frameworks": [{"name": "SOC 2", "passing": 1, "total": 1}],
    }


@pytest.mark.security
def test_control_title_is_escaped() -> None:
    page = render_html(parse_report(_data_with(title=_XSS)))
    assert _XSS not in page
    assert "&lt;script&gt;" in page


@pytest.mark.security
def test_category_is_escaped() -> None:
    page = render_html(parse_report(_data_with(category=_XSS)))
    assert "<script>" not in page.replace("</script>", "")  # only legit tags remain


@pytest.mark.security
def test_as_of_is_escaped() -> None:
    page = render_html(parse_report(_data_with(as_of='"><img src=x onerror=alert(1)>')))
    assert "onerror" not in page or "&gt;" in page
    assert '"><img' not in page


@pytest.mark.security
def test_unknown_status_fails_closed() -> None:
    data = _data_with()
    data["controls"] = [{"id": "C", "title": "t", "category": "c", "status": "trusted"}]
    with pytest.raises(TrustDataError):
        parse_report(data)


@pytest.mark.security
def test_framework_name_is_escaped() -> None:
    data = _data_with()
    data["frameworks"] = [{"name": _XSS, "passing": 1, "total": 1}]
    page = render_html(parse_report(data))
    assert _XSS not in page
