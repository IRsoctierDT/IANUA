"""Unit tests for scripts/generate_sbom.py helpers."""

import pytest
from scripts.generate_sbom import _serial_number


@pytest.mark.unit
def test_serial_number_is_urn_uuid() -> None:
    serial = _serial_number("2026-06-23T00:00:00Z", [{"purl": "pkg:pypi/x@1"}])
    assert serial.startswith("urn:uuid:")


@pytest.mark.unit
def test_serial_number_is_deterministic() -> None:
    comps = [{"purl": "pkg:pypi/a@1"}, {"purl": "pkg:npm/b@2"}]
    a = _serial_number("2026-06-23T00:00:00Z", comps)
    b = _serial_number("2026-06-23T00:00:00Z", list(reversed(comps)))
    # Stable across component ordering (purls are sorted internally).
    assert a == b


@pytest.mark.unit
def test_serial_number_changes_with_content() -> None:
    base = [{"purl": "pkg:pypi/a@1"}]
    assert _serial_number("2026-06-23T00:00:00Z", base) != _serial_number(
        "2026-06-23T00:00:01Z", base
    )
    assert _serial_number("2026-06-23T00:00:00Z", base) != _serial_number(
        "2026-06-23T00:00:00Z", [{"purl": "pkg:pypi/a@2"}]
    )
