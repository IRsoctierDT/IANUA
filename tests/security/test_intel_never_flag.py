"""Never-flag enforcement: at ingest AND at query, with the disjointness pin."""

from __future__ import annotations

import ipaddress
import json
from datetime import date
from pathlib import Path

import pytest
from intel import load_store, lookup_indicator

_INTEL = Path(__file__).resolve().parents[2] / "intel"


@pytest.mark.security
def test_query_suppression_for_internal_space() -> None:
    store = load_store()
    for probe in ("10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.169.254", "100.64.0.1"):
        verdict = lookup_indicator(store, probe, as_of=date(2026, 8, 21))
        assert verdict.risk == "suppressed", f"{probe} must be policy-suppressed"
        assert not verdict.matched


@pytest.mark.security
def test_cgnat_suppressed_despite_is_private_disagreement() -> None:
    # 100.64/10 is exactly where ipaddress.is_private heuristics wobble across
    # versions — the explicit CIDR list, not the stdlib heuristic, is policy.
    store = load_store()
    assert "100.64.0.0/10" in store.never_flag
    verdict = lookup_indicator(store, "100.64.0.1", as_of=date(2026, 8, 21))
    assert verdict.risk == "suppressed"


@pytest.mark.security
def test_seed_and_never_flag_are_disjoint() -> None:
    # The committed seed uses RFC 5737 documentation ranges precisely so this
    # assertion is meaningful: no seed address may sit in a never-flag CIDR.
    store = load_store()
    networks = [ipaddress.ip_network(cidr) for cidr in store.never_flag]
    for indicator in store.atomic.values():
        if indicator.indicator_type in ("ipv4", "ipv6"):
            address = ipaddress.ip_address(indicator.value)
            assert not any(address in network for network in networks), (
                f"seed indicator {indicator.value} is inside a never-flag range"
            )


@pytest.mark.security
def test_documentation_ranges_deliberately_not_never_flagged() -> None:
    document = json.loads((_INTEL / "never_flag.json").read_text(encoding="utf-8"))
    for doc_range in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"):
        assert doc_range not in document["cidrs"], (
            "documentation ranges host the synthetic seed; never-flagging them "
            "would make the disjointness test unsatisfiable"
        )
