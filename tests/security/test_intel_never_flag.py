# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Never-flag enforcement: at ingest AND at query, with the disjointness pin."""

from __future__ import annotations

import ipaddress
import json
import shutil
from datetime import date
from pathlib import Path

import pytest

from intel import IntelStoreError, load_store, lookup_indicator, never_flagged

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
def test_ipv4_mapped_spelling_cannot_bypass_never_flag(tmp_path: Path) -> None:
    # ``::ffff:10.0.0.1`` is how a dual-stack socket records the IPv4 peer
    # 10.0.0.1. Measured before the unwrap: never_flagged() was False, the
    # query verdict was "unknown" rather than "suppressed", and a malicious
    # ``ipv6`` seed record for it loaded — internal space branded by a feed
    # through a spelling the CIDR list does not contain.
    store = load_store()
    for probe in (
        "::ffff:10.0.0.1",
        "::FFFF:169.254.169.254",
        "::ffff:7f00:1",
        "::ffff:100.64.0.1",
    ):
        assert never_flagged(probe, store.never_flag), f"{probe} must be never-flagged"
        verdict = lookup_indicator(store, probe, as_of=date(2026, 8, 21))
        assert verdict.risk == "suppressed" and not verdict.matched, probe
    # The list stays explicit: a mapped *public* address is not suppressed.
    assert not never_flagged("::ffff:203.0.113.5", store.never_flag)

    work = tmp_path / "intel"
    shutil.copytree(
        _INTEL, work, ignore=shutil.ignore_patterns("*.py", "*.sha256", "*.md", "__pycache__")
    )
    seed_path = work / "seed" / "indicators.json"
    seed = json.loads(seed_path.read_text(encoding="utf-8"))
    record = dict(seed["indicators"][0])
    record.update(type="ipv6", value="::ffff:10.0.0.1", risk="malicious")
    seed["indicators"].append(record)
    seed_path.write_text(json.dumps(seed), encoding="utf-8")
    with pytest.raises(IntelStoreError, match="never-flag"):
        load_store(work)


@pytest.mark.security
def test_documentation_ranges_deliberately_not_never_flagged() -> None:
    document = json.loads((_INTEL / "never_flag.json").read_text(encoding="utf-8"))
    for doc_range in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"):
        assert doc_range not in document["cidrs"], (
            "documentation ranges host the synthetic seed; never-flagging them "
            "would make the disjointness test unsatisfiable"
        )
