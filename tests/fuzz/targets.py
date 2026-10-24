# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Fuzz targets: one bytes-in function per surface, and the invariants it keeps.

Free of Atheris on purpose, so the same functions run under coverage-guided
fuzzing (``python -m tests.fuzz``) and under pytest over their seeds on every
platform, including the ones Atheris ships no wheel for. A broken invariant
raises :class:`AssertionError` explicitly, never through ``assert``, so running
under ``-O`` cannot turn a target into one that accepts everything.

Each target asserts what its module already promises, not a new rule. Two
contracts that do **not** hold today are deliberately absent, because a target
that fails on every run teaches nobody anything: the event store's 64 KiB
projection ceiling (``normalize`` can build an event the store refuses) and the
MCP transport's "malformed input never crashes the loop". A third is asserted
in a weaker form, said where it is: an unclaimed record's excerpt escapes
non-ASCII. Each needs its own fix, and its full check joins this file with that
fix.
"""

from __future__ import annotations

import atexit
import contextlib
import functools
import ipaddress
import json
import math
import re
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

from agents.policies.egress import (
    EgressAllowlist,
    EgressAllowlistError,
    EgressDenied,
    LabHost,
    parse_address,
    parse_port,
)
from ingest.errors import MalformedProjectionError
from ingest.keyvalue import MAX_KEY_LEN, MAX_PAIRS, MAX_VALUE_LEN, MIN_PAIRS, decode
from ingest.normalize import normalize
from ingest.schema import (
    MAX_FIELD_LEN,
    MAX_NOTES,
    MAX_OBSERVABLES,
    MAX_RAW_EXCERPT,
    NormalizedEvent,
)
from store.schema import canonical_json

#: The key grammar ``ingest.keyvalue`` documents, restated here rather than
#: imported, so a change to the module's pattern is checked against the
#: contract instead of against itself.
_KEY = re.compile(rf"[A-Za-z_][A-Za-z0-9_.\-]{{0,{MAX_KEY_LEN - 1}}}")

_LIMITED_BROADCAST = ipaddress.IPv4Address("255.255.255.255")

#: A fixed allow-list for the egress target: one host per family and port shape,
#: using loopback and the RFC 5737 / RFC 3849 documentation ranges.
_ALLOWLIST = EgressAllowlist(
    LabHost(ipaddress.ip_address(address), port, "fuzz harness fixture")
    for address, port in (
        ("127.0.0.1", 8443),
        ("::1", 8443),
        ("192.0.2.10", 443),
        ("2001:db8::10", 443),
    )
)


def _check(condition: bool, message: str) -> None:
    """Raise :class:`AssertionError` when an invariant does not hold."""
    if not condition:
        raise AssertionError(message)


def _check_bounded(event: NormalizedEvent) -> None:
    """The per-field ceilings ``ingest/schema.py`` applies to untrusted data."""
    _check(len(event.message) <= MAX_FIELD_LEN, f"message is {len(event.message)} characters")
    _check(
        len(event.raw_excerpt) <= MAX_RAW_EXCERPT,
        f"raw_excerpt is {len(event.raw_excerpt)} characters",
    )
    _check(len(event.observables) <= MAX_OBSERVABLES, f"{len(event.observables)} observables")
    _check(len(event.notes) <= MAX_NOTES, f"{len(event.notes)} notes")


def one_input_normalize(data: bytes) -> None:
    """``ingest.normalize`` on the bytes path ``collect/`` feeds it.

    Nothing may raise for bytes: malformed content degrades instead of being
    lost. The result is bounded, deterministic, and survives the exact
    read-back the store performs before it writes. An unclaimed record keeps
    every observable inside its retained excerpt, because there the excerpt is
    the evidence.
    """
    event = normalize(data)
    _check_bounded(event)
    _check(normalize(data) == event, "the same bytes normalized to two different events")
    back = NormalizedEvent.from_dict(json.loads(canonical_json(event.to_dict())))
    _check(back == event, "the event does not survive the store's read-back")
    if event.vendor == "unrecognized":
        for observable in event.observables:
            # Also compared in its JSON-escaped form. The unclaimed excerpt is
            # serialized with json.dumps' default ensure_ascii=True, so a
            # non-ASCII indicator is retained as \uXXXX; this harness found that
            # on its first run. The fix is a change of its own because it alters
            # event_id for every such record. The escaped form still
            # fails for an indicator scanned from outside the retained evidence.
            escaped = json.dumps(observable)[1:-1]
            _check(
                observable in event.raw_excerpt or escaped in event.raw_excerpt,
                f"observable {observable!r} is not inside the retained excerpt",
            )


def one_input_keyvalue(data: bytes) -> None:
    """``ingest.keyvalue.decode``: prose is ``None``; pairs obey the grammar.

    Values are captured, never unescaped, so every key and value must occur in
    the line as written.
    """
    line = data.decode("utf-8", errors="replace")
    pairs = decode(line)
    if pairs is None:
        return
    _check(MIN_PAIRS <= len(pairs) <= MAX_PAIRS, f"{len(pairs)} pairs")
    for key, value in pairs.items():
        _check(_KEY.fullmatch(key) is not None, f"key {key!r} is outside the documented grammar")
        _check(len(value) <= MAX_VALUE_LEN, f"value of {key!r} is {len(value)} characters")
        _check(key in line, f"key {key!r} does not occur in the line")
        _check(value in line, f"value of {key!r} does not occur in the line")
    _check(decode(line) == pairs, "the same line decoded to two different mappings")


def one_input_egress(data: bytes) -> None:
    """``agents.policies.egress``: what an address and port check may accept.

    The first two bytes are a port and the rest is the address text. An
    accepted address is the stdlib's parse of that text, is never unspecified,
    multicast, limited-broadcast, link-local, IPv4-mapped or scoped, and
    survives its own rendering. ``permits`` answers exactly when ``require``
    would return, and neither raises anything but its documented error.
    """
    if len(data) < 2:
        return
    port = int.from_bytes(data[:2], "big")
    text = data[2:].decode("utf-8", errors="replace")

    address: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    try:
        address = parse_address(text)
    except EgressAllowlistError:
        address = None
    if address is not None:
        _check(address == ipaddress.ip_address(text), f"{text!r} was accepted as {address}")
        if isinstance(address, ipaddress.IPv6Address):
            _check(address.ipv4_mapped is None, f"IPv4-mapped {address} was accepted")
            _check(address.scope_id is None, f"scoped {address} was accepted")
        _check(not address.is_unspecified, f"unspecified {address} was accepted")
        _check(not address.is_multicast, f"multicast {address} was accepted")
        _check(not address.is_link_local, f"link-local {address} was accepted")
        _check(address != _LIMITED_BROADCAST, "the limited-broadcast address was accepted")
        _check(parse_address(str(address)) == address, f"{address} does not survive rendering")

    try:
        accepted_port: int | None = parse_port(port)
    except EgressAllowlistError:
        accepted_port = None
    _check((accepted_port is not None) == (1 <= port <= 65535), f"port {port} misclassified")

    permitted = _ALLOWLIST.permits(text, port)
    try:
        host = _ALLOWLIST.require(text, port)
    except EgressDenied:
        _check(not permitted, f"permits() allowed {text!r}:{port} but require() refused it")
        return
    _check(permitted, f"require() returned {host.destination} but permits() refused it")
    _check((host.address, host.port) == (address, port), f"require() returned {host.destination}")


@functools.cache
def _allowlist_file() -> Path:
    """The one file :func:`one_input_allowlist` writes, made on first use.

    Reused rather than made per input, because a fresh directory per input
    halved this target's throughput under Atheris (measured: 1.6k against 3.0k
    inputs a second) and fed ``tempfile``'s own code to the coverage signal.
    Every input overwrites the whole file, so none can see another's bytes.

    Removed at interpreter exit, which covers the pytest replay. An Atheris run
    ends in libFuzzer's own ``exit()``, which skips that (measured), so there
    the directory stays in the system temp directory holding the last input;
    the CI runner is discarded with it.
    """
    directory = Path(tempfile.mkdtemp(prefix="ianua-fuzz-allowlist-"))
    atexit.register(shutil.rmtree, directory, ignore_errors=True)
    return directory / "egress.json"


def one_input_allowlist(data: bytes) -> None:
    """``EgressAllowlist.load`` on the bytes as a whole file: accepted, or its own error.

    Anything else escaping is a finding, as it is for the projection reader.
    Only the documented type is caught, not its ``ValueError`` base, because a
    bare ``ValueError`` is one of the three foreign exceptions (with
    ``UnicodeDecodeError`` and ``RecursionError``) that escaped the loader
    before it caught them.

    A target of its own rather than a check inside :func:`one_input_egress`:
    the file round trip took that target from 24.6k inputs a second to 3.0k
    (measured), which would have cost the address checks most of their budget.
    """
    path = _allowlist_file()
    path.write_bytes(data)
    with contextlib.suppress(EgressAllowlistError):
        EgressAllowlist.load(path)


def one_input_projection(data: bytes) -> None:
    """``NormalizedEvent.from_dict``: the only reader of a stored projection.

    A mapping is refused with :class:`MalformedProjectionError` or rebuilt
    into an event that is bounded, unchanged by the write-time bounds, has a
    finite timestamp, and round-trips. Anything else escaping it is what
    ``store/`` calls a defect in the reader.
    """
    try:
        payload = json.loads(data)
    except (ValueError, RecursionError):
        # json's own refusals (including undecodable bytes and the int-digit
        # limit) are not the reader under test.
        return
    if not isinstance(payload, dict):
        return
    try:
        event = NormalizedEvent.from_dict(payload)
    except MalformedProjectionError:
        return
    _check_bounded(event)
    _check(event.bounded() == event, "write-time bounds would change an event the reader accepted")
    _check(
        event.timestamp is None or math.isfinite(event.timestamp),
        f"timestamp {event.timestamp!r} was accepted",
    )
    _check(NormalizedEvent.from_dict(event.to_dict()) == event, "the event does not round-trip")


#: Every target, by the name the runner, the replay test and the CI matrix use.
TARGETS: dict[str, Callable[[bytes], None]] = {
    "allowlist": one_input_allowlist,
    "egress": one_input_egress,
    "keyvalue": one_input_keyvalue,
    "normalize": one_input_normalize,
    "projection": one_input_projection,
}
