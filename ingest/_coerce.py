# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Bounded, defensive coercion helpers shared by every domain parser.

Everything a parser reads is attacker-influenceable: a hostname is whatever
the endpoint reported, a command line is whatever the adversary typed, a mail
subject is whatever the sender chose. These helpers are the single place that
assumption is enforced, so a parser author cannot forget it — a parser calls
``text()`` and gets back something bounded, control-character free, and
safe to render, or ``None``.

Nothing here touches the filesystem, the network, or the clock. Timestamps
are parsed from the event's own value and never substituted with "now".
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from ingest.schema import (
    MAX_FIELD_LEN,
    MAX_NESTING_DEPTH,
    MAX_OBSERVABLES,
    MAX_PROJECTED_ITEMS,
)

#: C0/C1 control characters, minus tab/newline/carriage-return, which are
#: folded to spaces instead. These are the characters that corrupt terminal
#: output, truncate C-string consumers, and smuggle content past a reviewer.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_WHITESPACE_RUN = re.compile(r"[\t\n\r]+")
#: A bare epoch value, possibly already stringified by an upstream shipper.
_NUMERIC = re.compile(r"\d{1,14}(?:\.\d{1,9})?")

#: Observable extraction. Deliberately conservative: these patterns run only
#: over values a parser hands in, never over a whole raw payload, so the
#: observable set stays explainable ("it came from this field").
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b")
_HASH = re.compile(r"\b(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})\b")
_URL = re.compile(r"\bhttps?://[^\s\"'<>\\]{3,256}", re.IGNORECASE)
_DOMAIN = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,6}[A-Za-z]{2,24}\b")


def text(value: Any, *, limit: int = MAX_FIELD_LEN) -> str | None:
    """Coerce a scalar to a bounded, printable string, or ``None``.

    Returns ``None`` for absent, empty, or whitespace-only values so that a
    field a source did not carry stays genuinely absent. An empty string
    would read downstream as "the source said this is blank", which is a
    different and false claim.

    Containers (dict, list) return ``None`` rather than being stringified:
    a parser that wants a nested value must say which one.
    """
    if value is None or isinstance(value, (Mapping, list, tuple, set)):
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        raw = str(value)
    elif isinstance(value, str):
        raw = value
    else:
        return None
    cleaned = _CONTROL_CHARS.sub("", _WHITESPACE_RUN.sub(" ", raw)).strip()
    if not cleaned:
        return None
    return cleaned[:limit]


def dig(payload: Mapping[str, Any], *path: str) -> Any:
    """Walk a dotted path through nested mappings, returning ``None`` if absent.

    Tolerates a non-mapping mid-path (returns ``None``) because telemetry
    routinely disagrees with its own documented schema.
    """
    current: Any = payload
    for key in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


#: Sentinel for "this record did not carry that path at all", which is not
#: the same claim as "it carried nothing there". ``dig`` collapses the two
#: into ``None``; a projection must not, because absent keys are omitted and
#: a present-but-empty one is reported.
_ABSENT = object()

#: Field path. One component per mapping level, so a key that is *literally*
#: dotted — Zeek's ``id.orig_h`` — is a one-component path and unambiguous.
FieldPath = tuple[str, ...]


def project(payload: Mapping[str, Any], paths: Iterable[FieldPath]) -> dict[str, Any]:
    """Rebuild a record from only the paths a parser declared it reads.

    This is the evidence allow-list. ``raw_excerpt`` is serialized from the
    result, so a field no parser modelled — a mail ``Body``, a vendor's new
    column, a key an attacker chose — has no route into the event store at
    all. Redaction after the fact is not available to us: the store is
    append-only and ``event_id`` is a digest over the projection, so what
    ``ingest`` writes is what is kept (DESIGN.md §5 boundary 9).

    Three rules make an over-broad declaration safe rather than merely
    discouraged:

    * **Absent stays absent.** A path the record did not carry is omitted,
      never rendered as ``null`` — the same reason ``text()`` returns
      ``None`` instead of ``""``.
    * **An object yields its shape, never its values.** A declared path that
      lands on a mapping contributes a sorted list of its key names. So
      declaring a container by mistake can reveal *which* keys a record
      carried, and never what was in them.
    * **Everything is bounded.** Values coerce through :func:`text`;
      containers contribute at most :data:`MAX_PROJECTED_ITEMS` entries; the
      walk stops at :data:`MAX_NESTING_DEPTH` rather than trusting the
      caller to have checked.

    Args:
        payload: A decoded record. Untrusted in both keys and values.
        paths: The declared paths, each a tuple of mapping keys. A path
            continuing through a list applies to each element, which is how
            Entra's ``authenticationDetails`` list of method objects is read.

    Returns:
        A new mapping holding only the declared paths that the record
        carried, nested as they were.
    """
    out: dict[str, Any] = {}
    for path in paths:
        if not path:
            continue
        value = _walk(payload, path, 0)
        if value is _ABSENT:
            continue
        _graft(out, path, value)
    return out


def _walk(node: Any, path: FieldPath, depth: int) -> Any:
    """Follow one declared path, returning :data:`_ABSENT` if it is not there."""
    if depth > MAX_NESTING_DEPTH:
        return _ABSENT
    for index, key in enumerate(path):
        if isinstance(node, Mapping):
            if key not in node:
                return _ABSENT
            node = node[key]
        elif isinstance(node, (list, tuple)):
            # The path continues *through* a sequence: apply the rest of it
            # to each element and keep the ones that have it.
            kept = [
                found
                for found in (
                    _walk(item, path[index:], depth + 1) for item in node[:MAX_PROJECTED_ITEMS]
                )
                if found is not _ABSENT
            ]
            return kept or _ABSENT
        else:
            return _ABSENT
    return _leaf(node, depth)


def _leaf(value: Any, depth: int) -> Any:
    """Render a value found at a declared path, withholding anything unnamed."""
    if depth > MAX_NESTING_DEPTH:
        return None
    if isinstance(value, Mapping):
        # Shape, not content. See ``project``'s second rule.
        named = [text(key) for key in list(value)[:MAX_PROJECTED_ITEMS]]
        return sorted(key for key in named if key is not None)
    if isinstance(value, (list, tuple, set)):
        ordered = sorted(value, key=repr) if isinstance(value, set) else list(value)
        return [_leaf(item, depth + 1) for item in ordered[:MAX_PROJECTED_ITEMS]]
    return text(value)


def _graft(out: dict[str, Any], path: FieldPath, value: Any) -> None:
    """Place ``value`` at ``path`` in ``out``, creating the levels it needs.

    A shallower declared path can already hold a scalar where a deeper one
    needs a mapping (Azure declares both ``status`` and ``status.value``,
    because the export spells it either way). The deeper path wins, since a
    named leaf is better evidence than the shape of its parent.
    """
    cursor = out
    for key in path[:-1]:
        existing = cursor.get(key)
        if not isinstance(existing, dict):
            existing = {}
            cursor[key] = existing
        cursor = existing
    leaf = path[-1]
    if leaf not in cursor or not isinstance(cursor[leaf], dict):
        cursor[leaf] = value


def first(*values: Any) -> str | None:
    """First value that coerces to a non-empty bounded string."""
    for value in values:
        coerced = text(value)
        if coerced is not None:
            return coerced
    return None


def strings(value: Any, *, limit: int) -> tuple[str, ...]:
    """Coerce a scalar or sequence into a bounded, deduplicated string tuple."""
    # A bare string is one value, not a sequence of characters — getting that
    # backwards would turn one recipient into 30 single-letter "recipients".
    scalar = isinstance(value, str) or not isinstance(value, Sequence)
    candidates: Iterable[Any] = (value,) if scalar else value
    out: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        coerced = text(item)
        if coerced is None or coerced in seen:
            continue
        seen.add(coerced)
        out.append(coerced)
        if len(out) >= limit:
            break
    return tuple(out)


def epoch(value: Any) -> float | None:
    """Parse an event's own timestamp into epoch seconds, or ``None``.

    Accepts epoch seconds, epoch milliseconds, and ISO 8601 (including a
    trailing ``Z``). A naive timestamp is read as UTC and the assumption is
    the parser's to note; an unparseable one yields ``None`` rather than a
    substituted clock read, because fabricated ordering would silently
    corrupt every correlation built on top of it.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        seconds = float(value)
        # Values past ~2286 in seconds are almost certainly milliseconds.
        if seconds > 1e11:
            seconds /= 1000.0
        return seconds if 0 < seconds < 4e10 else None
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    # Zeek and several JSON exports carry epoch seconds as a bare number,
    # sometimes already stringified by an upstream shipper.
    if _NUMERIC.fullmatch(candidate):
        return epoch(float(candidate))
    if candidate.endswith(("Z", "z")):
        candidate = candidate[:-1] + "+00:00"
    # Sysmon and several Windows exports use "YYYY-MM-DD HH:MM:SS.mmm".
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.timestamp()


def depth_within(value: Any, limit: int = MAX_NESTING_DEPTH) -> bool:
    """Whether a decoded payload nests no deeper than ``limit``.

    Deep nesting is the cheap way to turn a recursive consumer into a stack
    overflow, and no real telemetry record needs 32 levels. Iterative by
    construction — a recursive checker would be vulnerable to the very input
    it is meant to reject.
    """
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        node, level = stack.pop()
        if level > limit:
            return False
        if isinstance(node, Mapping):
            stack.extend((child, level + 1) for child in node.values())
        elif isinstance(node, (list, tuple)):
            stack.extend((child, level + 1) for child in node)
    return True


def observables(*values: Any, limit: int = MAX_OBSERVABLES) -> tuple[str, ...]:
    """Extract atomic indicators from parser-selected values.

    Order is stable and by kind (URLs, hashes, IPs, domains) so two runs over
    the same event produce byte-identical output — the digests and fixtures
    downstream depend on it. The result is bounded: an event that mentions a
    thousand hosts contributes at most ``limit`` of them, and the truncation
    is the caller's to note.
    """
    found: list[str] = []
    seen: set[str] = set()

    def _add(items: Iterable[str]) -> None:
        for item in items:
            key = item.lower()
            if key in seen or len(found) >= limit:
                continue
            seen.add(key)
            found.append(item)

    corpus = [coerced for coerced in (text(value) for value in values) if coerced]
    joined = " ".join(corpus)
    urls = _URL.findall(joined)
    _add(urls)
    _add(_HASH.findall(joined))
    _add(match for match in _IPV4.findall(joined) if _is_dotted_quad(match))
    _add(_IPV6.findall(joined))
    # Domains are extracted last and never from inside an already-captured
    # URL, so a single indicator is not double-counted as two.
    url_text = " ".join(urls)
    _add(match for match in _DOMAIN.findall(joined) if match not in url_text)
    return tuple(found)


def _is_dotted_quad(candidate: str) -> bool:
    """Whether a four-octet match is a real IPv4 address.

    The regex matches ``999.1.2.3`` and software version strings; this is the
    check that keeps those out of the indicator set.
    """
    parts = candidate.split(".")
    return len(parts) == 4 and all(part.isdigit() and int(part) <= 255 for part in parts)
