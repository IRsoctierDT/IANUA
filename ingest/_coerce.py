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

from ingest.schema import MAX_FIELD_LEN, MAX_NESTING_DEPTH, MAX_OBSERVABLES

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
