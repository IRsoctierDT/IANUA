"""Fail-closed loader for the committed threat-intelligence library.

DESIGN.md §5 boundary 6: committed intel content is first-party or synthetic
only; no live feed ships. Whole-store rejection on any anomaly, in the
``compliance/attestations.py`` style: exact field sets, strict shapes, and a
loud, specific error. Poisoning defenses are structural:

* an unlisted ``source_id`` rejects the record (source allow-listing);
* a source whose license is not on the allow-list rejects the store;
* TLP above CLEAR is refused at ingest — an intel hit's restricted datum IS
  the indicator value, and reports carrying hits are tracked files;
* every atomic indicator carries a mandatory ``expires``;
* indicators inside the explicit never-flag CIDR list are rejected at ingest
  (and suppressed again at query — defense in depth);
* load bounds (record count, file size) fail closed rather than OOM.

ATT&CK anchors on behavioral records are validated against the pinned corpus:
unknown or malformed IDs reject (an authoring error); deprecated/revoked
anchors are ACCEPTED — they degrade the record to ``stale-anchor`` at match
time rather than letting an external taxonomy switch off a working local
detection twice a year.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import date
from pathlib import Path

from attack import AttackError, Corpus, load_corpus, validate_reference

from intel.model import AtomicIndicator, BehavioralRecord, IntelStore, Source

INTEL_DIR = Path(__file__).resolve().parent

#: Licenses committed intel content may carry. First-party and synthetic
#: content is Apache-2.0 (the repo's own grant); MIT covers the vetted
#: Unit 42 corpora should their distilled records ever be committed.
ALLOWED_LICENSES = frozenset({"Apache-2.0", "MIT", "CC0-1.0"})

MAX_ATOMIC_RECORDS = 5000
MAX_BEHAVIOR_RECORDS = 500
MAX_FILE_BYTES = 512 * 1024
MAX_STRING = 1000
MAX_LIST = 16

_SOURCE_FIELDS = {"source_id", "name", "url", "license", "upstream", "retrieved"}
_ATOMIC_FIELDS = {
    "type",
    "value",
    "risk",
    "confidence",
    "source_id",
    "first_seen",
    "retrieved",
    "expires",
    "tlp",
    "reference",
}
_BEHAVIOR_FIELDS = {
    "id",
    "title",
    "description",
    "attack_techniques",
    "event_types",
    "markers",
    "false_positives",
    "confidence",
    "source_id",
    "last_reviewed",
    "review_interval_days",
}
_ATOMIC_TYPES = {"ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email"}
_RISKS = {"malicious", "suspicious", "benign"}
_CONFIDENCES = {"low", "medium", "high"}


class IntelStoreError(ValueError):
    """Raised when the committed intel library fails validation (whole-store)."""


def _reject(reason: str) -> IntelStoreError:
    return IntelStoreError(f"invalid intel store: {reason}")


def _read_json(path: Path) -> object:
    if not path.is_file():
        raise _reject(f"missing file: {path.name}")
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise _reject(f"{path.name} exceeds {MAX_FILE_BYTES} bytes")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _reject(f"{path.name} is not valid JSON ({exc})") from exc


def _iso(value: object, context: str) -> str:
    if not isinstance(value, str):
        raise _reject(f"{context} must be an ISO date string")
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise _reject(f"{context} is not a valid ISO date: {value!r}") from exc
    return value


def _bounded_str(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_STRING:
        raise _reject(f"{context} must be a non-empty string of <= {MAX_STRING} chars")
    return value


def _str_tuple(value: object, context: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or len(value) > MAX_LIST
        or (not value and not allow_empty)
        or not all(isinstance(item, str) and 0 < len(item) <= MAX_STRING for item in value)
    ):
        raise _reject(f"{context} must be a list of <= {MAX_LIST} bounded strings")
    return tuple(value)


def _load_never_flag(path: Path) -> tuple[str, ...]:
    document = _read_json(path)
    if not isinstance(document, dict) or set(document) != {"cidrs"}:
        raise _reject("never_flag.json must carry exactly a 'cidrs' list")
    cidrs = document["cidrs"]
    if not isinstance(cidrs, list) or not cidrs:
        raise _reject("never_flag.json cidrs must be a non-empty list")
    for cidr in cidrs:
        try:
            ipaddress.ip_network(cidr)
        except ValueError as exc:
            raise _reject(f"never_flag cidr invalid: {cidr!r}") from exc
    return tuple(cidrs)


def never_flagged(value: str, never_flag: tuple[str, ...]) -> bool:
    """True when ``value`` is an IP address inside a never-flag CIDR."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(cidr) for cidr in never_flag)


def _load_sources(path: Path) -> dict[str, Source]:
    document = _read_json(path)
    if not isinstance(document, dict) or set(document) != {"sources"}:
        raise _reject("sources.json must carry exactly a 'sources' list")
    sources: dict[str, Source] = {}
    for raw in document["sources"]:
        if not isinstance(raw, dict) or set(raw) != _SOURCE_FIELDS:
            raise _reject(f"source must carry exactly {sorted(_SOURCE_FIELDS)}")
        source_id = _bounded_str(raw["source_id"], "source_id")
        if source_id in sources:
            raise _reject(f"duplicate source_id {source_id!r}")
        license_name = _bounded_str(raw["license"], f"source {source_id!r} license")
        if license_name not in ALLOWED_LICENSES:
            raise _reject(
                f"source {source_id!r} license {license_name!r} is not on the "
                f"allow-list {sorted(ALLOWED_LICENSES)}"
            )
        sources[source_id] = Source(
            source_id=source_id,
            name=_bounded_str(raw["name"], f"source {source_id!r} name"),
            url=_bounded_str(raw["url"], f"source {source_id!r} url"),
            license=license_name,
            upstream=_bounded_str(raw["upstream"], f"source {source_id!r} upstream"),
            retrieved=_iso(raw["retrieved"], f"source {source_id!r} retrieved"),
        )
    if not sources:
        raise _reject("sources.json declares no sources")
    return sources


def _parse_atomic(
    raw: object, sources: dict[str, Source], never_flag: tuple[str, ...]
) -> AtomicIndicator:
    if not isinstance(raw, dict) or set(raw) != _ATOMIC_FIELDS:
        raise _reject(f"atomic indicator must carry exactly {sorted(_ATOMIC_FIELDS)}")
    indicator_type = raw["type"]
    if indicator_type not in _ATOMIC_TYPES:
        raise _reject(f"unknown atomic type {indicator_type!r}")
    value = _bounded_str(raw["value"], "indicator value")
    context = f"indicator {value!r}"
    if raw["risk"] not in _RISKS:
        raise _reject(f"{context}: unknown risk {raw['risk']!r}")
    if raw["confidence"] not in _CONFIDENCES:
        raise _reject(f"{context}: unknown confidence {raw['confidence']!r}")
    source_id = raw["source_id"]
    if source_id not in sources:
        raise _reject(f"{context}: source {source_id!r} is not registered in sources.json")
    tlp = raw["tlp"]
    if tlp != "clear":
        raise _reject(
            f"{context}: TLP {tlp!r} refused — only TLP:CLEAR content may be committed "
            "(restricted markings cannot survive a public repo and tracked reports)"
        )
    first_seen = _iso(raw["first_seen"], f"{context} first_seen")
    retrieved = _iso(raw["retrieved"], f"{context} retrieved")
    expires = _iso(raw["expires"], f"{context} expires")
    if expires < first_seen:
        raise _reject(f"{context}: expires before first_seen")
    if indicator_type in ("ipv4", "ipv6"):
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError as exc:
            raise _reject(f"{context}: not a valid IP address") from exc
        if (parsed.version == 4) != (indicator_type == "ipv4"):
            raise _reject(f"{context}: IP version disagrees with declared type")
        if never_flagged(value, never_flag):
            raise _reject(
                f"{context}: inside a never-flag range — internal/reserved space "
                "must never enter the indicator store"
            )
    return AtomicIndicator(
        indicator_type=indicator_type,
        value=value.lower(),
        risk=raw["risk"],
        confidence=raw["confidence"],
        source_id=source_id,
        first_seen=first_seen,
        retrieved=retrieved,
        expires=expires,
        tlp=tlp,
        reference=_bounded_str(raw["reference"], f"{context} reference"),
    )


def _parse_behavior(raw: object, sources: dict[str, Source], corpus: Corpus) -> BehavioralRecord:
    if not isinstance(raw, dict) or set(raw) != _BEHAVIOR_FIELDS:
        raise _reject(f"behavioral record must carry exactly {sorted(_BEHAVIOR_FIELDS)}")
    record_id = _bounded_str(raw["id"], "behavior id")
    context = f"behavior {record_id!r}"
    techniques = _str_tuple(raw["attack_techniques"], f"{context} attack_techniques")
    for technique_id in techniques:
        try:
            verdict = validate_reference(technique_id, corpus)
        except AttackError as exc:
            raise _reject(f"{context}: {exc}") from exc
        if verdict.status == "unknown":
            raise _reject(f"{context}: {technique_id} does not exist in the pinned ATT&CK release")
        # deprecated/revoked anchors are accepted here and degrade the record
        # to stale-anchor at match time (see module docstring).
    source_id = raw["source_id"]
    if source_id not in sources:
        raise _reject(f"{context}: source {source_id!r} is not registered in sources.json")
    if raw["confidence"] not in _CONFIDENCES:
        raise _reject(f"{context}: unknown confidence {raw['confidence']!r}")
    interval = raw["review_interval_days"]
    if not isinstance(interval, int) or isinstance(interval, bool) or not 0 < interval <= 730:
        raise _reject(f"{context}: review_interval_days must be an integer in 1..730")
    return BehavioralRecord(
        record_id=record_id,
        title=_bounded_str(raw["title"], f"{context} title"),
        description=_bounded_str(raw["description"], f"{context} description"),
        attack_techniques=techniques,
        event_types=_str_tuple(raw["event_types"], f"{context} event_types"),
        markers=_str_tuple(raw["markers"], f"{context} markers"),
        false_positives=_str_tuple(raw["false_positives"], f"{context} false_positives"),
        confidence=raw["confidence"],
        source_id=source_id,
        last_reviewed=_iso(raw["last_reviewed"], f"{context} last_reviewed"),
        review_interval_days=interval,
    )


def load_store(intel_dir: Path | None = None, *, corpus: Corpus | None = None) -> IntelStore:
    """Load and validate the whole library. Any anomaly rejects everything."""
    directory = INTEL_DIR if intel_dir is None else intel_dir
    resolved_corpus = load_corpus() if corpus is None else corpus

    never_flag = _load_never_flag(directory / "never_flag.json")
    sources = _load_sources(directory / "sources.json")

    seed = _read_json(directory / "seed" / "indicators.json")
    if not isinstance(seed, dict) or set(seed) != {"indicators"}:
        raise _reject("seed/indicators.json must carry exactly an 'indicators' list")
    raw_indicators = seed["indicators"]
    if not isinstance(raw_indicators, list) or len(raw_indicators) > MAX_ATOMIC_RECORDS:
        raise _reject(f"indicators must be a list of <= {MAX_ATOMIC_RECORDS}")
    atomic: dict[str, AtomicIndicator] = {}
    for raw in raw_indicators:
        indicator = _parse_atomic(raw, sources, never_flag)
        key = f"{indicator.indicator_type}:{indicator.value}:{indicator.source_id}"
        if key in atomic:
            raise _reject(f"duplicate indicator {key!r}")
        atomic[key] = indicator

    behaviors: list[BehavioralRecord] = []
    seen_ids: set[str] = set()
    behavior_paths = sorted((directory / "behaviors").glob("*.json"))
    for path in behavior_paths:
        document = _read_json(path)
        if not isinstance(document, dict) or set(document) != {"behaviors"}:
            raise _reject(f"{path.name} must carry exactly a 'behaviors' list")
        for raw in document["behaviors"]:
            record = _parse_behavior(raw, sources, resolved_corpus)
            if record.record_id in seen_ids:
                raise _reject(f"duplicate behavior id {record.record_id!r}")
            seen_ids.add(record.record_id)
            behaviors.append(record)
    if len(behaviors) > MAX_BEHAVIOR_RECORDS:
        raise _reject(f"behavior records exceed {MAX_BEHAVIOR_RECORDS}")

    return IntelStore(
        sources=sources,
        atomic=atomic,
        behaviors=tuple(behaviors),
        never_flag=never_flag,
        attack_version=resolved_corpus.attack_version,
    )
