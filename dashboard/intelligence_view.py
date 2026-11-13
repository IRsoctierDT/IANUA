# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Presentation helpers for the dashboard's Detection Intelligence tab.

Pure functions over the ``attack/``, ``intel/``, ``detections/behaviors/``,
and ``agents/response/`` layers, kept free of any Streamlit import so they are
unit-testable in isolation (the same posture as ``compliance_view``).

Two invariants shape everything here:

* **Fail soft, but never silently.** Each loader returns a render-ready
  structure; when a layer is unavailable the structure says so explicitly
  rather than rendering as empty-and-healthy. A missing corpus that looks
  like "no problems" is the failure mode this whole subsystem exists to
  prevent.
* **Staleness is the headline, not a footnote.** Corpus version distance,
  intel expiry, and behavioral review dates are surfaced as first-class
  status, because the credibility of an "ongoing" database rests on saying
  plainly when it has stopped being current.

The clock is always injected (``as_of``): these helpers stay deterministic
and unit-testable, matching the layers they read.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from agents.tools.behavior_runtime import load_behavioral_rules
from ingest.schema import NormalizedEvent
from intel import IntelStore

_UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class LayerStatus:
    """One headline row: a layer, its health, and why."""

    layer: str
    status: str
    detail: str

    def as_row(self) -> dict[str, str]:
        return {"Layer": self.layer, "Status": self.status, "Detail": self.detail}


def _badge(ok: bool, warn: bool = False) -> str:
    """Text-first badge — readable without color, matching compliance_view."""
    if warn:
        return "⚠️ attention"
    return "✅ current" if ok else "❌ unavailable"


def attack_corpus_status(*, as_of: date) -> LayerStatus:
    """Pinned ATT&CK corpus health: version, distance, tombstones."""
    try:
        from attack import freshness, load_corpus, load_pin

        pin = load_pin()
        corpus = load_corpus(pin=pin)
        report = freshness(today=as_of, pin=pin)
    except Exception as exc:
        return LayerStatus("ATT&CK corpus", _badge(False), f"{_UNAVAILABLE}: {exc}")

    signed = "signed pin" if pin.signature is not None else "unsigned pin"
    detail = (
        f"ATT&CK {corpus.attack_version} ({signed}) · {len(corpus.techniques)} techniques · "
        f"{len(corpus.tombstones)} tombstoned · latest known {report.latest_known_version}"
    )
    if report.version_distance:
        return LayerStatus(
            "ATT&CK corpus",
            _badge(False, warn=True),
            f"{report.version_distance} release(s) behind — {detail}",
        )
    return LayerStatus("ATT&CK corpus", _badge(True), detail)


def mapping_status() -> LayerStatus:
    """Event→technique ruleset health."""
    try:
        from agents.mapping import load_store

        store = load_store()
    except Exception as exc:
        return LayerStatus("Mapping ruleset", _badge(False), f"{_UNAVAILABLE}: {exc}")
    attributions = sum(len(rule.techniques) for rule in store.rules)
    return LayerStatus(
        "Mapping ruleset",
        _badge(True),
        f"{len(store.rules)} rules · {attributions} technique attributions · "
        f"validated against ATT&CK {store.attack_version}",
    )


def intel_status(*, as_of: date, local: IntelStore | None = None) -> LayerStatus:
    """Distinguish demo indicator aging from an operator-staged snapshot."""
    try:
        from intel import load_store
        from intel.decay import FLOOR, decayed_score

        store = load_store() if local is None else local
    except Exception as exc:
        return LayerStatus("Threat-intel library", _badge(False), f"{_UNAVAILABLE}: {exc}")

    live = sum(decayed_score(ind, as_of=as_of) >= FLOOR for ind in store.atomic.values())
    inactive = len(store.atomic) - live
    scope = "synthetic demo" if local is None else "pinned local snapshot"
    detail = (
        f"{len(store.sources)} registered sources · {len(store.behaviors)} behavioral records · "
        f"{live} current / {inactive} inactive atomic records ({scope})"
    )
    if local is None:
        return LayerStatus("Threat-intel library", "demo data", detail)
    return LayerStatus("Threat-intel library", _badge(True, warn=inactive > live), detail)


def intel_source_rows(*, as_of: date, local: IntelStore | None) -> list[dict[str, str | int]]:
    """Show snapshot provenance and distinguish expired, decayed and future records."""
    from intel import load_store
    from intel.decay import FLOOR, decayed_score

    try:
        store = load_store() if local is None else local
    except (ValueError, OSError):
        return []
    rows: dict[str, dict[str, str | int]] = {}
    for indicator in store.atomic.values():
        source = store.sources[indicator.source_id]
        row = rows.setdefault(
            source.source_id,
            {
                "Source": source.source_id,
                "Upstream": source.upstream,
                "License": source.license,
                "Source retrieved": source.retrieved,
                "Current": 0,
                "Expired": 0,
                "Decayed": 0,
                "Future-dated": 0,
            },
        )
        if as_of < date.fromisoformat(indicator.retrieved):
            status = "Future-dated"
        elif as_of > date.fromisoformat(indicator.expires):
            status = "Expired"
        elif decayed_score(indicator, as_of=as_of) < FLOOR:
            status = "Decayed"
        else:
            status = "Current"
        row[status] = int(row[status]) + 1
    return [rows[key] for key in sorted(rows)]


def behavior_status(observed: frozenset[str] = frozenset()) -> LayerStatus:
    """Separate executable coverage from recent sensor evidence."""
    try:
        catalog = load_behavioral_rules()
    except (ValueError, OSError):
        return LayerStatus("Behavioral detections", _badge(False), "rule index unavailable")
    total = len(catalog.rules)
    seen = sum(bool(observed.intersection(rule.signals)) for rule in catalog.rules)
    return LayerStatus(
        "Behavioral detections",
        _badge(True, warn=seen < total),
        f"{total} executable rules · {seen} with observed telemetry · "
        f"{total - seen} awaiting telemetry verification",
    )


def ingest_status() -> LayerStatus:
    """Multi-source coverage: which of the five domains can actually be read.

    Reported as domains covered rather than parsers written, because "ten
    parsers" says nothing about whether a defender is blind to cloud.
    """
    try:
        from ingest import SIGNATURES

        domains = {signature.source_type for signature in SIGNATURES}
    except Exception as exc:
        return LayerStatus("Telemetry ingest", _badge(False), f"{_UNAVAILABLE}: {exc}")
    expected = {"endpoint", "network", "cloud", "identity", "email"}
    missing = sorted(expected - domains)
    detail = (
        f"{len(SIGNATURES)} parsers across {len(domains & expected)}/5 domains "
        f"({', '.join(sorted(domains & expected))}) · unrecognized sources are "
        "labelled, never guessed"
    )
    if missing:
        return LayerStatus(
            "Telemetry ingest",
            _badge(False, warn=True),
            f"no parser for {', '.join(missing)} — {detail}",
        )
    return LayerStatus("Telemetry ingest", _badge(True), detail)


def response_status() -> LayerStatus:
    """Response layer: always plan-only. The status IS the guarantee."""
    try:
        from agents.response import load_catalogue

        catalogue = load_catalogue()
    except Exception as exc:
        return LayerStatus("Response layer", _badge(False), f"{_UNAVAILABLE}: {exc}")
    return LayerStatus(
        "Response layer",
        "📝 plan-only",
        f"{len(catalogue)} catalogued actions · PLAN ONLY — IANUA never executes a plan; "
        "every action is performed by a named human operator",
    )


def layer_rows(
    *,
    as_of: date,
    observed: frozenset[str] = frozenset(),
    local: IntelStore | None = None,
) -> list[dict[str, str]]:
    """Headline table across every detection-intelligence layer."""
    return [
        status.as_row()
        for status in (
            ingest_status(),
            attack_corpus_status(as_of=as_of),
            mapping_status(),
            intel_status(as_of=as_of, local=local),
            behavior_status(observed),
            response_status(),
        )
    ]


def behavior_rows(
    observed: frozenset[str] = frozenset(),
) -> list[dict[str, str]]:
    """Show runtime prerequisites for each rule and which signals were observed."""
    try:
        rules = load_behavioral_rules().rules
    except (ValueError, OSError):
        return []
    return [
        {
            "Telemetry": "Observed" if observed.intersection(rule.signals) else "Awaiting evidence",
            "Rule": rule.name,
            "Level": rule.level,
            "Techniques": ", ".join(rule.techniques),
            "Signals (any)": ", ".join(rule.signals),
        }
        for rule in sorted(
            rules, key=lambda rule: (not observed.intersection(rule.signals), rule.name)
        )
    ]


def behavior_evidence(
    events: Iterable[NormalizedEvent],
) -> tuple[frozenset[str], list[dict[str, str]]]:
    """Evaluate sampled endpoint events and return metadata-only evidence rows."""
    catalog = load_behavioral_rules()
    observed: set[str] = set()
    hits: list[dict[str, str]] = []
    for event in events:
        signals, matches = catalog.evaluate_event(event)
        observed.update(signals)
        for rule in matches:
            stamp = (
                datetime.fromtimestamp(event.timestamp, UTC).isoformat()
                if event.timestamp is not None and 0 <= event.timestamp <= 253402300799
                else "unavailable"
            )
            hits.append(
                {
                    "Rule": rule.name,
                    "Severity": rule.level,
                    "Source time (UTC)": stamp,
                    "ATT&CK": ", ".join(rule.techniques),
                    "Version": catalog.attack_version,
                }
            )
    return frozenset(observed), hits


def review_due_rows(*, as_of: date) -> list[dict[str, str]] | None:
    """Behavioral intel records whose human review interval has lapsed.

    This is the maintenance-debt view: an "ongoing" library that nobody
    re-reviews is stale whether or not anything looks broken, so the debt is
    surfaced rather than left to be discovered.
    """
    try:
        from attack import load_corpus
        from intel import load_store, match_behaviors

        store = load_store()
        corpus = load_corpus()
    except (ValueError, OSError):
        return None
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for record in store.behaviors:
        for event_type in record.event_types:
            for match in match_behaviors(store, event_type, corpus, as_of=as_of):
                if match.record.record_id in seen or match.status == "active":
                    continue
                seen.add(match.record.record_id)
                rows.append(
                    {
                        "Status": "⏰ review due"
                        if match.status == "review-due"
                        else "🔗 stale anchor",
                        "Record": match.record.title,
                        "Last reviewed": match.record.last_reviewed,
                        "Note": match.notes[0] if match.notes else "",
                    }
                )
    return rows


def response_plan_rows(response_plan: dict[str, Any] | None) -> list[dict[str, str]]:
    """Render a draft plan's actions, finality and ownership foremost."""
    if not response_plan:
        return []
    rows = []
    for action in response_plan.get("actions", []):
        rows.append(
            {
                "Tier": str(action.get("tier", "")),
                "Action": str(action.get("title", "")),
                "Target": str(action.get("target", "")),
                "Performed by": str(action.get("owner", "")),
                "Reversible": "yes" if action.get("reversible") else "⚠️ NO",
                "Rollback": str(action.get("rollback", "")),
            }
        )
    return rows
