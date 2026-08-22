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

from dataclasses import dataclass
from datetime import date
from typing import Any

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


def intel_status(*, as_of: date) -> LayerStatus:
    """Threat-intel library health: sources, live indicators, review debt."""
    try:
        from intel import load_store
        from intel.decay import FLOOR, decayed_score

        store = load_store()
    except Exception as exc:
        return LayerStatus("Threat-intel library", _badge(False), f"{_UNAVAILABLE}: {exc}")

    live = sum(1 for ind in store.atomic.values() if decayed_score(ind, as_of=as_of) >= FLOOR)
    expired = len(store.atomic) - live
    detail = (
        f"{len(store.sources)} sources · {len(store.behaviors)} behavioral records · "
        f"{live} live / {expired} decayed atomic indicators"
    )
    return LayerStatus("Threat-intel library", _badge(True, warn=expired > live), detail)


def behavior_status() -> LayerStatus:
    """Behavioral corpus health, with the telemetry-honesty split."""
    try:
        from agents.detection_matcher_agent import DetectionMatcherAgent

        entries = DetectionMatcherAgent()._load_behavior_index()
    except Exception as exc:
        return LayerStatus("Behavioral detections", _badge(False), f"{_UNAVAILABLE}: {exc}")
    if not entries:
        return LayerStatus(
            "Behavioral detections", _badge(False), f"{_UNAVAILABLE}: index empty or missing"
        )
    available = sum(1 for e in entries if e.get("validation") == "telemetry-available")
    required = len(entries) - available
    return LayerStatus(
        "Behavioral detections",
        _badge(True, warn=required > 0),
        f"{len(entries)} rules · {available} live · {required} awaiting telemetry",
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
        f"{len(catalogue)} catalogued actions · PLAN ONLY — IANUA executes nothing; "
        "every action is performed by a named human operator",
    )


def layer_rows(*, as_of: date) -> list[dict[str, str]]:
    """Headline table across every detection-intelligence layer."""
    return [
        status.as_row()
        for status in (
            ingest_status(),
            attack_corpus_status(as_of=as_of),
            mapping_status(),
            intel_status(as_of=as_of),
            behavior_status(),
            response_status(),
        )
    ]


def behavior_rows() -> list[dict[str, str]]:
    """One row per behavioral rule, telemetry status first."""
    try:
        from agents.detection_matcher_agent import DetectionMatcherAgent

        entries = DetectionMatcherAgent()._load_behavior_index()
    except Exception:
        return []
    rows = []
    for entry in sorted(entries, key=lambda e: (str(e.get("validation")), str(e.get("title")))):
        live = entry.get("validation") == "telemetry-available"
        rows.append(
            {
                "Telemetry": "✅ live" if live else "⏳ required",
                "Rule": str(entry.get("title", "")),
                "Level": str(entry.get("level", "")),
                "Techniques": ", ".join(str(t) for t in entry.get("techniques", [])),
                "File": str(entry.get("file", "")),
            }
        )
    return rows


def review_due_rows(*, as_of: date) -> list[dict[str, str]]:
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
    except Exception:
        return []
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
