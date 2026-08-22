"""Detection Matcher Agent — links triage to detection content.

Given a MITRE ATT&CK technique (the one the SOC Analyst / MITRE Mapper agents
emit), it returns the Sigma rules in ``detections/sigma/`` that cover that
technique. This closes the loop between *triage* (what happened) and *detection
engineering* (what alerts on it), using the shared ATT&CK vocabulary.

It also reports **behavioral** coverage from ``detections/behaviors/`` — the
post-compromise TTP corpus aimed at payloads already resident on a host. That
corpus is authored in YAML but consumed here through its committed JSON
projection (``detections/behaviors.index.json``, built and reference-gated by
``scripts/build_behavior_index.py``), so behavioral coverage is available with
stdlib ``json`` alone and never depends on PyYAML at runtime. Each behavioral
match carries its ``validation`` marker, so a rule whose telemetry this
platform does not yet ingest is reported as *aspirational coverage* rather
than silently counted as real.

Design (DESIGN.md §5):
- **Read-only, network-free, deterministic.** It only reads the local corpora
  and matches on technique tags.
- **Fails soft.** A missing corpus — or PyYAML not being installed — yields no
  matches rather than an error, so the agent pipeline degrades gracefully and the
  package keeps a dependency-free core.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, ClassVar

try:  # PyYAML ships with the dev/dashboard extras; core stays import-safe without it.
    import yaml
except ModuleNotFoundError:  # pragma: no cover - yaml is present in dev/CI
    yaml = None

DEFAULT_SIGMA_DIR = Path("detections/sigma")
DEFAULT_BEHAVIOR_INDEX = Path("detections/behaviors.index.json")

# Sigma severity order for ranking matches (most severe first).
_LEVEL_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}


@dataclass(frozen=True)
class DetectionMatch:
    """A Sigma rule that covers a given technique."""

    rule_id: str
    title: str
    level: str
    technique: str
    file: str


@dataclass(frozen=True)
class BehaviorMatch:
    """A behavioral rule covering a technique, with its telemetry honesty flag.

    ``validation`` is ``telemetry-available`` when this platform actually
    ingests the signal the rule needs, or ``telemetry-required`` when the rule
    replays green against fixtures but cannot fire in production until the
    sensor exists. Reporting it keeps aspirational coverage visibly
    aspirational instead of inflating a coverage claim.
    """

    rule_id: str
    title: str
    level: str
    technique: str
    validation: str
    file: str


class DetectionMatcherAgent:
    """Map a MITRE technique to the Sigma rules that detect it."""

    def __init__(
        self,
        sigma_dir: Path | str = DEFAULT_SIGMA_DIR,
        behavior_index: Path | str = DEFAULT_BEHAVIOR_INDEX,
    ) -> None:
        self.sigma_dir = Path(sigma_dir)
        self.behavior_index = Path(behavior_index)

    @staticmethod
    def _normalize(technique_id: str) -> str:
        """``"T1136.001"`` -> ``"t1136.001"`` to compare against Sigma tags."""
        return technique_id.strip().lower()

    def _load_rules(self) -> list[dict[str, Any]]:
        if yaml is None or not self.sigma_dir.is_dir():
            return []
        rules: list[dict[str, Any]] = []
        for path in sorted(self.sigma_dir.glob("*.yml")):
            try:
                parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError:
                continue
            if isinstance(parsed, dict):
                parsed["__file__"] = path.name
                rules.append(parsed)
        return rules

    def match_for_technique(self, technique_id: str) -> list[dict[str, Any]]:
        """Return Sigma rules whose ATT&CK tags include ``technique_id``.

        Matching is exact on the technique (e.g. ``T1110``). A rule tagged with a
        sub-technique (``t1136.001``) matches its parent query only if the parent
        id is supplied; callers pass whatever the MITRE Mapper emitted.
        """
        target = self._normalize(technique_id)
        if not target or target in {"unknown", "t"}:
            return []
        wanted = f"attack.{target}"

        matches: list[DetectionMatch] = []
        for rule in self._load_rules():
            tags = [str(t).lower() for t in rule.get("tags", [])]
            if wanted in tags:
                matches.append(
                    DetectionMatch(
                        rule_id=str(rule.get("id", "")),
                        title=str(rule.get("title", "")),
                        level=str(rule.get("level", "unknown")),
                        technique=technique_id.strip().upper(),
                        file=str(rule.get("__file__", "")),
                    )
                )
        # Most severe first; ties broken by title for a stable order.
        matches.sort(key=lambda m: (_LEVEL_RANK.get(m.level, 99), m.title))
        return [asdict(m) for m in matches]

    def match_for_event(self, mitre_result: dict[str, Any]) -> list[dict[str, Any]]:
        """Convenience: match using the ``technique_id`` from a MITRE result."""
        technique_id = mitre_result.get("technique_id")
        if not isinstance(technique_id, str):
            return []
        return self.match_for_technique(technique_id)

    # --------------------------------------------------- behavioral matching
    def _load_behavior_index(self) -> list[dict[str, Any]]:
        """Read the committed JSON projection (stdlib only; fails soft)."""
        if not self.behavior_index.is_file():
            return []
        try:
            document = json.loads(self.behavior_index.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        behaviors = document.get("behaviors") if isinstance(document, dict) else None
        return behaviors if isinstance(behaviors, list) else []

    def match_behaviors_for_technique(self, technique_id: str) -> list[dict[str, Any]]:
        """Behavioral rules covering ``technique_id``, most severe first.

        Matching is exact on the technique id, mirroring
        :meth:`match_for_technique`. Each result carries ``validation`` so a
        caller can distinguish coverage that can fire today from coverage
        waiting on telemetry.
        """
        target = self._normalize(technique_id)
        if not target or target in {"unknown", "t"}:
            return []
        wanted = target.upper()

        matches: list[BehaviorMatch] = []
        for entry in self._load_behavior_index():
            if not isinstance(entry, dict):
                continue
            techniques = entry.get("techniques", [])
            if not isinstance(techniques, list) or wanted not in techniques:
                continue
            matches.append(
                BehaviorMatch(
                    rule_id=str(entry.get("id", "")),
                    title=str(entry.get("title", "")),
                    level=str(entry.get("level", "unknown")),
                    technique=wanted,
                    validation=str(entry.get("validation", "unknown")),
                    file=str(entry.get("file", "")),
                )
            )
        matches.sort(key=lambda m: (_LEVEL_RANK.get(m.level, 99), m.title))
        return [asdict(m) for m in matches]

    def match_behaviors_for_event(self, mitre_result: dict[str, Any]) -> list[dict[str, Any]]:
        """Behavioral coverage across every technique a mapping result attributes.

        Uses the mapper's full ``techniques`` list when present (the
        multi-technique view) and falls back to the legacy scalar, so a
        secondary attribution can still surface its behavioral coverage.
        Deduplicated by rule id; deterministic order.
        """
        wanted: list[str] = []
        for attribution in mitre_result.get("techniques", []) or []:
            if isinstance(attribution, dict):
                technique_id = attribution.get("technique_id")
                if isinstance(technique_id, str):
                    wanted.append(technique_id)
        if not wanted:
            legacy = mitre_result.get("technique_id")
            if isinstance(legacy, str):
                wanted.append(legacy)

        seen: set[str] = set()
        combined: list[dict[str, Any]] = []
        for technique_id in wanted:
            for match in self.match_behaviors_for_technique(technique_id):
                key = match["rule_id"] or f"{match['file']}|{match['title']}"
                if key in seen:
                    continue
                seen.add(key)
                combined.append(match)
        combined.sort(key=lambda m: (_LEVEL_RANK.get(m["level"], 99), m["title"]))
        return combined

    # ------------------------------------------------- sequence-level matching
    # A multi-event finding is covered by multi-event detection content: only
    # Sigma *correlation* rules are eligible here, so a base rule that merely
    # shares the technique tag (e.g. a single failed-password rule for a
    # brute-force finding) is never presented as covering a sequence pattern.
    _SEQUENCE_PATTERN_TECHNIQUES: ClassVar[dict[str, tuple[str, ...]]] = {
        "brute_force": ("T1110",),
        "auth_failure_then_success": ("T1110", "T1078"),
        "arp_spoof_burst": ("T1557", "T1557.002"),
    }

    def match_for_finding(self, finding: dict[str, Any]) -> list[dict[str, Any]]:
        """Return Sigma **correlation** rules covering a correlated finding.

        ``finding`` is one entry of ``SequenceAnalysisResult.findings`` (from
        ``SocAnalystAgent.analyze_sequence``). Its ``pattern`` maps to the
        ATT&CK techniques that describe the behavior, and only rules with a
        ``correlation`` block whose tags include one of those techniques
        match. Unknown patterns yield no matches (fail soft, like the rest of
        this agent). Each match dict carries the ``pattern`` it covers.
        """
        pattern = finding.get("pattern")
        techniques = self._SEQUENCE_PATTERN_TECHNIQUES.get(str(pattern), ())
        if not techniques:
            return []
        wanted = {f"attack.{self._normalize(t)}" for t in techniques}

        matches: list[DetectionMatch] = []
        for rule in self._load_rules():
            if "correlation" not in rule:
                continue
            tags = {str(t).lower() for t in rule.get("tags", [])}
            hit = sorted(wanted & tags)
            if hit:
                matches.append(
                    DetectionMatch(
                        rule_id=str(rule.get("id", "")),
                        title=str(rule.get("title", "")),
                        level=str(rule.get("level", "unknown")),
                        technique=hit[0].removeprefix("attack.").upper(),
                        file=str(rule.get("__file__", "")),
                    )
                )
        matches.sort(key=lambda m: (_LEVEL_RANK.get(m.level, 99), m.title))
        return [{**asdict(m), "pattern": str(pattern)} for m in matches]

    def match_for_sequence(self, sequence_result: dict[str, Any]) -> list[dict[str, Any]]:
        """Match every correlated finding of a sequence analysis, deduplicated.

        Aggregates ``match_for_finding`` across ``sequence_result["findings"]``;
        a rule covering several findings appears once (first pattern wins —
        findings arrive in the analyzer's deterministic order). The overall
        list is ranked most-severe first, then by title, so callers can render
        it directly.
        """
        seen: set[str] = set()
        combined: list[dict[str, Any]] = []
        for finding in sequence_result.get("findings", []):
            if not isinstance(finding, dict):
                continue
            for match in self.match_for_finding(finding):
                key = match["rule_id"] or f"{match['file']}|{match['title']}"
                if key in seen:
                    continue
                seen.add(key)
                combined.append(match)
        combined.sort(key=lambda m: (_LEVEL_RANK.get(m["level"], 99), m["title"]))
        return combined


if __name__ == "__main__":
    import json

    agent = DetectionMatcherAgent()
    print(json.dumps(agent.match_for_technique("T1110"), indent=2))
