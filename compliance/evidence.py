"""Evidence recording for compliance runs — tamper-evident and exportable.

Two artifacts per run, both under the gitignored ``data/compliance/``:

* ``evidence.jsonl`` — one JSON line per control result (the auditor-facing
  detail trail), written owner-only.
* ``audit.log`` — one summary event per run appended through the platform's
  hash-chained :class:`~agents.policies.audit.AuditLogger`, so a tampered or
  truncated evidence history is detectable via chain verification.

Security considerations:
- Records carry control ids, statuses, and short details only — never file
  contents, environment values, or secrets (AGENTS.md §5).
- All paths are validated to stay inside the repository's ``data/`` directory
  (fail closed on escape attempts).
- Files are created owner-read/write only, matching the audit logger's posture.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from agents.policies.audit import AuditLogger, VerificationReport, signing_key_from_env

from compliance.engine import ComplianceReport

_EVIDENCE_DIR = Path("data") / "compliance"
_EVIDENCE_FILE = "evidence.jsonl"
_AUDIT_FILE = "audit.log"
_FILE_MODE = 0o600
_MAX_TAIL_BYTES = 1_000_000


def _opener_owner_only(path: str, flags: int) -> int:
    return os.open(path, flags, _FILE_MODE)


@dataclass(frozen=True)
class EvidenceRecord:
    """One persisted control outcome."""

    recorded_at: str
    control_id: str
    title: str
    category: str
    severity: str
    status: str
    detail: str


def _evidence_dir(root: Path) -> Path:
    resolved = (root / _EVIDENCE_DIR).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError("evidence directory escapes repository root")
    return resolved


def _logger(root: Path, clock: Callable[[], str] | None) -> AuditLogger:
    return AuditLogger(
        _evidence_dir(root) / _AUDIT_FILE,
        clock=clock,
        signing_key=signing_key_from_env(),
    )


def record_run(
    report: ComplianceReport, *, root: Path, clock: Callable[[], str] | None = None
) -> tuple[EvidenceRecord, ...]:
    """Persist one evidence record per control and chain a run summary.

    Returns the records written. ``clock`` is injectable for deterministic
    tests and defaults to the report's own timestamp for the evidence lines.
    """
    directory = _evidence_dir(root)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    records = tuple(
        EvidenceRecord(
            recorded_at=report.generated_at,
            control_id=result.control.id,
            title=result.control.title,
            category=result.control.category.value,
            severity=result.control.severity.value,
            status=result.status.value,
            detail=result.detail,
        )
        for result in report.results
    )
    evidence_path = directory / _EVIDENCE_FILE
    with open(evidence_path, "a", encoding="utf-8", opener=_opener_owner_only) as fh:
        for record in records:
            fh.write(json.dumps(record.__dict__, sort_keys=True) + "\n")
    automated = len(report.automated)
    _logger(root, clock).record(
        actor="compliance-engine",
        action="compliance_run",
        action_class="read_only",
        decision="pass" if report.passing == automated else "attention",
        reason=f"{report.passing}/{automated} automated controls passing",
    )
    return records


def load_recent(root: Path, limit: int = 200) -> tuple[EvidenceRecord, ...]:
    """Return up to ``limit`` most recent evidence records (newest last).

    Malformed lines are skipped rather than trusted (fail closed on shape).
    """
    if limit <= 0:
        raise ValueError("limit must be positive")
    path = _evidence_dir(root) / _EVIDENCE_FILE
    if not path.is_file():
        return ()
    size = path.stat().st_size
    with path.open("rb") as fh:
        if size > _MAX_TAIL_BYTES:
            fh.seek(-_MAX_TAIL_BYTES, os.SEEK_END)
        raw = fh.read().decode("utf-8", errors="replace")
    records: list[EvidenceRecord] = []
    fields = set(EvidenceRecord.__dataclass_fields__)
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except ValueError:
            continue
        if not isinstance(data, dict) or set(data) != fields:
            continue
        records.append(EvidenceRecord(**{k: str(v) for k, v in data.items()}))
    return tuple(records[-limit:])


def verify_chain(root: Path) -> VerificationReport:
    """Verify the compliance audit chain (fail closed if it was tampered)."""
    return _logger(root, clock=None).verify_report()


def export_bundle(report: ComplianceReport, *, root: Path, dest: Path) -> Path:
    """Write an auditor-facing JSON bundle of the current run to ``dest``.

    ``dest`` must resolve inside the repository root (fail closed otherwise).
    Returns the written path.
    """
    resolved = dest.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError("export destination escapes repository root")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": report.generated_at,
        "score": report.score,
        "passing": report.passing,
        "automated_total": len(report.automated),
        "controls": [
            {
                "id": r.control.id,
                "title": r.control.title,
                "category": r.control.category.value,
                "severity": r.control.severity.value,
                "status": r.status.value,
                "detail": r.detail,
                "frameworks": sorted(
                    f"{ref.framework.value}: {ref.reference}" for ref in r.control.framework_refs
                ),
            }
            for r in report.results
        ],
        "framework_rollups": [
            {
                "framework": ru.framework.value,
                "passing": ru.passing,
                "total": ru.total,
                "percent": ru.percent,
            }
            for ru in report.framework_rollups()
        ],
        "disclaimer": (
            "Automated posture evidence generated by the IANUA compliance "
            "engine. Framework mappings are indicative and do not constitute "
            "an audit or certification."
        ),
    }
    with open(resolved, "w", encoding="utf-8", opener=_opener_owner_only) as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return resolved
