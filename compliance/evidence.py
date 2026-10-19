# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

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
- :func:`record_run` reaches ``data/compliance`` by descriptor, one component
  at a time with ``O_NOFOLLOW``, so a symlink at ``data`` or
  ``data/compliance`` is refused (even one pointing back inside the root) and
  ``evidence.jsonl`` is appended in the directory that was checked, whatever
  is swapped in afterwards. Any entry of that directory that is a symlink or
  not a regular file is refused before anything is written — every name, not
  a list, because the chain writes sidecars of its own: measured before this,
  a link at ``audit.log``, ``audit.log.lock`` or ``.audit.log.sig.tmp`` each
  carried a write out of the root with no error (the last truncating its
  target), as one at ``evidence.jsonl`` had before it was refused by name.
- **Residual, stated rather than implied:** the chain record is written by
  :class:`~agents.policies.audit.AuditLogger`, which opens by *path* with no
  ``O_NOFOLLOW``. The scan and a check that the path still reaches the walked
  directory are repeated immediately before it, which narrows the window and
  does not close it: an actor with write access to ``data/`` or
  ``data/compliance`` who swaps in a link inside the logger's own call still
  redirects the chain record (measured). Closing that needs ``dir_fd`` support
  in ``agents/policies/audit.py``, which serves every chain on the platform.
  Hard links are not refused (an operator's snapshot tool may make them).
- :func:`verify_chain` checks by path when called (a point-in-time check,
  not a walk): it fails a linked ``audit.log`` and raises on a linked
  ``data`` or ``data/compliance``. :func:`load_recent` confines the directory
  by ``resolve()`` and does not refuse a link at ``evidence.jsonl``;
  :func:`export_bundle` confines its destination by ``resolve()`` and refuses
  a link at the final component only.
- Files are created owner-read/write only, matching the audit logger's posture.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from agents.policies.audit import (
    AuditLogger,
    VerificationReport,
    signer_from_env,
    verifier_from_env,
)
from compliance.engine import ComplianceReport

_EVIDENCE_DIR = Path("data") / "compliance"
_EVIDENCE_FILE = "evidence.jsonl"
_AUDIT_FILE = "audit.log"
_FILE_MODE = 0o600
_MAX_TAIL_BYTES = 1_000_000


def _opener_owner_only(path: str, flags: int) -> int:
    """``open()`` opener: files are created 0o600, and a symlink at the final
    component is not followed (``ELOOP``). The directory components are not
    covered; :func:`export_bundle` confines them by ``resolve()`` alone."""
    return os.open(path, flags | os.O_NOFOLLOW, _FILE_MODE)


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


def _open_evidence_dir(root: Path) -> int:
    """Open ``data/compliance`` as a descriptor, refusing a link at any component.

    Each component is created if missing (``data`` at the umask, the leaf
    ``0o700``, as ``mkdir(parents=True)`` did) and opened relative to its
    parent's descriptor with ``O_NOFOLLOW``. The root is the operator's
    argument and is followed. Raises ``ValueError`` on a symlinked or
    non-directory component; the caller closes the returned descriptor.
    """
    fd = os.open(root.resolve(), os.O_RDONLY | os.O_DIRECTORY)
    walked = Path()
    try:
        for part in _EVIDENCE_DIR.parts:
            walked /= part
            with contextlib.suppress(FileExistsError):
                os.mkdir(part, 0o700 if walked == _EVIDENCE_DIR else 0o777, dir_fd=fd)
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError as exc:
                if exc.errno not in (errno.ELOOP, errno.ENOTDIR):
                    raise
                raise ValueError(
                    f"{walked} is a symlink or not a directory; refusing to write evidence "
                    "through it"
                ) from exc
            os.close(fd)
            fd = child
    except BaseException:
        os.close(fd)
        raise
    return fd


def _confirm_chain_path(root: Path, directory_fd: int) -> Path:
    """Return the chain's path once it is shown to lead into ``directory_fd``.

    Refuses any entry of the directory that is a symlink or not a regular
    file, and refuses a path that no longer reaches the walked directory
    (compared by device and inode). Point-in-time: see the module docstring.
    """
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                raise ValueError(
                    f"{_EVIDENCE_DIR / entry.name} is a symlink or not a regular file; "
                    "refusing to write evidence beside it"
                )
    directory = _evidence_dir(root)
    walked, current = os.fstat(directory_fd), directory.stat()
    if (walked.st_dev, walked.st_ino) != (current.st_dev, current.st_ino):
        raise ValueError(f"{_EVIDENCE_DIR} no longer leads to the checked directory; refusing")
    return directory / _AUDIT_FILE


def _logger(chain: Path, clock: Callable[[], str] | None) -> AuditLogger:
    return AuditLogger(chain, clock=clock, signer=signer_from_env())


def record_run(
    report: ComplianceReport, *, root: Path, clock: Callable[[], str] | None = None
) -> tuple[EvidenceRecord, ...]:
    """Persist one evidence record per control and chain a run summary.

    Returns the records written. ``clock`` is injectable for deterministic
    tests and defaults to the report's own timestamp for the evidence lines.
    """
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
    directory_fd = _open_evidence_dir(root)
    try:
        _confirm_chain_path(root, directory_fd)  # before anything is written
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
        evidence_fd = os.open(_EVIDENCE_FILE, flags, _FILE_MODE, dir_fd=directory_fd)
        with os.fdopen(evidence_fd, "a", encoding="utf-8") as fh:
            for record in records:
                fh.write(json.dumps(record.__dict__, sort_keys=True) + "\n")
        # Again, immediately before the logger opens the chain by path.
        chain = _confirm_chain_path(root, directory_fd)
    finally:
        os.close(directory_fd)
    automated = len(report.automated)
    # ``automated and`` because ``0 == 0``: a run that evaluated no automated
    # control chained ``decision=pass`` with the reason "0/0 automated controls
    # passing" — measured — which is the empty-conjunction shape ``sli`` and
    # ``ComplianceReport.score`` (0 for no controls) both already refuse. A
    # chain record is what an auditor reads; it must not attest to a pass
    # nothing was measured for.
    _logger(chain, clock).record(
        actor="compliance-engine",
        action="compliance_run",
        action_class="read_only",
        decision="pass" if automated and report.passing == automated else "attention",
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


def _reader(root: Path) -> AuditLogger:
    """A read-only view of the chain, resolving the *verifier* scheme.

    Separate from :func:`_logger`, which writes through ``signer_from_env``: a
    writer needs a key that can sign and :class:`Ed25519Verifier` cannot, so the
    two cannot share one resolution. Reading through the HMAC-only
    ``signing_key_from_env`` reported an Ed25519
    chain as ``unsigned`` — the same defect ``scripts.audit_maintenance`` was
    fixed for, surviving here because nothing checked that every reader agreed.
    """
    return AuditLogger(_evidence_dir(root) / _AUDIT_FILE, signer=verifier_from_env())


def verify_chain(root: Path) -> VerificationReport:
    """Verify the compliance audit chain (fail closed if it was tampered).

    A symlink at ``audit.log`` is a failed verification that names it. The
    logger does not read a linked segment, so without this such a chain read
    ``intact=True, entries=0`` — measured with the link aimed at another chain
    holding a genuine entry, the shape a redirected chain write leaves. A
    symlink at ``data`` or ``data/compliance`` raises ``ValueError``, as
    :func:`record_run` does, rather than verifying whatever it points at.
    """
    walked = root
    for part in _EVIDENCE_DIR.parts:
        walked /= part
        if walked.is_symlink():
            raise ValueError(
                f"{walked.relative_to(root)} is a symlink; refusing to verify through it"
            )
    report = _reader(root).verify_report()
    if (_evidence_dir(root) / _AUDIT_FILE).is_symlink():
        failure = (
            f"{_EVIDENCE_DIR / _AUDIT_FILE} is a symlink; the chain is not where it is believed"
        )
        return replace(report, intact=False, failure=failure)
    return report


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
