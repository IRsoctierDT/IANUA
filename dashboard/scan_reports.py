"""Bounded, offline import and comparison of untrusted IANUA-Broker JSON reports.

Only display fields are retained. Strings remain untrusted plain text: callers must
use text/table widgets, never HTML or Markdown interpolation. Schema validation
cannot establish that uploaded text is redacted. Locations are labels, never read.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 12
MAX_STRING_LENGTH = 8192
MAX_COLLECTION_ITEMS = 5000
MAX_NODES = 100000
MAX_SERVERS = 200
MAX_FINDINGS = 5000
SEVERITIES = ("critical", "high", "medium", "low", "info")
DIMENSIONS = ("exposure", "credential", "tool_scope", "pinning")
GRADES = ("A", "B", "C", "D", "F")
Identity = tuple[str, str, str, int | None]
ChangeStatus = Literal["new", "resolved", "changed", "unchanged", "not observed"]


class ReportImportError(ValueError):
    """A rejected upload; messages never include uploaded values."""


@dataclass(frozen=True)
class Finding:
    """Allowlisted finding text; identity includes server and literal location."""

    server_id: str
    id: str
    path: str
    line: int | None
    title: str
    severity: str
    dimension: str
    rationale: str
    remediation: str

    @property
    def identity(self) -> Identity:
        """Return the stable tuple used for comparison, without dereferencing paths."""
        return (self.server_id, self.id, self.path, self.line)


@dataclass(frozen=True)
class ScanReport:
    """Immutable display projection; reported grades are not independently verified."""

    schema_version: str
    overall_grade: str
    generated_with_online: bool
    dimension_grades: tuple[tuple[str, str], ...]
    server_ids: tuple[str, ...]
    incomplete_server_ids: tuple[str, ...]
    findings: tuple[Finding, ...]

    @property
    def inspection_incomplete(self) -> bool:
        """Whether any reported server has an inspection gap."""
        return bool(self.incomplete_server_ids)


@dataclass(frozen=True)
class FindingChange:
    """Comparison observation; absence does not prove a vulnerability was fixed."""

    status: ChangeStatus
    finding: Finding
    previous: Finding | None = None


def _reject() -> None:
    raise ReportImportError("Report format or limits are invalid.")


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _reject()
        result[key] = value
    return result


def _constant(_value: str) -> object:
    _reject()
    return None


def _preflight(text: str) -> None:
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                _reject()
        elif char in "]}":
            depth -= 1
            if depth < 0:
                _reject()


def _validate_tree(root: object) -> None:
    pending = [root]
    count = 0
    while pending:
        node = pending.pop()
        count += 1
        if count > MAX_NODES:
            _reject()
        if isinstance(node, str):
            if len(node) > MAX_STRING_LENGTH or any(
                (ord(c) < 32 and c not in "\n\r\t") or 0xD800 <= ord(c) <= 0xDFFF for c in node
            ):
                _reject()
        elif isinstance(node, dict):
            if len(node) > MAX_COLLECTION_ITEMS:
                _reject()
            pending.extend(node.keys())
            pending.extend(node.values())
        elif isinstance(node, list):
            if len(node) > MAX_COLLECTION_ITEMS:
                _reject()
            pending.extend(node)
        elif isinstance(node, float) and not math.isfinite(node):
            _reject()


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        _reject()
        return {}
    return value


def _text(value: object, *, limit: int = MAX_STRING_LENGTH, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty) or len(value) > limit:
        _reject()
        return ""
    return value


def _choice(value: object, choices: tuple[str, ...]) -> str:
    text = _text(value)
    if text not in choices:
        _reject()
    return text


def _bool(value: object) -> bool:
    if type(value) is not bool:
        _reject()
    return bool(value)


def _integer(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _reject()
        return 0
    return value


def _list(value: object, maximum: int) -> list[object]:
    if not isinstance(value, list) or len(value) > maximum:
        _reject()
        return []
    return value


def _finding(value: object, server_id: str, schema: str) -> Finding:
    obj = _object(value)
    location = _object(obj.get("location"))
    line = location.get("line")
    if line is not None:
        line = _integer(line, 1, 2**31 - 1)
    if "secret" in obj:
        secret = _object(obj["secret"])
        if "masked" in secret:
            raise ReportImportError("Reports containing masked secrets are not accepted.")
        fingerprint = _text(secret.get("sha256_8"), limit=8)
        if len(fingerprint) != 8 or any(c not in "0123456789abcdef" for c in fingerprint):
            _reject()
        _integer(secret.get("length"), 0, 2**31 - 1)
    if "acceptance" in obj:
        if schema != "1.1":
            _reject()
        acceptance = _object(obj["acceptance"])
        for key in ("owner", "accepted", "expires", "reason"):
            _text(acceptance.get(key))
        _bool(acceptance.get("expired"))
    return Finding(
        server_id=server_id,
        id=_text(obj.get("id"), limit=256),
        path=_text(location.get("path"), limit=2048),
        line=line,
        title=_text(obj.get("title"), limit=1024),
        severity=_choice(obj.get("severity"), SEVERITIES),
        dimension=_choice(obj.get("dimension"), DIMENSIONS),
        rationale=_text(obj.get("rationale"), allow_empty=True),
        remediation=_text(obj.get("remediation"), allow_empty=True),
    )


def parse_report(data: bytes) -> ScanReport:
    """Import bounded UTF-8 JSON bytes; discard unknown fields and secret metadata.

    No files, URLs, processes, or clock are consulted. Duplicate keys and finding
    identities reject the whole upload; errors never quote source data.
    """
    if not isinstance(data, bytes) or not data or len(data) > MAX_REPORT_BYTES:
        _reject()
    try:
        text = data.decode("utf-8")
        _preflight(text)
        raw: object = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
        _validate_tree(raw)
        obj = _object(raw)
        if obj.get("tool") != "ianua-broker":
            _reject()
        schema = _choice(obj.get("schema_version"), ("1.0", "1.1"))
        grade = _choice(obj.get("overall_grade"), GRADES)
        online = _bool(obj.get("generated_with_online"))
        dimensions = _object(obj.get("dimension_grades"))
        if set(dimensions) != set(DIMENSIONS):
            _reject()
        grades = tuple((dim, _choice(dimensions[dim], GRADES)) for dim in DIMENSIONS)
        server_ids: list[str] = []
        incomplete_ids: list[str] = []
        findings: list[Finding] = []
        identities: set[Identity] = set()
        for value in _list(obj.get("servers"), MAX_SERVERS):
            server = _object(value)
            server_id = _text(server.get("id"), limit=256)
            if server_id in server_ids:
                _reject()
            server_ids.append(server_id)
            if _bool(server.get("inspection_incomplete")):
                incomplete_ids.append(server_id)
            _choice(server.get("state"), ("running", "declared"))
            _bool(server.get("running"))
            _choice(server.get("grade"), GRADES)
            if server.get("bind_addr") is not None:
                _text(server["bind_addr"], limit=256)
            if server.get("port") is not None:
                _integer(server["port"], 0, 65535)
            for entry in _list(server.get("findings"), MAX_FINDINGS):
                finding = _finding(entry, server_id, schema)
                if finding.identity in identities or len(findings) >= MAX_FINDINGS:
                    _reject()
                identities.add(finding.identity)
                findings.append(finding)
        return ScanReport(
            schema, grade, online, grades, tuple(server_ids), tuple(incomplete_ids), tuple(findings)
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError, OverflowError) as exc:
        if isinstance(exc, ReportImportError):
            raise ReportImportError(str(exc)) from None
        raise ReportImportError("Report format or limits are invalid.") from None


def compare_reports(baseline: ScanReport, current: ScanReport) -> tuple[FindingChange, ...]:
    """Compare stable identities; missing servers/gaps cannot establish resolution.

    Even 'resolved' means absent in these reports, not verified remediation; scan
    scope or detector changes cannot be established from this report schema.
    """
    old = {finding.identity: finding for finding in baseline.findings}
    new = {finding.identity: finding for finding in current.findings}
    changes: list[FindingChange] = []
    for finding in current.findings:
        previous = old.get(finding.identity)
        status: ChangeStatus
        if previous is None:
            status = (
                "not observed"
                if baseline.inspection_incomplete or finding.server_id not in baseline.server_ids
                else "new"
            )
        else:
            status = "unchanged" if previous == finding else "changed"
        changes.append(FindingChange(status, finding, previous))
    for finding in baseline.findings:
        if finding.identity not in new:
            status = (
                "not observed"
                if (current.inspection_incomplete or finding.server_id not in current.server_ids)
                else "resolved"
            )
            changes.append(FindingChange(status, finding, finding))
    return tuple(changes)


def filter_findings(
    report: ScanReport,
    *,
    severities: Iterable[str] = (),
    dimensions: Iterable[str] = (),
    query: str = "",
) -> tuple[Finding, ...]:
    """Filter display fields by literal, case-insensitive text; no regex execution."""
    selected_severities, selected_dimensions = set(severities), set(dimensions)
    needle = query[:MAX_STRING_LENGTH].casefold()
    return tuple(
        f
        for f in report.findings
        if (not selected_severities or f.severity in selected_severities)
        and (not selected_dimensions or f.dimension in selected_dimensions)
        and (
            not needle
            or needle
            in " ".join((f.server_id, f.id, f.title, f.path, f.rationale, f.remediation)).casefold()
        )
    )


def finding_rows(findings: Iterable[Finding]) -> list[dict[str, str | int | None]]:
    """Return allowlisted table cells, all text intended for plain-text rendering."""
    return [
        {
            "Server": f.server_id,
            "ID": f.id,
            "Severity": f.severity,
            "Dimension": f.dimension,
            "Title": f.title,
            "Path": f.path,
            "Line": f.line,
            "Rationale": f.rationale,
            "Remediation": f.remediation,
        }
        for f in findings
    ]
