#!/usr/bin/env python3
"""Render the Command Center status page for GitHub Pages.

The status page is a single, self-contained observability surface for the
platform: which components are operational, degraded, planned, or offline. It is
built **deterministically and offline** from one committed source of truth,
``docs/status.data.json``, so the published page can never silently diverge from
the repository's declared state.

Outputs (written into ``docs/`` for the Pages deploy):

* ``status.html`` — the human-facing dashboard (dark command-center theme).
* ``status.json`` — the same report as machine-readable JSON (for badges/tools).

Security considerations (AGENTS.md §5, §6.1):
    * **Input validation, fail-closed** — the source JSON is schema-checked;
      an unknown status value or a missing field raises rather than emitting a
      broken or misleading page.
    * **Output escaping (defense in depth)** — every dynamic string is passed
      through :func:`html.escape` before it reaches the HTML, so a component
      name or detail can never inject markup, even though the source is trusted
      and committed. Covered by ``tests/security/test_status_page_escaping.py``.
    * **No network, no untrusted input** — only local repository files are read;
      the version is taken from ``pyproject.toml`` (the release source of truth)
      and the timestamp from the committed data, so the build is reproducible.

Determinism: the page carries no wall-clock time. Its "as of" date comes from the
``as_of`` field in the data file, so re-running with unchanged inputs reproduces
byte-identical outputs — which is what the ``--check`` drift gate relies on.

Usage:
    # Regenerate docs/status.html and docs/status.json from the source data:
    python scripts/build_status_page.py

    # CI/pre-commit drift gate — exit non-zero if the committed outputs are
    # stale relative to the source data (no files written):
    python scripts/build_status_page.py --check

Exit codes: ``0`` success / in sync · ``1`` drift detected · ``2`` bad input.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
import tomllib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA = REPO_ROOT / "docs" / "status.data.json"
DEFAULT_HTML = REPO_ROOT / "docs" / "status.html"
DEFAULT_JSON = REPO_ROOT / "docs" / "status.json"
DEFAULT_PYPROJECT = REPO_ROOT / "pyproject.toml"


class Status(Enum):
    """Health of a component. The value is the token used in the source JSON."""

    OPERATIONAL = "operational"
    DEGRADED = "degraded"
    PLANNED = "planned"
    OFFLINE = "offline"

    @property
    def label(self) -> str:
        """Human-readable label for the status pill."""
        return {
            Status.OPERATIONAL: "Operational",
            Status.DEGRADED: "Degraded",
            Status.PLANNED: "Planned",
            Status.OFFLINE: "Offline",
        }[self]


@dataclass(frozen=True)
class Component:
    """A single tracked component and its current status."""

    name: str
    status: Status
    detail: str


@dataclass(frozen=True)
class Section:
    """A named group of related components (e.g. "AI Components")."""

    title: str
    components: tuple[Component, ...]


@dataclass(frozen=True)
class StatusReport:
    """The full status report rendered to the page."""

    title: str
    tagline: str
    version: str
    as_of: str
    sections: tuple[Section, ...]

    def tally(self) -> dict[Status, int]:
        """Count components by status, across all sections (all statuses keyed)."""
        counts = dict.fromkeys(Status, 0)
        for section in self.sections:
            for component in section.components:
                counts[component.status] += 1
        return counts


class StatusDataError(ValueError):
    """Raised when the source data is missing required fields or is malformed."""


def _require(mapping: object, key: str, context: str) -> object:
    """Return ``mapping[key]`` or fail closed with a precise message."""
    if not isinstance(mapping, dict):
        raise StatusDataError(f"{context}: expected an object, got {type(mapping).__name__}")
    if key not in mapping:
        raise StatusDataError(f"{context}: missing required field '{key}'")
    return mapping[key]


def _as_str(value: object, context: str) -> str:
    """Coerce a JSON value to ``str``, failing closed on the wrong type."""
    if not isinstance(value, str):
        raise StatusDataError(f"{context}: expected a string, got {type(value).__name__}")
    return value


def _parse_status(value: object, context: str) -> Status:
    """Map a status token to :class:`Status`, failing closed on unknown values."""
    token = _as_str(value, context)
    try:
        return Status(token)
    except ValueError:
        allowed = ", ".join(s.value for s in Status)
        raise StatusDataError(f"{context}: unknown status '{token}' (allowed: {allowed})") from None


def project_version(pyproject: Path = DEFAULT_PYPROJECT) -> str:
    """Read ``[project].version`` from ``pyproject.toml`` (the release source of truth)."""
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = data.get("project", {})
    version = project.get("version")
    if not isinstance(version, str):
        raise StatusDataError(f"{pyproject.name}: [project].version is missing or not a string")
    return version


def parse_report(data: object, *, version: str) -> StatusReport:
    """Validate a decoded JSON document into a :class:`StatusReport` (fail-closed)."""
    title = _as_str(_require(data, "title", "root"), "title")
    tagline = _as_str(_require(data, "tagline", "root"), "tagline")
    as_of = _as_str(_require(data, "as_of", "root"), "as_of")

    raw_sections = _require(data, "sections", "root")
    if not isinstance(raw_sections, list) or not raw_sections:
        raise StatusDataError("sections: expected a non-empty array")

    sections: list[Section] = []
    for i, raw_section in enumerate(raw_sections):
        ctx = f"sections[{i}]"
        s_title = _as_str(_require(raw_section, "title", ctx), f"{ctx}.title")
        raw_components = _require(raw_section, "components", ctx)
        if not isinstance(raw_components, list) or not raw_components:
            raise StatusDataError(f"{ctx}.components: expected a non-empty array")

        components: list[Component] = []
        for j, raw_component in enumerate(raw_components):
            cctx = f"{ctx}.components[{j}]"
            components.append(
                Component(
                    name=_as_str(_require(raw_component, "name", cctx), f"{cctx}.name"),
                    status=_parse_status(_require(raw_component, "status", cctx), f"{cctx}.status"),
                    detail=_as_str(_require(raw_component, "detail", cctx), f"{cctx}.detail"),
                )
            )
        sections.append(Section(title=s_title, components=tuple(components)))

    return StatusReport(
        title=title,
        tagline=tagline,
        version=version,
        as_of=as_of,
        sections=tuple(sections),
    )


def load_report(
    data_path: Path = DEFAULT_DATA,
    *,
    pyproject: Path = DEFAULT_PYPROJECT,
) -> StatusReport:
    """Load and validate the status report from disk (fail-closed on bad input)."""
    try:
        decoded = json.loads(data_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise StatusDataError(f"{data_path.name}: invalid JSON — {exc}") from exc
    return parse_report(decoded, version=project_version(pyproject))


def render_json(report: StatusReport) -> str:
    """Serialise the report to canonical (sorted, indented) JSON with a summary."""
    tally = report.tally()
    payload = {
        "title": report.title,
        "tagline": report.tagline,
        "version": report.version,
        "as_of": report.as_of,
        "summary": {status.value: tally[status] for status in Status},
        "sections": [
            {
                "title": section.title,
                "components": [
                    {
                        "name": component.name,
                        "status": component.status.value,
                        "detail": component.detail,
                    }
                    for component in section.components
                ],
            }
            for section in report.sections
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _summary_row(report: StatusReport) -> str:
    """Render the top-of-page tally of components by status."""
    tally = report.tally()
    cells = "".join(
        f'<div class="stat stat--{status.value}">'
        f'<span class="stat-num">{tally[status]}</span>'
        f'<span class="stat-label">{html.escape(status.label)}</span>'
        f"</div>"
        for status in Status
    )
    return f'<div class="summary">{cells}</div>'


def _component_row(component: Component) -> str:
    """Render one component row with an escaped name, pill, and detail."""
    name = html.escape(component.name)
    detail = html.escape(component.detail)
    status = component.status
    return (
        '<li class="row">'
        f'<span class="dot dot--{status.value}" aria-hidden="true"></span>'
        f'<span class="row-name">{name}</span>'
        f'<span class="pill pill--{status.value}">{html.escape(status.label)}</span>'
        f'<span class="row-detail">{detail}</span>'
        "</li>"
    )


def _section_block(section: Section) -> str:
    """Render a titled section with its component rows."""
    rows = "".join(_component_row(c) for c in section.components)
    return (
        '<section class="card">'
        f'<h2 class="card-title">{html.escape(section.title)}</h2>'
        f'<ul class="rows">{rows}</ul>'
        "</section>"
    )


# Page chrome. Kept inline so the artifact is self-contained; the palette mirrors
# docs/index.html (the SENTINEL command-center theme).
_STYLE = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0d11;--surface:rgba(255,255,255,.03);--border:rgba(255,255,255,.08);
  --text-0:#e6e9ee;--text-1:#aeb6c2;--text-2:#8b94a3;--text-3:#5b636f;
  --green:oklch(.74 .12 150);--amber:oklch(.80 .12 80);
  --blue:oklch(.70 .13 235);--red:oklch(.64 .17 25);
  --sans:'IBM Plex Sans',system-ui,sans-serif;--mono:'IBM Plex Mono',ui-monospace,monospace;
}
body{background:var(--bg);color:var(--text-0);font-family:var(--sans);
  -webkit-font-smoothing:antialiased;line-height:1.5;padding:48px 20px}
.wrap{max-width:900px;margin:0 auto}
.eyebrow{font:600 12px/1 var(--mono);letter-spacing:.14em;color:var(--blue);
  text-transform:uppercase}
h1{font-size:30px;font-weight:700;margin:12px 0 6px}
.tagline{color:var(--text-1);font-size:15px}
.meta{margin-top:10px;font:500 12px/1.6 var(--mono);color:var(--text-3)}
.meta a{color:var(--text-2)}
.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:28px 0}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:16px;text-align:center}
.stat-num{display:block;font:700 26px/1 var(--mono)}
.stat-label{display:block;margin-top:6px;font-size:12px;color:var(--text-2)}
.stat--operational .stat-num{color:var(--green)}
.stat--degraded .stat-num{color:var(--amber)}
.stat--planned .stat-num{color:var(--blue)}
.stat--offline .stat-num{color:var(--red)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:14px;
  padding:20px 22px;margin-bottom:16px}
.card-title{font:600 13px/1 var(--mono);letter-spacing:.08em;color:var(--text-1);
  text-transform:uppercase;margin-bottom:14px}
.rows{list-style:none}
.row{display:grid;grid-template-columns:14px minmax(0,1fr) auto;align-items:center;
  gap:10px 12px;padding:11px 0;border-top:1px solid var(--border)}
.row:first-child{border-top:0}
.row-name{font-weight:600;font-size:14px}
.row-detail{grid-column:2/4;color:var(--text-2);font-size:13px}
.dot{width:9px;height:9px;border-radius:50%}
.pill{justify-self:end;font:600 11px/1 var(--mono);letter-spacing:.04em;
  padding:5px 9px;border-radius:999px;white-space:nowrap}
.dot--operational{background:var(--green)}
.dot--degraded{background:var(--amber)}
.dot--planned{background:var(--blue)}
.dot--offline{background:var(--red)}
.pill--operational{color:var(--green);background:oklch(.74 .12 150/.13)}
.pill--degraded{color:var(--amber);background:oklch(.80 .12 80/.13)}
.pill--planned{color:var(--blue);background:oklch(.70 .13 235/.13)}
.pill--offline{color:var(--red);background:oklch(.64 .17 25/.13)}
.foot{margin-top:24px;color:var(--text-3);font-size:12px;text-align:center}
.foot a{color:var(--text-2)}
@media(max-width:560px){.summary{grid-template-columns:repeat(2,1fr)}
  .pill{justify-self:start}}
""".strip()


def render_html(report: StatusReport) -> str:
    """Render the full status page. Every dynamic value is HTML-escaped."""
    title = html.escape(report.title)
    tagline = html.escape(report.tagline)
    version = html.escape(report.version)
    as_of = html.escape(report.as_of)
    body = "".join(_section_block(section) for section in report.sections)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        f"<title>{title} · Status</title>\n"
        f'<meta name="description" content="{tagline}">\n'
        '<link rel="preconnect" href="https://fonts.googleapis.com">\n'
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n'
        '<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600'
        '&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">\n'
        f"<style>{_STYLE}</style>\n"
        "</head>\n<body>\n"
        '<main class="wrap">\n'
        '<p class="eyebrow">System Status</p>\n'
        f"<h1>{title}</h1>\n"
        f'<p class="tagline">{tagline}</p>\n'
        f'<p class="meta">Version {version} · as of {as_of} · '
        '<a href="./index.html">← command center</a></p>\n'
        f"{_summary_row(report)}\n"
        f"{body}\n"
        '<p class="foot">Generated deterministically from '
        "<code>docs/status.data.json</code> · no wall-clock, reproducible build.</p>\n"
        "</main>\n</body>\n</html>\n"
    )


def build(
    *,
    data_path: Path = DEFAULT_DATA,
    html_path: Path = DEFAULT_HTML,
    json_path: Path = DEFAULT_JSON,
    pyproject: Path = DEFAULT_PYPROJECT,
) -> StatusReport:
    """Regenerate the HTML and JSON outputs from the source data."""
    report = load_report(data_path, pyproject=pyproject)
    html_path.write_text(render_html(report), encoding="utf-8")
    json_path.write_text(render_json(report), encoding="utf-8")
    return report


def check(
    *,
    data_path: Path = DEFAULT_DATA,
    html_path: Path = DEFAULT_HTML,
    json_path: Path = DEFAULT_JSON,
    pyproject: Path = DEFAULT_PYPROJECT,
) -> list[str]:
    """Return drift messages if committed outputs are stale (empty = in sync)."""
    report = load_report(data_path, pyproject=pyproject)
    problems: list[str] = []
    for path, expected in ((html_path, render_html(report)), (json_path, render_json(report))):
        actual = path.read_text(encoding="utf-8") if path.is_file() else None
        if actual != expected:
            problems.append(f"{path.name} is stale — run `python scripts/build_status_page.py`")
    return problems


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA, help="Source status JSON.")
    parser.add_argument("--out-html", type=Path, default=DEFAULT_HTML, help="HTML output path.")
    parser.add_argument("--out-json", type=Path, default=DEFAULT_JSON, help="JSON output path.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify committed outputs are in sync with the source data; write nothing.",
    )
    args = parser.parse_args(argv)

    try:
        if args.check:
            problems = check(data_path=args.data, html_path=args.out_html, json_path=args.out_json)
            if problems:
                print("Status page has drifted from its source data:", file=sys.stderr)
                for msg in problems:
                    print(f"  {msg}", file=sys.stderr)
                return 1
            print("OK: status page is in sync with docs/status.data.json")
            return 0

        report = build(data_path=args.data, html_path=args.out_html, json_path=args.out_json)
    except StatusDataError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: not found: {exc}", file=sys.stderr)
        return 2

    total = sum(report.tally().values())
    print(f"Wrote {args.out_html.name} and {args.out_json.name} ({total} components).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
