#!/usr/bin/env python3
"""Render the IANUA trust page for GitHub Pages (Vanta-style trust center).

Publishes a public-safe view of the platform's compliance posture: control
titles, statuses, and per-framework coverage — never check details, paths, or
environment facts. Like the status page, it is built **deterministically and
offline** from one committed source of truth, ``docs/trust.data.json``, so the
published page can never silently diverge from the repository's declared state.

Outputs (written into ``docs/`` for the human-gated Pages deploy):

* ``trust.html`` — the human-facing trust page (command-center theme).
* ``trust.json`` — the same data as machine-readable JSON.

Modes:
    # Refresh the committed snapshot from a live compliance-engine run
    # (the only step that reads the repository posture):
    python scripts/build_trust_page.py --snapshot

    # Regenerate docs/trust.html and docs/trust.json from the snapshot:
    python scripts/build_trust_page.py

    # CI/pre-commit drift gate — exit non-zero if committed outputs are stale
    # relative to the snapshot (no files written):
    python scripts/build_trust_page.py --check

Security considerations (AGENTS.md §5, §6.1):
    * **Public-safe by construction** — the snapshot schema has no field for
      check details; only ids, titles, categories, statuses, and framework
      tallies can reach the page.
    * **Input validation, fail-closed** — the snapshot is schema-checked; an
      unknown status or missing field raises rather than emitting a
      misleading page.
    * **Output escaping (defense in depth)** — every dynamic string passes
      through :func:`html.escape`; covered by
      ``tests/security/test_trust_page_escaping.py``.
    * **No network** — only local repository files are read.

Exit codes: ``0`` success / in sync · ``1`` drift detected · ``2`` bad input.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA = REPO_ROOT / "docs" / "trust.data.json"
DEFAULT_HTML = REPO_ROOT / "docs" / "trust.html"
DEFAULT_JSON = REPO_ROOT / "docs" / "trust.json"

_STATUSES = ("pass", "fail", "error", "manual")
_STATUS_LABELS = {"pass": "Passing", "fail": "Failing", "error": "Error", "manual": "Attestation"}
_DISCLAIMER = "Framework mappings are indicative — not an audit, certification, or legal advice."


class TrustDataError(ValueError):
    """Raised when the snapshot is missing required fields or is malformed."""


@dataclass(frozen=True)
class TrustControl:
    """One public-safe control row: no details, no paths, no environment."""

    id: str
    title: str
    category: str
    status: str


@dataclass(frozen=True)
class TrustFramework:
    """Coverage of one framework."""

    name: str
    passing: int
    total: int

    @property
    def percent(self) -> int:
        return 0 if self.total == 0 else round(100 * self.passing / self.total)


@dataclass(frozen=True)
class TrustReport:
    """The full trust snapshot rendered to the page."""

    as_of: str
    score: int
    controls: tuple[TrustControl, ...]
    frameworks: tuple[TrustFramework, ...]

    def tally(self) -> dict[str, int]:
        counts = dict.fromkeys(_STATUSES, 0)
        for control in self.controls:
            counts[control.status] += 1
        return counts


def _require(mapping: object, key: str, context: str) -> object:
    if not isinstance(mapping, dict):
        raise TrustDataError(f"{context}: expected an object, got {type(mapping).__name__}")
    if key not in mapping:
        raise TrustDataError(f"{context}: missing required field '{key}'")
    return mapping[key]


def _as_str(value: object, context: str) -> str:
    if not isinstance(value, str):
        raise TrustDataError(f"{context}: expected a string, got {type(value).__name__}")
    return value


def _as_int(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TrustDataError(f"{context}: expected an integer, got {type(value).__name__}")
    return value


def parse_report(data: object) -> TrustReport:
    """Validate a decoded JSON snapshot into a :class:`TrustReport` (fail-closed)."""
    as_of = _as_str(_require(data, "as_of", "root"), "as_of")
    score = _as_int(_require(data, "score", "root"), "score")
    if not 0 <= score <= 100:
        raise TrustDataError(f"score: expected 0..100, got {score}")

    raw_controls = _require(data, "controls", "root")
    if not isinstance(raw_controls, list) or not raw_controls:
        raise TrustDataError("controls: expected a non-empty array")
    controls: list[TrustControl] = []
    for i, raw in enumerate(raw_controls):
        ctx = f"controls[{i}]"
        status = _as_str(_require(raw, "status", ctx), f"{ctx}.status")
        if status not in _STATUSES:
            raise TrustDataError(
                f"{ctx}.status: unknown status '{status}' (allowed: {', '.join(_STATUSES)})"
            )
        controls.append(
            TrustControl(
                id=_as_str(_require(raw, "id", ctx), f"{ctx}.id"),
                title=_as_str(_require(raw, "title", ctx), f"{ctx}.title"),
                category=_as_str(_require(raw, "category", ctx), f"{ctx}.category"),
                status=status,
            )
        )

    raw_frameworks = _require(data, "frameworks", "root")
    if not isinstance(raw_frameworks, list):
        raise TrustDataError("frameworks: expected an array")
    frameworks: list[TrustFramework] = []
    for i, raw in enumerate(raw_frameworks):
        ctx = f"frameworks[{i}]"
        passing = _as_int(_require(raw, "passing", ctx), f"{ctx}.passing")
        total = _as_int(_require(raw, "total", ctx), f"{ctx}.total")
        if passing < 0 or total < 0 or passing > total:
            raise TrustDataError(f"{ctx}: passing/total out of range")
        frameworks.append(
            TrustFramework(
                name=_as_str(_require(raw, "name", ctx), f"{ctx}.name"),
                passing=passing,
                total=total,
            )
        )

    return TrustReport(
        as_of=as_of, score=score, controls=tuple(controls), frameworks=tuple(frameworks)
    )


def load_report(data_path: Path = DEFAULT_DATA) -> TrustReport:
    """Load and validate the snapshot from disk (fail-closed on bad input)."""
    try:
        decoded = json.loads(data_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TrustDataError(f"{data_path.name}: invalid JSON — {exc}") from exc
    return parse_report(decoded)


def snapshot(data_path: Path = DEFAULT_DATA, *, root: Path = REPO_ROOT) -> TrustReport:
    """Refresh the committed snapshot from a live compliance-engine run.

    The only mode that inspects the repository. Details are dropped here — the
    snapshot never carries them, so they cannot leak to the page.
    """
    if str(REPO_ROOT) not in sys.path:  # script may run from anywhere
        sys.path.insert(0, str(REPO_ROOT))
    from compliance.engine import run_controls

    report = run_controls(root)
    payload = {
        "as_of": report.generated_at[:10],
        "score": report.score,
        "controls": [
            {
                "id": r.control.id,
                "title": r.control.title,
                "category": r.control.category.value,
                "status": r.status.value,
            }
            for r in report.results
        ],
        "frameworks": [
            {"name": ru.framework.value, "passing": ru.passing, "total": ru.total}
            for ru in report.framework_rollups()
        ],
    }
    data_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return parse_report(payload)


def render_json(report: TrustReport) -> str:
    """Serialise the report to canonical JSON with a summary."""
    payload = {
        "as_of": report.as_of,
        "score": report.score,
        "summary": report.tally(),
        "controls": [
            {"id": c.id, "title": c.title, "category": c.category, "status": c.status}
            for c in report.controls
        ],
        "frameworks": [
            {"name": f.name, "passing": f.passing, "total": f.total, "percent": f.percent}
            for f in report.frameworks
        ],
        "disclaimer": _DISCLAIMER,
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


# Palette mirrors docs/status.html (SENTINEL command-center theme).
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
.stat--pass .stat-num{color:var(--green)}
.stat--fail .stat-num{color:var(--red)}
.stat--error .stat-num{color:var(--amber)}
.stat--manual .stat-num{color:var(--blue)}
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
.dot--pass{background:var(--green)}
.dot--fail{background:var(--red)}
.dot--error{background:var(--amber)}
.dot--manual{background:var(--blue)}
.pill--pass{color:var(--green);background:oklch(.74 .12 150/.13)}
.pill--fail{color:var(--red);background:oklch(.64 .17 25/.13)}
.pill--error{color:var(--amber);background:oklch(.80 .12 80/.13)}
.pill--manual{color:var(--blue);background:oklch(.70 .13 235/.13)}
.score{font:700 44px/1 var(--mono);color:var(--green)}
.bar{height:8px;border-radius:999px;background:var(--border);overflow:hidden;
  margin:8px 0 14px}
.bar-fill{height:100%;background:var(--green)}
.fw-name{font-weight:600;font-size:14px}
.fw-cov{float:right;font:500 12px/1.6 var(--mono);color:var(--text-2)}
.foot{margin-top:24px;color:var(--text-3);font-size:12px;text-align:center}
.foot a{color:var(--text-2)}
@media(max-width:560px){.summary{grid-template-columns:repeat(2,1fr)}
  .pill{justify-self:start}}
""".strip()


def _summary_row(report: TrustReport) -> str:
    tally = report.tally()
    cells = "".join(
        f'<div class="stat stat--{status}">'
        f'<span class="stat-num">{tally[status]}</span>'
        f'<span class="stat-label">{html.escape(_STATUS_LABELS[status])}</span>'
        f"</div>"
        for status in _STATUSES
    )
    return f'<div class="summary">{cells}</div>'


def _framework_block(report: TrustReport) -> str:
    if not report.frameworks:
        return ""
    bars = "".join(
        f'<div><span class="fw-name">{html.escape(fw.name)}</span>'
        f'<span class="fw-cov">{fw.passing}/{fw.total} · {fw.percent}%</span>'
        f'<div class="bar"><div class="bar-fill" style="width:{fw.percent}%"></div></div></div>'
        for fw in report.frameworks
    )
    return (
        '<section class="card"><h2 class="card-title">Framework coverage</h2>'
        f"{bars}"
        f'<p class="row-detail">{html.escape(_DISCLAIMER)}</p></section>'
    )


def _control_rows(report: TrustReport) -> str:
    categories: dict[str, list[TrustControl]] = {}
    for control in report.controls:
        categories.setdefault(control.category, []).append(control)
    blocks = []
    for category, controls in categories.items():
        rows = "".join(
            '<li class="row">'
            f'<span class="dot dot--{c.status}" aria-hidden="true"></span>'
            f'<span class="row-name">{html.escape(c.title)}</span>'
            f'<span class="pill pill--{c.status}">{html.escape(_STATUS_LABELS[c.status])}</span>'
            "</li>"
            for c in controls
        )
        blocks.append(
            '<section class="card">'
            f'<h2 class="card-title">{html.escape(category)}</h2>'
            f'<ul class="rows">{rows}</ul></section>'
        )
    return "".join(blocks)


def render_html(report: TrustReport) -> str:
    """Render the full trust page. Every dynamic value is HTML-escaped."""
    as_of = html.escape(report.as_of)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        "<title>IANUA · Trust</title>\n"
        '<meta name="description" content="Continuous security posture for the IANUA platform.">\n'
        '<link rel="preconnect" href="https://fonts.googleapis.com">\n'
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n'
        '<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600'
        '&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">\n'
        f"<style>{_STYLE}</style>\n"
        "</head>\n<body>\n"
        '<main class="wrap">\n'
        '<p class="eyebrow">Trust Center</p>\n'
        "<h1>IANUA</h1>\n"
        '<p class="tagline">Continuous, automated security-posture monitoring — '
        "controls evaluated against the platform itself.</p>\n"
        f'<p class="meta">Posture score <span class="score">{report.score}%</span> · '
        f"as of {as_of} · "
        '<a href="./status.html">system status</a> · '
        '<a href="./index.html">← command center</a></p>\n'
        f"{_summary_row(report)}\n"
        f"{_framework_block(report)}\n"
        f"{_control_rows(report)}\n"
        '<p class="foot">Generated deterministically from '
        "<code>docs/trust.data.json</code> · no wall-clock, reproducible build.</p>\n"
        "</main>\n</body>\n</html>\n"
    )


def build(
    *,
    data_path: Path = DEFAULT_DATA,
    html_path: Path = DEFAULT_HTML,
    json_path: Path = DEFAULT_JSON,
) -> TrustReport:
    """Regenerate the HTML and JSON outputs from the snapshot."""
    report = load_report(data_path)
    html_path.write_text(render_html(report), encoding="utf-8")
    json_path.write_text(render_json(report), encoding="utf-8")
    return report


def check(
    *,
    data_path: Path = DEFAULT_DATA,
    html_path: Path = DEFAULT_HTML,
    json_path: Path = DEFAULT_JSON,
) -> list[str]:
    """Return drift messages if committed outputs are stale (empty = in sync)."""
    report = load_report(data_path)
    problems: list[str] = []
    for path, expected in ((html_path, render_html(report)), (json_path, render_json(report))):
        actual = path.read_text(encoding="utf-8") if path.is_file() else None
        if actual != expected:
            problems.append(f"{path.name} is stale — run `python scripts/build_trust_page.py`")
    return problems


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA, help="Snapshot JSON path.")
    parser.add_argument("--out-html", type=Path, default=DEFAULT_HTML, help="HTML output path.")
    parser.add_argument("--out-json", type=Path, default=DEFAULT_JSON, help="JSON output path.")
    parser.add_argument(
        "--snapshot",
        action="store_true",
        help="Refresh the snapshot from a live compliance-engine run, then rebuild.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify committed outputs are in sync with the snapshot; write nothing.",
    )
    args = parser.parse_args(argv)

    try:
        if args.check:
            problems = check(data_path=args.data, html_path=args.out_html, json_path=args.out_json)
            if problems:
                print("Trust page has drifted from its snapshot:", file=sys.stderr)
                for msg in problems:
                    print(f"  {msg}", file=sys.stderr)
                return 1
            print("OK: trust page is in sync with docs/trust.data.json")
            return 0

        if args.snapshot:
            snapshot(args.data)
        report = build(data_path=args.data, html_path=args.out_html, json_path=args.out_json)
    except TrustDataError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: not found: {exc}", file=sys.stderr)
        return 2

    print(
        f"Wrote {args.out_html.name} and {args.out_json.name} "
        f"({len(report.controls)} controls, score {report.score}%)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
