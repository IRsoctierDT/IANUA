#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Report the platform's own service-level indicators (stage 9, self-monitoring).

Measures every objective in :mod:`sli` against durable state under the
lab-data root and prints the verdict. Read-only in the strongest sense
available here: it opens nothing outside the root, creates nothing inside it,
runs no subprocess, reaches no network, and appends to no audit chain.

    python scripts/report_sli.py --root /srv/ianua
    python scripts/report_sli.py --root /srv/ianua --json

**Exit codes.** ``0`` every objective met · ``1`` one or more breached or
unmeasurable · ``2`` bad arguments or configuration · ``3`` the policy bundle
refused the action.

``1`` for an unmeasurable indicator is the whole point and is the opposite of
the choice ``run_pipeline.py`` makes for "nothing new" (which exits ``0``,
because a quiet SOC is the common case and paging on it nightly is useless).
Here the common case is healthy and the exception is worth waking someone
for, so a monitor that could not read a signal must not be silent:
``DESIGN.md`` §11 records three signals that read healthy while the subsystem
behind them was not.

**Why it appends no audit record.** Every other scheduled CLI records its run
in a hash chain. This one deliberately does not. At the documented ``*/5``
cadence it would write more chain entries than everything else in the
platform combined, and ``audit-chains-intact`` is one of the objectives it
measures — a monitor whose own writes dominate the thing it monitors is
measuring itself. The policy decision is still enforced (``read_only``), just
not recorded; nothing is mutated, so there is no state change for a chain to
be evidence of.

**Scheduling.** A systemd timer or crontab entry alongside the others:

    */5 * * * *  cd /srv/ianua && /srv/ianua/.venv/bin/python \\
        scripts/report_sli.py --root /srv/ianua --caller soc-timer --json \\
        >> /srv/ianua/data/sli/report.log 2>&1

Create the directory once before scheduling it — the shell opens a redirect
before the program runs, and this CLI creates nothing, so a missing directory
makes the first firing die in the shell rather than in Python.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:  # script may run from anywhere
    sys.path.insert(0, str(REPO_ROOT))

from agents.policies import ActionClass, Principal, PrincipalError  # noqa: E402
from agents.policies.bundle import (  # noqa: E402
    DEFAULT_BUNDLE_PATH,
    PolicyBundleError,
    load_bundle,
)
from agents.tools.guarded import ToolBlockedError, enforce  # noqa: E402
from sli import measure  # noqa: E402
from store.paths import validated_root  # noqa: E402

ACTION_NAME = "report_sli"
#: Nothing existing is read outside the root, nothing is written anywhere, and
#: no network is reached. The same class ``scripts/run_backup.py`` carries for
#: a local copy of evidence, and for the same reason.
REPORT_CLASS: ActionClass = "read_only"


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        required=True,
        help="Lab-data root (absolute). The directory holding data/.",
    )
    parser.add_argument(
        "--caller",
        default="soc-operator",
        help="Principal recorded in the policy decision.",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=DEFAULT_BUNDLE_PATH,
        help="Policy bundle to enforce (default: the committed bundle).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the report as JSON on stdout instead of a human summary.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Measure every objective and report. See the module docstring for exits."""
    args = _parse_args(argv)

    try:
        # Absolute, existing, and not the filesystem root — the shared helper,
        # because four private copies of this check is how three stayed fixed
        # and one did not (DESIGN.md §11).
        args.root = validated_root(args.root, error=ValueError, what="--root")
        principal = Principal("sli", args.caller)
        engine = load_bundle(args.policy)
    except (PrincipalError, PolicyBundleError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        # ``audit=None``: see the module docstring on why this run is enforced
        # but not recorded.
        enforce(action_class=REPORT_CLASS, name=ACTION_NAME, engine=engine, actor=principal)
    except ToolBlockedError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3

    report = measure(args.root, now=time.time())

    if args.json:
        print(json.dumps(report.to_dict(), sort_keys=True))
    else:
        print(f"{'ok' if report.healthy else 'DEGRADED'}: {report.headline()}")
        for indicator in report.indicators:
            print(f"  {indicator.summary()}")

    return 0 if report.healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
