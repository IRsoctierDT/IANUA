# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Service-level indicators for the SOC platform itself.

The platform collects, stores and detects. This package answers whether it is
actually doing those things, from durable state under the lab-data root and
nothing else — no network, no subprocess, no clock of its own, and nothing
outside the root, not even a ``stat``.

    from pathlib import Path
    import time

    from sli import measure

    report = measure(Path("/srv/ianua"), now=time.time())
    print(report.headline())
    for indicator in report.indicators:
        print(indicator.summary())

**Why a separate package, and why it fails closed.** ``DESIGN.md`` §11
records three signals that read healthy while the subsystem behind them was
not — a maintenance job green on a log that was never there, an unnamed
``--root`` that becomes a shadow SOC, a lock failure that tracebacked past
its own documented exit code — and the sentence it ends on is the brief for
everything here: *an SLI computed over a signal that fails open measures
nothing*. So the status enum has three values rather than two, and only
``MET`` is healthy. An indicator that cannot be read is not a pass.

The targets live in :mod:`sli.objectives` as data, each with its derivation
recorded beside it, and each target whose number has a source in the
repository imports it rather than retyping it. One target was deliberately
*not* set: there is no documented backup cadence, so the backup objective
asks whether the platform is restorable at all and reports the newest
backup's age as detail for an operator to judge.

:mod:`compliance` summarises this as two controls, because a framework asks
both "is there monitoring" and "is it green" and a platform with none must not
report the same as a healthy one. ``AUD-02`` is automated and asserts the
monitoring is defined, derived and fail-closed. ``AUD-03`` is an expiring
*attestation* over the live verdict, and manual by necessity rather than by
preference: these objectives measure a running platform, a repository checkout
is not one, and an automated check would have been permanently red everywhere
the control suite runs. The gate on a deployed node is
``scripts/report_sli.py``'s exit code, which is non-zero for any objective
breached **or** unmeasurable.
"""

from __future__ import annotations

from sli.indicators import CHAIN_FILES, MEASURERS, Measurement
from sli.objectives import BY_ID, OBJECTIVES, Direction, Objective, Status
from sli.report import Indicator, SliReport, measure

__all__ = [
    "BY_ID",
    "CHAIN_FILES",
    "MEASURERS",
    "OBJECTIVES",
    "Direction",
    "Indicator",
    "Measurement",
    "Objective",
    "SliReport",
    "Status",
    "measure",
]
