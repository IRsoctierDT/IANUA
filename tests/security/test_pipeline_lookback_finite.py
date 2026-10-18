# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""A non-finite ``--lookback`` is a bad argument, not a silently partitioned stream.

``run_cycle`` gates its trailing-context read on ``lookback > 0``, which ``nan``
fails, so ``--lookback nan`` ran as ``--lookback 0``. Measured through the CLI
before the fix, with a cursor present and ten new events inside the default
window: the default correlated **50** events (10 new + 40 context) and ``nan``
correlated **10** — the partitioning the overlap exists to prevent, at exit 0,
``context_limited`` false, nothing in the output saying so. That is the failure
class the ``--batch`` cap already closed, reachable through a different flag.

The refusal is exit 2 before the gate records an attempt, and it is paired with
acceptance: the same root under the default lookback runs and correlates context.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from ingest import normalize
from pipeline import cursor_path
from scripts.run_pipeline import main as pipeline_main
from store import EventStore

_RECORD = 'type=USER_AUTH msg=audit(1760000000.1:1): acct="svc-%d" addr=203.0.113.9 res=failed'


def _seed(root: Path, start: int, count: int, base: float) -> None:
    with EventStore.open(root) as store:
        for index in range(start, start + count):
            store.append(normalize(_RECORD % index), ingested_at=store.next_stamp(base + index))


def _cycle(root: Path, *extra: str) -> int:
    return pipeline_main(["--root", str(root), "--caller", "test", "--json", *extra])


def _audit_lines(root: Path) -> int:
    log = cursor_path(root).parent / "audit.log"
    return len(log.read_text(encoding="utf-8").splitlines()) if log.exists() else 0


@pytest.mark.security
@pytest.mark.parametrize("value", ["nan", "inf"])
def test_a_non_finite_lookback_is_refused_before_the_gate(
    tmp_path: Path, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "lab"
    root.mkdir()
    now = time.time()
    _seed(root, 0, 40, now)
    assert _cycle(root) == 0, "the first cycle must run and advance the cursor"
    _seed(root, 40, 10, now + 100)  # ten more, inside the default 900 s lookback
    recorded = _audit_lines(root)
    capsys.readouterr()

    # Acceptance: the default window still correlates the context behind the cursor.
    assert _cycle(root, "--dry-run") == 0
    control = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert control["events_read"] == 10
    assert control["events_correlated"] > control["events_read"], control
    recorded = _audit_lines(root)

    # Refusal: a non-finite window is a bad argument, exit 2, nothing recorded.
    assert _cycle(root, "--dry-run", "--lookback", value) == 2
    err = capsys.readouterr().err
    assert "lookback must be finite" in err, err
    assert _audit_lines(root) == recorded, "a refused argument recorded a gate decision"
