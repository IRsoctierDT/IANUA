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
``run_cycle`` itself refuses the same values, for a caller that is not the CLI.
"""

from __future__ import annotations

import json
import math
import time
from pathlib import Path

import pytest

from ingest import normalize
from pipeline import cursor_path, run_cycle
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


@pytest.mark.security
@pytest.mark.parametrize("value", [math.nan, math.inf], ids=["nan", "inf"])
def test_run_cycle_refuses_a_non_finite_lookback_as_the_cli_does(
    tmp_path: Path, value: float
) -> None:
    """The same refusal one layer down, for a caller that is not the CLI.

    ``run_cycle`` refused only ``lookback < 0``, so the CLI check above was the
    whole control. Measured through the function before the fix, with a cursor
    and ten new events inside the default window: ``nan`` correlated **10**
    against the default's **50**, the partitioning above with nothing in the
    result saying so. ``inf`` correlated 50 by accident, reading context from
    ``ingested_from=-inf``, which the store now refuses as a bound rather than
    reading it as "unset". Paired with acceptance on the same store.
    """
    root = tmp_path / "lab"
    root.mkdir()
    now = time.time()
    _seed(root, 0, 40, now)
    with EventStore.open(root) as store:
        cursor = run_cycle(store, batch=40).cursor
    assert cursor is not None, "the first cycle must advance"
    _seed(root, 40, 10, now + 100)

    with EventStore.open(root) as store:
        control = run_cycle(store, cursor=cursor, batch=40)
        assert control.events_read == 10
        assert control.events_correlated > control.events_read, control
        with pytest.raises(ValueError, match="lookback must be finite"):
            run_cycle(store, cursor=cursor, batch=40, lookback=value)
