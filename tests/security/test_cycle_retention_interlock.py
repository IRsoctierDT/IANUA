# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The detection cycle and the retention pass must not aim at the same rows.

``scripts/run_retention.py`` clamps its threshold to the pipeline cursor, so a
pass deletes only *processed* events. ``pipeline/cycle.py``'s lookback exists to
re-read *processed* events as correlation context. Nobody noticed those were the
same rows until it was measured, and the measurement needed no concurrency, no
unusual flag and no short window: a story straddling the 90-day boundary was
reported by the cycle at score 52 across three domains before the documented
retention pass and at **score 30 across two** after it.

That shape is what makes it a security test rather than a correctness one. The
pass does not crash, does not exit non-zero and does not report a loss — the
incident an analyst reads is still an incident, with a lower score and one
domain missing, which is indistinguishable from a quieter attack. AGENTS.md §3
requires auditability of security-relevant actions, and DESIGN.md §5 boundary 13
refuses a blind spot that reports success.

**On the framing this replaced.** The defect was first written down as "retention
and the cycle take different locks, so a prune can run mid-cycle" — a mutual
exclusion problem. Measured, that framing is wrong: driving the prune
deterministically between the cycle's two queries produced the *same* score-30
outcome as running the two passes strictly one after the other, because the row
is gone either way. A lock would have serialised the passes and changed nothing.
The fix is therefore data disjointness — retention leaves ``--lookback-margin``
seconds of processed history behind the cursor — and :func:`test_a_prune_driven_mid_cycle_cannot_narrow_the_window`
is what stands in for the lock that is deliberately not being added.
"""

from __future__ import annotations

import io
import json
import time
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest

from ingest import normalize
from pipeline import cursor_path, load_cursor, run_cycle
from store import EventStore, Query

_DAY = 86_400.0

# The same three-domain story the pipeline suite uses, kept identical so a
# parser change breaks both files together rather than quietly making this one
# assemble nothing.
_CLOUD = {
    "eventVersion": "1.08",
    "eventSource": "sts.amazonaws.com",
    "eventName": "AssumeRole",
    "eventTime": "2026-10-14T01:00:00Z",
    "awsRegion": "us-east-1",
    "recipientAccountId": "1",
    "userIdentity": {"type": "IAMUser", "userName": "svc-deploy"},
    "sourceIPAddress": "198.51.100.7",
    "eventID": "e1",
}
_IDENTITY = {
    "userPrincipalName": "svc-deploy@corp.example",
    "ipAddress": "198.51.100.7",
    "createdDateTime": "2026-10-14T01:05:00Z",
    "id": "e2",
    "appDisplayName": "Portal",
    "status": {"errorCode": 0},
    "userDisplayName": "Svc Deploy",
}
_ENDPOINT = {"type": "SYSCALL", "node": "web-01", "auid": "svc-deploy", "comm": "bash"}
# Keeps the store's high-water mark recent, so the forward-clock-step refusal
# (a 200-day window reaching past every stored event) does not fire instead.
_UNRELATED = {"type": "SYSCALL", "node": "web-99", "auid": "someone-else", "comm": "sh"}


def _pipeline_main() -> Any:
    from scripts.run_pipeline import main

    return main


def _retention_main() -> Any:
    from scripts.run_retention import main

    return main


def _grant(tmp_path: Path, *labels: str) -> Path:
    """The committed bundle with exactly ``labels`` allowed."""
    repo_root = Path(__file__).resolve().parents[2]
    bundle = json.loads(
        (repo_root / "agents" / "policies" / "policy.json").read_text(encoding="utf-8")
    )
    bundle["allow"] = list(labels)
    path = tmp_path / f"granted-{'-'.join(labels) or 'none'}.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return path


def _run(main: Any, argv: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(out):
        code = main(argv)
    return code, out.getvalue()


def _straddle_the_boundary(root: Path) -> None:
    """A three-step story spanning the 90-day retention boundary.

    All three steps sit inside one default 900s lookback, so the cycle can
    assemble them; two of them sit *past* the 90-day window, so a default
    retention pass matches them. That overlap is the whole point: the window
    boundary is an instant, and events fifteen minutes apart straddle it.
    """
    boundary = time.time() - 90 * _DAY
    for record, at in (
        (_CLOUD, boundary - 600.0),
        (_IDENTITY, boundary - 300.0),
        (_ENDPOINT, boundary + 300.0),
        (_UNRELATED, time.time() - 60.0),
    ):
        with EventStore.open(root) as store:
            store.append_many((normalize(record),), ingested_at=at)


def _best_score(payload: dict[str, Any]) -> int | None:
    return max((int(i["score"]) for i in payload["incidents"]), default=None)


def _cycle(root: Path, *extra: str) -> dict[str, Any]:
    code, out = _run(_pipeline_main(), ["--root", str(root), "--json", *extra])
    assert code == 0, f"the cycle exited {code}: {out}"
    return dict(json.loads(out.strip()))


@pytest.mark.security
def test_a_default_retention_pass_cannot_degrade_an_incident_mid_story(tmp_path: Path) -> None:
    """The reproduction, turned into a regression test. Every flag defaulted.

    Two documented timer firings with the documented retention pass between
    them. Before the margin the second firing reported score 30 over two
    domains; the control below shows the undisturbed answer is 52 over three.
    """
    root = tmp_path / "root"
    root.mkdir()
    _straddle_the_boundary(root)

    first = _cycle(root, "--batch", "2")
    assert first["events_read"] == 2, f"the fixture did not consume the context: {first}"

    code, out = _run(
        _retention_main(),
        ["--root", str(root), "--apply", "--policy", str(_grant(tmp_path, "retain_events:apply"))],
    )
    assert code == 0, f"the retention pass exited {code}: {out}"

    second = _cycle(root, "--batch", "10")
    best = _best_score(second)
    assert best == 52, (
        f"the retention pass degraded the incident to score {best}; the "
        f"correlation window was narrowed under it ({second['events_correlated']} correlated)"
    )
    assert second["incidents"], "the story was lost entirely"
    assert sorted(second["incidents"][0]["domains"]) == ["cloud", "endpoint", "identity"]


@pytest.mark.security
def test_the_undisturbed_control_reports_the_same_incident(tmp_path: Path) -> None:
    """No retention pass at all. Pins what "undegraded" is worth.

    Without this the test above could pass because the fixture never produced
    a score-52 incident in the first place.
    """
    root = tmp_path / "root"
    root.mkdir()
    _straddle_the_boundary(root)
    _cycle(root, "--batch", "2")
    second = _cycle(root, "--batch", "10")
    assert _best_score(second) == 52, f"the fixture's own answer is not 52: {second}"


@pytest.mark.security
def test_a_zero_margin_still_degrades_it(tmp_path: Path) -> None:
    """The counter-test, and the one that makes the other two mean something.

    ``--lookback-margin 0`` is the documented way back to pruning right up to
    the cursor. It must still produce the damage, or the margin is not what the
    regression test above is measuring.
    """
    root = tmp_path / "root"
    root.mkdir()
    _straddle_the_boundary(root)
    _cycle(root, "--batch", "2")

    code, out = _run(
        _retention_main(),
        [
            "--root",
            str(root),
            "--apply",
            "--lookback-margin",
            "0",
            "--policy",
            str(_grant(tmp_path, "retain_events:apply")),
        ],
    )
    assert code == 0, f"the retention pass exited {code}: {out}"

    second = _cycle(root, "--batch", "10")
    best = _best_score(second)
    assert best != 52, (
        "a zero margin pruned to the cursor and the incident was still whole; "
        "the margin is then not the control these tests claim it is"
    )
    assert best == 30, (
        f"expected the measured two-domain degradation (score 30), got {best}: "
        "the fixture may no longer straddle the boundary"
    )


@pytest.mark.security
def test_a_prune_driven_mid_cycle_cannot_narrow_the_window(tmp_path: Path) -> None:
    """What stands in for the lock that is deliberately not added.

    The interleaving is **deterministic, not probabilistic**: the prune is
    driven between the cycle's progress read and its context read, which is the
    worst case a lock would have been there to prevent. With the margin the two
    passes touch disjoint rows, so serialising them is unnecessary — and this
    asserts that, rather than asserting a lock exists.

    The proxy is duck-typed because ``EventStore`` is slotted and the instance
    cannot be patched; ``run_cycle`` only ever calls ``.query``.
    """
    grant = _grant(tmp_path, "retain_events:apply")

    def interleaved(root: Path, *margin: str) -> tuple[int | None, int, int]:
        """Drive a prune between the cycle's two reads; return what survived.

        Returns ``(best score, events correlated, reads observed)``.
        """
        _straddle_the_boundary(root)
        _cycle(root, "--batch", "2")
        cursor = load_cursor(cursor_path(root))
        assert cursor is not None
        reads = 0
        ran = ""

        class Interleaving:
            """Runs a full retention pass between the cycle's two reads."""

            def __init__(self, inner: EventStore) -> None:
                self._inner = inner

            def query(self, spec: Query) -> Any:
                nonlocal reads, ran
                reads += 1
                rows = self._inner.query(spec)
                if reads == 1:
                    code, out = _run(
                        _retention_main(),
                        [
                            "--root",
                            str(root),
                            "--apply",
                            *margin,
                            "--policy",
                            str(grant),
                        ],
                    )
                    ran = f"exit {code}: {out.strip()}"
                return rows

        with EventStore.open(root) as store:
            page = run_cycle(Interleaving(store), cursor=cursor, batch=10)  # type: ignore[arg-type]
        assert ran.startswith("exit 0"), (
            f"the interleaved retention pass did not run cleanly: {ran}"
        )
        best = max((incident.score for incident in page.incidents), default=None)
        return best, page.events_correlated, reads

    protected = tmp_path / "protected"
    protected.mkdir()
    guarded_score, guarded_window, reads = interleaved(protected)

    assert reads >= 2, (
        f"the cycle made {reads} read(s), so there was no gap between a progress "
        "read and a context read for the prune to land in — this test would "
        "pass without exercising anything"
    )
    assert guarded_score == 52, (
        f"a prune between the two reads narrowed the correlation window to "
        f"{guarded_window} events and the incident fell to score {guarded_score}"
    )

    # The same interleaving with the margin switched off. Without this the
    # assertion above would hold even if the prune never deleted anything for
    # an unrelated reason — a pass that is a no-op cannot narrow a window.
    exposed = tmp_path / "exposed"
    exposed.mkdir()
    bare_score, bare_window, _ = interleaved(exposed, "--lookback-margin", "0")
    assert bare_score != 52, (
        "the same interleaving with --lookback-margin 0 left the incident whole, "
        "so this harness does not reach the hazard it claims to cover"
    )
    assert bare_window < guarded_window, (
        f"the unprotected window ({bare_window}) was not smaller than the "
        f"protected one ({guarded_window})"
    )


@pytest.mark.security
def test_the_margin_is_reported_so_an_operator_can_see_the_cost(tmp_path: Path) -> None:
    """A control that holds evidence back must say how much, and why.

    The two withheld figures have opposite meanings — a stalled cycle versus a
    working one — so they are counted separately and both reach the report.
    """
    root = tmp_path / "root"
    root.mkdir()
    _straddle_the_boundary(root)
    _cycle(root, "--batch", "2")

    code, out = _run(_retention_main(), ["--root", str(root), "--json"])
    assert code == 0, out
    payload = json.loads(out.strip())

    assert payload["lookback_margin"] == 900.0
    assert payload["events_withheld_for_correlation"] >= 1, (
        f"the margin held rows back and did not report them: {payload}"
    )
    assert payload["effective_threshold"] == (
        payload["cursor_ingested_at"] - payload["lookback_margin"]
    )

    code, text = _run(_retention_main(), ["--root", str(root)])
    assert code == 0, text
    assert "correlation context" in text, (
        f"the human-readable form does not explain the margin: {text}"
    )


@pytest.mark.security
def test_a_margin_smaller_than_the_lookback_still_degrades(tmp_path: Path) -> None:
    """The limit of the control, pinned rather than left to the prose.

    Disjointness holds only while ``margin >= lookback``: retention deletes
    below ``cursor - margin`` and the cycle's context read starts at
    ``first - lookback``, which since ``first >= cursor`` is at or above
    ``cursor - lookback`` — above ``cursor - margin`` exactly when the margin
    is the larger. An operator who raises the pipeline's ``--lookback`` without
    raising the pass's ``--lookback-margin`` is back in the hazard, and nothing
    can detect that for them because the cycle's flag is not recorded anywhere
    the retention pass can read.

    Asserting it means nobody later reads the margin as an unconditional
    guarantee, and it is the reason both flags default to the same constant.
    """
    root = tmp_path / "root"
    root.mkdir()
    boundary = time.time() - 90 * _DAY
    # The story is spread over two hours, so a 900s margin cannot cover it
    # while a 7200s --lookback still correlates it.
    for record, at in (
        (_CLOUD, boundary - 5_400.0),
        (_IDENTITY, boundary - 3_600.0),
        (_ENDPOINT, boundary + 1_800.0),
        (_UNRELATED, time.time() - 60.0),
    ):
        with EventStore.open(root) as store:
            store.append_many((normalize(record),), ingested_at=at)

    first = _cycle(root, "--batch", "2", "--lookback", "7200")
    assert first["events_read"] == 2, f"the fixture did not consume the context: {first}"

    # The default 900s margin, against a 7200s correlation window.
    code, out = _run(
        _retention_main(),
        ["--root", str(root), "--apply", "--policy", str(_grant(tmp_path, "retain_events:apply"))],
    )
    assert code == 0, f"the retention pass exited {code}: {out}"

    second = _cycle(root, "--batch", "10", "--lookback", "7200")
    assert _best_score(second) != 52, (
        "a 900s margin protected a 7200s lookback; if that is now true the "
        "margin no longer needs to be raised alongside --lookback and both the "
        "flag help and DESIGN.md overstate the residual risk"
    )


@pytest.mark.security
def test_a_matched_margin_protects_a_widened_lookback(tmp_path: Path) -> None:
    """And the remedy the flag help prescribes actually works.

    The counterpart to the test above: the same widened window, with the margin
    raised to match, keeps the incident whole. Without this the test above
    would only show that *something* about the wide window fails.
    """
    root = tmp_path / "root"
    root.mkdir()
    boundary = time.time() - 90 * _DAY
    for record, at in (
        (_CLOUD, boundary - 5_400.0),
        (_IDENTITY, boundary - 3_600.0),
        (_ENDPOINT, boundary + 1_800.0),
        (_UNRELATED, time.time() - 60.0),
    ):
        with EventStore.open(root) as store:
            store.append_many((normalize(record),), ingested_at=at)

    _cycle(root, "--batch", "2", "--lookback", "7200")
    code, out = _run(
        _retention_main(),
        [
            "--root",
            str(root),
            "--apply",
            "--lookback-margin",
            "7200",
            "--policy",
            str(_grant(tmp_path, "retain_events:apply")),
        ],
    )
    assert code == 0, f"the retention pass exited {code}: {out}"

    second = _cycle(root, "--batch", "10", "--lookback", "7200")
    assert _best_score(second) == 52, (
        f"a matched margin did not protect the widened window: {second}"
    )
