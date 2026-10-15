# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Behaviour of local log collection: positioning, rotation, and the CLI.

The tests that matter here are about *not losing a region of a file* and *not
re-reading one forever*, which are the same test seen from two sides. File
tailing looks like ``seek`` and ``read`` and is not: a log can rotate under you
(same name, new identity), be truncated in place (same identity, reset size),
or be caught mid-write (a partial final line). Each of those has a wrong
behaviour that is silent, and silence is the failure this platform exists to
prevent — so each gets its own test naming which loss it holds closed.

The CLI tests pin the exit-code contract, because a scheduler acts on the exit
code and nothing else.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from collect import (
    OFFSETS_VERSION,
    OffsetError,
    Position,
    SourceError,
    declare,
    declare_all,
    load_offsets,
    offsets_path,
    read_new,
    save_offsets,
)
from ingest import normalize
from store import EventStore, Query

_AUDITD = "type=SYSCALL msg=audit(1760000001.200:2): node=web-01 auid=svc-deploy comm=bash"
_CLOUD = json.dumps(
    {
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
)


def _log(tmp_path: Path, name: str = "app.log", body: str = "") -> Path:
    """A log file outside the lab-data root, which is where real logs live."""
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    path = logs / name
    path.write_text(body, encoding="utf-8")
    return path


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    root.mkdir(exist_ok=True)
    return root


# --------------------------------------------------------------------------
# Declaring a source
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_a_plain_log_file_is_declarable(tmp_path: Path) -> None:
    path = _log(tmp_path, body="one\n")
    source = declare(path)
    assert source.path == path
    assert source.key == str(path.resolve())
    assert source.name == "app.log"


@pytest.mark.unit
def test_two_spellings_of_one_file_share_a_key(tmp_path: Path) -> None:
    """Otherwise each spelling keeps its own offset and re-reads the whole file."""
    path = _log(tmp_path, body="one\n")
    indirect = path.parent / "." / path.name
    assert declare(path).key == declare(indirect).key


@pytest.mark.unit
def test_a_relative_source_is_refused(tmp_path: Path) -> None:
    """A relative path means whatever the scheduler's working directory is."""
    with pytest.raises(SourceError, match="not absolute"):
        declare("logs/app.log")


@pytest.mark.unit
def test_a_missing_source_is_refused_not_skipped(tmp_path: Path) -> None:
    """An operator who declared a source is entitled to know it is not collected.

    Skipping would start the run with a known blind spot and still exit 0.
    """
    with pytest.raises(SourceError, match="does not exist"):
        declare(tmp_path / "nope.log")


@pytest.mark.unit
def test_a_directory_is_refused(tmp_path: Path) -> None:
    with pytest.raises(SourceError, match="not a regular file"):
        declare(tmp_path)


@pytest.mark.unit
def test_declare_all_is_all_or_nothing(tmp_path: Path) -> None:
    """Collecting the valid subset would begin with a blind spot and exit 0."""
    good = _log(tmp_path, body="one\n")
    with pytest.raises(SourceError):
        declare_all((good, tmp_path / "missing.log"))


# --------------------------------------------------------------------------
# Offsets
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_absent_offsets_read_as_empty_not_an_error(tmp_path: Path) -> None:
    """A first run is legitimate; only a *corrupt* file is a refusal."""
    assert load_offsets(offsets_path(_root(tmp_path))) == {}


@pytest.mark.unit
def test_offsets_round_trip(tmp_path: Path) -> None:
    path = offsets_path(_root(tmp_path))
    positions = {"/var/log/a": Position(offset=10, inode=1, device=2, size=10)}
    save_offsets(path, positions)
    assert load_offsets(path) == positions


@pytest.mark.unit
def test_saving_twice_replaces_rather_than_appends(tmp_path: Path) -> None:
    path = offsets_path(_root(tmp_path))
    save_offsets(path, {"a": Position(offset=1, inode=1, device=1, size=1)})
    save_offsets(path, {"a": Position(offset=2, inode=1, device=1, size=2)})
    assert load_offsets(path)["a"].offset == 2
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == OFFSETS_VERSION


@pytest.mark.unit
@pytest.mark.parametrize(
    "payload",
    [
        "{not json",
        "[]",
        '{"version": 99, "sources": {}}',
        '{"version": 1}',
        '{"version": 1, "sources": []}',
        '{"version": 1, "sources": {"a": 3}}',
        '{"version": 1, "sources": {"a": {"offset": 1}}}',
        '{"version": 1, "sources": {"a": {"offset": -1, "inode": 1, "device": 1, "size": 1}}}',
        '{"version": 1, "sources": {"a": {"offset": true, "inode": 1, "device": 1, "size": 1}}}',
        '{"version": 1, "sources": {"a": {"offset": "1", "inode": 1, "device": 1, "size": 1}}}',
    ],
)
def test_corrupt_offsets_are_refused_not_treated_as_absent(tmp_path: Path, payload: str) -> None:
    """The distinction that matters: absent means start over, corrupt does not.

    Treating corruption as absent re-ingests every line of every source;
    treating it as "nothing new" skips everything written since the last run.
    Refusing is the only option that tells someone. ``True`` is in the list
    because ``bool`` is an ``int`` subclass and would otherwise pass as 1.
    """
    path = offsets_path(_root(tmp_path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(OffsetError):
        load_offsets(path)


# --------------------------------------------------------------------------
# Tailing: the three cases that make this harder than seek+read
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_a_first_run_reads_from_the_beginning(tmp_path: Path) -> None:
    """The conventional tailer default is the end, and it is wrong here.

    Starting at the end silently skips everything already in the file — which
    is exactly the history a SOC most wants on the day it is switched on.
    """
    source = declare(_log(tmp_path, body="one\ntwo\n"))
    result = read_new(source, None)
    assert [line.decode() for line in result.lines] == ["one", "two"]
    assert result.reset == "first-run"


@pytest.mark.unit
def test_nothing_new_yields_nothing(tmp_path: Path) -> None:
    source = declare(_log(tmp_path, body="one\n"))
    first = read_new(source, None)
    second = read_new(source, first.position)
    assert second.count == 0
    assert second.position is not None
    assert second.position.offset == first.position.offset  # type: ignore[union-attr]


@pytest.mark.unit
def test_only_appended_lines_are_read(tmp_path: Path) -> None:
    path = _log(tmp_path, body="one\n")
    source = declare(path)
    first = read_new(source, None)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("two\n")
    second = read_new(source, first.position)
    assert [line.decode() for line in second.lines] == ["two"]


@pytest.mark.unit
def test_a_partial_final_line_is_not_consumed(tmp_path: Path) -> None:
    """Consuming it truncates the record *and* loses the rest.

    The offset would advance past a fragment, so when the writer finished the
    line its beginning would already be behind the cursor. Holding position
    until the newline arrives is what makes the line arrive whole.
    """
    path = _log(tmp_path, body="one\n")
    source = declare(path)
    first = read_new(source, None)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("partial without newl")
    held = read_new(source, first.position)
    assert held.count == 0
    assert held.position.offset == first.position.offset  # type: ignore[union-attr]
    with path.open("a", encoding="utf-8") as handle:
        handle.write("ine\n")
    finished = read_new(source, held.position)
    assert [line.decode() for line in finished.lines] == ["partial without newline"]


@pytest.mark.unit
def test_truncation_in_place_is_detected(tmp_path: Path) -> None:
    """``: > file`` keeps the identity and resets the size.

    An offset-only reader would seek past the new end and report "nothing new"
    forever — the file would go dark and no signal would say so.
    """
    path = _log(tmp_path, body="one\ntwo\nthree\n")
    source = declare(path)
    first = read_new(source, None)
    path.write_text("fresh\n", encoding="utf-8")
    after = read_new(source, first.position)
    assert after.reset == "truncated"
    assert [line.decode() for line in after.lines] == ["fresh"]


@pytest.mark.unit
def test_rotation_is_detected_by_identity_not_by_name(tmp_path: Path) -> None:
    """A rotated log keeps its name and changes its ``(device, inode)``.

    Applying the old byte offset to the new file would skip its first ``offset``
    bytes — silently, and in the most interesting moment, since rotation
    usually follows volume.
    """
    path = _log(tmp_path, body="old one\nold two\n")
    source = declare(path)
    first = read_new(source, None)
    path.rename(path.parent / "app.log.1")
    path.write_text("brand new\n", encoding="utf-8")
    after = read_new(declare(path), first.position)
    assert after.reset == "rotated"
    assert [line.decode() for line in after.lines] == ["brand new"]


@pytest.mark.unit
def test_a_read_is_bounded_and_reports_that_more_waits(tmp_path: Path) -> None:
    """A backlog must be visible as a backlog, not as a quiet file."""
    body = "".join(f"line {index}\n" for index in range(200))
    source = declare(_log(tmp_path, body=body))
    first = read_new(source, None, max_bytes=64)
    assert first.capped is True
    assert 0 < first.count < 200
    # Progress is monotone: repeated bounded reads reach the end.
    seen, position = first.count, first.position
    for _ in range(200):
        page = read_new(source, position, max_bytes=64)
        if page.count == 0:
            break
        seen += page.count
        position = page.position
    assert seen == 200


@pytest.mark.unit
def test_an_over_long_line_is_truncated_and_counted_not_dropped(tmp_path: Path) -> None:
    """Degrade visibly: ``ingest/`` marks a truncated record, a drop is silent."""
    source = declare(_log(tmp_path, body="x" * 500 + "\nshort\n"))
    result = read_new(source, None, max_line=100)
    assert result.truncated == 1
    assert len(result.lines[0]) == 100
    assert result.lines[1] == b"short"


@pytest.mark.unit
def test_blank_lines_are_skipped(tmp_path: Path) -> None:
    source = declare(_log(tmp_path, body="one\n\n\ntwo\n"))
    assert [line.decode() for line in read_new(source, None).lines] == ["one", "two"]


@pytest.mark.unit
@pytest.mark.parametrize("bad", [0, -1])
def test_a_non_positive_cap_is_refused_rather_than_clamped(tmp_path: Path, bad: int) -> None:
    source = declare(_log(tmp_path, body="one\n"))
    with pytest.raises(ValueError):
        read_new(source, None, max_bytes=bad)
    with pytest.raises(ValueError):
        read_new(source, None, max_line=bad)


# --------------------------------------------------------------------------
# The CLI's exit-code contract
# --------------------------------------------------------------------------


def _cli_main() -> Any:
    from scripts.run_collector import main

    return main


@pytest.mark.unit
def test_a_first_pass_collects_stores_and_advances(tmp_path: Path) -> None:
    root = _root(tmp_path)
    log = _log(tmp_path, name="audit.log", body=f"{_AUDITD}\n")
    assert _cli_main()(["--root", str(root), "--source", str(log)]) == 0
    with EventStore.open(root) as store:
        assert store.count() == 1
    assert load_offsets(offsets_path(root))[str(log.resolve())].offset > 0


@pytest.mark.unit
def test_a_second_pass_with_nothing_new_exits_zero_and_stores_nothing(
    tmp_path: Path,
) -> None:
    """Nothing-new is the common outcome; a non-zero exit would page nightly."""
    root = _root(tmp_path)
    log = _log(tmp_path, name="audit.log", body=f"{_AUDITD}\n")
    main = _cli_main()
    assert main(["--root", str(root), "--source", str(log)]) == 0
    assert main(["--root", str(root), "--source", str(log)]) == 0
    with EventStore.open(root) as store:
        assert store.count() == 1


@pytest.mark.unit
def test_a_dry_run_reports_without_storing_or_advancing(tmp_path: Path) -> None:
    root = _root(tmp_path)
    log = _log(tmp_path, name="audit.log", body=f"{_AUDITD}\n")
    assert _cli_main()(["--root", str(root), "--source", str(log), "--dry-run"]) == 0
    with EventStore.open(root) as store:
        assert store.count() == 0
    assert load_offsets(offsets_path(root)) == {}


@pytest.mark.unit
@pytest.mark.parametrize(
    "argv,reason",
    [
        ([], "no source declared means nothing to do, stated rather than assumed"),
        (["--source", "relative.log"], "a relative path depends on the scheduler's cwd"),
        (["--source", "/nonexistent/x.log"], "a declared source is refused, not skipped"),
        (["--max-bytes", "0"], "a zero cap collects nothing while appearing to run"),
    ],
)
def test_a_bad_argument_exits_two(tmp_path: Path, argv: list[str], reason: str) -> None:
    root = _root(tmp_path)
    log = _log(tmp_path, body="one\n")
    base = ["--root", str(root)]
    if "--source" not in argv and argv:
        base += ["--source", str(log)]
    assert _cli_main()(base + argv) == 2, reason


@pytest.mark.unit
def test_a_root_that_does_not_exist_is_refused(tmp_path: Path) -> None:
    """A typo would otherwise build a shadow tree and report success forever."""
    log = _log(tmp_path, body="one\n")
    missing = tmp_path / "typo"
    assert _cli_main()(["--root", str(missing), "--source", str(log)]) == 2
    assert not (missing / "data").exists()


@pytest.mark.unit
def test_a_blocked_policy_exits_three_and_stores_nothing(tmp_path: Path) -> None:
    """Fail-closed: a refusal nobody can see afterwards is not a control."""
    root = _root(tmp_path)
    log = _log(tmp_path, name="audit.log", body=f"{_AUDITD}\n")
    bundle = tmp_path / "deny.json"
    bundle.write_text(
        json.dumps({"version": 1, "policy": {"collection": "deny"}}), encoding="utf-8"
    )
    assert _cli_main()(["--root", str(root), "--source", str(log), "--policy", str(bundle)]) == 3
    assert load_offsets(offsets_path(root)) == {}
    log_path = offsets_path(root).parent / "audit.log"
    records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert records[-1]["decision"] == "deny"


@pytest.mark.unit
def test_collected_logs_become_a_correlated_incident(tmp_path: Path) -> None:
    """The whole point of the stage, asserted end to end.

    An auditd text line and a CloudTrail JSON line, in two files on disk, with
    no network anywhere, must come out of the pipeline as one cross-domain
    incident. Before ``ingest/keyvalue.py`` the auditd line parsed to
    ``unknown``/``text`` with no fields and nothing could join on it.
    """
    from pipeline import run_cycle

    root = _root(tmp_path)
    audit = _log(tmp_path, name="audit.log", body=f"{_AUDITD}\n")
    cloud = _log(tmp_path, name="cloud.jsonl", body=f"{_CLOUD}\n")
    assert _cli_main()(["--root", str(root), "--source", str(audit), "--source", str(cloud)]) == 0
    with EventStore.open(root) as store:
        stored = store.query(Query(newest_first=False, limit=10))
        assert {event.event.source_type for event in stored} == {"endpoint", "cloud"}
        assert all(event.event.parse_status == "structured" for event in stored)
        result = run_cycle(store)
    assert result.fresh, "collected logs produced no incident"
    assert sorted(result.fresh[0].domains) == ["cloud", "endpoint"]


# --------------------------------------------------------------------------
# Defects found by review, each reproduced before it was fixed
# --------------------------------------------------------------------------


@pytest.mark.unit
def test_a_line_longer_than_the_byte_cap_does_not_wedge_the_source(tmp_path: Path) -> None:
    """Holding position on a no-newline read wedged the source permanently.

    Reproduced over five consecutive passes sitting at offset 0 while the CLI
    reported "nothing new" — a total blind spot on that source, forever. The
    read now extends far enough to hold one legal line, and a line past even
    that is emitted truncated so the offset still advances.
    """
    source = declare(_log(tmp_path, body="x" * 500 + "\nafter\n"))
    position, total, passes = None, 0, 0
    for _ in range(12):
        page = read_new(source, position, max_bytes=100, max_line=120)
        assert page.position is not None
        if page.count == 0 and position is not None and page.position.offset == position.offset:
            break
        total += page.count
        position = page.position
        passes += 1
    assert position is not None
    assert position.offset > 0, "the source is still wedged at offset 0"
    assert total >= 2, "the over-long line and the line after it were both lost"
    assert passes < 12, "the read never reached the end"


@pytest.mark.unit
def test_the_byte_cap_is_still_honoured_on_an_ordinary_file(tmp_path: Path) -> None:
    """The wedge fix must not become a silent override of --max-bytes.

    A floor on the cap would have raised every read to the line cap, ignoring
    an operator's explicit setting on every pass. The read is extended only
    when a legal line cannot otherwise fit.
    """
    body = "".join(f"line {index}\n" for index in range(200))
    source = declare(_log(tmp_path, body=body))
    page = read_new(source, None, max_bytes=64)
    assert page.capped is True
    assert page.position is not None
    assert page.position.offset <= 64, (
        f"read {page.position.offset} bytes under a 64-byte cap; the cap was overridden"
    )


@pytest.mark.unit
def test_truncation_followed_by_regrowth_is_detected(tmp_path: Path) -> None:
    """logrotate's copytruncate, and the case identity-plus-size cannot see.

    A file truncated and regrown PAST the old offset keeps its inode and has a
    larger size, so every other check passes and the reader resumes mid-stream.
    Reproduced: four of six new lines silently skipped with ``reset=''``. The
    trailing-byte digest is what catches it.
    """
    path = _log(tmp_path, body="aaaa\nbbbb\ncccc\ndddd\n")
    source = declare(path)
    first = read_new(source, None)
    assert first.position is not None
    path.write_text("NEW1\nNEW2\nNEW3\nNEW4\nNEW5\nNEW6\n", encoding="utf-8")
    after = read_new(source, first.position)
    assert after.reset == "replaced", f"undetected: reset={after.reset!r}"
    assert [line.decode() for line in after.lines] == [
        "NEW1",
        "NEW2",
        "NEW3",
        "NEW4",
        "NEW5",
        "NEW6",
    ]


@pytest.mark.unit
def test_a_reused_inode_does_not_resume_into_a_different_file(tmp_path: Path) -> None:
    """``(device, inode)`` can legitimately match a different file after delete.

    A filesystem is free to reuse an inode number, so identity alone is not
    proof of continuity. Simulated by crafting the stored position, which is
    what inode reuse looks like from the reader's side.
    """
    path = _log(tmp_path, body="old1\nold2\n")
    source = declare(path)
    first = read_new(source, None)
    assert first.position is not None
    path.write_text("fresh1\nfresh2\nfresh3\n", encoding="utf-8")
    status = path.stat()
    as_if_reused = Position(
        offset=first.position.offset,
        inode=status.st_ino,
        device=status.st_dev,
        size=status.st_size,
        fingerprint=first.position.fingerprint,
    )
    after = read_new(source, as_if_reused)
    assert after.reset == "replaced"
    assert [line.decode() for line in after.lines] == ["fresh1", "fresh2", "fresh3"]


@pytest.mark.unit
def test_paging_through_a_file_never_re_reads_it(tmp_path: Path) -> None:
    """The monotone-progress invariant that caught a fingerprint mismatch.

    Storing the digest of the just-consumed chunk and verifying it by reading
    back from the file agreed only while the chunk was at least
    FINGERPRINT_BYTES long, so every smaller page saw a mismatch, reset to
    zero, and re-read from the start: 1709 lines from a 200-line file. Both
    sides now compute it the same way, so they agree by construction.
    """
    body = "".join(f"line {index}\n" for index in range(200))
    source = declare(_log(tmp_path, body=body))
    seen, position = 0, None
    for _ in range(400):
        page = read_new(source, position, max_bytes=64)
        if page.count == 0:
            break
        seen += page.count
        position = page.position
        assert page.reset == "" or page.reset == "first-run", (
            f"a plain forward page reported reset={page.reset!r}"
        )
    assert seen == 200, f"read {seen} lines from a 200-line file"


@pytest.mark.unit
def test_one_unreadable_source_does_not_starve_the_others(tmp_path: Path) -> None:
    """Before this, a single failure returned 1 before any offset was saved.

    So every *healthy* source re-read its whole window every run and never
    advanced: one broken source took the others down with it, silently and
    forever. Each source is now isolated, and the pass reports 1 so a
    scheduler still knows something needs attention.
    """
    from unittest import mock

    import collect

    root = _root(tmp_path)
    good = _log(tmp_path, name="good.log", body=f"{_AUDITD}\n")
    bad = _log(tmp_path, name="bad.log", body=f"{_AUDITD}\n")
    real_read = collect.read_new

    def fail_for_bad(source: Any, previous: Any, **kwargs: Any) -> Any:
        if source.name == "bad.log":
            raise OSError("simulated unreadable source")
        return real_read(source, previous, **kwargs)

    with mock.patch("scripts.run_collector.read_new", fail_for_bad):
        code = _cli_main()(["--root", str(root), "--source", str(good), "--source", str(bad)])
    assert code == 1, "a failed source must still report that attention is needed"
    saved = load_offsets(offsets_path(root))
    assert str(good.resolve()) in saved, "the healthy source's progress was discarded"
    assert str(bad.resolve()) not in saved
    with EventStore.open(root) as store:
        assert store.count() == 1, "the healthy source's events were not stored"


@pytest.mark.unit
def test_offsets_are_not_advanced_when_the_report_cannot_be_written(tmp_path: Path) -> None:
    """Report, then advance — the ordering stage 4 learned the hard way.

    Moving the offsets consumes the lines: nothing will ever read that region
    again. So a report that fails *after* the save leaves events in the store
    that no operator was ever told about, and a pass that exits 1 while having
    silently made progress. Doing it the other way round costs a re-read,
    which is noise, instead of an unannounced blind spot.

    Asserted by failing the report write rather than by reading the source
    order, because the ordering is only a real control if the failure path
    honours it — the suite stayed green with the two blocks swapped until this
    existed.
    """
    from unittest import mock

    root = _root(tmp_path)
    log = _log(tmp_path, name="ordered.log", body=f"{_AUDITD}\n")

    with mock.patch("scripts.run_collector._print_text", side_effect=OSError("stdout closed")):
        code = _cli_main()(["--root", str(root), "--source", str(log)])

    assert code == 1, "a report that could not be written must not look like success"
    saved = load_offsets(offsets_path(root))
    assert str(log.resolve()) not in saved, (
        "the offsets advanced past lines nobody was told about; the report must be "
        "written before the position moves"
    )


@pytest.mark.unit
def test_an_unusable_lock_directory_is_an_error_not_a_traceback(tmp_path: Path) -> None:
    """Every other startup failure in this CLI is a message and exit 2.

    The lock's ``mkdir``/``touch``/``chmod`` used to run at ``__enter__``,
    outside every ``try``, so an unwritable ``data/collect`` reached the
    terminal as a traceback. The operator who hits it first is the one
    following the runbook: the documented manual pass, run as themselves,
    after the documented root cron entry has already created the directory as
    root. Found by review.
    """
    from unittest import mock

    root = _root(tmp_path)
    log = _log(tmp_path, name="locked.log", body=f"{_AUDITD}\n")

    with mock.patch.object(
        Path, "mkdir", side_effect=PermissionError("Permission denied: data/collect")
    ):
        code = _cli_main()(["--root", str(root), "--source", str(log)])

    assert code == 2, "an unusable lock directory must exit 2 like other startup failures"


@pytest.mark.unit
def test_the_same_source_declared_twice_is_collected_once(tmp_path: Path) -> None:
    """Otherwise the pass double-reads it and then misreports what it did.

    ``--source X --source X`` produced two ``Source`` objects sharing one key,
    so the same region was read twice from one stored position and appended
    twice, while ``results[key]`` collapsed to a single entry — the audit
    record then said "read N lines from 1 of 2 sources" about a pass that read
    one file twice. The store's content addressing hid the duplicate events;
    the misstated record is the part that cannot be undone. Found by review.
    """
    root = _root(tmp_path)
    log = _log(tmp_path, name="twice.log", body=f"{_AUDITD}\n")

    code = _cli_main()(["--root", str(root), "--source", str(log), "--source", str(log)])
    assert code == 0
    with EventStore.open(root) as store:
        assert store.count() == 1
    audit = (offsets_path(root).parent / "audit.log").read_text(encoding="utf-8")
    assert "collect_logs:1" in audit, (
        "the gate record counted the same source twice: " + audit.splitlines()[-1][:200]
    )


@pytest.mark.unit
def test_offsets_are_not_saved_when_the_store_rejects_the_events(tmp_path: Path) -> None:
    """The ordering claim: offsets advance only after the events are durable.

    Nothing asserted it, so moving the save into the read loop would have lost
    lines permanently with the suite green.
    """
    from unittest import mock

    root = _root(tmp_path)
    log = _log(tmp_path, name="audit.log", body=f"{_AUDITD}\n")

    def refuse(*args: Any, **kwargs: Any) -> int:
        raise OSError("simulated store failure")

    with mock.patch.object(EventStore, "append_many", refuse):
        assert _cli_main()(["--root", str(root), "--source", str(log)]) == 1
    assert load_offsets(offsets_path(root)) == {}, (
        "offsets advanced over lines whose events were never stored"
    )


@pytest.mark.unit
def test_the_collector_stamps_strictly_after_the_stores_mark(tmp_path: Path) -> None:
    """A clock behind the mark must not produce an event at exactly the mark.

    The pipeline's keyset is strictly after ``(ingested_at, event_id)``, so an
    event written at exactly the mark with a lower event_id sits behind a
    cursor that has already passed it. Removing the clamp halts collection with
    exit 1; using plain ``max(now, mark)`` loses events silently.
    """
    root = _root(tmp_path)
    log = _log(tmp_path, name="audit.log", body=f"{_AUDITD}\n")
    with EventStore.open(root) as store:
        store.append_many((normalize(_CLOUD),), ingested_at=4_000_000_000.0)
        mark = store.high_water_mark()
    assert mark is not None
    assert _cli_main()(["--root", str(root), "--source", str(log)]) == 0
    with EventStore.open(root) as store:
        advanced = store.high_water_mark()
        assert advanced is not None
        assert advanced > mark, "the pass did not advance the mark, so it stamped at or below it"
        assert store.count() == 2


@pytest.mark.unit
def test_an_over_long_line_at_the_end_of_the_file_is_not_extended_past_it(
    tmp_path: Path,
) -> None:
    """The extension is bounded by what is actually there, not by ``max_line``.

    ``extra = min(max_line + 1, available) - len(chunk)`` can be zero or
    negative when the budget already reached end-of-file, and reading a
    negative count would drain the rest of the handle. Exercised with a final
    line that has no newline and exactly fills the budget.
    """
    # The budget already holds more than one legal line, so the extension is
    # negative and must not be read: a negative count would drain the handle.
    source = declare(_log(tmp_path, name="exact.log", body="X" * 200))
    page = read_new(source, None, max_bytes=100, max_line=20)
    assert page.position is not None
    # The line cannot end inside the budget, so it is emitted truncated and the
    # offset advances by exactly what was EMITTED — not by what was read.
    # Advancing by the whole chunk is what discarded the rest, and the first
    # version of this test asserted `offset == 100` while only 20 bytes were
    # emitted, blessing an 80% silent loss as correct. Found by review.
    assert page.truncated == 1
    assert len(page.lines[0]) == 20
    assert page.position.offset == 20, "the offset moved past bytes nobody read"
    assert page.capped is True


@pytest.mark.unit
def test_an_over_long_record_arrives_whole_across_passes_rather_than_being_discarded(
    tmp_path: Path,
) -> None:
    """The module's claim — "the remainder may arrive as further truncated
    records; that is degradation, not loss" — was false as written.

    The no-newline branch advanced by ``len(chunk)`` while emitting only
    ``max_line`` bytes, so ``len(chunk) - max_line`` bytes were passed over and
    could never be re-read. With the shipped caps that discarded up to 8 MiB
    minus 64 KiB *per pass* while the report said ``truncated: 1``,
    indistinguishable from an ordinary backlog. Measured at 4505 of 5410 bytes
    before the fix. Found by review.

    Asserted as byte accounting rather than as an offset, because an offset
    assertion is exactly what blessed the loss.
    """
    filler = 5000
    tail = "".join(f"line {index}\n" for index in range(5))
    body = "X" * filler + "\n" + tail
    source = declare(_log(tmp_path, name="long.log", body=body))
    size = len(body.encode())

    emitted = 0
    truncated = 0
    collected: list[bytes] = []
    position = None
    for _ in range(500):
        page = read_new(source, position, max_bytes=1000, max_line=100)
        emitted += sum(len(line) for line in page.lines)
        truncated += page.truncated
        collected.extend(page.lines)
        position = page.position
        if not page.capped:
            break

    assert position is not None
    assert position.offset == size, "the source did not reach the end of the file"

    # The mechanism, not a ratio. Advancing by `max_line` means the 5000-byte
    # run arrives as one piece per `max_line` bytes — about 50 of them. The
    # broken version advanced by the whole 1000-byte budget, so it emitted 5
    # pieces and silently passed over the other 900 bytes of each window.
    assert truncated >= filler // 100 - 10, (
        f"only {truncated} truncated pieces for a {filler}-byte run; the remainder "
        "is being passed over rather than arriving as further records"
    )
    # Byte accounting: what is not emitted is only ever the per-line cap's own
    # truncation, which is pre-existing, documented and counted. Measured at
    # 4230 of 5036 here, against 905 before the fix.
    assert emitted > 4 * 905, (
        f"only {emitted} of {size} bytes were ever emitted; the no-newline branch "
        "is still discarding its budget"
    )
    # And the genuine records after the over-long run arrive intact — byte for
    # byte, not carrying a tail of the filler fused onto the front. A fused
    # record is worse than a lost one: `Xtype=USER_AUTH …` normalizes to
    # `unrecognized`/`partial` with no user and no address, so a real auth
    # record becomes an unattributed one.
    assert b"line 4" in collected, "the records after the over-long run did not arrive"
    assert not [line for line in collected if line.startswith(b"X") and b"line" in line], (
        "a genuine record arrived fused onto the tail of the over-long run"
    )


@pytest.mark.unit
def test_the_default_caps_are_exercised(tmp_path: Path) -> None:
    """Every other tail test passes explicit caps, so the defaults were untested.

    A default of zero would make the collector read nothing while reporting
    success, and no test would have noticed.
    """
    from collect import MAX_BYTES_PER_RUN, MAX_LINE_BYTES

    assert MAX_BYTES_PER_RUN >= MAX_LINE_BYTES, (
        "the byte cap below the line cap makes every long line need an extended read"
    )
    source = declare(_log(tmp_path, body="one\ntwo\n"))
    page = read_new(source, None)  # no caps passed: the defaults must work
    assert [line.decode() for line in page.lines] == ["one", "two"]
