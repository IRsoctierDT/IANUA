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
