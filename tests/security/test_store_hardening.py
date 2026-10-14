# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The event store holds evidence — hold its properties closed.

``store/`` is the first package in this platform that writes a database, and
it writes one whose rows are security evidence. Three classes of failure
matter, and each gets assertions rather than a comment:

* **Integrity** — history cannot be rewritten (the engine refuses ``UPDATE``),
  and a row edited outside this platform is detected on read rather than
  returned as a plausible event.
* **Containment** — the database cannot escape the gitignored lab-data root,
  the package reaches no network or subprocess, and it reads no clock.
* **Injection** — no caller value becomes SQL text. Asserted over the AST,
  because "we used parameters" is a property of today's code and this test is
  what keeps it a property of tomorrow's.

The store also inherits ``ingest/``'s no-message-body invariant, and that is
checked here on the *read* path: an email body smuggled into a stored row
must not survive reconstruction.
"""

from __future__ import annotations

import ast
import sqlite3
from pathlib import Path

import pytest
from ingest.schema import MAX_RAW_EXCERPT, NormalizedEvent
from store import (
    MAX_PROJECTION_BYTES,
    MAX_QUERY_LIMIT,
    EventStore,
    Query,
    SchemaVersionError,
    StoreIntegrityError,
    StorePathError,
    canonical_json,
    event_id,
)

from ingest import normalize

_REPO_ROOT = Path(__file__).resolve().parents[2]
_STORE_ROOT = _REPO_ROOT / "store"

#: The store needs sqlite3, hashlib, json, re and pathlib. It must not be able
#: to reach the network, spawn anything, or import code dynamically.
_BANNED_IMPORTS = {
    "socket",
    "subprocess",
    "requests",
    "urllib",
    "http",
    "ftplib",
    "telnetlib",
    "smtplib",
    "importlib",
    "pickle",
    "shelve",
    "ctypes",
}
_BANNED_CALLS = {"eval", "exec", "compile", "__import__", "input"}

#: A literal is "SQL-ish" if it carries a statement keyword. Used to decide
#: which strings must never be built by interpolation.
_SQL_KEYWORDS = (
    "SELECT ",
    "INSERT ",
    "UPDATE ",
    "DELETE ",
    "WHERE ",
    "ORDER BY",
    "FROM ",
    "CREATE ",
    "DROP ",
    "PRAGMA ",
)


def _store_modules() -> list[Path]:
    return sorted(_STORE_ROOT.rglob("*.py"))


def _is_sql(text: str) -> bool:
    upper = text.upper()
    return any(keyword in upper for keyword in _SQL_KEYWORDS)


# --------------------------------------------------------------------------
# Injection
# --------------------------------------------------------------------------


@pytest.mark.security
def test_no_sql_statement_is_built_by_interpolation() -> None:
    """No f-string, ``%``, or ``.format()`` may produce SQL text.

    The three real injection vectors, each checked separately so a failure
    names which one appeared. A fragment assembled from module literals is
    fine — what must never happen is a caller's value reaching the statement
    as text instead of as a bound parameter.
    """
    for path in _store_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            # f"... {value} ..." containing SQL
            if isinstance(node, ast.JoinedStr):
                literal = "".join(
                    part.value
                    for part in node.values
                    if isinstance(part, ast.Constant) and isinstance(part.value, str)
                )
                assert not _is_sql(literal), f"{path}: SQL built by f-string: {literal!r}"
            # "SELECT ..." % value
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                left = node.left
                if isinstance(left, ast.Constant) and isinstance(left.value, str):
                    assert not _is_sql(left.value), f"{path}: SQL built by %: {left.value!r}"
            # "SELECT ...".format(value)
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
                and isinstance(node.func.value, ast.Constant)
                and isinstance(node.func.value.value, str)
            ):
                assert not _is_sql(node.func.value.value), (
                    f"{path}: SQL built by .format(): {node.func.value.value!r}"
                )


@pytest.mark.security
def test_a_quote_in_a_filter_value_cannot_alter_the_query(tmp_path: Path) -> None:
    """The positive half: a classic payload matches nothing, and does not error."""
    with EventStore.open(tmp_path) as store:
        store.append(
            normalize("Failed password for root from 10.0.0.5 port 22 ssh2"), ingested_at=1.0
        )
        store.append(
            normalize("Accepted password for alice from 10.0.0.9 port 22 ssh2"), ingested_at=2.0
        )
        assert store.count() == 2
        for payload in ("' OR '1'='1", "'; DROP TABLE events; --", '" OR 1=1 --'):
            assert store.query(Query(user_name=payload)) == ()
            assert store.query(Query(hostname=payload)) == ()
            assert store.query(Query(observable=payload)) == ()
        # The table is still there, which a successful DROP would have ended.
        assert store.count() == 2


# --------------------------------------------------------------------------
# Integrity
# --------------------------------------------------------------------------


@pytest.mark.security
def test_stored_events_cannot_be_rewritten(tmp_path: Path) -> None:
    """Append-only is enforced by the engine, not by API discipline."""
    event = normalize("Failed password for root from 10.0.0.5 port 22 ssh2")
    assert event.observables, (
        "this test needs an event with an observable: a BEFORE UPDATE trigger "
        "fires per matched row, so an empty observables table would make the "
        "second assertion below pass vacuously"
    )
    with EventStore.open(tmp_path) as store:
        identifier = store.append(event, ingested_at=1.0)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._conn.execute(
                "UPDATE events SET projection = ? WHERE event_id = ?", ("{}", identifier)
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._conn.execute(
                "UPDATE observables SET value = ? WHERE event_id = ?", ("x", identifier)
            )
        # Unchanged, and still readable.
        assert len(store.query()) == 1


@pytest.mark.security
def test_a_row_edited_outside_the_platform_is_detected_on_read(tmp_path: Path) -> None:
    """Content addressing makes tampering loud instead of plausible."""
    with EventStore.open(tmp_path) as store:
        store.append(normalize("sshd: session opened for user root"), ingested_at=1.0)
        # UPDATE is refused, so forge by inserting a row whose projection does
        # not hash to its id — the shape a direct sqlite3 edit would leave.
        with store._conn:
            store._conn.execute(
                "INSERT INTO events (event_id, ingested_at, occurred_at, source_type, "
                "vendor, parse_status, user_name, hostname, src_ip, dst_ip, projection) "
                "VALUES (?, ?, NULL, 'unknown', 'forged', 'text', NULL, NULL, NULL, NULL, ?)",
                ("0" * 64, 2.0, "{}"),
            )
        with pytest.raises(StoreIntegrityError, match="modified outside this platform"):
            store.query()


@pytest.mark.security
def test_a_schema_written_by_another_version_is_refused(tmp_path: Path) -> None:
    """No implicit migration: old rows must not be read into a new shape."""
    with EventStore.open(tmp_path) as store, store._conn:
        store._conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
    with pytest.raises(SchemaVersionError, match="version 99"):
        EventStore.open(tmp_path).close()


# --------------------------------------------------------------------------
# Containment
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize(
    "filename",
    [
        "../escape.sqlite3",
        "../../escape.sqlite3",
        "/etc/passwd",
        "sub/dir.sqlite3",
        "..",
        ".",
        ".hidden",
        "",
        "a\x00b",
    ],
)
def test_the_database_cannot_escape_the_events_directory(tmp_path: Path, filename: str) -> None:
    with pytest.raises(StorePathError):
        EventStore.open(tmp_path, filename=filename).close()


@pytest.mark.security
def test_the_database_lands_under_the_gitignored_lab_root(tmp_path: Path) -> None:
    with EventStore.open(tmp_path) as store:
        assert store.path.parent == (tmp_path / "data" / "events").resolve()


@pytest.mark.security
def test_store_imports_nothing_that_could_reach_out_or_execute() -> None:
    for path in _store_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in _BANNED_IMPORTS, f"{path}: {alias.name}"
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in _BANNED_IMPORTS, f"{path}: {node.module}"


@pytest.mark.security
def test_store_calls_no_executor() -> None:
    for path in _store_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in _BANNED_CALLS, f"{path}: calls {node.func.id}()"


@pytest.mark.security
def test_store_reads_no_clock() -> None:
    """``ingested_at`` is injected, so the storage timeline is reproducible.

    Asserted over the AST rather than the raw source, because the package
    docstring deliberately shows a *caller* passing ``time.time()`` in. A
    text search cannot tell the documented caller apart from the module doing
    it itself, and the property under test is only the latter.
    """
    forbidden = {"now", "utcnow", "today", "time", "monotonic", "time_ns"}
    for path in _store_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in forbidden, (
                    f"{path}: reads the clock via .{node.func.attr}()"
                )


@pytest.mark.security
def test_store_adds_no_runtime_dependency() -> None:
    """``dependencies = []`` is a load-bearing repository property.

    Read from ``pyproject.toml``, not installed metadata, so this runs
    everywhere rather than skipping wherever the package is not pip-installed.
    Installed metadata is checked too when available, since that would also
    catch a dependency the build backend injected rather than one declared
    here.
    """
    import tomllib

    config = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = config["project"]["dependencies"]
    assert declared == [], f"store must not introduce runtime dependencies: {declared}"

    import importlib.metadata as metadata

    try:
        installed = metadata.requires("ianua") or []
    except metadata.PackageNotFoundError:
        return  # not installed here; the committed declaration is the contract
    runtime = [req for req in installed if "extra ==" not in req]
    assert runtime == [], f"installed metadata declares runtime dependencies: {runtime}"


# --------------------------------------------------------------------------
# Bounds
# --------------------------------------------------------------------------


@pytest.mark.security
def test_an_oversized_projection_is_refused(tmp_path: Path) -> None:
    """A hand-built event that skipped ingest/'s bounds does not get stored."""
    huge = NormalizedEvent(
        source_type="unknown",
        vendor="hand-built",
        vendor_event_id=None,
        timestamp=None,
        message="m",
        activity=None,
        parse_status="text",
        raw_excerpt="x" * (MAX_PROJECTION_BYTES + 1),
    )
    with EventStore.open(tmp_path) as store:
        with pytest.raises(StoreIntegrityError, match="ceiling"):
            store.append(huge, ingested_at=1.0)
        assert store.count() == 0, "a refused event must leave nothing behind"


@pytest.mark.security
def test_a_query_limit_cannot_exceed_the_ceiling(tmp_path: Path) -> None:
    with EventStore.open(tmp_path) as store:
        store.append(normalize("sshd: session opened for user root"), ingested_at=1.0)
        # Asking for more than the ceiling is clamped, not honored.
        assert len(store.query(Query(limit=MAX_QUERY_LIMIT * 100))) == 1
        # A non-positive limit yields nothing rather than everything.
        for limit in (0, -1, -10_000):
            assert store.query(Query(limit=limit)) == ()


# --------------------------------------------------------------------------
# Inherited invariant: no message body, including on the read path
# --------------------------------------------------------------------------


@pytest.mark.security
def test_a_smuggled_email_body_cannot_survive_reconstruction(tmp_path: Path) -> None:
    """``from_dict`` rejects undeclared keys, so the no-body rule holds on read.

    ``ingest/`` proves no parser *reads* a body. This is the other direction:
    if a row somehow carries one, rebuilding the event refuses rather than
    quietly dropping it — a silent drop would let the field round-trip through
    storage for anything reading the raw projection.
    """
    event = normalize("sshd: session opened for user root")
    payload = event.to_dict()
    payload["email"]["body"] = "secret contents"
    forged = canonical_json(payload)
    with EventStore.open(tmp_path) as store:
        with store._conn:
            store._conn.execute(
                "INSERT INTO events (event_id, ingested_at, occurred_at, source_type, "
                "vendor, parse_status, user_name, hostname, src_ip, dst_ip, projection) "
                "VALUES (?, ?, NULL, 'unknown', 'forged', 'text', NULL, NULL, NULL, NULL, ?)",
                (event_id(forged), 1.0, forged),
            )
        with pytest.raises(Exception, match="undeclared key"):
            store.query()


@pytest.mark.security
def test_a_bound_is_reasserted_on_read_not_trusted(tmp_path: Path) -> None:
    """The writer bounded the field, but the bytes have been on disk since."""
    event = normalize("sshd: session opened for user root")
    payload = event.to_dict()
    payload["raw_excerpt"] = "x" * (MAX_RAW_EXCERPT + 1)
    forged = canonical_json(payload)
    with EventStore.open(tmp_path) as store:
        with store._conn:
            store._conn.execute(
                "INSERT INTO events (event_id, ingested_at, occurred_at, source_type, "
                "vendor, parse_status, user_name, hostname, src_ip, dst_ip, projection) "
                "VALUES (?, ?, NULL, 'unknown', 'forged', 'text', NULL, NULL, NULL, NULL, ?)",
                (event_id(forged), 1.0, forged),
            )
        with pytest.raises(Exception, match="exceeds"):
            store.query()


@pytest.mark.security
def test_a_symlinked_events_directory_cannot_relocate_the_database(tmp_path: Path) -> None:
    """The one escape a filename cannot express, so the path check must catch it.

    The filename regex forbids separators and traversal, which makes the
    containment check look redundant. It is not: if ``data/events`` is itself a
    symlink pointing elsewhere, every valid filename resolves outside the root.
    Relocating an evidence database by planting a symlink is precisely the move
    the check exists for.
    """
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    events = tmp_path / "data" / "events"
    events.parent.mkdir(parents=True)
    events.symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(StorePathError, match="refusing to relocate"):
        EventStore.open(tmp_path).close()


@pytest.mark.security
def test_a_store_with_tables_but_no_version_row_is_refused(tmp_path: Path) -> None:
    """Re-stamping the current version would assert what cannot be known.

    Creation writes the tables and the version row in one transaction, so this
    state only arises if the row was removed. Treating it as a fresh database
    would re-stamp the running version onto rows of unknown provenance — a
    fail-open, and the reason this refuses instead.
    """
    with EventStore.open(tmp_path) as store, store._conn:
        store._conn.execute("DELETE FROM meta WHERE key = 'schema_version'")
    with pytest.raises(SchemaVersionError, match="no recorded schema version"):
        EventStore.open(tmp_path).close()


@pytest.mark.security
def test_a_projection_that_is_not_json_is_refused(tmp_path: Path) -> None:
    """Hash-consistent but undecodable: a row only a direct edit could produce."""
    forged = "this is not json"
    with EventStore.open(tmp_path) as store:
        with store._conn:
            store._conn.execute(
                "INSERT INTO events (event_id, ingested_at, occurred_at, source_type, "
                "vendor, parse_status, user_name, hostname, src_ip, dst_ip, projection) "
                "VALUES (?, ?, NULL, 'unknown', 'forged', 'text', NULL, NULL, NULL, NULL, ?)",
                (event_id(forged), 1.0, forged),
            )
        with pytest.raises(StoreIntegrityError, match="not JSON"):
            store.query()


@pytest.mark.security
def test_a_symlinked_database_file_cannot_relocate_the_store(tmp_path: Path) -> None:
    """The file-level twin of the directory case, checked for the same reason."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    decoy = elsewhere / "real.sqlite3"
    decoy.touch()
    events = tmp_path / "data" / "events"
    events.mkdir(parents=True)
    (events / "events.sqlite3").symlink_to(decoy)
    with pytest.raises(StorePathError, match="refusing to relocate"):
        EventStore.open(tmp_path).close()
