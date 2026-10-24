# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""Three loaders raise the error type their docstrings promise, and nothing else.

A caller handles a loader's documented type, and anything else reaches it as a
traceback. Measured on ``2090519`` under CPython 3.11, 3.12 and 3.13, these
escaped:

* ``EgressAllowlist.load``: invalid UTF-8 as ``UnicodeDecodeError``, 100,000
  nested brackets as ``RecursionError``, a 5000-digit integer as a bare
  ``ValueError``, and a path with an embedded NUL as ``ValueError`` from
  ``open()``. Its docstring promises ``EgressAllowlistError`` "on a missing,
  unreadable or malformed file".
* ``collect.declare``: a 5000-byte path and a 300-byte component as
  ``OSError`` (ENAMETOOLONG), and a log under a directory the collector's user
  may not search as ``PermissionError``. ``SourceError`` is the documented
  refusal.
* ``collect.load_offsets``: 100,000 nested brackets as ``RecursionError``,
  which neither caller catches. The collector's pass and the SLO monitor's
  ``collection-pending`` measurement both died with a traceback.

All three already failed closed, so none of this was a bypass. It was a
contract that did not hold, which is a crash for exactly the caller written
against the contract.

Every refusal names the file and quotes none of its content. The decoder's own
text quotes the offending byte, so the UTF-8 refusal says where it is instead.
"""

from __future__ import annotations

import contextlib
import errno
import json
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

from agents.policies.egress import MAX_ALLOWLIST_BYTES, EgressAllowlist, EgressAllowlistError
from collect import OffsetError, SourceError, declare, load_offsets, offsets_path
from collect.offsets import MAX_OFFSETS_BYTES
from sli.indicators import measure_collection_pending

#: 100,000 nested brackets: past json's recursion limit on every interpreter.
_DEPTH_BOMB = b"[" * 100_000

#: The inputs measured escaping ``EgressAllowlist.load``, each with the exception
#: it escaped as (now the refusal's cause) and the words the refusal must use.
_HOSTILE_ALLOWLISTS = {
    "invalid-utf8": (b'{"hosts": ["\xff"]}', UnicodeDecodeError, "not valid UTF-8"),
    "depth-bomb": (_DEPTH_BOMB, RecursionError, "nesting depth exceeds parser limits"),
    "int-digit-limit": (b'{"version": ' + b"9" * 5000 + b"}", ValueError, "not valid JSON"),
}


def _quotes_none_of(message: str, content: bytes) -> bool:
    """No 12-byte run of ``content`` is in ``message``, nor any non-ASCII byte as hex."""
    text = content.decode("latin-1")
    if any(text[i : i + 12] in message for i in range(max(1, len(text) - 11))):
        return False
    return not any(f"0x{byte:02x}" in message for byte in content if byte > 0x7F)


def _pathlib_raises(path: Path) -> bool:
    """Does ``Path.is_symlink()`` raise for ``path``, or swallow the error?

    Probed rather than read off ``sys.version_info``. Through 3.13 it raises
    ENAMETOOLONG and EACCES; on 3.14 it is ``os.path.islink``, which swallows
    every ``OSError``, so ``declare`` refuses those paths as "does not exist".
    Both are a :class:`SourceError`, which is the contract; only the first
    reaches the new "cannot be examined" refusal.
    """
    try:
        path.is_symlink()
    except OSError:
        return True
    return False


def _dac_enforced(tmp_path: Path) -> bool:
    """Does this process get EACCES from a directory it cannot search?

    Probed rather than read off ``geteuid()``, as in
    ``test_backup_manifest_shape.py``: the CI runner is not root, and root with
    ``CAP_DAC_OVERRIDE`` dropped is refused like anyone else.
    """
    probe = tmp_path / "dac-probe"
    probe.mkdir()
    (probe / "f").write_text("x", encoding="utf-8")
    probe.chmod(0o600)
    try:
        (probe / "f").stat()
    except PermissionError:
        return True
    else:
        return False
    finally:
        probe.chmod(0o700)


# --------------------------------------------------------------------------
# EgressAllowlist.load
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize(
    ("body", "cause", "reason"),
    list(_HOSTILE_ALLOWLISTS.values()),
    ids=list(_HOSTILE_ALLOWLISTS),
)
def test_a_malformed_allowlist_is_refused_as_an_allowlist_error(
    tmp_path: Path, body: bytes, cause: type[BaseException], reason: str
) -> None:
    """Each escaped before, past every ``except EgressAllowlistError`` a caller writes."""
    path = tmp_path / "egress.json"
    path.write_bytes(body)
    with pytest.raises(EgressAllowlistError, match=reason) as caught:
        EgressAllowlist.load(path)
    message = str(caught.value)
    assert str(path) in message, f"the refusal does not name the file: {message!r}"
    assert isinstance(caught.value.__cause__, cause), "the original error is not chained"
    assert _quotes_none_of(message, body), f"the refusal quotes the file: {message!r}"


@pytest.mark.security
def test_the_duplicate_key_refusal_is_not_rewrapped(tmp_path: Path) -> None:
    """``EgressAllowlistError`` is a ``ValueError``, and so is the int-digit limit.

    The parse step therefore re-raises the duplicate-key hook's own refusal
    before its ``except ValueError`` clause. Without that, the hook's message
    would arrive wrapped as "not valid JSON", which is wrong about the file, and
    the existing ``match="duplicate key"`` tests would not notice, because the
    wrapped text still contains it.
    """
    path = tmp_path / "egress.json"
    path.write_text('{"version": 1, "hosts": [], "hosts": []}', encoding="utf-8")
    with pytest.raises(EgressAllowlistError) as caught:
        EgressAllowlist.load(path)
    assert str(caught.value).startswith("duplicate key 'hosts'"), str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.security
def test_an_unopenable_allowlist_path_is_refused_as_an_allowlist_error(tmp_path: Path) -> None:
    """``open()`` refuses an embedded NUL with ``ValueError``, not ``OSError``."""
    with pytest.raises(EgressAllowlistError, match="not readable") as caught:
        EgressAllowlist.load(str(tmp_path / "egress\x00.json"))
    assert isinstance(caught.value.__cause__, ValueError)


# --------------------------------------------------------------------------
# collect.declare
# --------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.parametrize(
    "make",
    [
        pytest.param(lambda tmp: "/var/log/" + "a" * 5000, id="path-past-PATH_MAX"),
        pytest.param(lambda tmp: str(tmp / ("a" * 300)), id="component-past-NAME_MAX"),
    ],
)
def test_a_path_too_long_to_examine_is_a_source_error(
    tmp_path: Path, make: Callable[[Path], str]
) -> None:
    """ENAMETOOLONG escaped ``declare`` from its first probe, on 3.11 to 3.13.

    The path is named once. The OSError's own text repeats it, and for this
    error the path is the long part.
    """
    raw = make(tmp_path)
    with pytest.raises(SourceError) as caught:
        declare(raw)
    message = str(caught.value)
    assert message.count(raw) == 1, "the refusal should name the path exactly once"
    if _pathlib_raises(Path(raw)):
        assert "cannot be examined" in message, message[-200:]
        assert getattr(caught.value.__cause__, "errno", None) == errno.ENAMETOOLONG


@pytest.mark.security
def test_a_source_behind_an_unsearchable_directory_is_a_source_error(tmp_path: Path) -> None:
    """The realistic case: an unprivileged collector declares a root-only log.

    Measured on 3.11, 3.12 and 3.13 by running ``declare`` as an unprivileged
    user: ``PermissionError: [Errno 13]`` escaped. Skipped where it would be
    vacuous, which is not on the CI runner.
    """
    if not _dac_enforced(tmp_path):
        pytest.skip("this process bypasses DAC checks, so the result would be vacuous")
    locked = tmp_path / "locked"
    locked.mkdir()
    log = locked / "app.log"
    log.write_text("x\n", encoding="utf-8")
    locked.chmod(0o600)  # listable, not searchable: a child's lstat is EACCES
    try:
        with pytest.raises(SourceError) as caught:
            declare(log)
        assert str(log) in str(caught.value)
        if _pathlib_raises(log):
            assert "cannot be examined" in str(caught.value)
            assert isinstance(caught.value.__cause__, PermissionError)
    finally:
        locked.chmod(0o700)


@pytest.mark.security
@pytest.mark.parametrize("probe", ["is_symlink", "exists", "is_file", "resolve", "readlink"])
def test_every_filesystem_probe_is_refused_not_only_the_first(tmp_path: Path, probe: str) -> None:
    """A real ENAMETOOLONG or EACCES surfaces at the first probe, and races at later ones.

    So each probe is made to fail in turn. ``readlink`` runs only to name a
    symlink's target in its refusal, so for it the declared path is a link, and
    a link removed between the two calls is the race it stands for.
    """
    declared = tmp_path / "app.log"
    if probe == "readlink":
        target = tmp_path / "target.log"
        target.write_text("x\n", encoding="utf-8")
        declared.symlink_to(target)
    else:
        declared.write_text("x\n", encoding="utf-8")
    real = getattr(Path, probe)

    def denied(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == declared:
            raise PermissionError(errno.EACCES, "Permission denied", str(self))
        return real(self, *args, **kwargs)

    with (
        mock.patch.object(Path, probe, denied),
        pytest.raises(SourceError, match=r"cannot be examined \(Permission denied\)") as caught,
    ):
        declare(declared)
    assert isinstance(caught.value.__cause__, PermissionError)


# --------------------------------------------------------------------------
# collect.load_offsets
# --------------------------------------------------------------------------


@pytest.mark.security
def test_a_depth_bombed_offsets_file_is_an_offset_error(tmp_path: Path) -> None:
    """It caught ``(OSError, ValueError)``, and ``RecursionError`` is neither."""
    path = offsets_path(tmp_path)
    path.parent.mkdir(mode=0o700, parents=True)
    path.write_bytes(_DEPTH_BOMB)
    with pytest.raises(OffsetError, match="nesting depth exceeds parser limits") as caught:
        load_offsets(path)
    message = str(caught.value)
    assert str(path) in message
    assert isinstance(caught.value.__cause__, RecursionError)
    assert _quotes_none_of(message, _DEPTH_BOMB)


def _broken_offsets_paths(tmp_path: Path) -> dict[str, Path]:
    """Offsets paths that are broken rather than new, one per errno regime.

    Each used to read as ``{}`` — "never collected" — because ``load`` asked
    ``path.exists()`` first and ``exists()`` answers False for any error it
    meets, not only for ENOENT. Measured on CPython 3.13.17 before the fix.
    """
    blocker = tmp_path / "parent-is-a-file"
    blocker.write_text("not a directory\n", encoding="utf-8")
    loop, other = tmp_path / "loop.json", tmp_path / "loop2.json"
    loop.symlink_to(other)
    other.symlink_to(loop)
    return {
        "enotdir": blocker / "offsets.json",
        "eloop": loop,
        "embedded-nul": Path(f"{tmp_path}/off\x00sets.json"),
    }


@pytest.mark.security
@pytest.mark.parametrize("regime", ["enotdir", "eloop", "embedded-nul"])
def test_a_broken_offsets_path_is_refused_not_read_as_never_collected(
    tmp_path: Path, regime: str
) -> None:
    """The residual #300 recorded, and it was never 3.14-only.

    ``exists()`` answers False for ENOTDIR, ELOOP and an embedded NUL on every
    supported interpreter, so all three returned ``{}`` and the collector
    restarted every source from byte zero without saying so — which is what
    this module's own absent-vs-corrupt rule forbids. Only ENOENT is absent.
    """
    path = _broken_offsets_paths(tmp_path)[regime]
    with pytest.raises(OffsetError) as caught:
        load_offsets(path)
    assert "cannot be read" in str(caught.value), str(caught.value)
    assert caught.value.__cause__ is not None, "the original error is not chained"


@pytest.mark.security
def test_a_genuinely_absent_offsets_file_still_reads_as_never_collected(
    tmp_path: Path,
) -> None:
    """The control for the test above: ENOENT must stay ``{}``, not become a refusal.

    Both spellings of a first run: the file missing from an existing directory,
    and the whole ``data/collect`` tree not made yet, which is what the very
    first pass on a fresh root actually sees.
    """
    made = tmp_path / "made"
    path = offsets_path(made)
    path.parent.mkdir(mode=0o700, parents=True)
    assert load_offsets(path) == {}, "a missing file in an existing directory"
    assert load_offsets(offsets_path(tmp_path / "fresh")) == {}, "a missing tree"


@pytest.mark.security
def test_an_unreadable_offsets_file_is_refused_rather_than_read_as_absent(
    tmp_path: Path,
) -> None:
    """EACCES is the case 3.14 adds, and the one an operator hits for real.

    Through 3.13 ``exists()`` propagates it, so the old code raised a bare
    ``PermissionError``; on 3.14 pathlib's predicates swallow every ``OSError``
    and it would have read as ``{}``. Reading first makes both a refusal.
    """
    if not _dac_enforced(tmp_path):
        pytest.skip("this process bypasses DAC checks, so the result would be vacuous")
    path = offsets_path(tmp_path)
    path.parent.mkdir(mode=0o700, parents=True)
    path.write_text('{"version": 2, "sources": {}}', encoding="utf-8")
    path.chmod(0o000)
    try:
        with pytest.raises(OffsetError, match="cannot be read") as caught:
            load_offsets(path)
        assert isinstance(caught.value.__cause__, PermissionError)
    finally:
        path.chmod(0o600)


@pytest.mark.security
def test_an_invalid_utf8_offsets_file_names_the_reason_and_not_the_byte(
    tmp_path: Path,
) -> None:
    """``UnicodeDecodeError``'s own text quotes the offending byte; this does not.

    The refusal already had the right *type* — ``UnicodeDecodeError`` is a
    ``ValueError``, which the old clause caught — but it interpolated the
    decoder's message, so one byte of the file reached the error. Same
    treatment ``EgressAllowlist.load`` gives invalid UTF-8: the reason and the
    offset, never the value.
    """
    body = b'{"version": 2, "sources": {"\xff": {}}}'
    path = offsets_path(tmp_path)
    path.parent.mkdir(mode=0o700, parents=True)
    path.write_bytes(body)
    with pytest.raises(OffsetError, match="not valid UTF-8") as caught:
        load_offsets(path)
    message = str(caught.value)
    assert "invalid start byte" in message, message
    assert str(path) in message
    assert isinstance(caught.value.__cause__, UnicodeDecodeError)
    assert _quotes_none_of(message, body), f"the refusal quotes the file: {message!r}"


# --------------------------------------------------------------------------
# Neither loader reads an unbounded file
# --------------------------------------------------------------------------


@pytest.mark.security
def test_an_oversized_offsets_file_is_refused_rather_than_read_into_memory(
    tmp_path: Path,
) -> None:
    """An unbounded read is a ``MemoryError``, which is neither documented outcome.

    The real ceiling, not a patched one: the size check runs before any parse,
    so the body does not have to be valid JSON. The refusal states the ceiling
    and no measurement of the file, so it quotes nothing about its content.
    """
    path = offsets_path(tmp_path)
    path.parent.mkdir(mode=0o700, parents=True)
    path.write_bytes(b"a" * (MAX_OFFSETS_BYTES + 1))
    with pytest.raises(OffsetError, match="larger than") as caught:
        load_offsets(path)
    assert str(MAX_OFFSETS_BYTES) in str(caught.value)
    assert str(path) in str(caught.value)


@pytest.mark.security
def test_an_offsets_file_exactly_at_the_ceiling_still_loads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bound is inclusive: a file *at* the ceiling is fine, one byte past is not.

    The ceiling is patched down to the document's own length so the boundary is
    exercised exactly, rather than by writing four mebibytes of valid JSON.
    """
    body = '{"version": 2, "sources": {}}'
    path = offsets_path(tmp_path)
    path.parent.mkdir(mode=0o700, parents=True)
    path.write_text(body, encoding="utf-8")
    monkeypatch.setattr("collect.offsets.MAX_OFFSETS_BYTES", len(body))
    assert load_offsets(path) == {}, "a file exactly at the ceiling must load"
    monkeypatch.setattr("collect.offsets.MAX_OFFSETS_BYTES", len(body) - 1)
    with pytest.raises(OffsetError, match="larger than"):
        load_offsets(path)


@pytest.mark.security
def test_an_oversized_allowlist_is_refused_rather_than_read_into_memory(
    tmp_path: Path,
) -> None:
    """Same hole, same fix, in the sibling loader."""
    path = tmp_path / "egress.json"
    path.write_bytes(b"a" * (MAX_ALLOWLIST_BYTES + 1))
    with pytest.raises(EgressAllowlistError, match="larger than") as caught:
        EgressAllowlist.load(path)
    assert str(MAX_ALLOWLIST_BYTES) in str(caught.value)


@pytest.mark.security
def test_an_allowlist_exactly_at_the_ceiling_still_loads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The inclusive boundary again, and the shipped default is far below it."""
    body = '{"version": 1, "hosts": []}'
    path = tmp_path / "egress.json"
    path.write_text(body, encoding="utf-8")
    monkeypatch.setattr("agents.policies.egress.MAX_ALLOWLIST_BYTES", len(body))
    assert EgressAllowlist.load(path).hosts == ()
    monkeypatch.setattr("agents.policies.egress.MAX_ALLOWLIST_BYTES", len(body) - 1)
    with pytest.raises(EgressAllowlistError, match="larger than"):
        EgressAllowlist.load(path)


# --------------------------------------------------------------------------
# declare() promises a Source or a SourceError, even when resolve() raises
# --------------------------------------------------------------------------


@pytest.mark.security
def test_a_symlink_loop_at_resolve_is_a_source_error(tmp_path: Path) -> None:
    """``resolve()`` reports a symlink loop as ``RuntimeError``, with no errno.

    So ``declare``'s ``except OSError`` never saw it. Measured: ``RuntimeError``
    on CPython 3.11.15 and 3.12.13; on 3.13.17 a non-strict resolve tolerates a
    loop and returns the path, so the real loop is unreachable there and the
    clause is driven by a mock on every interpreter instead. Reachable in
    production only by a race — an ancestor becoming a loop after ``is_file()``
    has succeeded — which is exactly why the contract has to hold.
    """
    declared = tmp_path / "app.log"
    declared.write_text("x\n", encoding="utf-8")
    real = Path.resolve

    def loops(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == declared:
            raise RuntimeError(f"Symlink loop from {self!r}")
        return real(self, *args, **kwargs)

    with (
        mock.patch.object(Path, "resolve", loops),
        pytest.raises(SourceError, match="cannot be resolved") as caught,
    ):
        declare(declared)
    assert isinstance(caught.value.__cause__, RuntimeError)
    assert str(declared) in str(caught.value)


@pytest.mark.security
@pytest.mark.parametrize("escaping", [RecursionError, NotImplementedError])
def test_resolve_does_not_swallow_the_other_runtime_errors(
    tmp_path: Path, escaping: type[BaseException]
) -> None:
    """The reason #300 left this unwrapped, answered rather than ignored.

    Both subclass ``RuntimeError``, and neither means "symlink loop": one is
    this process out of stack, the other a platform that cannot resolve. A bare
    ``except RuntimeError`` would have turned both into a ``SourceError`` that
    blames the operator's path. They must still propagate.
    """
    declared = tmp_path / "app.log"
    declared.write_text("x\n", encoding="utf-8")
    real = Path.resolve

    def raises(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == declared:
            raise escaping("planted")
        return real(self, *args, **kwargs)

    with mock.patch.object(Path, "resolve", raises), pytest.raises(escaping, match="planted"):
        declare(declared)


# --------------------------------------------------------------------------
# The callers, which already catch the documented types
# --------------------------------------------------------------------------


@pytest.mark.security
def test_the_collector_refuses_an_unexaminable_source_before_doing_anything(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 2 as before, now through ``CollectError`` rather than ``OSError``.

    The exit code was already right, because ``run_collector`` catches
    ``OSError`` at startup too. What changes is the message: the operator's
    path and a reason, instead of ``[Errno 36]`` and the path a second time.
    """
    from scripts.run_collector import main

    root = tmp_path / "root"
    root.mkdir()
    raw = "/var/log/" + "a" * 5000
    assert main(["--root", str(root), "--source", raw]) == 2
    err = capsys.readouterr().err
    assert err.startswith(f"error: source {raw} "), err[:120]
    assert "Traceback" not in err
    if _pathlib_raises(Path(raw)):
        assert "cannot be examined" in err
    assert not (root / "data").exists(), "a refused startup created the data tree"


@pytest.mark.security
def test_the_collector_refuses_a_depth_bombed_offsets_file_and_keeps_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Before: ``RecursionError`` out of ``main``, past ``except (CollectError, ...)``.

    Now exit 1, as for every other corrupt offsets file. Nothing is read or
    stored, and the damaged file stays as it was for the operator to inspect.
    """
    from scripts.run_collector import main

    root = tmp_path / "root"
    root.mkdir()
    log = tmp_path / "app.log"
    log.write_text("type=SYSCALL node=web-01 auid=x comm=bash\n", encoding="utf-8")
    path = offsets_path(root)
    path.parent.mkdir(mode=0o700, parents=True)
    path.write_bytes(_DEPTH_BOMB)
    assert main(["--root", str(root), "--source", str(log)]) == 1
    err = capsys.readouterr().err
    assert "nesting depth exceeds parser limits" in err, err[-300:]
    assert "Traceback" not in err
    assert path.read_bytes() == _DEPTH_BOMB, "the refused offsets file was rewritten"
    assert not (root / "data" / "events").exists(), "a refused pass opened the store"


@pytest.mark.security
def test_the_slo_monitor_grades_a_depth_bombed_offsets_file_unknown(tmp_path: Path) -> None:
    """Before: ``RecursionError`` out of the measurement, past ``(OffsetError, OSError)``."""
    path = offsets_path(tmp_path)
    path.parent.mkdir(mode=0o700, parents=True)
    path.write_bytes(_DEPTH_BOMB)
    measurement = measure_collection_pending(tmp_path, now=0.0)
    assert measurement.value is None
    assert measurement.detail == "offsets are unreadable (OffsetError)"


# --------------------------------------------------------------------------
# Every depth, and every byte string
# --------------------------------------------------------------------------


def _deepest_parse() -> int:
    """The deepest array nesting ``json.loads`` accepts when called from here."""
    low, high = 1, 1 << 18
    while low < high:
        middle = (low + high + 1) // 2
        try:
            json.loads("[" * middle + "]" * middle)
        except RecursionError:
            high = middle - 1
        else:
            low = middle
    return low


#: Each JSON loader, a document holding a nested value (at ``NESTED``) three
#: levels down, and the words its schema refusal of that value uses.
_SWEPT = [
    pytest.param(
        EgressAllowlist.load,
        EgressAllowlistError,
        '{"version": 1, "hosts": [{"address": NESTED, "port": 1, "authorization": "x"}]}',
        "must be a string",
        id="egress",
    ),
    pytest.param(
        load_offsets,
        OffsetError,
        '{"version": 2, "sources": {"/var/log/x": {"offset": NESTED}}}',
        "has a bad offset",
        id="offsets",
    ),
]


@pytest.mark.security
@pytest.mark.parametrize(("load", "error", "document", "schema_refusal"), _SWEPT)
def test_no_nesting_depth_escapes_the_documented_type(
    tmp_path: Path,
    load: Callable[[Path], object],
    error: type[Exception],
    document: str,
    schema_refusal: str,
) -> None:
    """Swept across the parser's limit, both regimes must raise the loader's type.

    Just past the limit the parser refuses. Just inside it the parse succeeds
    and the schema refusal formats the value with ``{value!r}``, and ``repr``
    recurses as deeply as the parse did. On 3.11 the two share one recursion
    budget with the Python frames between them. No depth reaches ``repr``'s
    limit once the parser has accepted, which is why only ``json.loads`` is
    guarded, but the margin is finite: measured on 3.11, six frames added
    between ``load`` and the egress refusal still fit, and a seventh turned the
    inside regime into a ``RecursionError`` that this test reports.
    """
    deepest = _deepest_parse()
    path = tmp_path / "nested.json"
    regimes: set[str] = set()
    for depth in range(deepest - 12, deepest + 3):
        path.write_text(document.replace("NESTED", "[" * depth + "]" * depth), encoding="utf-8")
        with pytest.raises(error) as caught:
            load(path)
        message = str(caught.value)
        if "nesting depth exceeds parser limits" in message:
            regimes.add("parser")
        else:
            assert schema_refusal in message, message[:200]
            regimes.add("schema")
    assert regimes == {"parser", "schema"}, f"the sweep reached only {regimes}"


#: Deterministic, as in ``test_fuzz_validators.py``, so a counterexample reproduces.
_PROPERTY = settings(max_examples=200, derandomize=True, deadline=None)

_SCALARS = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**64), max_value=2**64)
    | st.floats()
    | st.text(max_size=12)
)

#: Keys both loaders read, so generated documents reach the schema walk rather
#: than stopping at the top-level shape check.
_KEYS = st.sampled_from(
    ["version", "hosts", "address", "port", "authorization", "sources", "offset", "inode"]
) | st.text(max_size=8)

_DOCUMENTS = st.recursive(
    _SCALARS | st.sampled_from([1, 2]),
    lambda inner: st.lists(inner, max_size=3) | st.dictionaries(_KEYS, inner, max_size=4),
    max_leaves=16,
).map(lambda value: json.dumps(value).encode("utf-8"))


@pytest.mark.security
@_PROPERTY
@given(body=st.binary(max_size=512) | _DOCUMENTS)
@example(body=_HOSTILE_ALLOWLISTS["invalid-utf8"][0])
@example(body=_DEPTH_BOMB)
@example(body=_HOSTILE_ALLOWLISTS["int-digit-limit"][0])
def test_any_bytes_load_or_raise_only_the_documented_type(body: bytes) -> None:
    """The property a fuzz target would assert, run everywhere and deterministically.

    Either loader may accept the bytes or refuse them with its own type.
    Anything else propagates and fails the test, with Hypothesis naming the
    input. The measured escapes are pinned as examples.
    """
    with tempfile.TemporaryDirectory() as scratch:
        path = Path(scratch) / "loaded.json"
        path.write_bytes(body)
        with contextlib.suppress(EgressAllowlistError):
            EgressAllowlist.load(path)
        with contextlib.suppress(OffsetError):
            load_offsets(path)
