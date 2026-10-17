# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The staged collection index is bounded and validated before anything is written.

`--build` applies a fail-closed order to the bundle — size ceiling, nesting
scan, hash, parse — and then read `data/attack/index.json` with a bare
`json.loads` and bare subscripts, *after* every shard and the pin were on
disk. Same upstream, same trust (DESIGN.md §5 boundary 5), none of the same
controls. Measured on the unpatched script: a 400 KB index of nested arrays
crashed with an uncaught `RecursionError` leaving five new shards and a new
pin written and no `.REJECTED` marker; a well-formed index whose version row
lacked `version` crashed with `KeyError`.

Every path the build touches is redirected into `tmp_path`, including
`REPO_ROOT` so the rejection audit never lands in the repository's `data/`.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.unit.test_update_attack import _fixture_bundle, _upd

_BUNDLE = "enterprise-attack-99.1.json"


@pytest.fixture
def staging(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    staged = tmp_path / "staging"
    staged.mkdir()
    (staged / _BUNDLE).write_text(json.dumps(_fixture_bundle()), encoding="utf-8")
    monkeypatch.setattr(_upd, "STAGING_DIR", staged)
    monkeypatch.setattr(_upd, "DATA_DIR", tmp_path / "shards")
    monkeypatch.setattr(_upd, "DEFAULT_PIN_PATH", tmp_path / "pins" / "pin.json")
    monkeypatch.setattr(_upd, "COLLECTION_INDEX", tmp_path / "collection-index.json")
    monkeypatch.setattr(_upd, "REPO_ROOT", tmp_path)
    return staged


_OUTPUTS = ("shards", "pins", "collection-index.json")


def _nothing_written(tmp_path: Path) -> bool:
    return not any((tmp_path / name).exists() for name in _OUTPUTS)


def _nested(path: Path) -> None:
    path.write_text("[" * 200_000 + "]" * 200_000, encoding="utf-8")


def _oversized(path: Path) -> None:
    with path.open("wb") as handle:
        handle.seek(_upd._MAX_INDEX_BYTES)
        handle.write(b"\0")


def _row_without_version(path: Path) -> None:
    rows = [{"modified": "2026-01-01"}]
    path.write_text(json.dumps({"collections": [{"name": "Enterprise ATT&CK", "versions": rows}]}))


def _non_numeric_version(path: Path) -> None:
    rows = [{"version": "latest"}]
    path.write_text(json.dumps({"collections": [{"name": "Enterprise ATT&CK", "versions": rows}]}))


def _not_an_object(path: Path) -> None:
    path.write_text("[]", encoding="utf-8")


def _enterprise(version: str, modified: str) -> bytes:
    """An index whose one row carries ``version`` and the raw JSON ``modified``."""
    row = f'{{"version": {json.dumps(version)}, "modified": {modified}}}'
    return f'{{"collections": [{{"name": "Enterprise ATT&CK", "versions": [{row}]}}]}}'.encode()


# Each passed the 7e948df validator. Measured there: the surrogates wrote five
# shards and the pin, then crashed at the snapshot write with no marker; the
# versions were committed and then crashed attack.freshness; the parse errors
# crashed with no marker; the UTF-16 index evaded the depth scan (depth 150).
_BYPASSES = {
    "surrogate-escape": _enterprise("99.1", '"\\ud800"'),
    "surrogate-raw-bytes": _enterprise("99.1", '"x"').replace(b'"x"', b'"\xed\xa0\x80"'),
    "superscript-digit": _enterprise("19.\u00b2", '"2026-01-01"'),
    "circled-digit": _enterprise("19.\u2460", '"2026-01-01"'),
    "fullwidth-digits": _enterprise("\uff11\uff19.1", '"2026-01-01"'),
    "5000-digit-component": _enterprise("1." + "9" * 5000, '"2026-01-01"'),
    "5000-digit-integer-literal": _enterprise("99.1", "9" * 5000),
    "invalid-utf8": _enterprise("99.1", '"x"').replace(b'"x"', b'"\xff"'),
    "utf16-depth-150": (
        '{"collections": [{"name": "\u5b22", "x": ' + "[" * 150 + "]" * 150 + "}]}"
    ).encode("utf-16-be"),
    "object-in-modified": _enterprise("99.1", '{"a": 1}'),
    "terminal-escape-in-modified": _enterprise("99.1", json.dumps("\x1b[31m\r\nfake: line")),
}


@pytest.mark.unit
@pytest.mark.parametrize("content", list(_BYPASSES.values()), ids=list(_BYPASSES))
def test_review_bypasses_are_rejected_before_any_write(
    staging: Path, tmp_path: Path, content: bytes
) -> None:
    (staging / "index.json").write_bytes(content)
    assert _upd.build(_BUNDLE, "2026-10-17") == 1
    assert (staging / "index.json.REJECTED").is_file(), "forensic marker missing"
    assert _nothing_written(tmp_path), "a rejected index must not leave shards or a pin behind"


@pytest.mark.unit
def test_a_bom_and_an_index_at_the_ceiling_are_accepted(staging: Path, tmp_path: Path) -> None:
    enterprise = {"name": "Enterprise ATT&CK", "versions": [{"version": "99.1", "modified": ""}]}
    body = b"\xef\xbb\xbf" + json.dumps({"collections": [enterprise]}).encode()
    (staging / "index.json").write_bytes(body + b" " * (_upd._MAX_INDEX_BYTES - len(body)))
    assert _upd.build(_BUNDLE, "2026-10-17") == 0
    assert (tmp_path / "collection-index.json").read_bytes() == _upd._canonical(enterprise)


@pytest.mark.unit
@pytest.mark.parametrize(
    "stage_index",
    [_nested, _oversized, _row_without_version, _non_numeric_version, _not_an_object],
)
def test_a_bad_index_is_rejected_before_any_write(
    staging: Path, tmp_path: Path, stage_index: Callable[[Path], None]
) -> None:
    stage_index(staging / "index.json")
    assert _upd.build(_BUNDLE, "2026-10-17") == 1
    assert (staging / "index.json.REJECTED").is_file(), "forensic marker missing"
    assert _nothing_written(tmp_path), "a rejected index must not leave shards or a pin behind"


@pytest.mark.unit
def test_a_valid_index_is_snapshotted_canonically(staging: Path, tmp_path: Path) -> None:
    rows = [{"version": "99.1", "modified": "2026-01-01"}, {"version": "99.0"}]
    enterprise = {"name": "Enterprise ATT&CK", "versions": rows}
    (staging / "index.json").write_text(
        json.dumps({"collections": [{"name": "Other"}, enterprise]})
    )
    assert _upd.build(_BUNDLE, "2026-10-17") == 0
    rows[1]["modified"] = ""  # absent upstream, rendered as the empty string
    assert (tmp_path / "collection-index.json").read_bytes() == _upd._canonical(enterprise)
    assert (tmp_path / "shards" / "catalog.json").is_file()
    assert json.loads((tmp_path / "pins" / "pin.json").read_bytes())["signature"] is None


@pytest.mark.unit
def test_no_staged_index_means_no_snapshot(staging: Path, tmp_path: Path) -> None:
    assert _upd.build(_BUNDLE, "2026-10-17") == 0
    assert not (tmp_path / "collection-index.json").exists()
    assert (tmp_path / "shards" / "catalog.json").is_file()
