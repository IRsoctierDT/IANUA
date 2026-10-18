# SPDX-FileCopyrightText: 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0

"""The IANUA-rename gate must leave the gitignored lab-data root alone.

`data/` is "Local/lab data ONLY — gitignored" (AGENTS.md §4) and sensitive by
default (§5): telemetry, evidence reports, staged third-party bundles. None of
it is a repository identifier, yet the gate walked it. Measured on the
unpatched gate: a probe report under `data/reports/` carrying a legacy
identifier turned `--check` red — a required check failing on content that is
never committed, the same local-only false red `.claude/worktrees` produced
(see `test_rename_gate_scope.py`) — and `--apply` rewrote the report, which is
evidence mutated by a repository-hygiene tool.

The exclusion is matched on the first path component relative to ROOT only,
mirroring `.gitignore`'s `/data/`. It must not reach `attack/data/`, where the
committed ATT&CK shards live and must stay in scope; `EXCLUDED_PARTS` matches a
component anywhere and so could not express this. Probes are real files
carrying a real legacy identifier, so no assertion holds for want of a file.
"""

from __future__ import annotations

import pytest

from scripts.rename_to_ianua import EXCLUDED_TOP_LEVEL, REPLACEMENTS, ROOT, eligible, migrate

LEGACY = REPLACEMENTS[5][0]


@pytest.mark.unit
def test_the_lab_data_root_is_excluded() -> None:
    root_existed = (ROOT / "data").is_dir()
    probe_dir = ROOT / "data" / "_rename_gate_lab_data_probe"
    probe = probe_dir / "report.md"
    probe_dir.mkdir(parents=True, exist_ok=True)
    probe.write_text(f"# incident\nhost {LEGACY}-01 observed\n", encoding="utf-8")
    try:
        assert probe.is_file(), "the probe must exist or this test is vacuous"
        assert not eligible(probe), "lab data under data/ is scanned — and rewritten by --apply"
        changed, remaining = migrate(apply=False)
        touched = {str(p) for p in changed} | {str(p) for p, _ in remaining}
        assert str(probe.relative_to(ROOT)) not in touched
    finally:
        probe.unlink()
        probe_dir.rmdir()
        # Only remove what this test created: an operator's data/ is theirs.
        if not root_existed and not any((ROOT / "data").iterdir()):
            (ROOT / "data").rmdir()


@pytest.mark.unit
def test_committed_data_directories_elsewhere_stay_in_scope() -> None:
    """The match is on the first component only, like `.gitignore`'s `/data/`."""
    shard = ROOT / "attack" / "data" / "catalog.json"
    assert shard.is_file(), "the committed ATT&CK catalog shard is expected here"
    assert eligible(shard), "attack/data/ is committed content and must stay gated"

    nested = ROOT / ".claude" / "data" / "test_rename_gate_lab_data_probe.md"
    nested.parent.mkdir(parents=True, exist_ok=True)
    nested.write_text(f"a legacy {LEGACY} identifier\n", encoding="utf-8")
    try:
        assert eligible(nested), "a non-top-level data/ component must not be excluded"
    finally:
        nested.unlink()
        if not any(nested.parent.iterdir()):
            nested.parent.rmdir()


@pytest.mark.unit
def test_the_exclusion_names_top_level_directories_only() -> None:
    assert set(EXCLUDED_TOP_LEVEL) == {"data"}
    assert all("/" not in name and name for name in EXCLUDED_TOP_LEVEL), (
        "a top-level exclusion is one path component; a subtree goes in EXCLUDED_PREFIXES"
    )
